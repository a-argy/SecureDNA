// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::sync::Arc;

use crate::error::DoprfError;
use crate::instant::get_now;
use crate::operations::{incorporate_responses_and_hash, make_keyserver_querysets};
use crate::scep_client::{ClientConfig, HdbClient, KeyserverSetClient};
use crate::server_selection::{ChosenSelectionSubset, SelectedKeyserver, ServerSelector};
use crate::server_version_handler::LastServerVersionHandler;
use crate::windows::Windows;
use certificates::{ExemptionTokenGroup, TokenBundle};
use doprf::active_security::ActiveSecurityKey;
use doprf::party::{KeyserverIdSet, KeyserverId};
use doprf::prf::{Query, QueryStateSet, SerializableQueryStateSet, HashPart, VerificationInput};
use doprf::tagged::{HashTag, TaggedHash};
use http_client::BaseApiClient;
use packed_ristretto::{PackableRistretto, PackedRistrettos};
use quickdna::ToNucleotideLike;
use scep_client_helpers::ClientCerts;
use shared_types::et::WithOtps;
use shared_types::hash::HashSpec;
use shared_types::hdb::HdbScreeningResult;
use shared_types::requests::RequestContext;
use shared_types::requests::RequestId;
use shared_types::requests::SerializableRequestContext;
use shared_types::synthesis_permission::Region;
use tracing::{debug, info};
use sp1_sdk::{
    include_elf, HashableKey, ProverClient, SP1Proof, SP1ProofWithPublicValues, SP1Stdin,
    SP1VerifyingKey,
};

pub struct DoprfConfig<'a, S> {
    pub api_client: &'a BaseApiClient,
    pub server_selector: Arc<ServerSelector>,
    pub request_ctx: &'a RequestContext,
    pub certs: Arc<ClientCerts>,
    pub region: Region,
    /// Whether to request debug_info from the servers
    pub debug_info: bool,
    pub sequences: &'a [S],
    pub max_windows: u64,
    /// A freeform version hint for the caller, used for tracking client
    /// distribution (similar to User-Agent in HTTP)
    pub version_hint: String,
    /// Exemption tokens.
    pub ets: Vec<WithOtps<TokenBundle<ExemptionTokenGroup>>>,
    pub server_version_handler: &'a LastServerVersionHandler,
}

impl<'a, S> DoprfConfig<'a, S> {
    fn client_config(&self) -> ClientConfig {
        ClientConfig {
            api_client: self.api_client.clone(),
            certs: self.certs.clone(),
            version_hint: self.version_hint.clone(),
            debug_info: self.debug_info,
        }
    }

    pub fn nucleotide_total_count<N>(&self) -> Result<u64, DoprfError>
    where
        S: AsRef<[N]>,
    {
        self.sequences
            .iter()
            .map(|seq| seq.as_ref().len())
            .try_fold(0u64, |total, len| total.checked_add(len.try_into().ok()?))
            .ok_or(DoprfError::SequencesTooBig)
    }
}

#[derive(Debug)]
pub struct DoprfOutput {
    /// The number of hashes sent to the HDB
    pub n_hashes: u64,
    /// True iff all sequences are shorter than the minimum length demanded by the hash spec.
    pub too_short: bool,
    /// The consolidation returned from the HDB
    pub response: HdbScreeningResult,
}

impl DoprfOutput {
    fn too_short() -> DoprfOutput {
        Self {
            n_hashes: 0,
            too_short: true,
            response: HdbScreeningResult::default(),
        }
    }
}

/// An internal struct representing the result of the windowing step of DOPRF.
#[derive(Debug)]
struct DoprfWindows {
    /// Total window count.
    count: u64,
    /// Combined windows from the supplied sequences.
    combined_windows: Vec<(HashTag, String)>,
    /// The indices of records that generated at least one window.
    /// These are used to fix up the indices returned by the HDB.
    non_empty_records: Vec<u64>,
}

impl DoprfWindows {
    /// Turn a sequence into hashable windows.
    fn create<N: ToNucleotideLike + Copy, S: AsRef<[N]>>(
        sequences: impl Iterator<Item = S>,
        hash_spec: &HashSpec,
        max_windows: u64,
    ) -> Result<Self, DoprfError> {
        let window_iters = sequences
            .map(|seq| Windows::from_dna(seq.as_ref().iter().copied(), hash_spec))
            .collect::<Result<Vec<_>, _>>()?;

        let n_windows = window_iters
            .iter()
            .map(|iter| iter.size_hint().1)
            .try_fold(0u64, |total, len| total.checked_add(len?.try_into().ok()?))
            .ok_or(DoprfError::SequencesTooBig)?;

        if n_windows > max_windows {
            return Err(DoprfError::SequencesTooBig);
        }

        // Allows us to assume the next `as u64` will always work.
        if u64::try_from(window_iters.len()).is_err() {
            return Err(DoprfError::SequencesTooBig);
        }

        let non_empty_records: Vec<u64> = window_iters
            .iter()
            .enumerate()
            .filter_map(|(record, iter)| (iter.size_hint().0 > 0).then_some(record as u64))
            .collect();

        let combined_windows: Vec<(HashTag, String)> = window_iters.into_iter().flatten().collect();

        Ok(DoprfWindows {
            count: n_windows,
            combined_windows,
            non_empty_records,
        })
    }
}

struct DoprfClient<'a, S> {
    config: DoprfConfig<'a, S>,
    nucleotide_total_count: u64,
    keyserver_id_set: KeyserverIdSet,
    keyservers: Vec<(SelectedKeyserver, Option<u64>)>,
    keyserver_threshold: u32,
    active_security_key: ActiveSecurityKey,
    hdb_client: HdbClient,
}

impl<'a, S> DoprfClient<'a, S> {
    /// Given a DOPRF config, select keyservers and a hdbserver, and open
    /// a connection to the HDB.
    async fn open(
        config: DoprfConfig<'a, S>,
        nucleotide_total_count: u64,
    ) -> Result<Self, DoprfError> {
        // if either of these return an error, then a refresh is required by whoever holds the server selector
        // not our problem! they need to check DoprfError::SelectionRefreshRequired
        let ChosenSelectionSubset {
            keyserver_threshold,
            active_security_key,
            keyservers,
            hdb,
        } = config.server_selector.clone().choose().await?;

        let keyserver_id_set: KeyserverIdSet =
            keyservers.iter().map(|ks| ks.id).collect::<Vec<_>>().into();

        info!(
            "{}: selected keyservers=[{}], hdb={}",
            config.request_ctx.id,
            keyservers
                .iter()
                .fold(String::new(), |mut s, ks| {
                    s.push_str(", ");
                    s.push_str(&ks.to_string());
                    s
                })
                .trim_start_matches([' ', ',']),
            hdb
        );

        let keyservers = {
            let mut v = Vec::with_capacity(keyservers.len());
            for keyserver in keyservers {
                let last_server_version = config
                    .server_version_handler
                    .get_server_version(keyserver.domain.clone())
                    .await?;
                v.push((keyserver, last_server_version));
            }
            v
        };

        let last_hdbserver_version = config
            .server_version_handler
            .get_server_version(hdb.domain.clone())
            .await?;

        let hdb_client = HdbClient::open(
            hdb,
            config.client_config(),
            nucleotide_total_count,
            last_hdbserver_version,
            keyserver_id_set.clone(),
            config.region,
            !config.ets.is_empty(),
        )
        .await?;

        config
            .server_version_handler
            .set_server_version(hdb_client.domain().to_string(), hdb_client.server_version())
            .await;

        Ok(Self {
            config,
            nucleotide_total_count,
            keyserver_id_set,
            keyservers,
            hdb_client,
            keyserver_threshold,
            active_security_key,
        })
    }

    fn id(&self) -> &RequestId {
        &self.config.request_ctx.id
    }

    fn sequences_too_short_for_hash_spec<N>(&self) -> bool
    where
        S: AsRef<[N]>,
    {
        match self.hdb_client.state.hash_spec.min_width_bp() {
            Some(min) => self.config.sequences.iter().all(|s| s.as_ref().len() < min),
            None => false,
        }
    }

    async fn connect_to_keyservers(&self) -> Result<KeyserverSetClient, DoprfError> {
        let keyserver_set_client = KeyserverSetClient::open(
            self.keyservers.clone(),
            self.config.client_config(),
            self.nucleotide_total_count,
            self.keyserver_id_set.clone(),
        )
        .await?;

        for client in keyserver_set_client.clients() {
            self.config
                .server_version_handler
                .set_server_version(client.domain().to_string(), client.server_version())
                .await;
        }

        Ok(keyserver_set_client)
    }

    /// Window the given sequences using the hash spec from the current HDB
    /// connection and the configured max window size.
    fn window<N: ToNucleotideLike + Copy, T: AsRef<[N]>>(
        &self,
        sequences: impl Iterator<Item = T>,
    ) -> Result<DoprfWindows, DoprfError> {
        DoprfWindows::create(
            sequences,
            &self.hdb_client.state.hash_spec,
            self.config.max_windows,
        )
    }

    async fn hash<R>(&self, windows: &DoprfWindows) -> Result<(PackedRistrettos<R>, VerificationInput), DoprfError>
    where
        R: From<TaggedHash> + PackableRistretto + 'static,
        <R as PackableRistretto>::Array: Send + 'static,
    {
        if windows.combined_windows.is_empty() {
            return Err(DoprfError::SequencesTooBig);
        }

        // add one for active security checksum
        let hash_total_count = windows
            .count
            .checked_add(1)
            .ok_or(DoprfError::SequencesTooBig)?;

        // added 'inputs' return value for recursive proof
        let (querystate, inputs) = make_keyserver_querysets(
            self.config.request_ctx,
            &windows.combined_windows,
            self.keyserver_threshold as usize,
            &self.active_security_key,
        );

        let ks = self.connect_to_keyservers().await?;

        // query keyservers with initial hash to get keyserver response querysets of hashes
        let now = get_now();
        let querystate_ristrettos = PackedRistrettos::<Query>::from(&querystate);
        let keyserver_responses = ks.query(hash_total_count, &querystate_ristrettos).await?;
        let querying_duration = now.elapsed();
        debug!("Querying key servers done. Took: {:.2?}", querying_duration);

        const VERIFICATION_ELF: &[u8] = include_bytes!("../../../verification_proof/elf/riscv32im-succinct-zkvm-elf");

        // Initialize the proving client.
        let client = ProverClient::new();
        // Setup the proving and verifying keys.
        let (verification_pk, verification_vk) = client.setup(VERIFICATION_ELF);

        let mut stdin = SP1Stdin::new();

        // Write the verification keys: recursive proof
        let vkeys = inputs.iter().map(|input| input.vk.hash_u32()).collect::<Vec<_>>();
        stdin.write::<Vec<[u32; 8]>>(&vkeys);

        // Write the public values: recursive proof
        let public_values_write =
            inputs.iter().map(|input| input.proof.public_values.to_vec()).collect::<Vec<_>>();
        stdin.write::<Vec<Vec<u8>>>(&public_values_write);

        // Write the proofs: recursive proof
        //
        // Note: this data will not directly read by the aggregation program, instead it will be
        // witnessed by the prover during the recursive aggregation process inside SP1 itself.
        for input in inputs {
            let SP1Proof::Compressed(proof) = input.proof.proof else { panic!() };
            stdin.write_proof(*proof, input.vk.vk);
        }

        // Write values needed to incorporate responses and hash
        stdin.write::<SerializableQueryStateSet>(&querystate.to_serializable_set());
        stdin.write::<Vec<(KeyserverId, PackedRistrettos<HashPart>)>>(&keyserver_responses);
        stdin.write::<SerializableRequestContext>(&self.config.request_ctx.to_serializable_request_context());

        // DEBUGGING SECTION START
        // Execute the verification_proof program using the `ProverClient.execute` method,
        let (mut public_values, execution_report) = client.execute(VERIFICATION_ELF, stdin.clone()).run().unwrap();
        println!(
            "Verification program executed with {} cycles",
            execution_report.total_instruction_count() + execution_report.total_syscall_count()
        );

        // Read the public values
        let verified_status = public_values.read::<bool>();
        println!("Verificationation Proof: Recursive proof return value --> {:?}", verified_status);
        let proof_tagged_hash = public_values.read::<PackedRistrettos<TaggedHash>>();

        let local_tagged_hash: PackedRistrettos<TaggedHash> = incorporate_responses_and_hash(self.config.request_ctx, querystate, keyserver_responses)
            .await?;

        if proof_tagged_hash.encoded_items() == local_tagged_hash.encoded_items() {
            println!("Verificationation Proof: Incorporated responses match.");
        } else {
            println!("Verificationation Proof: Incorporated responses do not match.EDIT");
        }
        
        let verification_proof = 
            SP1ProofWithPublicValues::load("/client/output/verification_proof-with-pis.bin").expect("loading proof failed");
        let hdb_verification_input = VerificationInput {
            proof: verification_proof,
            vk: verification_vk.clone(),
        };
        // DEBUGGING SECTION END

        // // PROOF GENERATION
        // // Generate the proof for the given program and input
        // let (verification_pk, verification_vk) = client.setup(VERIFICATION_ELF);
        // let mut verification_proof = client.prove(&verification_pk, stdin).run().unwrap();
        // println!("generated proof");

        // // Verify proof and public values
        // client.verify(&verification_proof, &verification_vk).expect("verification failed");

        // // Save the proof to file
        // verification_proof.save("/client/output/verification_proof-with-pis.bin").expect("saving proof failed");

        // let local_tagged_hash: PackedRistrettos<TaggedHash> = incorporate_responses_and_hash(self.config.request_ctx, querystate, keyserver_responses)
        //     .await?;

        // let hdb_verification_input = VerificationInput {
        //     proof: verification_proof,
        //     vk: verification_vk.clone(),
        // };
        // // PROOF GENERATION SECTION END
        let packed_ristrettos: PackedRistrettos<R> = local_tagged_hash
            .iter_decoded()
            .map(|item| R::from(item.unwrap()))
            .collect();

        Ok((packed_ristrettos, hdb_verification_input))
    }
}

/// Takes a slice of sequences, hashes them, sends them to the keyservers,
/// then sends the results to the hdb, per the DOPRF protocol.
pub async fn process<'a, NLike, SliceN>(
    config: DoprfConfig<'a, SliceN>,
) -> Result<DoprfOutput, DoprfError>
where
    NLike: ToNucleotideLike + Copy + 'a,
    SliceN: AsRef<[NLike]>,
{
    let nucleotide_total_count = config.nucleotide_total_count()?;

    if nucleotide_total_count == 0 {
        info!("{}: all sequences were empty", config.request_ctx.id);
        return Ok(DoprfOutput::too_short());
    }

    let client = DoprfClient::open(config, nucleotide_total_count).await?;

    if client.sequences_too_short_for_hash_spec() {
        return Ok(DoprfOutput::too_short());
    }

    let windows = client.window(client.config.sequences.iter())?;

    if windows.count == 0 {
        info!("{}: didn't generate any windows", client.id());
        return Ok(DoprfOutput {
            n_hashes: 0,
            too_short: false,
            response: HdbScreeningResult::default(),
        });
    }

    info!("{}: generated {} windows", client.id(), windows.count);
    let (hashes, hdb_verification_input) = client.hash(&windows).await?;

    let mut response = match &client.config.ets {
        ets if !ets.is_empty() => {
            let et_windows = client.window(ets.iter().flat_map(|w| w.et.token.dna_sequences()))?;
            let (et_hashes, _) = client.hash(&et_windows).await?;
            let now = get_now();
            let response = client
                .hdb_client
                .query_with_ets(&hashes, ets, et_hashes)
                .await?;
            let hdb_duration = now.elapsed();
            debug!("Querying HDB done. Took: {:.2?}", hdb_duration);
            response
        }
        _ => {
            let now = get_now();
            let response = client.hdb_client.query(&hashes, hdb_verification_input).await?;
            let hdb_duration = now.elapsed();
            debug!("Querying HDB done. Took: {:.2?}", hdb_duration);
            response
        }
    };

    // The HDB sets `record` based on how many new-record flags it has encountered, but
    // sufficiently small FASTA records won't produce windows, so the `record`s returned
    // by the HDB need to be fixed up to account for records without windows.
    for hazard in &mut response.results {
        hazard.record = *usize::try_from(hazard.record)
            .ok()
            .and_then(|hdb_record| windows.non_empty_records.get(hdb_record))
            .ok_or(DoprfError::InvalidRecord)?;
    }

    Ok(DoprfOutput {
        n_hashes: windows.count,
        too_short: false,
        response,
    })
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    use futures::FutureExt;
    use quickdna::{BaseSequence, DnaSequence, FastaContent, Nucleotide};

    use crate::server_selection::test_utils::{
        make_test_selection, make_test_selector, peek_selector_selection,
    };
    use crate::server_selection::{
        ServerEnumerationSource, ServerSelectionConfig, ServerSelectionError,
    };
    use http_client::test_utils::ApiClientCoreMock;
    use shared_types::requests::RequestId;

    #[tokio::test]
    async fn test_bad_mark_applied() {
        // set up every request to fail (retriably)
        let mock_api_client = BaseApiClient::from(ApiClientCoreMock::from(
            |url: String, _body, _content_type, _headers, _expected_content_type| {
                async {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    Err(http_client::error::HttpError::RequestError {
                        ctx: url,
                        status: Some(418),
                        retriable: true,
                        source: "i'm a teapot".into(),
                    })
                }
                .boxed()
            },
        ));

        // define 3 keyservers (all with unique ids--no replicas) with a 2-server threshold
        let selection = make_test_selection(
            2,
            &[
                ("seattle.keyserver", 1),
                ("sf.keyserver", 2),
                ("portland.keyserver", 3),
            ],
            &["hdb"],
        );
        let selector = Arc::new(make_test_selector(
            ServerSelectionConfig {
                enumeration_source: ServerEnumerationSource::Fixed {
                    keyserver_domains: vec![],
                    hdb_domains: vec![],
                },
                soft_timeout: None,
                blocking_timeout: None,
                soft_extra_keyserver_threshold: None,
                soft_extra_hdb_threshold: None,
            },
            mock_api_client.clone(),
            selection,
            get_now(),
        ));

        let request_ctx = RequestContext::single(RequestId::new_unique());
        let certs = Arc::new(ClientCerts::load_test_certs());

        let dna = DnaSequence::<Nucleotide>::parse(0, "atcgatcgatcgatcgatcg").unwrap();

        // take a first spin
        process(DoprfConfig {
            api_client: &mock_api_client,
            server_selector: selector.clone(),
            request_ctx: &request_ctx,
            certs: certs.clone(),
            region: Region::All,
            debug_info: false,
            sequences: &[dna.as_slice()],
            max_windows: u64::MAX,
            version_hint: "test".to_owned(),
            ets: vec![],
            server_version_handler: &Default::default(),
        })
        .await
        .unwrap_err();

        let selection = peek_selector_selection(&selector).await;
        // The hdb should be marked bad, since it's telling us it's a teapot.
        assert_eq!(selection.available_hdbs(), 0);
        // The keyservers should not be marked bad, since they weren't reached.
        assert_eq!(selection.available_keyservers(), 3);

        // trying to choose should fail, since the hdb is bad, and the fixed DNS is empty
        assert!(matches!(
            selector.choose().await.unwrap_err(),
            ServerSelectionError::NoQuorum(_),
        ));
    }
}
