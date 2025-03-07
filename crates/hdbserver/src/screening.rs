// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::sync::Arc;
use tracing::debug;
use anyhow::Context;
use doprf::prf::{CompletedHashValue, VerificationInput};
use futures::{StreamExt, TryStreamExt};
use http_body_util::{BodyExt, Full};
use bytes::Bytes;
use hyper::body::{Body, Incoming};
use hyper::{Request, StatusCode};
use scep::states::{EtState, ServerStateForClient};
use scep::steps::{server_et_client, server_et_seq_hashes_client};
use tracing::{error, info, warn};
use packed_ristretto::PackedRistrettos;
use sp1_sdk::{
    include_elf, HashableKey, ProverClient, SP1Proof, SP1ProofWithPublicValues, SP1Stdin,
    SP1VerifyingKey,
};

use certificates::Issued;
use doprf::tagged::{HashTag, TaggedHash};
use hdb::consolidate_windows::{consolidate_windows, HashId};
use hdb::{Exemptions, HdbConfig, HdbParams};
use minhttp::response::{self, GenericResponse};
use once_cell::sync::Lazy;
use scep::error::ScepError;
use scep::types::{ScreenCommon, ScreenWithExemptionParams};
use shared_types::hdb::HdbScreeningResult;
use shared_types::requests::RequestId;
use shared_types::synthesis_permission::SynthesisPermission;
use streamed_ristretto::hyper::{check_content_length, from_request};
use streamed_ristretto::stream::{check_content_type, ShortErrorMsg, StreamableRistretto, decode, encode};
use streamed_ristretto::HasContentType;

use crate::event_store;
use crate::state::HdbServerState;
use crate::validation::exemptions_after_validation;

static NO_EXEMPTIONS: Lazy<Arc<Exemptions>> = Lazy::new(Arc::default);

struct UnparsedTaggedHash([u8; TaggedHash::SIZE]);

impl UnparsedTaggedHash {
    fn hash_tag(&self) -> HashTag {
        HashTag::from_bytes(self.0[..4].try_into().unwrap())
    }
    fn hash_bytes(&self) -> &[u8; 32] {
        self.0[4..].try_into().unwrap()
    }
}

impl HasContentType for UnparsedTaggedHash {
    const CONTENT_TYPE: &'static str = TaggedHash::CONTENT_TYPE;
}

impl From<[u8; TaggedHash::SIZE]> for UnparsedTaggedHash {
    fn from(bytes: [u8; TaggedHash::SIZE]) -> Self {
        Self(bytes)
    }
}

impl From<UnparsedTaggedHash> for [u8; TaggedHash::SIZE] {
    fn from(hash: UnparsedTaggedHash) -> Self {
        hash.0
    }
}

impl StreamableRistretto for UnparsedTaggedHash {
    type Array = [u8; TaggedHash::SIZE];
    type ConversionError = <Self::Array as TryInto<Self>>::Error;

    fn fit_error(error: &ShortErrorMsg) -> Self::Array {
        let mut data = [255; TaggedHash::SIZE];
        data[4 + 1..TaggedHash::SIZE - 1].copy_from_slice(error);
        data
    }
}

pub async fn scep_endpoint_screen_and_verify(
    request_id: &RequestId,
    hdbs_state: Arc<HdbServerState>,
    request: Request<Incoming>,
) -> Result<GenericResponse, scep::error::ScepError<scep::error::Screen>> {
    #[derive(serde::Deserialize)]
    struct RequestWithVerification {
        ristretto_data: Vec<u8>,
        verification: VerificationInput,
    }

    // Check content type for JSON
    check_content_type(request.headers(), "application/json")
        .context("in screen_and_verify")
        .map_err(scep::error::ScepError::InvalidMessage)?;

    // Get session cookie
    let cookie = scep_server_helpers::request::get_session_cookie(request.headers())?;

    let client_state = hdbs_state
        .scep
        .clients
        .write()
        .await
        .take_session(&cookie)
        .ok_or_else(|| {
            scep::error::ScepError::InvalidMessage(anyhow::anyhow!("unknown cookie {cookie}"))
        })?;
    let client_mid = client_state.open_request().client_mid();
    let debug_info = client_state.open_request().debug_info;

    // Consume body and deserialize
    let bytes = request
        .into_body()
        .collect()
        .await
        .map_err(|e| scep::error::ScepError::InvalidMessage(e.into()))?
        .to_bytes();

    // Deserialize into our struct
    let request_data: RequestWithVerification = serde_json::from_slice(&bytes)
        .map_err(|e| scep::error::ScepError::InvalidMessage(e.into()))?;

    // Verify the proof
    let client = ProverClient::new();
    let VerificationInput { proof, vk } = request_data.verification;
    client.verify(&proof, &vk).expect("verification failed");
    println!("HDB verification successful");

    // Build a fake request to mimic the form expected in scep_endpoint_screen, data is moved
    let fake_request = Request::builder()
    .header("Content-Type", TaggedHash::CONTENT_TYPE)
    .body(Full::new(Bytes::from(request_data.ristretto_data)))
    .expect("failed to build fake request");

    let hash_count_from_content_len =
        check_content_length(fake_request.body().size_hint().exact(), TaggedHash::SIZE)
            .context("in screen")
            .map_err(scep::error::ScepError::InvalidMessage)?;

    let (params, client_state) =
        scep::steps::server_screen_client(hash_count_from_content_len, client_state)?;

    let ScreenCommon {
        region,
        provider_reference,
    } = params;

    let permit = match hdbs_state.throttle_heavy_requests() {
        Ok(permit) => permit,
        Err(err_response) => return Ok(err_response),
    };

    let (ets, exemptions) = match client_state.et_state {
        EtState::NoEt => (vec![], NO_EXEMPTIONS.clone()),
        EtState::AwaitingEtSize | EtState::PromisedEt { .. } => {
            return Err(scep::error::Screen::ScreenBeforeEt.into())
        }
        EtState::EtNeedsHashes { .. } => {
            return Err(scep::error::Screen::ScreenBeforeEtHashes.into())
        }
        EtState::EtReady { ets, hashes } => {
            let exemptions = exemptions_after_validation(
                ets.clone(),
                hashes.into_iter().collect(),
                &hdbs_state.validator,
                &hdbs_state.exemptions_roots,
                &hdbs_state.scep.revocation_list,
            )
            .await
            .map_err(|e| scep::error::Screen::EtValidation(e.to_string()))?;

            (ets, Arc::new(exemptions))
        }
    };

    if let Some(metrics) = &hdbs_state.metrics {
        metrics.requests.inc();
    }

    let num_hashes = check_content_length(fake_request.body().size_hint().exact(), TaggedHash::SIZE)
        .context("in screen")
        .map_err(ScepError::InvalidMessage)?;
    info!("{request_id}: Processing request of size {num_hashes}");

    let queries = from_request(fake_request)
        .context("in screen_and_verify")
        .map_err(ScepError::InvalidMessage)?;

    struct LogDone(RequestId);

    impl Drop for LogDone {
        fn drop(&mut self) {
            info!("{}: Done.", self.0);
        }
    }

    let logdone = LogDone(request_id.clone());

    let screen_evt_id = match event_store::insert_screen_event(
        &hdbs_state.persistence_connection,
        client_mid,
        client_state.open_request.nucleotide_total_count,
        region,
        &ets,
    )
    .await
    {
        Ok(id) => Some(id),
        Err(e) => {
            error!("Failed to persist screen event for {client_mid}: {e}");
            None
        }
    };

    let mut last_record = None;
    let hdbs_state2 = hdbs_state.clone();
    let exemptions2 = exemptions.clone();
    let hdb_responses: Result<Vec<_>, anyhow::Error> = queries
        .map(move |query| {
            let _permit = &permit;
            let _logdone = &logdone;

            let hash_id_and_query = query.map(|query: UnparsedTaggedHash| {
                let hash_id = HashId::new(query.hash_tag(), last_record);
                last_record = Some(hash_id.record);
                (hash_id, query)
            });

            let hdbs_state2 = hdbs_state2.clone();
            let exemptions2 = exemptions2.clone();
            async move {
                let (hash_id, query) = hash_id_and_query?;

                let permit = hdbs_state2
                    .hdb_queries
                    .clone()
                    .acquire_owned()
                    .await
                    .unwrap();
                // TODO: Maybe use a nursery to prevent orphans, so long as that's not too expensive?
                let hdbs_state3 = hdbs_state2.clone();
                let exemptions3 = exemptions2.clone();
                let resp = tokio::task::spawn_blocking(move || {
                    let _permit = permit;
                    let params = HdbParams {
                        region,
                        exemptions: &exemptions3,
                    };
                    let config = HdbConfig {
                        database: &hdbs_state3.database,
                        hlt: &hdbs_state3.hlt,
                    };
                    hdb::query_hdb(query.hash_bytes(), &params, &config)
                })
                .await
                .unwrap()?;

                // only incremented if there's no error
                if let Some(metrics) = &hdbs_state2.metrics {
                    metrics.hash_counter.inc();
                }

                Ok(resp.map(|r| (hash_id, r)))
            }
        })
        .buffered(hdbs_state.parallelism_per_request)
        .filter_map(|res| async { res.transpose() })
        .try_collect()
        .await;

    let hdb_responses = match hdb_responses {
        Ok(r) => r,
        Err(err) => {
            warn!("Error while processing HDB records: {err:?}");
            if let Some(metrics) = &hdbs_state.metrics {
                metrics.io_errors.inc();
            }
            return Ok(response::text(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal server error",
            ));
        }
    };

    let consolidation =
        consolidate_windows(hdb_responses.into_iter(), &hdbs_state.hash_spec, debug_info)
            .context("in screen consolidation")
            .map_err(ScepError::InternalError)?;

    let response: HdbScreeningResult = consolidation.to_hdb_screening_result(provider_reference);

    let merged_permission =
        SynthesisPermission::merge(response.results.iter().map(|r| r.synthesis_permission));
    info!(
        message = "screened",
        %client_mid,
        issued_to=client_state.open_request.cert_chain.token.issuer_description(),
        screened_bp=client_state.open_request.nucleotide_total_count,
        hash_count=hash_count_from_content_len,
        %merged_permission,
    );
    if let Some(screen_evt_id) = screen_evt_id {
        if let Err(e) = event_store::insert_screen_result(
            &hdbs_state.persistence_connection,
            screen_evt_id,
            shared_types::synthesis_permission::SynthesisPermission::merge(
                response.results.iter().map(|r| r.synthesis_permission),
            ),
        )
        .await
        {
            error!(
                "Failed to persist screening result for {}: {e}",
                client_state.open_request.client_mid()
            );
        }
    }

    let json = serde_json::to_string(&response)
        .context("in screen serialization")
        .map_err(ScepError::InternalError)?;

    Ok(response::json(StatusCode::OK, json))
}

pub async fn scep_endpoint_screen(
    request_id: &RequestId,
    hdbs_state: Arc<HdbServerState>,
    request: Request<Incoming>,
) -> Result<GenericResponse, scep::error::ScepError<scep::error::Screen>> {
    check_content_type(request.headers(), TaggedHash::CONTENT_TYPE)
        .context("in screen")
        .map_err(scep::error::ScepError::InvalidMessage)?;

    let cookie = scep_server_helpers::request::get_session_cookie(request.headers())?;

    let client_state = hdbs_state
        .scep
        .clients
        .write()
        .await
        .take_session(&cookie)
        .ok_or_else(|| {
            scep::error::ScepError::InvalidMessage(anyhow::anyhow!("unknown cookie {cookie}"))
        })?;
    let client_mid = client_state.open_request().client_mid();
    let debug_info = client_state.open_request().debug_info;

    let hash_count_from_content_len =
        check_content_length(request.body().size_hint().exact(), TaggedHash::SIZE)
            .context("in screen")
            .map_err(scep::error::ScepError::InvalidMessage)?;

    let (params, client_state) =
        scep::steps::server_screen_client(hash_count_from_content_len, client_state)?;

    let ScreenCommon {
        region,
        provider_reference,
    } = params;

    let permit = match hdbs_state.throttle_heavy_requests() {
        Ok(permit) => permit,
        Err(err_response) => return Ok(err_response),
    };

    let (ets, exemptions) = match client_state.et_state {
        EtState::NoEt => (vec![], NO_EXEMPTIONS.clone()),
        EtState::AwaitingEtSize | EtState::PromisedEt { .. } => {
            return Err(scep::error::Screen::ScreenBeforeEt.into())
        }
        EtState::EtNeedsHashes { .. } => {
            return Err(scep::error::Screen::ScreenBeforeEtHashes.into())
        }
        EtState::EtReady { ets, hashes } => {
            let exemptions = exemptions_after_validation(
                ets.clone(),
                hashes.into_iter().collect(),
                &hdbs_state.validator,
                &hdbs_state.exemptions_roots,
                &hdbs_state.scep.revocation_list,
            )
            .await
            .map_err(|e| scep::error::Screen::EtValidation(e.to_string()))?;

            (ets, Arc::new(exemptions))
        }
    };

    if let Some(metrics) = &hdbs_state.metrics {
        metrics.requests.inc();
    }

    let num_hashes = check_content_length(request.body().size_hint().exact(), TaggedHash::SIZE)
        .context("in screen")
        .map_err(ScepError::InvalidMessage)?;
    info!("{request_id}: Processing request of size {num_hashes}");

    let queries = from_request(request)
        .context("in screen")
        .map_err(ScepError::InvalidMessage)?;

    struct LogDone(RequestId);

    impl Drop for LogDone {
        fn drop(&mut self) {
            info!("{}: Done.", self.0);
        }
    }

    let logdone = LogDone(request_id.clone());

    let screen_evt_id = match event_store::insert_screen_event(
        &hdbs_state.persistence_connection,
        client_mid,
        client_state.open_request.nucleotide_total_count,
        region,
        &ets,
    )
    .await
    {
        Ok(id) => Some(id),
        Err(e) => {
            error!("Failed to persist screen event for {client_mid}: {e}");
            None
        }
    };

    let mut last_record = None;
    let hdbs_state2 = hdbs_state.clone();
    let exemptions2 = exemptions.clone();
    let hdb_responses: Result<Vec<_>, anyhow::Error> = queries
        .map(move |query| {
            let _permit = &permit;
            let _logdone = &logdone;

            let hash_id_and_query = query.map(|query: UnparsedTaggedHash| {
                let hash_id = HashId::new(query.hash_tag(), last_record);
                last_record = Some(hash_id.record);
                (hash_id, query)
            });

            let hdbs_state2 = hdbs_state2.clone();
            let exemptions2 = exemptions2.clone();
            async move {
                let (hash_id, query) = hash_id_and_query?;

                let permit = hdbs_state2
                    .hdb_queries
                    .clone()
                    .acquire_owned()
                    .await
                    .unwrap();
                // TODO: Maybe use a nursery to prevent orphans, so long as that's not too expensive?
                let hdbs_state3 = hdbs_state2.clone();
                let exemptions3 = exemptions2.clone();
                let resp = tokio::task::spawn_blocking(move || {
                    let _permit = permit;
                    let params = HdbParams {
                        region,
                        exemptions: &exemptions3,
                    };
                    let config = HdbConfig {
                        database: &hdbs_state3.database,
                        hlt: &hdbs_state3.hlt,
                    };
                    hdb::query_hdb(query.hash_bytes(), &params, &config)
                })
                .await
                .unwrap()?;

                // only incremented if there's no error
                if let Some(metrics) = &hdbs_state2.metrics {
                    metrics.hash_counter.inc();
                }

                Ok(resp.map(|r| (hash_id, r)))
            }
        })
        .buffered(hdbs_state.parallelism_per_request)
        .filter_map(|res| async { res.transpose() })
        .try_collect()
        .await;

    let hdb_responses = match hdb_responses {
        Ok(r) => r,
        Err(err) => {
            warn!("Error while processing HDB records: {err:?}");
            if let Some(metrics) = &hdbs_state.metrics {
                metrics.io_errors.inc();
            }
            return Ok(response::text(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal server error",
            ));
        }
    };

    let consolidation =
        consolidate_windows(hdb_responses.into_iter(), &hdbs_state.hash_spec, debug_info)
            .context("in screen consolidation")
            .map_err(ScepError::InternalError)?;

    let response: HdbScreeningResult = consolidation.to_hdb_screening_result(provider_reference);

    let merged_permission =
        SynthesisPermission::merge(response.results.iter().map(|r| r.synthesis_permission));
    info!(
        message = "screened",
        %client_mid,
        issued_to=client_state.open_request.cert_chain.token.issuer_description(),
        screened_bp=client_state.open_request.nucleotide_total_count,
        hash_count=num_hashes,
        %merged_permission,
    );
    if let Some(screen_evt_id) = screen_evt_id {
        if let Err(e) = event_store::insert_screen_result(
            &hdbs_state.persistence_connection,
            screen_evt_id,
            shared_types::synthesis_permission::SynthesisPermission::merge(
                response.results.iter().map(|r| r.synthesis_permission),
            ),
        )
        .await
        {
            error!(
                "Failed to persist screening result for {}: {e}",
                client_state.open_request.client_mid()
            );
        }
    }

    let json = serde_json::to_string(&response)
        .context("in screen serialization")
        .map_err(ScepError::InternalError)?;

    Ok(response::json(StatusCode::OK, json))
}

pub async fn scep_endpoint_screen_with_exemption(
    _request_id: &RequestId,
    hdbs_state: Arc<HdbServerState>,
    request: Request<Incoming>,
) -> Result<GenericResponse, scep::error::ScepError<scep::error::ScreenWithEL>> {
    let cookie = scep_server_helpers::request::get_session_cookie(request.headers())?;

    let client_state = hdbs_state
        .scep
        .clients
        .write()
        .await
        .take_session(&cookie)
        .ok_or_else(|| {
            scep::error::ScepError::InvalidMessage(anyhow::anyhow!("unknown cookie {cookie}"))
        })?;

    let bytes = request
        .into_body()
        .collect()
        .await
        .map_err(|e| scep::error::ScepError::InvalidMessage(e.into()))?
        .to_bytes();

    let params: ScreenWithExemptionParams = serde_json::from_slice(&bytes)
        .map_err(|e| scep::error::ScepError::InvalidMessage(e.into()))?;

    if params.et_size > hdbs_state.et_size_limit {
        return Err(scep::error::ScreenWithEL::EtSizeTooBig {
            actual: params.et_size,
            maximum: hdbs_state.et_size_limit,
        }
        .into());
    }

    let new_client_state = scep::steps::server_screen_with_el_client(params, client_state)?;

    hdbs_state
        .scep
        .clients
        .write()
        .await
        .add_session(
            cookie,
            ServerStateForClient::Authenticated(new_client_state),
        )
        .map_err(|_| {
            scep::error::ScepError::InternalError(anyhow::anyhow!(
                "failed to update state for cookie {cookie}"
            ))
        })?;

    // Give them the OK to hit /exemption next.
    Ok(response::json(StatusCode::OK, "{}"))
}

pub async fn scep_endpoint_exemption(
    _request_id: &RequestId,
    hdbs_state: Arc<HdbServerState>,
    request: Request<Incoming>,
) -> Result<GenericResponse, scep::error::ScepError<scep::error::ET>> {
    let cookie = scep_server_helpers::request::get_session_cookie(request.headers())?;

    let client_state = hdbs_state
        .scep
        .clients
        .write()
        .await
        .take_session(&cookie)
        .ok_or_else(|| {
            scep::error::ScepError::InvalidMessage(anyhow::anyhow!("unknown cookie {cookie}"))
        })?;

    let et_body = request
        .into_body()
        .collect()
        .await
        .map_err(|e| scep::error::ScepError::InvalidMessage(e.into()))?
        .to_bytes();

    let (client, response) = server_et_client(et_body, client_state)?;

    hdbs_state
        .scep
        .clients
        .write()
        .await
        .add_session(cookie, ServerStateForClient::Authenticated(client))
        .map_err(|_| {
            scep::error::ScepError::InternalError(anyhow::anyhow!(
                "failed to update state for cookie {cookie}"
            ))
        })?;

    // Give them the OK to hit /exemption-seq-hashes or /exemption-screen-hashes next.
    Ok(response::json(
        StatusCode::OK,
        serde_json::to_string(&response).map_err(|_| {
            scep::error::ScepError::InternalError(anyhow::anyhow!("failed to encode JSON response"))
        })?,
    ))
}

pub async fn scep_endpoint_exemption_seq_hashes(
    _request_id: &RequestId,
    hdbs_state: Arc<HdbServerState>,
    request: Request<Incoming>,
) -> Result<GenericResponse, scep::error::ScepError<scep::error::EtSeqHashes>> {
    let cookie = scep_server_helpers::request::get_session_cookie(request.headers())?;

    let client_state = hdbs_state
        .scep
        .clients
        .write()
        .await
        .take_session(&cookie)
        .ok_or_else(|| {
            scep::error::ScepError::InvalidMessage(anyhow::anyhow!("unknown cookie {cookie}"))
        })?;

    let hashes: Vec<_> = from_request::<_, CompletedHashValue>(request)
        .context("in exemption-seq-hashes")
        .map_err(ScepError::InvalidMessage)?
        .try_collect()
        .await
        .context("in exemption-seq-hashes")
        .map_err(ScepError::InvalidMessage)?;

    let client = server_et_seq_hashes_client(hashes, client_state)?;

    hdbs_state
        .scep
        .clients
        .write()
        .await
        .add_session(cookie, ServerStateForClient::Authenticated(client))
        .map_err(|_| {
            scep::error::ScepError::InternalError(anyhow::anyhow!(
                "failed to update state for cookie {cookie}"
            ))
        })?;

    // Give them the OK to hit /exemption-screen-hashes next.
    Ok(response::json(StatusCode::OK, "{}"))
}
