// These two lines are necessary for the program to properly compile.
//
// Under the hood, we wrap your main function with some extra code so that it behaves properly
// inside the zkVM.
#![no_main]
sp1_zkvm::entrypoint!(main);

use futures::executor::block_on;
use sha2::Digest;
use sha2::Sha256;
use alloy_sol_types::SolType;
use doprf::prf::{SerializableQueryStateSet, HashPart};
use doprf::party::KeyserverId;
use doprf::tagged::TaggedHash;
use packed_ristretto::datatype::PackedRistrettos;
use shared_types::requests::SerializableRequestContext;

pub fn main() -> () {
    // Read the verification keys.
    let vkeys = sp1_zkvm::io::read::<Vec<[u32; 8]>>();
    // Read the public values.
    let public_values = sp1_zkvm::io::read::<Vec<Vec<u8>>>();

    // Verify the proof recursively 
    assert_eq!(vkeys.len(), public_values.len());
    for i in 0..vkeys.len() {
        let vkey = &vkeys[i];
        let public_values = &public_values[i];
        let public_values_digest = Sha256::digest(public_values);
        sp1_zkvm::lib::verify::verify_sp1_proof(vkey, &public_values_digest.into());
    }

    // Indicate that the proofs verified
    sp1_zkvm::io::commit::<bool>(&true);

    // read the serializeed QueryStateSet and deserialized
    let serialize_querystate = sp1_zkvm::io::read::<SerializableQueryStateSet>();
    let mut querystate = serialize_querystate.to_query_state_set();

    let keyserver_responses = sp1_zkvm::io::read::<Vec<(KeyserverId, PackedRistrettos<HashPart>)>>();
    let request_ctx = sp1_zkvm::io::read::<SerializableRequestContext>().to_request_context();

    // Replicating incorporate_responses_and_hash in crates/doprf_client/src/operations.rs
    for (id, ks_pr) in keyserver_responses.into_iter() {
        // Handle error return type to avoid '?'
        let parts = match ks_pr.iter_decoded().collect::<Result<Vec<HashPart>, _>>() {
            Ok(p) => p,
            Err(e) => {
                println!("Error decoding parts: {:?}", e);
                return;
            }
        };
        
        // removes thread spawning
        if let Err(e) = querystate.incorporate_response(id, &parts) {
            println!("Error incorporating response: {:?}", e);
            return;
        }
    }

    // Computes final hash, subsequently calls randomized_target.validate_responses() where checksym is verified
    // Removes thread spawning
    let hash_values = match querystate.get_hash_values() {
        Ok(values) => values,
        Err(e) => {
            println!("Error getting hash values: {:?}", e);
            return;
        }
    };
    let packed_hashes: PackedRistrettos<TaggedHash> = hash_values.into_iter().collect();

    // Commit the final hash for comparison
    sp1_zkvm::io::commit::<PackedRistrettos<TaggedHash>>(&packed_hashes);
}
    
