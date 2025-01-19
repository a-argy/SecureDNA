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
use incorporate::incorporate::incorporate_responses_and_hash;

pub fn main() {
    // Read the verification keys.
    println!("at the top of main");
    let vkeys = sp1_zkvm::io::read::<Vec<[u32; 8]>>();

    // Read the public values.
    let public_values = sp1_zkvm::io::read::<Vec<Vec<u8>>>();

    let querystate = sp1_zkvm::io::read::<SerializableQueryStateSet>().to_query_state_set();
    println!("first deserailze worked");
    let keyserver_responses = sp1_zkvm::io::read::<Vec<(KeyserverId, PackedRistrettos<HashPart>)>>();
    println!("second deserailze worked");
    let request_ctx = sp1_zkvm::io::read::<SerializableRequestContext>().to_request_context();

    // Verify the proofs.
    assert_eq!(vkeys.len(), public_values.len());
    for i in 0..vkeys.len() {
        let vkey = &vkeys[i];
        let public_values = &public_values[i];
        let public_values_digest = Sha256::digest(public_values);
        sp1_zkvm::lib::verify::verify_sp1_proof(vkey, &public_values_digest.into());
    }

    // Indicate that the proofs verified successfully
    sp1_zkvm::io::commit::<bool>(&true);

    // let hashed: PackedRistrettos<TaggedHash> =
    //     block_on(incorporate_responses_and_hash(&request_ctx, querystate, keyserver_responses)).expect("failed");
    
    // sp1_zkvm::io::commit::<PackedRistrettos<TaggedHash>>(&hashed);
    
    }
