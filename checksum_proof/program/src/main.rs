// These two lines are necessary for the program to properly compile.
//
// Under the hood, we wrap your main function with some extra code so that it behaves properly
// inside the zkVM.
#![no_main]
sp1_zkvm::entrypoint!(main);

use alloy_sol_types::SolType;
use fibonacci_lib::{fibonacci, PublicValuesStruct};
use curve25519_dalek::ristretto::{RistrettoPoint, CompressedRistretto};
use curve25519_dalek::scalar::Scalar;
use doprf::active_security::ActiveSecurityKey;
use doprf::prf::Query;

pub fn main() {
    let hashed_concat_quries_bytes = sp1_zkvm::io::read::<[u8; 32]>();
    let hashed_concat_quries = Scalar::from_canonical_bytes(hashed_concat_quries_bytes).expect("Invalid scalar bytes");
    
    let active_security_key = sp1_zkvm::io::read::<ActiveSecurityKey>();
    
    let sum_bytes = sp1_zkvm::io::read::<[u8; 32]>();
    let sum_compressed = CompressedRistretto::from_slice(&sum_bytes).expect("Invalid compressed point");
    let sum = sum_compressed.decompress().expect("Invalid compressed point");

    let verification_factor_0_bytes = sp1_zkvm::io::read::<[u8; 32]>();
    let verification_factor_0 = Scalar::from_canonical_bytes(verification_factor_0_bytes).expect("Invalid scalar bytes");

    let blinding_factor_bytes = sp1_zkvm::io::read::<[u8; 32]>();
    let blinding_factor = Scalar::from_canonical_bytes(blinding_factor_bytes).expect("Invalid scalar bytes");

    let randomized_target = active_security_key.randomized_target(hashed_concat_quries);
    let checksum = randomized_target.get_checksum_point_for_validation(&sum);
    let x_0 = checksum * verification_factor_0.invert();

    let query = Query::from_rp(x_0 * blinding_factor);
    // Commit the compressed hash to the zkVM for public verification.
    sp1_zkvm::io::commit::<Query>(&query);
}
