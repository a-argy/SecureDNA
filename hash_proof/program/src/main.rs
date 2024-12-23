// These two lines are necessary for the program to properly compile.
//
// Under the hood, we wrap your main function with some extra code so that it behaves properly
// inside the zkVM.
#![no_main]
sp1_zkvm::entrypoint!(main);

use sha3::Sha3_512;
use curve25519_dalek::ristretto::RistrettoPoint;
use alloy_sol_types::SolType;
use fibonacci_lib::{fibonacci, PublicValuesStruct};

pub fn main() {
    // Process and commit each byte array.
    loop {
        // Read a single byte array from the input.
        let bytes = sp1_zkvm::io::read::<Vec<u8>>();
        // Check for the sentinel. If it's empty, break the loop.
        if bytes.is_empty() {
            break;
        }
        // Hash the byte array directly to a RistrettoPoint.
        let hashed_point = RistrettoPoint::hash_from_bytes::<Sha3_512>(&bytes);
        // Commit the compressed hash to the zkVM for public verification.
        sp1_zkvm::io::commit_slice(hashed_point.compress().as_bytes());
    }
    // Define the sentinel value
    let sentinel: [u8; 32] = [0u8; 32];
    sp1_zkvm::io::commit_slice(&sentinel);
}
