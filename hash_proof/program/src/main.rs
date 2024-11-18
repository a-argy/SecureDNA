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
    // Read the number of byte arrays.
    let num_arrays = sp1_zkvm::io::read::<usize>();

    // Process and commit each byte array.
    for _ in 0..num_arrays {
        // Read a single byte array from the input.
        let bytes = sp1_zkvm::io::read::<Vec<u8>>();

        // Hash the byte array directly to a RistrettoPoint.
        let hashed_point = RistrettoPoint::hash_from_bytes::<Sha3_512>(&bytes);

        // Commit the compressed hash to the zkVM for public verification.
        sp1_zkvm::io::commit_slice(hashed_point.compress().as_bytes());
    }
}
