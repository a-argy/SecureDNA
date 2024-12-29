// These two lines are necessary for the program to properly compile.

// Under the hood, we wrap your main function with some extra code so that it behaves properly
// inside the zkVM.
#![no_main]
sp1_zkvm::entrypoint!(main);

use sha3::Sha3_512;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use alloy_sol_types::SolType;
use fibonacci_lib::{fibonacci, PublicValuesStruct};
use doprf::prf::Query;

pub fn main() {
    // Read in each byte array from the input until we reach the sentinel value.
    loop {
        let bytes = sp1_zkvm::io::read::<Vec<u8>>();

        // Check for the sentinel, break the loop.
        if bytes.is_empty() {
            break;
        }

        // Hash the byte array directly to a RistrettoPoint.
        let hashed_point = RistrettoPoint::hash_from_bytes::<Sha3_512>(&bytes);

        // Read the serialized blinding factor from the input
        let blinding_factor_bytes = sp1_zkvm::io::read::<[u8; 32]>();
        // Convert the blinding factor to a Scalar (for use in from_rp)
        let blinding_factor = Scalar::from_canonical_bytes(blinding_factor_bytes).expect("Invalid scalar bytes");

        let query = Query::from_rp(hashed_point * blinding_factor);

        // Commit the compressed hash to the zkVM for public verification.
        sp1_zkvm::io::commit::<Query>(&query);
    }
    // Commit the sentinel value
    let sentinel = Query::sentinel();
    sp1_zkvm::io::commit::<Query>(&sentinel);
}
