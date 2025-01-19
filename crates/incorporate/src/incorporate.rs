// Copyright 2021-2024 SecureDNA Stiftung (SecureDNA Foundation) <licensing@securedna.org>
// SPDX-License-Identifier: MIT OR Apache-2.0

use crate::error::DoprfErrorNew;
use crate::instant::get_now;
use crate::progress::report_progress;
use doprf::active_security::ActiveSecurityKey;
use doprf::party::KeyserverId;
use doprf::prf::{HashPart, QueryStateSet};
use doprf::tagged::{HashTag, TaggedHash};
use packed_ristretto::{PackableRistretto, PackedRistrettos};

use shared_types::requests::RequestContext;
use tracing::debug;

#[cfg(target_arch = "wasm32")]
async fn spawn_blocking<F, R>(f: F) -> Result<R, ()>
where
    F: FnOnce() -> R + Send + 'static,
    R: Send + 'static,
{
    Ok(f())
}

#[cfg(not(target_arch = "wasm32"))]
fn spawn_blocking<F, R>(f: F) -> tokio::task::JoinHandle<R>
where
    F: FnOnce() -> R + Send + 'static,
    R: Send + 'static,
{
    tokio::task::spawn_blocking(f)
}

/// What size of chunks the requests will be made in.
/// Each chunk incurs a network roundtrip, so it's good to have larger chunks,
/// but too large and we start spending too long in CPU-bound work without yielding often enough.
///
/// Chunks should go away completely once we switch to a streaming model
pub const CHUNK_SIZE_DEFAULT: usize = 10_000;

/// Given a QueryStateSet, and a Vec of keyserver responses,
/// incorporate the responses into the querystate.
/// Then compute packed Ristretto hashes for the QueryStateSet.
/// The result is used to query HDB.
pub async fn incorporate_responses_and_hash<R>(
    request_ctx: &RequestContext,
    mut querystate: QueryStateSet,
    keyserver_responses: Vec<(KeyserverId, PackedRistrettos<HashPart>)>,
) -> Result<PackedRistrettos<R>, DoprfErrorNew>
where
    R: From<TaggedHash> + PackableRistretto + 'static,
    <R as PackableRistretto>::Array: Send + 'static,
{
    let now = get_now();
    report_progress(request_ctx);

    for (id, ks_pr) in keyserver_responses.into_iter() {
        let parts = ks_pr.iter_decoded().collect::<Result<Vec<HashPart>, _>>()?;

        querystate = spawn_blocking(move || -> Result<QueryStateSet, doprf::prf::QueryError> {
            querystate.incorporate_response(id, &parts)?;
            Ok(querystate) // hand back querystate for borrow-checking purposes
        })
        .await
        .expect("failed to join task")?;
    }

    let incorporating_duration = now.elapsed();
    debug!(
        "Incorporating keyserver answers done. Took: {:.2?}",
        incorporating_duration
    );

    let now = get_now();
    report_progress(request_ctx);
    let hash_values: PackedRistrettos<R> = spawn_blocking(move || {
        querystate
            .get_hash_values()
            .expect("error processing keyserver responses")
            .into_iter()
            .map(R::from)
            .collect()
    })
    .await
    .expect("could not join thread");

    let hash_duration = now.elapsed();
    debug!(
        "Calculating hashes with lagrange improvements done. Took: {:.2?}",
        hash_duration
    );

    report_progress(request_ctx);
    Ok(hash_values)
}
