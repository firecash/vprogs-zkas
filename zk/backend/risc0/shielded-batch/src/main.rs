//! Shielded-pool batch aggregator guest.
//!
//! For each transaction in the batch it verifies, **inside this proof**, a receipt of the spend
//! guest (`env::verify` against the pinned inner image id — resolved from assumptions the batch
//! prover supplies), so every journal it aggregates is backed by a real client proof. It then
//! replays the aggregate state transition:
//!
//! - every anchor must be a rolling root of this batch (previous settled root or later),
//! - every nullifier proves non-membership in the history-wide accumulator and is inserted —
//!   the double-spend gate against ALL history, not just this batch,
//! - commitments append to the frontier in order; fees and exits accumulate.
//!
//! The journal (`prev_state`, `new_state`, deposits hash, exits, fees, inner image id) is what a
//! settlement covenant binds on-chain: one proof, N private transactions.

use risc0_zkvm::guest::env;
use risc0_zkvm::Digest;
use vprogs_shielded_demo_types::{verify_batch, BatchWitness};

fn words_to_bytes(words: &[u32]) -> Vec<u8> {
    words.iter().flat_map(|w| w.to_le_bytes()).collect()
}

fn main() {
    let witness: BatchWitness = env::read();

    // Recursion: each aggregated journal must be vouched for by a receipt of the spend guest.
    let inner_id = Digest::from(witness.inner_image_id);
    for tx in &witness.txs {
        let words = risc0_zkvm::serde::to_vec(&tx.journal).expect("journal serialization");
        env::verify(inner_id, &words_to_bytes(&words)).expect("inner spend receipt must verify");
    }

    let journal = verify_batch(&witness).expect("invalid batch");
    env::commit(&journal);
}
