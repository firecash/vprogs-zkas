//! Shielded-pool spend guest.
//!
//! Reads the full private witness (notes, keys, paths — none of which ever leave the guest),
//! runs the exact verification the host builds state with, and commits the public journal:
//! anchor, nullifiers, new commitments, ciphertext hash, fee (asset, amount), optional exit.
//! In production this same guest runs on the USER'S machine — whoever proves sees the notes,
//! which is why proving is client-side by design.

use risc0_zkvm::guest::env;
use vprogs_shielded_demo_types::{verify_shielded_tx, ShieldedTxWitness};

fn main() {
    let witness: ShieldedTxWitness = env::read();
    let journal = verify_shielded_tx(&witness).expect("invalid shielded tx");
    env::commit(&journal);
}
