#![no_std]
#![no_main]

//! ZKas⇄Kaspa bridge peg-out guest.
//!
//! One transaction = one peg-out. The handler enforces, inside the proof:
//!
//! 1. **Well-formedness** — `ix_data` decodes as a v1 burn attestation with a non-zero value.
//! 2. **Inclusion** — the exit receipt `{v, recipient, n}` is a leaf under a burn root that binds
//!    to the claimed ZKas state root `r`. Tampering with `v` or `recipient` breaks the leaf hash,
//!    so a relayer cannot inflate or redirect a real burn.
//! 3. **Nullifier binding** — the transaction declares exactly one resource, and its `ResourceId`
//!    *is* the exit-nullifier `n`. Without this an attacker could point each replay at a fresh
//!    unrelated slot and mint repeatedly from one burn.
//! 4. **Single use** — that slot must be new. The slot is then written, so the L2 SMT records the
//!    nullifier as consumed.
//!
//! Invariants 3+4 are what make the peg-out replay-safe, and they are enforced *cryptographically
//! rather than by an operator*: resources are the L2 SMT state, the SMT root is `new_state` in the
//! settlement journal, and the covenant's state-continuation invariant chains it. Re-exiting a
//! burn cannot produce a valid continuation. No spent-exit registry is needed — vProgs' state
//! machine already is one.
//!
//! 5. **Canonical `R`** — the claimed state root `r` is committed by Kaspa's own proof-of-work. The
//!    relayer supplies a canonical-`R` witness (`vprogs_zk_abi::canonical_r`) alongside the
//!    attestation; the guest verifies, in-proof, the chain `r → H_fc → embedded in a Kaspa coinbase
//!    → that block's KIP-21 seq_commit`, and records the resulting `seq_commit` into the journal via
//!    the [`CanonicalSink`]. The settlement covenant then requires that `seq_commit` to equal
//!    `OpChainblockSeqCommit(canonical_kaspa_block)` for a buried block, at spend time. Together
//!    these turn "inclusion *relative to* `r`" into "inclusion in a state root Kaspa's consensus
//!    buried" — removing the checkpoint publisher the sprint bridge trusted. See
//!    `vprogs_zk_abi::zkas_bridge` and `vprogs_zk_abi::canonical_r`.
//!
//! [`CanonicalSink`]: vprogs_zk_abi::withdrawal::CanonicalSink

use vprogs_zk_abi::{
    ErrorCode,
    canonical_r::OwnedCanonicalRWitness,
    transaction_processor::process_transaction,
    withdrawal::StandardSpk,
    zkas_bridge::{BurnAttestation, split_ix_data},
};
use vprogs_zk_backend_risc0_api::{Host, Journal, Sha256};

risc0_zkvm::guest::entry!(main);

fn main() {
    process_transaction::<Sha256>(
        &mut Host,
        &mut Journal,
        |tx, _merge_idx, _context_hash, resources, exits, _deposit, canonical| {
            // (0) Split ix_data into the attestation and the trailing canonical-R witness.
            let (att_bytes, canon_bytes) = split_ix_data(tx.payload.ix_data)
                .ok_or(ErrorCode::BridgeMalformedCanonicalWitness)?;

            // (1) Decode the burn attestation the relayer put in the transaction payload.
            let att = BurnAttestation::decode(att_bytes)
                .map_err(|_| ErrorCode::BridgeMalformedAttestation)?;

            // A zero-value exit would commit a useless leaf and burn a nullifier for nothing.
            if att.receipt.v == 0 {
                return Err(ErrorCode::BridgeZeroValue.into());
            }

            // (2) The receipt must sit under a burn root that binds to the claimed state root.
            if !att.verify_inclusion::<Sha256>() {
                return Err(ErrorCode::BridgeReceiptNotIncluded.into());
            }

            // (2b) Canonical R: prove `r` is committed by the chain's proof-of-work, and record the
            // block's seq_commit for the covenant to bind on-chain. A peg-out with no valid
            // canonical-R witness produces no proof: the trust gap the sprint bridge left open.
            //
            // Single-chain deployment: the block committing `r` is itself a mergeset member of the
            // queried block, so `r` binds to seq_commit directly (verify_direct), with no `H_fc`
            // merge-mining indirection.
            let witness = OwnedCanonicalRWitness::decode(canon_bytes)
                .ok_or(ErrorCode::BridgeMalformedCanonicalWitness)?;
            let proof = witness
                .verify_direct(&att.r)
                .map_err(|_| ErrorCode::BridgeCanonicalVerifyFailed)?;
            canonical
                .set(&proof.seq_commit.as_bytes())
                .map_err(|_| ErrorCode::BridgeCanonicalVerifyFailed)?;

            // (3) Exactly one resource, and it must be the slot named by the exit-nullifier.
            let [slot] = resources else {
                return Err(ErrorCode::BridgeResourceShape.into());
            };
            if slot.id().as_slice() != att.receipt.n.as_slice() {
                return Err(ErrorCode::BridgeResourceNotNullifier.into());
            }

            // (4) First and only use of this nullifier.
            if !slot.is_new() {
                return Err(ErrorCode::BridgeReplayedExit.into());
            }
            // Commit the slot so the nullifier is recorded as consumed in the L2 SMT. The value
            // stored is the state root the exit was proven against, which makes the spend
            // auditable after the fact.
            slot.resize(32);
            slot.data_mut().copy_from_slice(&att.r);

            // (5) Emit the peg-out. From here the framework carries it: permission tree →
            // `permission_spk_hash` in the journal → covenant's two-output settlement path →
            // the recipient sweeps exactly `v` with a Merkle proof.
            exits.emit(StandardSpk::PubKey(&att.receipt.recipient), att.receipt.v)?;

            Ok(())
        },
    );
}
