//! Guest-side canonical-`R` witness: recompute a Kaspa block's KIP-21 `seq_commit` inside the
//! proof, so the peg-out covenant can confirm the ZKas state root was mined by Kaspa's own PoW.
//!
//! This is the guest half of `kaspa_shielded_core::witness_chain`. Both halves recompute
//! `seq_commit` with the **same** `kaspa_seq_commit` crate, so they cannot drift — there is no
//! hand-rolled vector to keep in sync (unlike the sha256/blake2b layers of the burn attestation).
//!
//! # What the guest proves with this
//!
//! Given the ZKas header hash `H_fc` the guest derived on the `R → H_fc` side, and a witness for
//! the Kaspa block that merge-mined it:
//!
//! 1. the Kaspa coinbase payload commits exactly that `H_fc` (`ZKMM || hex(H_fc)`, once);
//! 2. folding that payload through the sequencing hashers reproduces the Kaspa header's
//!    `seq_commit`.
//!
//! The guest then commits `(seq_commit, kaspa_block_hash)` to its journal, and the covenant requires
//! `seq_commit == OpChainblockSeqCommit(kaspa_block_hash)` at a buried depth. That is what makes `R`
//! canonical: Kaspa's own chain committed the ZKas block that produced it.

use alloc::vec::Vec;

use kaspa_hashes::Hash;
use kaspa_seq_commit::hashing::{
    miner_payload_leaf, miner_payload_root, payload_and_context_digest, seq_commit, seq_state_root,
};
use kaspa_seq_commit::types::{MinerPayloadLeafInput, SeqCommitInput, SeqState};

/// The 4-byte tag marking the 32-byte ZKas commitment in a Kaspa coinbase payload ("ZKas Merged
/// Mining"). Must equal `kaspa_consensus_core::auxpow::MERGE_MINE_MAGIC`.
pub const MERGE_MINE_MAGIC: [u8; 4] = *b"ZKMM";

/// Length of the lowercase-hex commitment following the magic (32 bytes → 64 hex chars).
const COMMITMENT_HEX_LEN: usize = 64;

/// Extract the single `H_fc` committed in a Kaspa coinbase payload, or `None` unless the magic
/// occurs **exactly once** followed by valid 64-char lowercase hex (the AuxPoW anti-ambiguity rule).
pub fn extract_hfc(payload: &[u8]) -> Option<Hash> {
    let mut found: Option<Hash> = None;
    let mut i = 0usize;
    while i + MERGE_MINE_MAGIC.len() <= payload.len() {
        if payload[i..i + MERGE_MINE_MAGIC.len()] == MERGE_MINE_MAGIC {
            let start = i + MERGE_MINE_MAGIC.len();
            let end = start + COMMITMENT_HEX_LEN;
            if end > payload.len() {
                return None;
            }
            let bytes = decode_hex32(&payload[start..end])?;
            if found.is_some() {
                return None;
            }
            found = Some(Hash::from_bytes(bytes));
            i = end;
        } else {
            i += 1;
        }
    }
    found
}

fn decode_hex32(hex: &[u8]) -> Option<[u8; 32]> {
    if hex.len() != COMMITMENT_HEX_LEN {
        return None;
    }
    let nibble = |c: u8| -> Option<u8> {
        match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'a'..=b'f' => Some(c - b'a' + 10),
            _ => None,
        }
    };
    let mut out = [0u8; 32];
    for (j, byte) in out.iter_mut().enumerate() {
        *byte = (nibble(hex[2 * j])? << 4) | nibble(hex[2 * j + 1])?;
    }
    Some(out)
}

/// A decoded canonical-`R` witness (parsed from the attestation's `ix_data`).
///
/// Borrowed to keep the guest allocation-light; only the leaf-list reconstruction allocates.
pub struct SeqCommitWitness<'a> {
    /// Kaspa coinbase payload of our mergeset block (embeds `H_fc`).
    pub kaspa_payload: &'a [u8],
    /// Our Kaspa block hash.
    pub block_hash: Hash,
    /// Big-endian blue-work bytes, as fed to `miner_payload_leaf`.
    pub blue_work_be: &'a [u8],
    /// The mergeset's other miner-payload leaves, in order, excluding ours.
    pub other_leaves: &'a [Hash],
    /// The position our leaf occupies in the ordered mergeset leaf list.
    pub leaf_index: usize,
    /// Opaque sequencing inputs, carried verbatim.
    pub activity_root: Hash,
    /// Opaque; carried verbatim.
    pub context_hash: Hash,
    /// Opaque; carried verbatim.
    pub parent_seq_commit: Hash,
}

impl<'a> SeqCommitWitness<'a> {
    /// The `H_fc` this witness's payload commits to.
    pub fn hfc(&self) -> Option<Hash> {
        extract_hfc(self.kaspa_payload)
    }

    /// Recompute the Kaspa header `seq_commit`, or `None` if `leaf_index` is out of range.
    pub fn recompute_seq_commit(&self) -> Option<Hash> {
        if self.leaf_index > self.other_leaves.len() {
            return None;
        }
        let our_leaf = miner_payload_leaf(MinerPayloadLeafInput {
            block_hash: &self.block_hash,
            blue_work_be_bytes: self.blue_work_be,
            payload: self.kaspa_payload,
        });
        let mut leaves: Vec<Hash> = Vec::with_capacity(self.other_leaves.len() + 1);
        leaves.extend_from_slice(&self.other_leaves[..self.leaf_index]);
        leaves.push(our_leaf);
        leaves.extend_from_slice(&self.other_leaves[self.leaf_index..]);

        let payload_root = miner_payload_root(leaves.into_iter());
        let pd = payload_and_context_digest(&self.context_hash, &payload_root);
        let state_root = seq_state_root(&SeqState { activity_root: &self.activity_root, payload_and_ctx_digest: &pd });
        Some(seq_commit(&SeqCommitInput { parent_seq_commit: &self.parent_seq_commit, state_root: &state_root }))
    }

    /// Full guest check: the payload commits exactly `expected_hfc`, and the recomputed `seq_commit`
    /// equals the value the covenant will read on-chain via `OpChainblockSeqCommit`.
    pub fn verify(&self, expected_hfc: Hash, expected_seq_commit: Hash) -> bool {
        self.hfc() == Some(expected_hfc) && self.recompute_seq_commit() == Some(expected_seq_commit)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn embed(hfc: Hash) -> Vec<u8> {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut out = Vec::new();
        out.extend_from_slice(b"cb-prefix");
        out.extend_from_slice(&MERGE_MINE_MAGIC);
        for b in hfc.as_bytes() {
            out.push(HEX[(b >> 4) as usize]);
            out.push(HEX[(b & 0x0f) as usize]);
        }
        out.extend_from_slice(b"tail");
        out
    }

    /// The guest recompute matches a reference `seq_commit` computed the canonical way, and `verify`
    /// binds it to the correct `H_fc`. This is the same assertion the ZKas-side `witness_chain`
    /// test makes — and because both call `kaspa_seq_commit`, agreement is structural, not vectored.
    #[test]
    fn guest_recompute_matches_reference() {
        let hfc = Hash::from_bytes([0x7c; 32]);
        let payload = embed(hfc);
        let block_hash = Hash::from_bytes([0x33; 32]);
        let blue_work_be = [0x01u8, 0x02, 0x03];
        let activity_root = Hash::from_bytes([0x44; 32]);
        let context_hash = Hash::from_bytes([0x55; 32]);
        let parent_seq_commit = Hash::from_bytes([0x66; 32]);
        let sib0 = Hash::from_bytes([0xA0; 32]);
        let sib1 = Hash::from_bytes([0xA1; 32]);

        let our_leaf = miner_payload_leaf(MinerPayloadLeafInput {
            block_hash: &block_hash,
            blue_work_be_bytes: &blue_work_be,
            payload: &payload,
        });
        let reference = {
            let ordered = [sib0, our_leaf, sib1];
            let payload_root = miner_payload_root(ordered.into_iter());
            let pd = payload_and_context_digest(&context_hash, &payload_root);
            let sr = seq_state_root(&SeqState { activity_root: &activity_root, payload_and_ctx_digest: &pd });
            seq_commit(&SeqCommitInput { parent_seq_commit: &parent_seq_commit, state_root: &sr })
        };

        let others = [sib0, sib1];
        let w = SeqCommitWitness {
            kaspa_payload: &payload,
            block_hash,
            blue_work_be: &blue_work_be,
            other_leaves: &others,
            leaf_index: 1,
            activity_root,
            context_hash,
            parent_seq_commit,
        };

        assert_eq!(w.hfc(), Some(hfc));
        assert_eq!(w.recompute_seq_commit(), Some(reference));
        assert!(w.verify(hfc, reference));
        assert!(!w.verify(Hash::from_bytes([0x99; 32]), reference), "wrong H_fc must fail");
    }

    #[test]
    fn extract_rejects_zero_or_two_commitments() {
        assert_eq!(extract_hfc(b"nope"), None);
        let hfc = Hash::from_bytes([0x11; 32]);
        let mut two = embed(hfc);
        let more = embed(hfc);
        two.extend_from_slice(&more);
        assert_eq!(extract_hfc(&two), None);
    }
}
