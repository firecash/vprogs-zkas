//! Composed canonical-`R` verification — the single guest entry point that chains every link of
//! the trust argument and returns what the covenant must check on-chain.
//!
//! Given the shielded state root `R` a burn was proven under, and a full witness for the Kaspa
//! block that merge-mined the ZKas block committing `R`, [`verify`] establishes:
//!
//! ```text
//!   coinbase.payload[16..48] == R                      (the ZKas #24 commitment)
//!   fold(tx_hash(coinbase), branch) == header.hash_merkle_root
//!   header_hash(header) == H_fc                        (kaspa_hashing)
//!   Kaspa payload embeds H_fc  ∧  recompute(seq_commit) == claimed   (seq_commit_witness)
//! ```
//!
//! and returns `(seq_commit, kaspa_block_hash)`. The guest journals those two values; the covenant
//! then requires `seq_commit == OpChainblockSeqCommit(kaspa_block_hash)` at a buried depth. At that
//! point `R` is canonical: **Kaspa's own PoW chain committed the ZKas block that produced it** — no
//! checkpoint publisher, no trusted operator.
//!
//! Every hash here runs in the zkVM (`kaspa_hashing`, `kaspa_merkle`, `kaspa_seq_commit`), each
//! pinned to a real reference. This module composes them; it introduces no new hashing.

use kaspa_hashes::Hash;
use kaspa_merkle::merkle_hash;

use crate::kaspa_hashing::{CoinbaseOutput, HeaderFields, coinbase_tx_hash_v0, header_hash};
use crate::seq_commit_witness::SeqCommitWitness;

/// Offset of `R` in a ZKas coinbase payload: `blue_score(8) + subsidy(8)`.
pub const SHIELDED_COMMITMENT_OFFSET: usize = 16;
/// Cap on the coinbase Merkle branch (mirrors the consensus / auxpow caps).
pub const MAX_COINBASE_MERKLE_BRANCH: usize = 64;

/// The full canonical-`R` witness the relayer supplies (decoded from `ix_data`).
pub struct CanonicalRWitness<'a> {
    /// ZKas coinbase transaction version (0, pre-Toccata).
    pub coinbase_version: u16,
    /// ZKas coinbase outputs.
    pub coinbase_outputs: &'a [CoinbaseOutput<'a>],
    /// ZKas coinbase lock time.
    pub coinbase_lock_time: u64,
    /// ZKas coinbase subnetwork id (coinbase).
    pub coinbase_subnetwork: [u8; 20],
    /// ZKas coinbase gas.
    pub coinbase_gas: u64,
    /// ZKas coinbase payload — commits `R` at [`SHIELDED_COMMITMENT_OFFSET`].
    pub coinbase_payload: &'a [u8],
    /// Merkle branch from the coinbase (leaf 0) to the ZKas header's `hash_merkle_root`.
    pub coinbase_branch: &'a [[u8; 32]],
    /// The ZKas header fields; `header_hash(header) == H_fc`.
    pub header: HeaderFields<'a>,
    /// Witness for the Kaspa block whose `seq_commit` commits `H_fc`.
    pub seq: SeqCommitWitness<'a>,
    /// The `seq_commit` the covenant will read on-chain for [`Self::kaspa_block_hash`].
    pub seq_commit: Hash,
    /// The Kaspa block hash the covenant queries via `OpChainblockSeqCommit`.
    pub kaspa_block_hash: Hash,
}

/// Why canonical-`R` verification failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CanonicalRError {
    /// The coinbase payload does not commit the expected `R`.
    StateRootMismatch,
    /// The coinbase Merkle branch does not reproduce the header's `hash_merkle_root`.
    MerkleRootMismatch,
    /// An over-long coinbase branch.
    BranchTooLong,
    /// The Kaspa payload does not embed `H_fc`, or the recomputed `seq_commit` differs.
    SeqCommitMismatch,
    /// The witness's block hash disagrees with the block the covenant will query.
    BlockHashMismatch,
}

/// The values the guest journals for the covenant to enforce on-chain.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CanonicalRProof {
    /// The Kaspa header `seq_commit` — checked on-chain against `OpChainblockSeqCommit`.
    pub seq_commit: Hash,
    /// The Kaspa block whose `seq_commit` this is.
    pub kaspa_block_hash: Hash,
}

/// Verify the full `R → seq_commit` chain. On success the returned pair is what the covenant checks.
pub fn verify(w: &CanonicalRWitness<'_>, expected_r: &[u8; 32]) -> Result<CanonicalRProof, CanonicalRError> {
    if w.coinbase_branch.len() > MAX_COINBASE_MERKLE_BRANCH {
        return Err(CanonicalRError::BranchTooLong);
    }

    // (1) The coinbase payload commits exactly R.
    let end = SHIELDED_COMMITMENT_OFFSET + 32;
    let committed = w
        .coinbase_payload
        .get(SHIELDED_COMMITMENT_OFFSET..end)
        .ok_or(CanonicalRError::StateRootMismatch)?;
    if committed != expected_r {
        return Err(CanonicalRError::StateRootMismatch);
    }

    // (2) tx_hash(coinbase) folds up the branch (leaf 0, left path) to the header's merkle root.
    let tx = coinbase_tx_hash_v0(
        w.coinbase_version,
        w.coinbase_outputs,
        w.coinbase_lock_time,
        &w.coinbase_subnetwork,
        w.coinbase_gas,
        w.coinbase_payload,
    );
    let mut acc = tx;
    for sibling in w.coinbase_branch {
        acc = merkle_hash(acc, Hash::from_bytes(*sibling));
    }
    if acc.as_bytes() != w.header.hash_merkle_root {
        return Err(CanonicalRError::MerkleRootMismatch);
    }

    // (3) H_fc is the ZKas header hash.
    let hfc = header_hash(&w.header);

    // (4) The Kaspa block's payload embeds H_fc and its recomputed seq_commit matches the claim.
    if !w.seq.verify(hfc, w.seq_commit) {
        return Err(CanonicalRError::SeqCommitMismatch);
    }

    // The witness's own block hash must be the one the covenant will query on-chain.
    if w.seq.block_hash != w.kaspa_block_hash {
        return Err(CanonicalRError::BlockHashMismatch);
    }

    Ok(CanonicalRProof { seq_commit: w.seq_commit, kaspa_block_hash: w.kaspa_block_hash })
}

/// Verify canonical-`R` when the ZKas chain is itself the sequencing chain (single-chain
/// deployment: one chain carries both the #24 `R` commitment and the KIP-21 `seq_commit`, and the
/// covenant reads that same chain's `OpChainblockSeqCommit`).
///
/// Here the block committing `R` *is* a mergeset member of the queried block, so `R` binds to
/// `seq_commit` directly: no `H_fc` indirection, no ZKas-header re-hash, no coinbase Merkle branch.
/// `seq` describes the mergeset member (its coinbase payload commits `R` at
/// [`SHIELDED_COMMITMENT_OFFSET`]); `queried_block_hash` is the block whose `seq_commit` the covenant
/// resolves on-chain (the merging block, whose mergeset includes the member). Returns the pair the
/// covenant checks, or [`CanonicalRError::StateRootMismatch`] if the member's coinbase does not
/// commit `expected_r`.
///
/// Soundness rests on the covenant's later `seq_commit == OpChainblockSeqCommit(queried_block_hash)`:
/// tampering with `seq.kaspa_payload` moves the recomputed leaf, so the recomputed `seq_commit` no
/// longer matches the real buried block, and the covenant rejects. The relayer is thus forced to
/// supply the genuine member coinbase, whose bytes carry the genuine `R`.
pub fn verify_single_chain(
    seq: &SeqCommitWitness<'_>,
    queried_block_hash: Hash,
    expected_r: &[u8; 32],
) -> Result<CanonicalRProof, CanonicalRError> {
    // The mergeset member's coinbase payload commits exactly R.
    let end = SHIELDED_COMMITMENT_OFFSET + 32;
    let committed = seq.kaspa_payload.get(SHIELDED_COMMITMENT_OFFSET..end).ok_or(CanonicalRError::StateRootMismatch)?;
    if committed != expected_r {
        return Err(CanonicalRError::StateRootMismatch);
    }

    // Recompute the queried block's seq_commit from the member leaf spliced into its mergeset.
    let seq_commit = seq.recompute_seq_commit().ok_or(CanonicalRError::SeqCommitMismatch)?;

    Ok(CanonicalRProof { seq_commit, kaspa_block_hash: queried_block_hash })
}

// ------------------------------- wire codec -------------------------------
//
// The relayer serializes an [`OwnedCanonicalRWitness`] into the attestation `ix_data`; the guest
// decodes it and calls [`OwnedCanonicalRWitness::verify`]. The owned form exists because the
// borrowed [`CanonicalRWitness`] has nested `&[&[..]]` lifetimes that cannot borrow directly from a
// flat byte buffer; `verify` rebuilds the borrowed views on the stack and delegates to [`verify`].

extern crate alloc;
use alloc::vec::Vec;

/// Wire version of the canonical-`R` witness.
pub const CANONICAL_R_V1: u8 = 1;

/// An owned, decoded canonical-`R` witness (all the fields of [`CanonicalRWitness`], heap-backed).
pub struct OwnedCanonicalRWitness {
    /// See [`CanonicalRWitness::coinbase_version`].
    pub coinbase_version: u16,
    /// Coinbase outputs as `(value, spk_version, spk_script)`.
    pub coinbase_outputs: Vec<(u64, u16, Vec<u8>)>,
    /// See [`CanonicalRWitness::coinbase_lock_time`].
    pub coinbase_lock_time: u64,
    /// See [`CanonicalRWitness::coinbase_subnetwork`].
    pub coinbase_subnetwork: [u8; 20],
    /// See [`CanonicalRWitness::coinbase_gas`].
    pub coinbase_gas: u64,
    /// See [`CanonicalRWitness::coinbase_payload`].
    pub coinbase_payload: Vec<u8>,
    /// See [`CanonicalRWitness::coinbase_branch`].
    pub coinbase_branch: Vec<[u8; 32]>,
    /// Header version.
    pub header_version: u16,
    /// Expanded parents, per level.
    pub header_parents: Vec<Vec<[u8; 32]>>,
    /// Header hash-merkle root.
    pub hash_merkle_root: [u8; 32],
    /// Header accepted-id merkle root.
    pub accepted_id_merkle_root: [u8; 32],
    /// Header UTXO commitment.
    pub utxo_commitment: [u8; 32],
    /// Header timestamp.
    pub timestamp: u64,
    /// Header difficulty bits.
    pub bits: u32,
    /// Header nonce.
    pub nonce: u64,
    /// Header DAA score.
    pub daa_score: u64,
    /// Header blue score.
    pub blue_score: u64,
    /// Header blue work, big-endian, leading zeros stripped.
    pub header_blue_work_be: Vec<u8>,
    /// Header pruning point.
    pub pruning_point: [u8; 32],
    /// Kaspa coinbase payload (embeds `H_fc`).
    pub kaspa_payload: Vec<u8>,
    /// Kaspa block hash.
    pub kaspa_block_hash: [u8; 32],
    /// Kaspa block blue work, big-endian, stripped.
    pub kaspa_blue_work_be: Vec<u8>,
    /// The mergeset's other miner-payload leaves.
    pub other_leaves: Vec<[u8; 32]>,
    /// Our leaf's position in the mergeset.
    pub leaf_index: u32,
    /// Sequencing activity root.
    pub activity_root: [u8; 32],
    /// Mergeset context hash.
    pub context_hash: [u8; 32],
    /// Parent block sequencing commitment.
    pub parent_seq_commit: [u8; 32],
    /// The claimed sequencing commitment for `kaspa_block_hash`.
    pub seq_commit: [u8; 32],
    /// Single-chain: the mergeset member whose coinbase commits `R`, distinct from the queried
    /// merging block in `kaspa_block_hash`. Equals `kaspa_block_hash` on the two-chain path.
    pub member_block_hash: [u8; 32],
}

/// Minimal length-prefixed reader over a byte slice.
struct Reader<'a> {
    b: &'a [u8],
    p: usize,
}

impl<'a> Reader<'a> {
    fn new(b: &'a [u8]) -> Self {
        Self { b, p: 0 }
    }
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let s = self.b.get(self.p..self.p + n)?;
        self.p += n;
        Some(s)
    }
    fn u8(&mut self) -> Option<u8> {
        Some(self.take(1)?[0])
    }
    fn u16(&mut self) -> Option<u16> {
        Some(u16::from_le_bytes(self.take(2)?.try_into().ok()?))
    }
    fn u32(&mut self) -> Option<u32> {
        Some(u32::from_le_bytes(self.take(4)?.try_into().ok()?))
    }
    fn u64(&mut self) -> Option<u64> {
        Some(u64::from_le_bytes(self.take(8)?.try_into().ok()?))
    }
    fn arr32(&mut self) -> Option<[u8; 32]> {
        self.take(32)?.try_into().ok()
    }
    fn arr20(&mut self) -> Option<[u8; 20]> {
        self.take(20)?.try_into().ok()
    }
    /// A `u32`-length-prefixed byte blob.
    fn blob(&mut self) -> Option<Vec<u8>> {
        let n = self.u32()? as usize;
        Some(self.take(n)?.to_vec())
    }
    /// A `u32`-count-prefixed list of 32-byte hashes.
    fn hashes(&mut self) -> Option<Vec<[u8; 32]>> {
        let n = self.u32()? as usize;
        let mut v = Vec::with_capacity(n);
        for _ in 0..n {
            v.push(self.arr32()?);
        }
        Some(v)
    }
}

/// Minimal length-prefixed writer. Encoding mirrors [`Reader`] exactly.
struct Writer {
    b: Vec<u8>,
}
impl Writer {
    fn new() -> Self {
        Self { b: Vec::new() }
    }
    fn u8(&mut self, v: u8) {
        self.b.push(v);
    }
    fn u16(&mut self, v: u16) {
        self.b.extend_from_slice(&v.to_le_bytes());
    }
    fn u32(&mut self, v: u32) {
        self.b.extend_from_slice(&v.to_le_bytes());
    }
    fn u64(&mut self, v: u64) {
        self.b.extend_from_slice(&v.to_le_bytes());
    }
    fn bytes(&mut self, v: &[u8]) {
        self.b.extend_from_slice(v);
    }
    fn blob(&mut self, v: &[u8]) {
        self.u32(v.len() as u32);
        self.b.extend_from_slice(v);
    }
    fn hashes(&mut self, v: &[[u8; 32]]) {
        self.u32(v.len() as u32);
        for h in v {
            self.b.extend_from_slice(h);
        }
    }
}

impl OwnedCanonicalRWitness {
    /// Encode to `ix_data` bytes (relayer side; also used by tests).
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.u8(CANONICAL_R_V1);
        w.u16(self.coinbase_version);
        w.u32(self.coinbase_outputs.len() as u32);
        for (value, spk_version, spk_script) in &self.coinbase_outputs {
            w.u64(*value);
            w.u16(*spk_version);
            w.blob(spk_script);
        }
        w.u64(self.coinbase_lock_time);
        w.bytes(&self.coinbase_subnetwork);
        w.u64(self.coinbase_gas);
        w.blob(&self.coinbase_payload);
        w.hashes(&self.coinbase_branch);
        w.u16(self.header_version);
        w.u32(self.header_parents.len() as u32);
        for level in &self.header_parents {
            w.hashes(level);
        }
        w.bytes(&self.hash_merkle_root);
        w.bytes(&self.accepted_id_merkle_root);
        w.bytes(&self.utxo_commitment);
        w.u64(self.timestamp);
        w.u32(self.bits);
        w.u64(self.nonce);
        w.u64(self.daa_score);
        w.u64(self.blue_score);
        w.blob(&self.header_blue_work_be);
        w.bytes(&self.pruning_point);
        w.blob(&self.kaspa_payload);
        w.bytes(&self.kaspa_block_hash);
        w.blob(&self.kaspa_blue_work_be);
        w.hashes(&self.other_leaves);
        w.u32(self.leaf_index);
        w.bytes(&self.activity_root);
        w.bytes(&self.context_hash);
        w.bytes(&self.parent_seq_commit);
        w.bytes(&self.seq_commit);
        w.bytes(&self.member_block_hash);
        w.b
    }

    /// Decode from `ix_data` bytes. Returns `None` on any malformed/truncated input.
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let mut r = Reader::new(bytes);
        if r.u8()? != CANONICAL_R_V1 {
            return None;
        }
        let coinbase_version = r.u16()?;
        let n_out = r.u32()? as usize;
        let mut coinbase_outputs = Vec::with_capacity(n_out);
        for _ in 0..n_out {
            let value = r.u64()?;
            let spk_version = r.u16()?;
            let spk_script = r.blob()?;
            coinbase_outputs.push((value, spk_version, spk_script));
        }
        let coinbase_lock_time = r.u64()?;
        let coinbase_subnetwork = r.arr20()?;
        let coinbase_gas = r.u64()?;
        let coinbase_payload = r.blob()?;
        let coinbase_branch = r.hashes()?;
        let header_version = r.u16()?;
        let n_levels = r.u32()? as usize;
        let mut header_parents = Vec::with_capacity(n_levels);
        for _ in 0..n_levels {
            header_parents.push(r.hashes()?);
        }
        let hash_merkle_root = r.arr32()?;
        let accepted_id_merkle_root = r.arr32()?;
        let utxo_commitment = r.arr32()?;
        let timestamp = r.u64()?;
        let bits = r.u32()?;
        let nonce = r.u64()?;
        let daa_score = r.u64()?;
        let blue_score = r.u64()?;
        let header_blue_work_be = r.blob()?;
        let pruning_point = r.arr32()?;
        let kaspa_payload = r.blob()?;
        let kaspa_block_hash = r.arr32()?;
        let kaspa_blue_work_be = r.blob()?;
        let other_leaves = r.hashes()?;
        let leaf_index = r.u32()?;
        let activity_root = r.arr32()?;
        let context_hash = r.arr32()?;
        let parent_seq_commit = r.arr32()?;
        let seq_commit = r.arr32()?;
        let member_block_hash = r.arr32()?;
        Some(Self {
            coinbase_version,
            coinbase_outputs,
            coinbase_lock_time,
            coinbase_subnetwork,
            coinbase_gas,
            coinbase_payload,
            coinbase_branch,
            header_version,
            header_parents,
            hash_merkle_root,
            accepted_id_merkle_root,
            utxo_commitment,
            timestamp,
            bits,
            nonce,
            daa_score,
            blue_score,
            header_blue_work_be,
            pruning_point,
            kaspa_payload,
            kaspa_block_hash,
            kaspa_blue_work_be,
            other_leaves,
            leaf_index,
            activity_root,
            context_hash,
            parent_seq_commit,
            seq_commit,
            member_block_hash,
        })
    }

    /// Verify against `expected_r`, rebuilding the borrowed views and delegating to [`verify`].
    pub fn verify(&self, expected_r: &[u8; 32]) -> Result<CanonicalRProof, CanonicalRError> {
        let outputs: Vec<CoinbaseOutput<'_>> = self
            .coinbase_outputs
            .iter()
            .map(|(value, spk_version, spk_script)| CoinbaseOutput {
                value: *value,
                spk_version: *spk_version,
                spk_script,
            })
            .collect();
        let parents: Vec<&[[u8; 32]]> = self.header_parents.iter().map(|l| l.as_slice()).collect();
        let other_leaves: Vec<Hash> = self.other_leaves.iter().map(|h| Hash::from_bytes(*h)).collect();
        let header = HeaderFields {
            version: self.header_version,
            parents: &parents,
            hash_merkle_root: self.hash_merkle_root,
            accepted_id_merkle_root: self.accepted_id_merkle_root,
            utxo_commitment: self.utxo_commitment,
            timestamp: self.timestamp,
            bits: self.bits,
            nonce: self.nonce,
            daa_score: self.daa_score,
            blue_score: self.blue_score,
            blue_work_be: &self.header_blue_work_be,
            pruning_point: self.pruning_point,
        };
        let seq = SeqCommitWitness {
            kaspa_payload: &self.kaspa_payload,
            block_hash: Hash::from_bytes(self.kaspa_block_hash),
            blue_work_be: &self.kaspa_blue_work_be,
            other_leaves: &other_leaves,
            leaf_index: self.leaf_index as usize,
            activity_root: Hash::from_bytes(self.activity_root),
            context_hash: Hash::from_bytes(self.context_hash),
            parent_seq_commit: Hash::from_bytes(self.parent_seq_commit),
        };
        let w = CanonicalRWitness {
            coinbase_version: self.coinbase_version,
            coinbase_outputs: &outputs,
            coinbase_lock_time: self.coinbase_lock_time,
            coinbase_subnetwork: self.coinbase_subnetwork,
            coinbase_gas: self.coinbase_gas,
            coinbase_payload: &self.coinbase_payload,
            coinbase_branch: &self.coinbase_branch,
            header,
            seq,
            seq_commit: Hash::from_bytes(self.seq_commit),
            kaspa_block_hash: Hash::from_bytes(self.kaspa_block_hash),
        };
        verify(&w, expected_r)
    }

    /// Verify against `expected_r` on the single-chain path, delegating to [`verify_single_chain`].
    ///
    /// The seq witness is anchored on `member_block_hash` (the mergeset member committing `R`), and
    /// `kaspa_block_hash` is the queried merging block. The two-chain-only fields (ZKas header,
    /// coinbase branch) are ignored.
    pub fn verify_direct(&self, expected_r: &[u8; 32]) -> Result<CanonicalRProof, CanonicalRError> {
        let other_leaves: Vec<Hash> = self.other_leaves.iter().map(|h| Hash::from_bytes(*h)).collect();
        let seq = SeqCommitWitness {
            kaspa_payload: &self.kaspa_payload,
            block_hash: Hash::from_bytes(self.member_block_hash),
            blue_work_be: &self.kaspa_blue_work_be,
            other_leaves: &other_leaves,
            leaf_index: self.leaf_index as usize,
            activity_root: Hash::from_bytes(self.activity_root),
            context_hash: Hash::from_bytes(self.context_hash),
            parent_seq_commit: Hash::from_bytes(self.parent_seq_commit),
        };
        verify_single_chain(&seq, Hash::from_bytes(self.kaspa_block_hash), expected_r)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kaspa_seq_commit::hashing::{
        miner_payload_leaf, miner_payload_root, payload_and_context_digest, seq_commit, seq_state_root,
    };
    use kaspa_seq_commit::types::{MinerPayloadLeafInput, SeqCommitInput, SeqState};

    /// Embed `MERGE_MINE_MAGIC || hex(hfc)` in a Kaspa coinbase payload.
    fn embed_hfc(hfc: &Hash) -> alloc::vec::Vec<u8> {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut out = alloc::vec::Vec::new();
        out.extend_from_slice(b"kaspa-cb");
        out.extend_from_slice(&crate::seq_commit_witness::MERGE_MINE_MAGIC);
        for b in hfc.as_bytes() {
            out.push(HEX[(b >> 4) as usize]);
            out.push(HEX[(b & 0x0f) as usize]);
        }
        out
    }

    /// A ZKas coinbase payload committing `r` at the right offset.
    fn zkas_payload(r: &[u8; 32]) -> alloc::vec::Vec<u8> {
        let mut p = alloc::vec::Vec::new();
        p.extend_from_slice(&7u64.to_le_bytes()); // blue_score
        p.extend_from_slice(&8u64.to_le_bytes()); // subsidy
        p.extend_from_slice(r);
        p.extend_from_slice(&[0x11, 0x22]); // trailing
        p
    }

    /// Single-chain path: the block committing `R` is a mergeset member of a *distinct* queried
    /// block, and `R` binds to that block's `seq_commit` with no `H_fc` indirection. Asserts the
    /// recomputed `seq_commit` matches the reference, the journaled block is the queried (merging)
    /// block rather than the member, and a wrong `R` is rejected.
    #[test]
    fn single_chain_binds_r_directly_to_seq_commit() {
        let r = [0x5a; 32];
        let member_payload = zkas_payload(&r);
        let member_block = Hash::from_bytes([0x33; 32]);
        let queried_block = Hash::from_bytes([0xBB; 32]);
        let blue_work_be = [0x01u8, 0x02];
        let activity_root = Hash::from_bytes([0x44; 32]);
        let context_hash = Hash::from_bytes([0x55; 32]);
        let parent_seq_commit = Hash::from_bytes([0x66; 32]);
        let other = [Hash::from_bytes([0xA0; 32])];

        let our_leaf = miner_payload_leaf(MinerPayloadLeafInput {
            block_hash: &member_block,
            blue_work_be_bytes: &blue_work_be,
            payload: &member_payload,
        });
        let reference = {
            let ordered = [our_leaf, other[0]];
            let payload_root = miner_payload_root(ordered.into_iter());
            let pd = payload_and_context_digest(&context_hash, &payload_root);
            let sr = seq_state_root(&SeqState { activity_root: &activity_root, payload_and_ctx_digest: &pd });
            seq_commit(&SeqCommitInput { parent_seq_commit: &parent_seq_commit, state_root: &sr })
        };

        let seq = SeqCommitWitness {
            kaspa_payload: &member_payload,
            block_hash: member_block,
            blue_work_be: &blue_work_be,
            other_leaves: &other,
            leaf_index: 0,
            activity_root,
            context_hash,
            parent_seq_commit,
        };

        let proof = verify_single_chain(&seq, queried_block, &r).expect("member coinbase commits R");
        assert_eq!(proof.seq_commit, reference, "recomputed seq_commit must match the reference");
        assert_eq!(proof.kaspa_block_hash, queried_block, "journaled block is the queried (merging) block, not the member");
        assert_ne!(proof.kaspa_block_hash, member_block, "member and queried block are distinct");

        let mut wrong = [0x5a; 32];
        wrong[0] ^= 0xff;
        assert_eq!(verify_single_chain(&seq, queried_block, &wrong), Err(CanonicalRError::StateRootMismatch));
    }

    /// The owned/wire form carries the single-chain path end to end: encode, decode, and
    /// [`OwnedCanonicalRWitness::verify_direct`] reproduces the queried block's `seq_commit` while
    /// keeping `member_block_hash` (the R-committing member) distinct from `kaspa_block_hash`.
    #[test]
    fn owned_witness_verifies_single_chain_direct() {
        let r = [0x5a; 32];
        let member_payload = zkas_payload(&r);
        let member_block = [0x33; 32];
        let queried_block = [0xBB; 32];
        let blue_work_be = alloc::vec![0x01u8, 0x02];
        let activity_root = [0x44; 32];
        let context_hash = [0x55; 32];
        let parent_seq_commit = [0x66; 32];
        let other = [0xA0u8; 32];

        let our_leaf = miner_payload_leaf(MinerPayloadLeafInput {
            block_hash: &Hash::from_bytes(member_block),
            blue_work_be_bytes: &blue_work_be,
            payload: &member_payload,
        });
        let expected_seq_commit = {
            let ordered = [our_leaf, Hash::from_bytes(other)];
            let payload_root = miner_payload_root(ordered.into_iter());
            let pd = payload_and_context_digest(&Hash::from_bytes(context_hash), &payload_root);
            let sr = seq_state_root(&SeqState { activity_root: &Hash::from_bytes(activity_root), payload_and_ctx_digest: &pd });
            seq_commit(&SeqCommitInput { parent_seq_commit: &Hash::from_bytes(parent_seq_commit), state_root: &sr })
        };

        // The two-chain-only fields are unused on this path; fill them with any well-formed values.
        let owned = OwnedCanonicalRWitness {
            coinbase_version: 0,
            coinbase_outputs: alloc::vec![],
            coinbase_lock_time: 0,
            coinbase_subnetwork: [0u8; 20],
            coinbase_gas: 0,
            coinbase_payload: alloc::vec![],
            coinbase_branch: alloc::vec![],
            header_version: 1,
            header_parents: alloc::vec![],
            hash_merkle_root: [0u8; 32],
            accepted_id_merkle_root: [0u8; 32],
            utxo_commitment: [0u8; 32],
            timestamp: 0,
            bits: 0,
            nonce: 0,
            daa_score: 0,
            blue_score: 0,
            header_blue_work_be: alloc::vec![],
            pruning_point: [0u8; 32],
            kaspa_payload: member_payload,
            kaspa_block_hash: queried_block,
            kaspa_blue_work_be: blue_work_be,
            other_leaves: alloc::vec![other],
            leaf_index: 0,
            activity_root,
            context_hash,
            parent_seq_commit,
            seq_commit: expected_seq_commit.as_bytes(),
            member_block_hash: member_block,
        };

        let bytes = owned.encode();
        let decoded = OwnedCanonicalRWitness::decode(&bytes).expect("must decode");
        assert_eq!(decoded.encode(), bytes, "re-encoding must be canonical");

        let proof = decoded.verify_direct(&r).expect("single-chain witness must verify");
        assert_eq!(proof.seq_commit, expected_seq_commit);
        assert_eq!(proof.kaspa_block_hash, Hash::from_bytes(queried_block));
        assert_ne!(proof.kaspa_block_hash, Hash::from_bytes(member_block));
    }

    /// Build a fully self-consistent witness for `r` and verify the whole chain end to end. This is
    /// the happy path: a real coinbase→header→H_fc→Kaspa-payload→seq_commit, all recomputed by the
    /// same functions the guest uses.
    #[test]
    fn full_chain_verifies() {
        let r = [0x5a; 32];

        // --- ZKas side: coinbase commits R, header commits coinbase, H_fc = header hash ---
        let cb_payload = zkas_payload(&r);
        let cb_subnet = {
            let mut s = [0u8; 20];
            s[0] = 1;
            s
        };
        let outputs = [CoinbaseOutput { value: 50, spk_version: 0, spk_script: &[0xaa] }];
        let tx = coinbase_tx_hash_v0(0, &outputs, 0, &cb_subnet, 0, &cb_payload);
        // Single-tx block ⇒ merkle root == coinbase tx hash, empty branch.
        let merkle_root = tx.as_bytes();

        let level0: [[u8; 32]; 1] = [[0x01; 32]];
        let parents: [&[[u8; 32]]; 1] = [&level0];
        let header = HeaderFields {
            version: 1,
            parents: &parents,
            hash_merkle_root: merkle_root,
            accepted_id_merkle_root: [0x02; 32],
            utxo_commitment: [0x03; 32],
            timestamp: 111,
            bits: 22,
            nonce: 333,
            daa_score: 44,
            blue_score: 55,
            blue_work_be: &[9],
            pruning_point: [0x04; 32],
        };
        let hfc = header_hash(&header);

        // --- Kaspa side: a block whose coinbase payload embeds H_fc, and its seq_commit ---
        let kaspa_payload = embed_hfc(&hfc);
        let kaspa_block = Hash::from_bytes([0x33; 32]);
        let blue_work_be = [0x01u8, 0x02];
        let activity_root = Hash::from_bytes([0x44; 32]);
        let context_hash = Hash::from_bytes([0x55; 32]);
        let parent_seq_commit = Hash::from_bytes([0x66; 32]);
        let other = [Hash::from_bytes([0xA0; 32])];

        let our_leaf = miner_payload_leaf(MinerPayloadLeafInput {
            block_hash: &kaspa_block,
            blue_work_be_bytes: &blue_work_be,
            payload: &kaspa_payload,
        });
        let expected_seq_commit = {
            let ordered = [our_leaf, other[0]];
            let payload_root = miner_payload_root(ordered.into_iter());
            let pd = payload_and_context_digest(&context_hash, &payload_root);
            let sr = seq_state_root(&SeqState { activity_root: &activity_root, payload_and_ctx_digest: &pd });
            seq_commit(&SeqCommitInput { parent_seq_commit: &parent_seq_commit, state_root: &sr })
        };

        let seq = SeqCommitWitness {
            kaspa_payload: &kaspa_payload,
            block_hash: kaspa_block,
            blue_work_be: &blue_work_be,
            other_leaves: &other,
            leaf_index: 0,
            activity_root,
            context_hash,
            parent_seq_commit,
        };

        let w = CanonicalRWitness {
            coinbase_version: 0,
            coinbase_outputs: &outputs,
            coinbase_lock_time: 0,
            coinbase_subnetwork: cb_subnet,
            coinbase_gas: 0,
            coinbase_payload: &cb_payload,
            coinbase_branch: &[],
            header,
            seq,
            seq_commit: expected_seq_commit,
            kaspa_block_hash: kaspa_block,
        };

        let proof = verify(&w, &r).expect("full chain must verify");
        assert_eq!(proof.seq_commit, expected_seq_commit);
        assert_eq!(proof.kaspa_block_hash, kaspa_block);

        // A different R must fail at step 1.
        let mut r2 = r;
        r2[0] ^= 1;
        assert_eq!(verify(&w, &r2), Err(CanonicalRError::StateRootMismatch));
    }

    /// The wire codec round-trips, and the decoded owned witness verifies the same self-consistent
    /// chain the borrowed form does — proving the guest can verify against real `ix_data` bytes.
    #[test]
    fn owned_witness_encode_decode_verify() {
        let r = [0x5a; 32];
        let cb_payload = zkas_payload(&r);
        let mut cb_subnet = [0u8; 20];
        cb_subnet[0] = 1;
        let outputs = [CoinbaseOutput { value: 50, spk_version: 0, spk_script: &[0xaa] }];
        let tx = coinbase_tx_hash_v0(0, &outputs, 0, &cb_subnet, 0, &cb_payload);

        let level0: [[u8; 32]; 1] = [[0x01; 32]];
        let parents: [&[[u8; 32]]; 1] = [&level0];
        let header = HeaderFields {
            version: 1,
            parents: &parents,
            hash_merkle_root: tx.as_bytes(),
            accepted_id_merkle_root: [0x02; 32],
            utxo_commitment: [0x03; 32],
            timestamp: 111,
            bits: 22,
            nonce: 333,
            daa_score: 44,
            blue_score: 55,
            blue_work_be: &[9],
            pruning_point: [0x04; 32],
        };
        let hfc = header_hash(&header);
        let kaspa_payload = embed_hfc(&hfc);
        let kaspa_block = Hash::from_bytes([0x33; 32]);
        let blue_work_be = [0x01u8, 0x02];
        let activity_root = Hash::from_bytes([0x44; 32]);
        let context_hash = Hash::from_bytes([0x55; 32]);
        let parent_seq_commit = Hash::from_bytes([0x66; 32]);
        let other = [Hash::from_bytes([0xA0; 32])];
        let our_leaf = miner_payload_leaf(MinerPayloadLeafInput {
            block_hash: &kaspa_block,
            blue_work_be_bytes: &blue_work_be,
            payload: &kaspa_payload,
        });
        let expected_seq_commit = {
            let ordered = [our_leaf, other[0]];
            let payload_root = miner_payload_root(ordered.into_iter());
            let pd = payload_and_context_digest(&context_hash, &payload_root);
            let sr = seq_state_root(&SeqState { activity_root: &activity_root, payload_and_ctx_digest: &pd });
            seq_commit(&SeqCommitInput { parent_seq_commit: &parent_seq_commit, state_root: &sr })
        };

        let owned = OwnedCanonicalRWitness {
            coinbase_version: 0,
            coinbase_outputs: alloc::vec![(50u64, 0u16, alloc::vec![0xaa])],
            coinbase_lock_time: 0,
            coinbase_subnetwork: cb_subnet,
            coinbase_gas: 0,
            coinbase_payload: cb_payload,
            coinbase_branch: alloc::vec![],
            header_version: 1,
            header_parents: alloc::vec![alloc::vec![[0x01; 32]]],
            hash_merkle_root: tx.as_bytes(),
            accepted_id_merkle_root: [0x02; 32],
            utxo_commitment: [0x03; 32],
            timestamp: 111,
            bits: 22,
            nonce: 333,
            daa_score: 44,
            blue_score: 55,
            header_blue_work_be: alloc::vec![9],
            pruning_point: [0x04; 32],
            kaspa_payload,
            kaspa_block_hash: [0x33; 32],
            kaspa_blue_work_be: alloc::vec![0x01, 0x02],
            other_leaves: alloc::vec![[0xA0; 32]],
            leaf_index: 0,
            activity_root: [0x44; 32],
            context_hash: [0x55; 32],
            parent_seq_commit: [0x66; 32],
            seq_commit: expected_seq_commit.as_bytes(),
            member_block_hash: [0x33; 32],
        };

        // Round-trip through the wire.
        let bytes = owned.encode();
        let decoded = OwnedCanonicalRWitness::decode(&bytes).expect("must decode");
        assert_eq!(decoded.encode(), bytes, "re-encoding must be identical (canonical)");

        // The decoded witness verifies the full chain.
        let proof = decoded.verify(&r).expect("decoded witness must verify");
        assert_eq!(proof.seq_commit, expected_seq_commit);
        assert_eq!(proof.kaspa_block_hash, kaspa_block);

        // Truncated / wrong-version inputs are rejected.
        assert!(OwnedCanonicalRWitness::decode(&bytes[..bytes.len() - 1]).is_none());
        let mut bad = bytes.clone();
        bad[0] = 0xFF;
        assert!(OwnedCanonicalRWitness::decode(&bad).is_none());
    }

    /// Tampering the coinbase branch breaks the merkle-root binding (so a fake coinbase committing a
    /// different R cannot fold to the real header).
    #[test]
    fn tampered_branch_fails() {
        let r = [0x5a; 32];
        let cb_payload = zkas_payload(&r);
        let cb_subnet = {
            let mut s = [0u8; 20];
            s[0] = 1;
            s
        };
        let outputs = [CoinbaseOutput { value: 50, spk_version: 0, spk_script: &[0xaa] }];

        let level0: [[u8; 32]; 1] = [[0x01; 32]];
        let parents: [&[[u8; 32]]; 1] = [&level0];
        // Header claims a merkle root unrelated to the coinbase.
        let header = HeaderFields {
            version: 1,
            parents: &parents,
            hash_merkle_root: [0xEE; 32],
            accepted_id_merkle_root: [0x02; 32],
            utxo_commitment: [0x03; 32],
            timestamp: 111,
            bits: 22,
            nonce: 333,
            daa_score: 44,
            blue_score: 55,
            blue_work_be: &[9],
            pruning_point: [0x04; 32],
        };
        let seq = SeqCommitWitness {
            kaspa_payload: &[],
            block_hash: Hash::from_bytes([0x33; 32]),
            blue_work_be: &[],
            other_leaves: &[],
            leaf_index: 0,
            activity_root: Hash::from_bytes([0x44; 32]),
            context_hash: Hash::from_bytes([0x55; 32]),
            parent_seq_commit: Hash::from_bytes([0x66; 32]),
        };
        let w = CanonicalRWitness {
            coinbase_version: 0,
            coinbase_outputs: &outputs,
            coinbase_lock_time: 0,
            coinbase_subnetwork: cb_subnet,
            coinbase_gas: 0,
            coinbase_payload: &cb_payload,
            coinbase_branch: &[],
            header,
            seq,
            seq_commit: Hash::from_bytes([0; 32]),
            kaspa_block_hash: Hash::from_bytes([0x33; 32]),
        };
        assert_eq!(verify(&w, &r), Err(CanonicalRError::MerkleRootMismatch));
    }
}
