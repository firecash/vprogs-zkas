//! Guest-side ZKas header + coinbase hashing — the `no_std` transcription of
//! `kaspa_consensus_core::hashing` needed to prove `R → H_fc` inside the peg-out proof.
//!
//! The guest holds a *trusted* `H_fc` (trusted because Kaspa's sequencing commitment witnessed it,
//! and the covenant checks that on-chain). To bind the burn's state root `R` to that `H_fc`, it must
//! recompute `H_fc = header_hash(header)` from a header whose `hash_merkle_root` folds up from the
//! coinbase — and the coinbase payload commits `R`. If the guest did not recompute the hash, an
//! attacker could pair a real `H_fc` with a header committing a fabricated `R`.
//!
//! # Why this is a hand transcription (and how it stays honest)
//!
//! `kaspa_consensus_core` is a `std` crate that pulls a heavy dependency tree; it cannot compile
//! into the RISC0 guest. So the exact byte serialization is replicated here against the `no_std`
//! `kaspa_hashes` blake3 hashers (`TransactionHash`, `BlockHash`) that *do* compile in the guest.
//! A wrong byte would be a silent soundness bug, so both functions are pinned to vectors generated
//! by the **real** functions (`kaspa_consensus_core::hashing::{tx,header}::hash`) — see
//! `consensus/core/src/zkas_state_binding.rs::gen_guest_hash_vectors` and the tests below.
//!
//! # ZKas is pre-Toccata (version 0 / block-version 1)
//!
//! ZKas runs at 1 BPS; its DAA score will not reach the inherited Toccata activation for ~15 years,
//! so in practice ZKas coinbases are `TX_VERSION = 0` and headers are `BLOCK_VERSION = 1`. That is
//! the shape transcribed here (it is also the *simpler* shape: no covenant output field, and the
//! coinbase mass field is omitted because coinbase mass is 0). A `TX_VERSION_TOCCATA` variant can be
//! added if the fork ever activates Toccata; it is intentionally rejected for now.

use kaspa_hashes::{Hash, HasherBase, BlockHash, TransactionHash};

/// `write_len`: a length as little-endian `u64` (mirrors `HasherExtensions::write_len`).
fn write_len<H: HasherBase>(h: &mut H, len: usize) {
    h.update((len as u64).to_le_bytes());
}

/// `write_var_bytes`: length-prefixed bytes.
fn write_var_bytes<H: HasherBase>(h: &mut H, bytes: &[u8]) {
    write_len(h, bytes.len());
    h.update(bytes);
}

/// One coinbase output as the guest sees it.
pub struct CoinbaseOutput<'a> {
    /// Output value in sompi.
    pub value: u64,
    /// `ScriptPublicKey` version.
    pub spk_version: u16,
    /// `ScriptPublicKey` script bytes.
    pub spk_script: &'a [u8],
}

/// Recompute the transaction hash of a **version-0 coinbase** (0 inputs, coinbase mass 0).
///
/// Byte-identical to `kaspa_consensus_core::hashing::tx::hash` for a `TX_VERSION` coinbase
/// (`TxEncodingFlags::FULL`): version, input count (0), outputs, lock_time, subnetwork_id, gas,
/// payload — and no covenant field and no mass field, both of which are exclusive to version ≥ 1 /
/// non-zero mass. Panics if asked for a non-zero version (not transcribed).
pub fn coinbase_tx_hash_v0(
    version: u16,
    outputs: &[CoinbaseOutput<'_>],
    lock_time: u64,
    subnetwork_id: &[u8; 20],
    gas: u64,
    payload: &[u8],
) -> Hash {
    assert_eq!(version, 0, "only the pre-Toccata TX_VERSION=0 coinbase is transcribed");
    let mut h = TransactionHash::new();
    h.update(version.to_le_bytes());
    write_len(&mut h, 0); // no inputs
    write_len(&mut h, outputs.len());
    for o in outputs {
        h.update(o.value.to_le_bytes());
        h.update(o.spk_version.to_le_bytes());
        write_var_bytes(&mut h, o.spk_script);
        // version < 1 ⇒ no covenant field.
    }
    h.update(lock_time.to_le_bytes());
    h.update(subnetwork_id);
    h.update(gas.to_le_bytes());
    write_var_bytes(&mut h, payload);
    // version < 1 and coinbase mass == 0 ⇒ no mass field.
    h.finalize()
}

/// All the header fields the block hash commits, as the guest receives them.
///
/// `parents` is the **expanded** parent-by-level list (the relayer expands the RLE-compressed form
/// off-chain); the guest just hashes it. `blue_work_be` is the big-endian blue work with leading
/// zeros already stripped (matching `write_blue_work`).
pub struct HeaderFields<'a> {
    /// Block version (`BLOCK_VERSION = 1` pre-Toccata).
    pub version: u16,
    /// Expanded parents, one slice of 32-byte hashes per level.
    pub parents: &'a [&'a [[u8; 32]]],
    /// Transaction Merkle root (commits the coinbase).
    pub hash_merkle_root: [u8; 32],
    /// Accepted-ID Merkle root.
    pub accepted_id_merkle_root: [u8; 32],
    /// UTXO commitment.
    pub utxo_commitment: [u8; 32],
    /// Block timestamp (ms).
    pub timestamp: u64,
    /// Difficulty bits.
    pub bits: u32,
    /// PoW nonce.
    pub nonce: u64,
    /// DAA score.
    pub daa_score: u64,
    /// Blue score.
    pub blue_score: u64,
    /// Blue work, big-endian, leading zeros stripped.
    pub blue_work_be: &'a [u8],
    /// Pruning point.
    pub pruning_point: [u8; 32],
}

/// Recompute a ZKas block hash `H_fc`.
///
/// Byte-identical to `kaspa_consensus_core::hashing::header::hash` (which delegates to
/// `hash_override_nonce_time` with the header's own nonce/timestamp).
pub fn header_hash(f: &HeaderFields<'_>) -> Hash {
    let mut h = BlockHash::new();
    h.update(f.version.to_le_bytes());
    write_len(&mut h, f.parents.len()); // number of parent levels
    for level in f.parents {
        // write_var_array: level length, then each 32-byte parent.
        write_len(&mut h, level.len());
        for parent in *level {
            h.update(parent);
        }
    }
    h.update(f.hash_merkle_root);
    h.update(f.accepted_id_merkle_root);
    h.update(f.utxo_commitment);
    h.update(f.timestamp.to_le_bytes());
    h.update(f.bits.to_le_bytes());
    h.update(f.nonce.to_le_bytes());
    h.update(f.daa_score.to_le_bytes());
    h.update(f.blue_score.to_le_bytes());
    // write_blue_work: var-bytes of the stripped big-endian work.
    write_var_bytes(&mut h, f.blue_work_be);
    h.update(f.pruning_point);
    h.finalize()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(h: &Hash) -> alloc::string::String {
        use alloc::string::String;
        use core::fmt::Write;
        let mut s = String::new();
        for b in h.as_bytes() {
            write!(&mut s, "{b:02x}").unwrap();
        }
        s
    }

    /// **Cross-implementation pin against the real hashers.** These two vectors were generated by
    /// `kaspa_consensus_core::hashing::{tx,header}::hash` on fixed inputs
    /// (`zkas_state_binding::gen_guest_hash_vectors`). If this transcription drifts by a single
    /// byte, one of these fails instead of every peg-out silently mis-binding `R`.
    #[test]
    fn matches_real_consensus_hashers() {
        // ---- coinbase (version 0) ----
        let mut payload = alloc::vec::Vec::new();
        payload.extend_from_slice(&123u64.to_le_bytes()); // blue_score
        payload.extend_from_slice(&456u64.to_le_bytes()); // subsidy
        payload.extend_from_slice(&[0x5a; 32]); // R
        payload.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]); // trailing

        let subnetwork_coinbase = {
            let mut s = [0u8; 20];
            s[0] = 1;
            s
        };
        let outputs = [CoinbaseOutput { value: 5000, spk_version: 0, spk_script: &[0xaa, 0xbb, 0xcc] }];
        let tx = coinbase_tx_hash_v0(0, &outputs, 7, &subnetwork_coinbase, 9, &payload);
        assert_eq!(hex(&tx), "1361ca2f0c2a4bb8a87bf82195bdd23670a175b8a838d6e0466ed702d7e92a48");

        // ---- header (block version 1), hash_merkle_root == the coinbase tx hash ----
        let level0: [[u8; 32]; 1] = [[0x01; 32]];
        let parents: [&[[u8; 32]]; 1] = [&level0];
        let hdr = HeaderFields {
            version: 1,
            parents: &parents,
            hash_merkle_root: tx.as_bytes(),
            accepted_id_merkle_root: [0x02; 32],
            utxo_commitment: [0x03; 32],
            timestamp: 234,
            bits: 23,
            nonce: 567,
            daa_score: 42,
            blue_score: 99,
            blue_work_be: &[5], // Uint192(5), big-endian, leading zeros stripped
            pruning_point: [0x04; 32],
        };
        assert_eq!(hex(&header_hash(&hdr)), "29ae2e8f1cde4aa8b7f95454aae1147b792a580a849ba2a4acb6ec06caf0caa4");
    }
}
