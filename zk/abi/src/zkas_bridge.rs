//! ZKas⇄Kaspa bridge wire contract: the burn attestation a peg-out lane transaction carries.
//!
//! This is the single shared definition used by three parties, and it is the reason it lives in
//! the ABI crate rather than in the guest:
//!
//! 1. the **ZKas burn seam**, which produces the [`ExitReceipt`]s and folds them into `burn_root`;
//! 2. the **relayer**, which encodes an attestation into an L2 transaction's `ix_data`;
//! 3. the **guest**, which decodes it, verifies inclusion, and emits the matching exit.
//!
//! ## What the attestation claims
//!
//! *"Exit receipt `{v, recipient, n}` is a leaf of the burn accumulator whose root, combined with
//! the declared shielded state `(anchor, nullifier_root, cumulative_coinbase, cumulative_fees)`,
//! hashes to exactly the claimed ZKas state root `r`."*
//!
//! The guest **recomputes `r`** — it is not taken on faith from the wire. The digest is
//! byte-identical to `kaspa_shielded_core::commitment::shielded_state_root`, which is the value the
//! ZKas coinbase commits to. So a relayer cannot pair a real burn set with an unrelated state root,
//! nor claim a state root that does not actually contain the burn it is presenting.
//!
//! ## What it deliberately does NOT claim
//!
//! That `r` is a **canonical, buried ZKas state root**. Nothing in this module establishes that;
//! the guest proves the receipt and the declared state are mutually consistent and hash to `r`, but
//! not that `r` was ever mined. Certifying `r` is the canonical-`R` problem, and it is the whole
//! trust delta between the sprint bridge (a checkpoint publisher asserts `r`) and the mainnet
//! bridge (the merged-mining witness chain proves it). Read every security property below as
//! conditional on `r` being a real ZKas state root.
//!
//! ## Domain separation
//!
//! Leaf and node hashes use disjoint 1-byte domains, so no interior node can be reinterpreted as
//! a leaf (the classic second-preimage attack on plain Merkle trees). This mirrors the permission
//! tree's `PermTags` approach.

use vprogs_core_hashing::Hasher;

use crate::{Error, Result};

/// Splits a peg-out transaction's `ix_data` into its two sections: the [`BurnAttestation`] bytes and
/// the trailing canonical-`R` witness ([`crate::canonical_r::OwnedCanonicalRWitness`]) bytes.
///
/// Framing: `attestation_len(u32 LE) | attestation | canonical_r_witness`. The length prefix is
/// required because [`BurnAttestation::decode`] treats every byte past its fixed header as Merkle
/// branch, so the two variable-length sections cannot be told apart without an explicit boundary.
///
/// Returns `None` if the prefix is missing or names a length past the end of the buffer. The
/// canonical section may be empty; the guest rejects an empty one, since every peg-out must carry a
/// canonical-`R` proof. The ZKas-side relayer (in `kaspa_shielded_core`) must frame `ix_data` with
/// [`frame_ix_data`]'s layout.
pub fn split_ix_data(ix: &[u8]) -> Option<(&[u8], &[u8])> {
    if ix.len() < 4 {
        return None;
    }
    let att_len = u32::from_le_bytes([ix[0], ix[1], ix[2], ix[3]]) as usize;
    let rest = &ix[4..];
    let attestation = rest.get(..att_len)?;
    let canonical = rest.get(att_len..)?;
    Some((attestation, canonical))
}

/// Frames a peg-out `ix_data` from its attestation and canonical-`R` witness sections. The inverse
/// of [`split_ix_data`]. Used by the relayer and by tests.
#[cfg(feature = "std")]
pub fn frame_ix_data(attestation: &[u8], canonical: &[u8]) -> alloc::vec::Vec<u8> {
    let mut out = alloc::vec::Vec::with_capacity(4 + attestation.len() + canonical.len());
    out.extend_from_slice(&(attestation.len() as u32).to_le_bytes());
    out.extend_from_slice(attestation);
    out.extend_from_slice(canonical);
    out
}

/// Domain byte for exit-receipt leaves.
pub const LEAF_DOMAIN: [u8; 1] = [0x00];
/// Domain byte for interior nodes.
pub const NODE_DOMAIN: [u8; 1] = [0x01];

/// Wire version of the attestation format.
///
/// v2 carries the full shielded-state preimage so the guest can recompute `r` rather than trust
/// it. v1 (which bound `r` as `sha256(burn_root)`) is not accepted.
pub const ATTESTATION_V2: u8 = 2;

/// Blake2b personalization of the ZKas shielded state root. Must stay byte-identical to
/// `kaspa_shielded_core::commitment::STATE_ROOT_PERSONAL`.
pub const STATE_ROOT_PERSONAL: &[u8; 16] = b"zkas_state_root0";

/// Maximum Merkle proof depth accepted (2^32 receipts; matches the permission tree's depth 32).
pub const MAX_BRANCH_DEPTH: usize = 32;

/// Fixed-size prefix:
/// `version(1) | v(8) | recipient(32) | n(32) | r(32) | leaf_index(4)
///  | anchor(32) | nullifier_root(32) | cumulative_coinbase(16) | cumulative_fees(16)`.
const HEADER_LEN: usize = 1 + 8 + 32 + 32 + 32 + 4 + 32 + 32 + 16 + 16;

/// A single peg-out: value `v` left the ZKas shielded pool, destined for `recipient` on Kaspa,
/// keyed by the exit-nullifier `n`.
///
/// `n` is the burned note's nullifier. It is the replay key: the guest binds the transaction's
/// `ResourceId` to it, so a given burn can be exited exactly once (see the module docs on
/// [`decode`](BurnAttestation::decode)).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ExitReceipt {
    /// Amount burned, in sompi.
    pub v: u64,
    /// Kaspa recipient — the 32-byte Schnorr public key the exit pays out to.
    pub recipient: [u8; 32],
    /// Exit-nullifier of the burned note. The replay key.
    pub n: [u8; 32],
}

impl ExitReceipt {
    /// Leaf hash: `H(LEAF_DOMAIN || v_le || recipient || n)`.
    pub fn leaf_hash<H: Hasher>(&self) -> [u8; 32] {
        H::hash_parts_with_domain(
            &LEAF_DOMAIN,
            [self.v.to_le_bytes().as_slice(), self.recipient.as_slice(), self.n.as_slice()],
        )
    }
}

/// A decoded burn attestation: an [`ExitReceipt`], the Merkle path proving it sits under
/// `burn_root`, and the rest of the shielded-state preimage needed to recompute the claimed
/// state root `r`.
pub struct BurnAttestation<'a> {
    /// The peg-out being claimed.
    pub receipt: ExitReceipt,
    /// ZKas shielded state root the receipt is claimed against. **Recomputed, not trusted.**
    pub r: [u8; 32],
    /// Index of the receipt's leaf in the burn accumulator; its bits select sibling sides.
    pub leaf_index: u32,
    /// Note-commitment tree root at that state.
    pub anchor: [u8; 32],
    /// Nullifier-set accumulator root at that state.
    pub nullifier_root: [u8; 32],
    /// Turnstile: total subsidy ever minted into the pool.
    pub cumulative_coinbase: u128,
    /// Turnstile: total fees ever removed from the pool.
    pub cumulative_fees: u128,
    /// Concatenated 32-byte sibling hashes, leaf-to-root. Length is a multiple of 32.
    pub branch: &'a [u8],
}

impl<'a> BurnAttestation<'a> {
    /// Decodes an attestation from a transaction's `ix_data`.
    ///
    /// Rejects: wrong version, short buffers, a branch that is not a whole number of 32-byte
    /// siblings, a branch deeper than [`MAX_BRANCH_DEPTH`], and a `leaf_index` that does not fit
    /// the branch depth (which would otherwise leave high index bits unconstrained, letting one
    /// branch authenticate several positions).
    pub fn decode(bytes: &'a [u8]) -> Result<Self> {
        if bytes.len() < HEADER_LEN {
            return Err(Error::Decode("attestation shorter than header".into()));
        }
        if bytes[0] != ATTESTATION_V2 {
            return Err(Error::Decode("unsupported attestation version".into()));
        }

        let v = u64::from_le_bytes(bytes[1..9].try_into().expect("8 bytes"));
        let recipient: [u8; 32] = bytes[9..41].try_into().expect("32 bytes");
        let n: [u8; 32] = bytes[41..73].try_into().expect("32 bytes");
        let r: [u8; 32] = bytes[73..105].try_into().expect("32 bytes");
        let leaf_index = u32::from_le_bytes(bytes[105..109].try_into().expect("4 bytes"));
        let anchor: [u8; 32] = bytes[109..141].try_into().expect("32 bytes");
        let nullifier_root: [u8; 32] = bytes[141..173].try_into().expect("32 bytes");
        let cumulative_coinbase = u128::from_le_bytes(bytes[173..189].try_into().expect("16 bytes"));
        let cumulative_fees = u128::from_le_bytes(bytes[189..205].try_into().expect("16 bytes"));

        let branch = &bytes[HEADER_LEN..];
        if branch.len() % 32 != 0 {
            return Err(Error::Decode("branch is not a multiple of 32 bytes".into()));
        }
        let depth = branch.len() / 32;
        if depth > MAX_BRANCH_DEPTH {
            return Err(Error::Decode("branch deeper than MAX_BRANCH_DEPTH".into()));
        }
        // A leaf_index with bits above the branch depth would be unconstrained by the path.
        if depth < 32 && (leaf_index >> depth) != 0 {
            return Err(Error::Decode("leaf_index exceeds branch depth".into()));
        }

        Ok(Self {
            receipt: ExitReceipt { v, recipient, n },
            r,
            leaf_index,
            anchor,
            nullifier_root,
            cumulative_coinbase,
            cumulative_fees,
            branch,
        })
    }

    /// Recomputes the accumulator root implied by the receipt and its branch.
    pub fn computed_root<H: Hasher>(&self) -> [u8; 32] {
        let mut acc = self.receipt.leaf_hash::<H>();
        for (level, sibling) in self.branch.chunks_exact(32).enumerate() {
            // Bit `level` of leaf_index says whether we are the right child at this level.
            acc = if (self.leaf_index >> level) & 1 == 1 {
                H::hash_parts_with_domain(&NODE_DOMAIN, [sibling, acc.as_slice()])
            } else {
                H::hash_parts_with_domain(&NODE_DOMAIN, [acc.as_slice(), sibling])
            };
        }
        acc
    }

    /// The ZKas shielded state root implied by a burn root and the declared shielded state.
    ///
    /// **Byte-identical to `kaspa_shielded_core::commitment::shielded_state_root`** — the digest
    /// the ZKas coinbase commits to, and thus the value proof-of-work stands behind. Both sides
    /// pin the same cross-implementation test vector; see `state_root_matches_the_shared_wire_contract`.
    pub fn state_root(
        anchor: &[u8; 32],
        nullifier_root: &[u8; 32],
        cumulative_coinbase: u128,
        cumulative_fees: u128,
        burn_root: &[u8; 32],
    ) -> [u8; 32] {
        let mut h =
            blake2b_simd::Params::new().hash_length(32).personal(STATE_ROOT_PERSONAL).to_state();
        h.update(anchor);
        h.update(nullifier_root);
        h.update(&cumulative_coinbase.to_le_bytes());
        h.update(&cumulative_fees.to_le_bytes());
        h.update(burn_root);
        let mut out = [0u8; 32];
        out.copy_from_slice(h.finalize().as_bytes());
        out
    }

    /// The state root this attestation's own contents imply.
    pub fn computed_state_root<H: Hasher>(&self) -> [u8; 32] {
        Self::state_root(
            &self.anchor,
            &self.nullifier_root,
            self.cumulative_coinbase,
            self.cumulative_fees,
            &self.computed_root::<H>(),
        )
    }

    /// Verifies the receipt is included in a burn accumulator which, together with the declared
    /// shielded state, hashes to exactly the claimed state root `r`.
    ///
    /// This is one equality doing two jobs: it pins the receipt into the burn tree, *and* pins that
    /// tree into the state root the ZKas chain committed. A relayer can satisfy it only by
    /// presenting a burn that genuinely sits in the state it names.
    pub fn verify_inclusion<H: Hasher>(&self) -> bool {
        self.computed_state_root::<H>() == self.r
    }

    /// Encodes an attestation to `ix_data` wire bytes. Used by the relayer and by tests.
    ///
    /// `r` is written as claimed; the guest recomputes it and rejects a mismatch, so an encoder
    /// cannot smuggle an inconsistent state root through.
    #[cfg(feature = "std")]
    #[allow(clippy::too_many_arguments)]
    pub fn encode(
        receipt: &ExitReceipt,
        r: &[u8; 32],
        leaf_index: u32,
        anchor: &[u8; 32],
        nullifier_root: &[u8; 32],
        cumulative_coinbase: u128,
        cumulative_fees: u128,
        branch: &[u8],
    ) -> alloc::vec::Vec<u8> {
        let mut out = alloc::vec::Vec::with_capacity(HEADER_LEN + branch.len());
        out.push(ATTESTATION_V2);
        out.extend_from_slice(&receipt.v.to_le_bytes());
        out.extend_from_slice(&receipt.recipient);
        out.extend_from_slice(&receipt.n);
        out.extend_from_slice(r);
        out.extend_from_slice(&leaf_index.to_le_bytes());
        out.extend_from_slice(anchor);
        out.extend_from_slice(nullifier_root);
        out.extend_from_slice(&cumulative_coinbase.to_le_bytes());
        out.extend_from_slice(&cumulative_fees.to_le_bytes());
        out.extend_from_slice(branch);
        out
    }
}

#[cfg(test)]
mod tests {
    use vprogs_core_hashing::Sha256;

    use super::*;

    const ANCHOR: [u8; 32] = [0x11; 32];
    const NULLROOT: [u8; 32] = [0x22; 32];
    const COINBASE: u128 = 1_000_000_000;
    const FEES: u128 = 12_345;

    fn receipt(v: u64, tag: u8) -> ExitReceipt {
        ExitReceipt { v, recipient: [tag; 32], n: [tag.wrapping_add(0x40); 32] }
    }

    /// Encodes with the standard shielded-state fields, deriving `r` from the given burn root.
    fn encode_for(rec: &ExitReceipt, burn_root: &[u8; 32], idx: u32, branch: &[u8]) -> alloc::vec::Vec<u8> {
        let r = BurnAttestation::state_root(&ANCHOR, &NULLROOT, COINBASE, FEES, burn_root);
        BurnAttestation::encode(rec, &r, idx, &ANCHOR, &NULLROOT, COINBASE, FEES, branch)
    }

    /// Builds a 2-leaf tree and returns (root, branch_for_leaf0, branch_for_leaf1).
    fn two_leaf_tree(a: &ExitReceipt, b: &ExitReceipt) -> ([u8; 32], [u8; 32], [u8; 32]) {
        let la = a.leaf_hash::<Sha256>();
        let lb = b.leaf_hash::<Sha256>();
        let root = Sha256::hash_parts_with_domain(&NODE_DOMAIN, [la.as_slice(), lb.as_slice()]);
        (root, lb, la)
    }

    fn hex(b: &[u8; 32]) -> alloc::string::String {
        use alloc::string::String;
        use core::fmt::Write;
        let mut s = String::new();
        for x in b {
            write!(&mut s, "{x:02x}").expect("write to string");
        }
        s
    }

    /// **Cross-implementation pin.** Computed independently in Python (`hashlib`), and asserted
    /// with the identical values by the ZKas side (`kaspa_shielded_core::burn` and
    /// `::commitment`). If the two ever drift in how they hash a receipt or fold the state root,
    /// every peg-out silently stops verifying — this fails first instead.
    #[test]
    fn hashing_matches_the_shared_wire_contract() {
        let a = ExitReceipt { v: 5_000_000, recipient: [0xA1; 32], n: [0x11; 32] };
        let b = ExitReceipt { v: 250_000, recipient: [0xB2; 32], n: [0x22; 32] };

        assert_eq!(
            hex(&a.leaf_hash::<Sha256>()),
            "27d9600250d03d6eea797a5a9d4a6c8ba66209121a104c8108412dc968ba7302",
        );
        assert_eq!(
            hex(&b.leaf_hash::<Sha256>()),
            "8d3b19448c8d4dd0a44fd1f75b82ff606ef048f2b121c95aeef6953a17ff271f",
        );

        let (burn_root, _, _) = two_leaf_tree(&a, &b);
        assert_eq!(hex(&burn_root), "4a457e6dd8976c5b52b7d7337244ef6478c87e916bdec6465d730ecd5e7fe5d3");

        // The real ZKas shielded state root over that burn root.
        let r = BurnAttestation::state_root(&ANCHOR, &NULLROOT, COINBASE, FEES, &burn_root);
        assert_eq!(hex(&r), "4c803ec34ec41afe760122a9e84802fa93d41e38bb84f5d369a9616a8f91dfc7");
    }

    /// **The cross-repository wire vector.**
    ///
    /// These are the exact `ix_data` bytes the ZKas relayer emits
    /// (`kaspa_shielded_core::attestation::tests::relayer_wire_vector_is_stable`), produced by an
    /// independent Python computation. Encoder and decoder live in separate repositories; this
    /// byte string is what keeps them from drifting. Decoding it and having inclusion verify means
    /// the two halves genuinely interoperate — not merely that they use the same hash functions.
    ///
    /// If this vector changes, the ZKas-side test must change with it.
    #[test]
    fn decodes_the_zkas_relayer_vector() {
        const VECTOR: &str = concat!(
            "02",
            "404b4c0000000000",
            "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
            "1111111111111111111111111111111111111111111111111111111111111111",
            "4c803ec34ec41afe760122a9e84802fa93d41e38bb84f5d369a9616a8f91dfc7",
            "00000000",
            "1111111111111111111111111111111111111111111111111111111111111111",
            "2222222222222222222222222222222222222222222222222222222222222222",
            "00ca9a3b000000000000000000000000",
            "39300000000000000000000000000000",
            "8d3b19448c8d4dd0a44fd1f75b82ff606ef048f2b121c95aeef6953a17ff271f",
        );

        let bytes = unhex(VECTOR);
        assert_eq!(bytes.len(), 237, "header(205) + one 32-byte sibling");

        let att = BurnAttestation::decode(&bytes).expect("relayer vector must decode");

        // The fields the payout depends on.
        assert_eq!(att.receipt.v, 5_000_000);
        assert_eq!(att.receipt.recipient, [0xA1; 32]);
        assert_eq!(att.receipt.n, [0x11; 32]);
        assert_eq!(att.leaf_index, 0);
        assert_eq!(att.anchor, ANCHOR);
        assert_eq!(att.nullifier_root, NULLROOT);
        assert_eq!(att.cumulative_coinbase, COINBASE);
        assert_eq!(att.cumulative_fees, FEES);

        // And the whole point: the guest's recomputed state root matches the relayer's claim.
        assert!(
            att.verify_inclusion::<Sha256>(),
            "a ZKas-produced attestation must verify in the guest",
        );
    }

    fn unhex(s: &str) -> alloc::vec::Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
            .collect()
    }

    #[test]
    fn single_leaf_roundtrips() {
        let rec = receipt(12_345, 7);
        let burn_root = rec.leaf_hash::<Sha256>();
        let bytes = encode_for(&rec, &burn_root, 0, &[]);
        let att = BurnAttestation::decode(&bytes).unwrap();

        assert_eq!(att.receipt, rec);
        assert_eq!(att.cumulative_coinbase, COINBASE);
        assert_eq!(att.cumulative_fees, FEES);
        assert!(att.verify_inclusion::<Sha256>());
    }

    #[test]
    fn both_leaves_of_a_two_leaf_tree_verify() {
        let a = receipt(100, 1);
        let b = receipt(200, 2);
        let (burn_root, branch_a, branch_b) = two_leaf_tree(&a, &b);

        for (rec, idx, branch) in [(a, 0u32, branch_a), (b, 1u32, branch_b)] {
            let bytes = encode_for(&rec, &burn_root, idx, &branch);
            assert!(BurnAttestation::decode(&bytes).unwrap().verify_inclusion::<Sha256>());
        }
    }

    /// Tampering with the amount must break inclusion — this is what stops a relayer inflating a
    /// real burn into a larger payout.
    #[test]
    fn tampered_amount_fails_inclusion() {
        let rec = receipt(100, 1);
        let burn_root = rec.leaf_hash::<Sha256>();
        let r = BurnAttestation::state_root(&ANCHOR, &NULLROOT, COINBASE, FEES, &burn_root);

        let mut tampered = rec;
        tampered.v = 1_000_000;
        let bytes = BurnAttestation::encode(&tampered, &r, 0, &ANCHOR, &NULLROOT, COINBASE, FEES, &[]);
        assert!(!BurnAttestation::decode(&bytes).unwrap().verify_inclusion::<Sha256>());
    }

    /// Likewise for redirecting the payout to another recipient.
    #[test]
    fn tampered_recipient_fails_inclusion() {
        let rec = receipt(100, 1);
        let burn_root = rec.leaf_hash::<Sha256>();
        let r = BurnAttestation::state_root(&ANCHOR, &NULLROOT, COINBASE, FEES, &burn_root);

        let mut tampered = rec;
        tampered.recipient = [0xff; 32];
        let bytes = BurnAttestation::encode(&tampered, &r, 0, &ANCHOR, &NULLROOT, COINBASE, FEES, &[]);
        assert!(!BurnAttestation::decode(&bytes).unwrap().verify_inclusion::<Sha256>());
    }

    /// The state root is recomputed, not trusted: pairing a genuine burn with a state root from a
    /// *different* shielded state must fail. This is the attack the v1 wire format allowed.
    #[test]
    fn state_root_from_a_different_state_fails() {
        let rec = receipt(100, 1);
        let burn_root = rec.leaf_hash::<Sha256>();

        // Honest burn, but the claimed root is for a different fee total.
        let wrong_r = BurnAttestation::state_root(&ANCHOR, &NULLROOT, COINBASE, FEES + 1, &burn_root);
        let bytes = BurnAttestation::encode(&rec, &wrong_r, 0, &ANCHOR, &NULLROOT, COINBASE, FEES, &[]);
        assert!(!BurnAttestation::decode(&bytes).unwrap().verify_inclusion::<Sha256>());

        // And the mirror image: honest root, but lying about the declared state in the preimage.
        let r = BurnAttestation::state_root(&ANCHOR, &NULLROOT, COINBASE, FEES, &burn_root);
        let bytes = BurnAttestation::encode(&rec, &r, 0, &ANCHOR, &NULLROOT, COINBASE, FEES + 1, &[]);
        assert!(!BurnAttestation::decode(&bytes).unwrap().verify_inclusion::<Sha256>());

        // A tampered anchor is caught the same way.
        let bytes = BurnAttestation::encode(&rec, &r, 0, &[0xEE; 32], &NULLROOT, COINBASE, FEES, &[]);
        assert!(!BurnAttestation::decode(&bytes).unwrap().verify_inclusion::<Sha256>());
    }

    /// A leaf hash must not be replayable as an interior node (domain separation).
    #[test]
    fn leaf_and_node_domains_are_disjoint() {
        let payload = [0xabu8; 64];
        assert_ne!(
            Sha256::hash_with_domain(&LEAF_DOMAIN, payload),
            Sha256::hash_with_domain(&NODE_DOMAIN, payload)
        );
    }

    #[test]
    fn rejects_malformed_attestations() {
        let rec = receipt(1, 1);
        let burn_root = [0u8; 32];

        // Truncated header.
        assert!(BurnAttestation::decode(&[2u8; 10]).is_err());

        // Bad version (including the retired v1).
        let mut bytes = encode_for(&rec, &burn_root, 0, &[]);
        bytes[0] = 1;
        assert!(BurnAttestation::decode(&bytes).is_err());

        // Branch not a multiple of 32.
        let mut bytes = encode_for(&rec, &burn_root, 0, &[]);
        bytes.extend_from_slice(&[0u8; 5]);
        assert!(BurnAttestation::decode(&bytes).is_err());

        // leaf_index has bits above the branch depth (depth 1 -> index must be 0 or 1).
        let bytes = encode_for(&rec, &burn_root, 2, &[0u8; 32]);
        assert!(BurnAttestation::decode(&bytes).is_err());

        // Branch deeper than MAX_BRANCH_DEPTH.
        let bytes = encode_for(&rec, &burn_root, 0, &[0u8; 32 * (MAX_BRANCH_DEPTH + 1)]);
        assert!(BurnAttestation::decode(&bytes).is_err());
    }
}
