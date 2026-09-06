//! Shared types and pure verification logic for the shielded-pool demo.
//!
//! The design mirrors the production plan (SHIELDED-KAS-PLAN §3): SHA-256 note commitments in a
//! fixed-depth Merkle tree, keyed nullifiers (spending requires `sk`; watching requires nothing —
//! nullifiers are unlinkable to commitments without the key), consensus-assigned output `rho`
//! (Faerie-Gold immunity), per-asset in-guest balance, and a dual-asset fee: ZKAS at 1x or KAS at
//! [`KAS_FEE_PREMIUM`]x. Both the host and the RISC0 guest call [`verify_shielded_tx`] — the host
//! to build state, the guest to prove it — so they can never disagree.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Re-exported so the host binary hashes with the exact same sha2 the pool logic uses.
pub use sha2;

/// Asset ids inside the pool. One tree, one anonymity set, asset hidden inside the note.
pub const ASSET_KAS: u8 = 0;
pub const ASSET_ZKAS: u8 = 1;

/// Merkle tree depth (demo: 2^16 notes).
pub const TREE_DEPTH: usize = 16;

/// Minimum fee when paid in ZKAS (canonical fee asset), in demo base units.
pub const MIN_FEE_ZKAS: u64 = 1_000;
/// Fee premium multiplier when paying the fee in KAS instead of ZKAS.
pub const KAS_FEE_PREMIUM: u64 = 3;

fn h(parts: &[&[u8]]) -> [u8; 32] {
    let mut d = Sha256::new();
    for p in parts {
        d.update(p);
    }
    d.finalize().into()
}

/// Spend-authority address: knowing `sk` IS the authority (the proof, not a signature,
/// authorizes the spend).
pub fn addr_from_sk(sk: &[u8; 32]) -> [u8; 32] {
    h(&[b"zkasL2.addr", sk])
}

/// Nullifier-deriving key. Separate from the address so a future viewing-key split is natural.
pub fn nk_from_sk(sk: &[u8; 32]) -> [u8; 32] {
    h(&[b"zkasL2.nk", sk])
}

/// Note commitment: binding by SHA-256, hiding by the 32-byte random `rseed`.
pub fn note_cm(n: &Note) -> [u8; 32] {
    h(&[b"zkasL2.note", &[n.asset], &n.value.to_le_bytes(), &n.pk, &n.rho, &n.rseed])
}

/// Keyed nullifier: unlinkable to the commitment without `nk`, deterministic per note.
pub fn nullifier(nk: &[u8; 32], rho: &[u8; 32]) -> [u8; 32] {
    h(&[b"zkasL2.nf", nk, rho])
}

/// Consensus-assigned output rho: a function of the tx's first nullifier and the output index,
/// so a sender can never choose it (Faerie-Gold immunity, ZIP-224 pattern).
pub fn output_rho(first_nullifier: &[u8; 32], output_index: u32) -> [u8; 32] {
    h(&[b"zkasL2.rho", first_nullifier, &output_index.to_le_bytes()])
}

/// Deposit rho: fixed by the L1 outpoint that funded the shield, so it is unique per deposit.
pub fn deposit_rho(l1_txid: &[u8; 32], output_index: u32) -> [u8; 32] {
    h(&[b"zkasL2.rho.deposit", l1_txid, &output_index.to_le_bytes()])
}

/// Internal Merkle node hash.
pub fn node_hash(l: &[u8; 32], r: &[u8; 32]) -> [u8; 32] {
    h(&[b"zkasL2.node", l, r])
}

/// The empty-subtree hash ladder: `zeros[0]` is the empty leaf, `zeros[d]` the empty subtree of
/// height `d`.
pub fn zero_ladder() -> [[u8; 32]; TREE_DEPTH + 1] {
    let mut z = [[0u8; 32]; TREE_DEPTH + 1];
    z[0] = h(&[b"zkasL2.leaf.empty"]);
    for d in 1..=TREE_DEPTH {
        let below = z[d - 1];
        z[d] = node_hash(&below, &below);
    }
    z
}

/// Fold a leaf up its authentication path to the root.
pub fn fold_path(leaf: &[u8; 32], leaf_index: u32, path: &[[u8; 32]]) -> [u8; 32] {
    let mut acc = *leaf;
    let mut idx = leaf_index;
    for sib in path {
        acc = if idx & 1 == 0 { node_hash(&acc, sib) } else { node_hash(sib, &acc) };
        idx >>= 1;
    }
    acc
}

/// A shielded note. Everything here is private; only the commitment ever appears in public data.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Note {
    pub asset: u8,
    pub value: u64,
    pub pk: [u8; 32],
    pub rho: [u8; 32],
    pub rseed: [u8; 32],
}

/// Private witness for one spent note.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SpendWitness {
    pub note: Note,
    /// Spending key; the guest checks `addr_from_sk(sk) == note.pk`.
    pub sk: [u8; 32],
    pub leaf_index: u32,
    /// Authentication path, exactly [`TREE_DEPTH`] siblings.
    pub path: Vec<[u8; 32]>,
}

/// A public exit (withdrawal) — leaving the pool reveals amount and recipient by definition.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExitDecl {
    pub asset: u8,
    pub value: u64,
    /// L1 recipient commitment (demo: 32 raw bytes of an L1 payout identity).
    pub recipient: [u8; 32],
}

/// The full private witness for one shielded transaction.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ShieldedTxWitness {
    /// A settled tree root the spends are proven against.
    pub anchor: [u8; 32],
    pub spends: Vec<SpendWitness>,
    pub outputs: Vec<Note>,
    /// One encrypted note per output (opaque to the guest; hashed into the journal so the
    /// on-chain ciphertexts are exactly the ones the proof committed to).
    pub ciphertexts: Vec<Vec<u8>>,
    pub fee_asset: u8,
    pub fee_amount: u64,
    pub exit: Option<ExitDecl>,
}

/// The public journal — the ONLY facts a transaction reveals.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShieldedTxJournal {
    pub anchor: [u8; 32],
    pub nullifiers: Vec<[u8; 32]>,
    pub new_cms: Vec<[u8; 32]>,
    pub ciphertext_hash: [u8; 32],
    pub fee_asset: u8,
    pub fee_amount: u64,
    pub exit: Option<ExitDecl>,
}

/// Hash the ciphertext list (length-prefixed, order-binding).
pub fn ciphertexts_hash(cts: &[Vec<u8>]) -> [u8; 32] {
    let mut d = Sha256::new();
    d.update(b"zkasL2.cts");
    d.update((cts.len() as u32).to_le_bytes());
    for ct in cts {
        d.update((ct.len() as u32).to_le_bytes());
        d.update(ct);
    }
    d.finalize().into()
}

/// Verify one shielded transaction and derive its public journal.
///
/// Enforced in-proof:
/// 1. spend authority (`sk` opens each spent note's address),
/// 2. membership (each spent commitment folds to `anchor`),
/// 3. keyed nullifiers, no duplicates within the tx,
/// 4. consensus-assigned output rho,
/// 5. per-asset conservation: inputs = outputs + fee + exit (u128, no overflow),
/// 6. the dual-asset fee floor: ZKAS at 1x or KAS at [`KAS_FEE_PREMIUM`]x,
/// 7. ciphertext binding (one ciphertext per output, hashed into the journal).
pub fn verify_shielded_tx(w: &ShieldedTxWitness) -> Result<ShieldedTxJournal, &'static str> {
    if w.spends.is_empty() {
        return Err("a shielded tx must spend at least one note");
    }
    if w.outputs.len() != w.ciphertexts.len() {
        return Err("one ciphertext per output");
    }

    // (6) Fee floor, dual-asset.
    match w.fee_asset {
        ASSET_ZKAS => {
            if w.fee_amount < MIN_FEE_ZKAS {
                return Err("fee below the ZKAS floor");
            }
        }
        ASSET_KAS => {
            if w.fee_amount < MIN_FEE_ZKAS.saturating_mul(KAS_FEE_PREMIUM) {
                return Err("fee below the KAS floor (KAS pays the premium)");
            }
        }
        _ => return Err("unknown fee asset"),
    }

    // (1)-(3) Spends.
    let mut nullifiers: Vec<[u8; 32]> = Vec::with_capacity(w.spends.len());
    let mut in_sum = [0u128; 2];
    for s in &w.spends {
        if addr_from_sk(&s.sk) != s.note.pk {
            return Err("spending key does not open the note's address");
        }
        if s.path.len() != TREE_DEPTH {
            return Err("bad path length");
        }
        let cm = note_cm(&s.note);
        if fold_path(&cm, s.leaf_index, &s.path) != w.anchor {
            return Err("spent note is not in the tree under the anchor");
        }
        let nf = nullifier(&nk_from_sk(&s.sk), &s.note.rho);
        if nullifiers.contains(&nf) {
            return Err("duplicate nullifier inside the tx");
        }
        nullifiers.push(nf);
        let a = s.note.asset as usize;
        if a > 1 {
            return Err("unknown asset on input");
        }
        in_sum[a] += s.note.value as u128;
    }

    // (4) Outputs: consensus-assigned rho, commitments derived in-proof.
    let mut out_sum = [0u128; 2];
    let mut new_cms: Vec<[u8; 32]> = Vec::with_capacity(w.outputs.len());
    for (i, o) in w.outputs.iter().enumerate() {
        if o.asset as usize > 1 {
            return Err("unknown asset on output");
        }
        if o.rho != output_rho(&nullifiers[0], i as u32) {
            return Err("output rho must be consensus-assigned");
        }
        if o.value == 0 {
            return Err("zero-value output");
        }
        out_sum[o.asset as usize] += o.value as u128;
        new_cms.push(note_cm(o));
    }

    // (5) Per-asset conservation.
    let mut need = out_sum;
    need[w.fee_asset as usize] += w.fee_amount as u128;
    if let Some(e) = &w.exit {
        if e.asset as usize > 1 {
            return Err("unknown asset on exit");
        }
        if e.value == 0 {
            return Err("zero-value exit");
        }
        need[e.asset as usize] += e.value as u128;
    }
    if need != in_sum {
        return Err("per-asset balance violated");
    }

    Ok(ShieldedTxJournal {
        anchor: w.anchor,
        nullifiers,
        new_cms,
        ciphertext_hash: ciphertexts_hash(&w.ciphertexts),
        fee_asset: w.fee_asset,
        fee_amount: w.fee_amount,
        exit: w.exit,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn note(asset: u8, value: u64, sk: &[u8; 32], rho: [u8; 32]) -> Note {
        Note { asset, value, pk: addr_from_sk(sk), rho, rseed: [9u8; 32] }
    }

    /// Build a tiny tree of the given leaves and return (root, path_for_index).
    fn tree(leaves: &[[u8; 32]]) -> ([u8; 32], impl Fn(u32) -> Vec<[u8; 32]> + '_) {
        let z = zero_ladder();
        let paths = move |target: u32| {
            let mut path = Vec::new();
            let mut level: Vec<[u8; 32]> = leaves.to_vec();
            let mut idx = target;
            for d in 0..TREE_DEPTH {
                let sib = idx ^ 1;
                path.push(*level.get(sib as usize).unwrap_or(&z[d]));
                let mut next = Vec::with_capacity(level.len().div_ceil(2) );
                for pair in level.chunks(2) {
                    let l = pair[0];
                    let r = *pair.get(1).unwrap_or(&z[d]);
                    next.push(node_hash(&l, &r));
                }
                level = next;
                idx >>= 1;
            }
            path
        };
        let mut root = z[0];
        {
            let mut level: Vec<[u8; 32]> = leaves.to_vec();
            for d in 0..TREE_DEPTH {
                let mut next = Vec::with_capacity(level.len().div_ceil(2));
                for pair in level.chunks(2) {
                    let l = pair[0];
                    let r = *pair.get(1).unwrap_or(&z[d]);
                    next.push(node_hash(&l, &r));
                }
                if next.is_empty() {
                    next.push(z[d + 1]);
                }
                level = next;
            }
            root = level[0];
        }
        (root, paths)
    }

    fn spend_of(n: Note, sk: [u8; 32], idx: u32, path: Vec<[u8; 32]>) -> SpendWitness {
        SpendWitness { note: n, sk, leaf_index: idx, path }
    }

    #[test]
    fn transfer_conserves_and_reveals_only_the_journal() {
        let sk_a = [1u8; 32];
        let kas = note(ASSET_KAS, 100_000, &sk_a, [7u8; 32]);
        let zk = note(ASSET_ZKAS, 50_000, &sk_a, [8u8; 32]);
        let leaves = [note_cm(&kas), note_cm(&zk)];
        let (root, paths) = tree(&leaves);

        let nf0 = nullifier(&nk_from_sk(&sk_a), &kas.rho);
        let sk_b = [2u8; 32];
        let out_b = Note {
            asset: ASSET_KAS,
            value: 30_000,
            pk: addr_from_sk(&sk_b),
            rho: output_rho(&nf0, 0),
            rseed: [3u8; 32],
        };
        let change_kas = Note {
            asset: ASSET_KAS,
            value: 70_000,
            pk: addr_from_sk(&sk_a),
            rho: output_rho(&nf0, 1),
            rseed: [4u8; 32],
        };
        let change_zk = Note {
            asset: ASSET_ZKAS,
            value: 50_000 - MIN_FEE_ZKAS,
            pk: addr_from_sk(&sk_a),
            rho: output_rho(&nf0, 2),
            rseed: [5u8; 32],
        };
        let w = ShieldedTxWitness {
            anchor: root,
            spends: vec![
                spend_of(kas, sk_a, 0, paths(0)),
                spend_of(zk, sk_a, 1, paths(1)),
            ],
            outputs: vec![out_b, change_kas, change_zk],
            ciphertexts: vec![vec![1], vec![2], vec![3]],
            fee_asset: ASSET_ZKAS,
            fee_amount: MIN_FEE_ZKAS,
            exit: None,
        };
        let j = verify_shielded_tx(&w).expect("valid transfer");
        assert_eq!(j.nullifiers.len(), 2);
        assert_eq!(j.new_cms.len(), 3);

        // Inflation attempt: grow an output by one unit.
        let mut bad = w.clone();
        bad.outputs[0].value += 1;
        assert_eq!(verify_shielded_tx(&bad).unwrap_err(), "per-asset balance violated");

        // Cross-asset laundering attempt: pay KAS out of ZKAS inputs.
        let mut cross = w.clone();
        cross.outputs[0].asset = ASSET_ZKAS;
        assert!(verify_shielded_tx(&cross).is_err());

        // Wrong key.
        let mut theft = w.clone();
        theft.spends[0].sk = [9u8; 32];
        assert_eq!(verify_shielded_tx(&theft).unwrap_err(), "spending key does not open the note's address");
    }

    #[test]
    fn kas_fee_pays_the_premium() {
        let sk = [1u8; 32];
        let kas = note(ASSET_KAS, 100_000, &sk, [7u8; 32]);
        let leaves = [note_cm(&kas)];
        let (root, paths) = tree(&leaves);
        let nf0 = nullifier(&nk_from_sk(&sk), &kas.rho);
        let mk = |fee: u64| ShieldedTxWitness {
            anchor: root,
            spends: vec![spend_of(kas, sk, 0, paths(0))],
            outputs: vec![Note {
                asset: ASSET_KAS,
                value: 100_000 - fee,
                pk: addr_from_sk(&sk),
                rho: output_rho(&nf0, 0),
                rseed: [3u8; 32],
            }],
            ciphertexts: vec![vec![1]],
            fee_asset: ASSET_KAS,
            fee_amount: fee,
            exit: None,
        };
        // ZKAS floor is not enough when paying in KAS…
        assert!(verify_shielded_tx(&mk(MIN_FEE_ZKAS)).is_err());
        // …the 3x premium is.
        verify_shielded_tx(&mk(MIN_FEE_ZKAS * KAS_FEE_PREMIUM)).expect("premium fee accepted");
    }
}

// =============================================================================================
// Batch layer: the aggregate state transition the covenant ultimately verifies.
// =============================================================================================

/// Depth of the nullifier sparse-Merkle accumulator (one bit per nullifier bit).
pub const NF_DEPTH: usize = 256;

/// Empty-leaf and member-leaf values of the nullifier accumulator.
pub fn nf_empty_leaf() -> [u8; 32] {
    h(&[b"zkasL2.nf.empty"])
}
pub fn nf_member_leaf() -> [u8; 32] {
    h(&[b"zkasL2.nf.member"])
}

/// Default (all-empty) subtree ladder for the nullifier accumulator: `d[l]` = empty subtree of
/// height `l`.
pub fn nf_default_ladder() -> Vec<[u8; 32]> {
    let mut d = Vec::with_capacity(NF_DEPTH + 1);
    d.push(nf_empty_leaf());
    for l in 0..NF_DEPTH {
        let below = d[l];
        d.push(node_hash(&below, &below));
    }
    d
}

/// Bit `i` (MSB-first) of a 32-byte value.
fn nf_bit(nf: &[u8; 32], i: usize) -> bool {
    (nf[i / 8] >> (7 - (i % 8))) & 1 == 1
}

/// Fold a leaf value up the nullifier path with the given siblings (level 0 = leaf level).
fn nf_fold(nf: &[u8; 32], leaf: [u8; 32], siblings: &[[u8; 32]]) -> [u8; 32] {
    let mut acc = leaf;
    for l in 0..NF_DEPTH {
        // The bit that chooses left/right at level l is bit (NF_DEPTH - 1 - l) of the key.
        let right = nf_bit(nf, NF_DEPTH - 1 - l);
        acc = if right { node_hash(&siblings[l], &acc) } else { node_hash(&acc, &siblings[l]) };
    }
    acc
}

/// Verify `nf` is NOT in the set with root `root` (its leaf is empty under `siblings`), then
/// insert it, returning the new root. This is the double-spend gate the batch proof enforces
/// against ALL history, not just within one batch.
pub fn nf_verify_and_insert(
    root: &[u8; 32],
    nf: &[u8; 32],
    siblings: &[[u8; 32]],
) -> Result<[u8; 32], &'static str> {
    if siblings.len() != NF_DEPTH {
        return Err("bad nullifier witness length");
    }
    if &nf_fold(nf, nf_empty_leaf(), siblings) != root {
        return Err("nullifier already spent (or stale witness)");
    }
    Ok(nf_fold(nf, nf_member_leaf(), siblings))
}

/// Incremental frontier of the commitment tree: appends in O(depth), root equals the padded
/// fixed-depth tree over the same leaves.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Frontier {
    pub count: u64,
    pub peaks: Vec<[u8; 32]>, // TREE_DEPTH entries; peaks[l] valid when bit l of count is set
}

impl Default for Frontier {
    fn default() -> Self {
        Frontier { count: 0, peaks: vec![[0u8; 32]; TREE_DEPTH] }
    }
}

impl Frontier {
    pub fn push(&mut self, leaf: [u8; 32]) {
        assert!(self.count < 1 << TREE_DEPTH, "tree full");
        let mut carry = leaf;
        for l in 0..TREE_DEPTH {
            if (self.count >> l) & 1 == 1 {
                carry = node_hash(&self.peaks[l], &carry);
            } else {
                self.peaks[l] = carry;
                break;
            }
        }
        self.count += 1;
    }

    pub fn root(&self) -> [u8; 32] {
        let z = zero_ladder();
        // Fold the right edge: at each level either close a pending peak or pad with zeros.
        let mut acc = z[0];
        let mut acc_is_empty = true;
        for l in 0..TREE_DEPTH {
            if (self.count >> l) & 1 == 1 {
                acc = if acc_is_empty { node_hash(&self.peaks[l], &z[l]) } else { node_hash(&self.peaks[l], &acc) };
                acc_is_empty = false;
            } else if !acc_is_empty {
                acc = node_hash(&acc, &z[l]);
            } else {
                acc = z[l + 1];
                // still empty
            }
        }
        if acc_is_empty { z[TREE_DEPTH] } else { acc }
    }
}

/// The combined L2 state the covenant tracks: commitment-tree root + nullifier-set root.
pub fn batch_state(tree_root: &[u8; 32], nf_root: &[u8; 32]) -> [u8; 32] {
    h(&[b"zkasL2.state", tree_root, nf_root])
}

/// Per-transaction batch witness: the (already receipt-verified) public journal plus one
/// accumulator witness per nullifier, captured at its insertion position.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BatchTxWitness {
    pub journal: ShieldedTxJournal,
    pub nf_siblings: Vec<Vec<[u8; 32]>>,
}

/// The full batch witness.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BatchWitness {
    /// Image id of the spend guest whose receipts vouch for the journals; committed to the
    /// batch journal so the verifier pins it.
    pub inner_image_id: [u8; 32],
    pub prev_frontier: Frontier,
    pub prev_nf_root: [u8; 32],
    /// Deposit commitments credited from L1 in this batch (appended before any transfer).
    pub deposits: Vec<[u8; 32]>,
    pub txs: Vec<BatchTxWitness>,
}

/// The batch's public journal — what the settlement covenant binds.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BatchJournal {
    pub inner_image_id: [u8; 32],
    pub prev_state: [u8; 32],
    pub new_state: [u8; 32],
    pub deposits_hash: [u8; 32],
    /// All exits this batch owes, in order — the settler builds the permission tree from these.
    pub exits: Vec<ExitDecl>,
    /// Fees claimable by the batch poster, per asset [KAS, ZKAS].
    pub fees: [u64; 2],
    pub tx_count: u32,
}

fn hash_cm_list(cms: &[[u8; 32]]) -> [u8; 32] {
    let mut d = Sha256::new();
    d.update(b"zkasL2.deposits");
    d.update((cms.len() as u32).to_le_bytes());
    for cm in cms {
        d.update(cm);
    }
    d.finalize().into()
}

/// Apply a whole batch to the L2 state, verifying every rule EXCEPT the receipts themselves
/// (the guest adds `env::verify` per journal; the host has verified receipts out-of-band).
///
/// Rules: every tx anchor must be a rolling root of THIS batch's history (the previous settled
/// root, or any intermediate root after deposits/earlier txs); every nullifier proves
/// non-membership against the accumulator and is inserted (history-wide double-spend gate);
/// commitments append in order; fees and exits accumulate.
pub fn verify_batch(w: &BatchWitness) -> Result<BatchJournal, &'static str> {
    let mut frontier = w.prev_frontier.clone();
    let prev_state = batch_state(&frontier.root(), &w.prev_nf_root);
    let mut nf_root = w.prev_nf_root;
    let mut roots_seen = vec![frontier.root()];

    for cm in &w.deposits {
        frontier.push(*cm);
    }
    roots_seen.push(frontier.root());

    let mut fees = [0u64; 2];
    let mut exits = Vec::new();
    for tx in &w.txs {
        let j = &tx.journal;
        if !roots_seen.contains(&j.anchor) {
            return Err("tx anchor is not a rolling root of this batch");
        }
        if j.nullifiers.len() != tx.nf_siblings.len() {
            return Err("one accumulator witness per nullifier");
        }
        for (nf, sib) in j.nullifiers.iter().zip(&tx.nf_siblings) {
            nf_root = nf_verify_and_insert(&nf_root, nf, sib)?;
        }
        for cm in &j.new_cms {
            frontier.push(*cm);
        }
        roots_seen.push(frontier.root());
        if j.fee_asset as usize > 1 {
            return Err("unknown fee asset");
        }
        fees[j.fee_asset as usize] =
            fees[j.fee_asset as usize].checked_add(j.fee_amount).ok_or("fee overflow")?;
        if let Some(e) = j.exit {
            exits.push(e);
        }
    }

    Ok(BatchJournal {
        inner_image_id: w.inner_image_id,
        prev_state,
        new_state: batch_state(&frontier.root(), &nf_root),
        deposits_hash: hash_cm_list(&w.deposits),
        exits,
        fees,
        tx_count: w.txs.len() as u32,
    })
}

#[cfg(test)]
mod batch_tests {
    use super::*;

    #[test]
    fn frontier_root_matches_padded_tree() {
        // The padded fixed-depth tree, computed the flat way.
        fn flat_root(leaves: &[[u8; 32]]) -> [u8; 32] {
            let z = zero_ladder();
            let mut level = leaves.to_vec();
            for d in 0..TREE_DEPTH {
                if level.is_empty() {
                    return z[TREE_DEPTH];
                }
                let mut next = Vec::new();
                for pair in level.chunks(2) {
                    next.push(node_hash(&pair[0], pair.get(1).unwrap_or(&z[d])));
                }
                level = next;
            }
            level[0]
        }
        let mut f = Frontier::default();
        let mut leaves = Vec::new();
        assert_eq!(f.root(), flat_root(&leaves), "empty");
        for i in 0..40u64 {
            let leaf = h(&[b"leaf", &i.to_le_bytes()]);
            f.push(leaf);
            leaves.push(leaf);
            assert_eq!(f.root(), flat_root(&leaves), "after {} appends", i + 1);
        }
    }

    #[test]
    fn nullifier_accumulator_rejects_replay() {
        // Host-side sparse set mirroring the accumulator.
        let ladder = nf_default_ladder();
        let mut nodes: std::collections::HashMap<(usize, Vec<u8>), [u8; 32]> =
            std::collections::HashMap::new();
        let mut root = ladder[NF_DEPTH];

        // Prefix of the first (NF_DEPTH - level) bits, byte-packed.
        fn prefix(nf: &[u8; 32], bits: usize) -> Vec<u8> {
            let mut p = nf[..bits.div_ceil(8)].to_vec();
            if bits % 8 != 0 {
                let last = p.len() - 1;
                p[last] &= 0xFFu8 << (8 - bits % 8);
            }
            p
        }
        fn get(
            nodes: &std::collections::HashMap<(usize, Vec<u8>), [u8; 32]>,
            ladder: &[[u8; 32]],
            level: usize,
            pfx: Vec<u8>,
        ) -> [u8; 32] {
            *nodes.get(&(level, pfx)).unwrap_or(&ladder[level])
        }
        let mut insert = |nf: &[u8; 32],
                          nodes: &mut std::collections::HashMap<(usize, Vec<u8>), [u8; 32]>,
                          root: &mut [u8; 32]|
         -> Result<Vec<[u8; 32]>, &'static str> {
            // Collect siblings bottom-up.
            let mut sibs = Vec::with_capacity(NF_DEPTH);
            for l in 0..NF_DEPTH {
                let bits = NF_DEPTH - l;
                let mut sib_key = *nf;
                // flip bit (bits-1)
                sib_key[(bits - 1) / 8] ^= 1 << (7 - ((bits - 1) % 8));
                sibs.push(get(nodes, &ladder, l, prefix(&sib_key, bits)));
            }
            let new_root = nf_verify_and_insert(root, nf, &sibs)?;
            // Write the member path.
            let mut acc = nf_member_leaf();
            nodes.insert((0, prefix(nf, NF_DEPTH)), acc);
            for l in 0..NF_DEPTH - 1 {
                let bits = NF_DEPTH - l;
                let right = nf_bit(nf, bits - 1);
                acc = if right { node_hash(&sibs[l], &acc) } else { node_hash(&acc, &sibs[l]) };
                nodes.insert((l + 1, prefix(nf, bits - 1)), acc);
            }
            *root = new_root;
            Ok(sibs)
        };

        let a = h(&[b"nf-a"]);
        let b = h(&[b"nf-b"]);
        insert(&a, &mut nodes, &mut root).expect("first insert");
        insert(&b, &mut nodes, &mut root).expect("second insert");
        assert_eq!(
            insert(&a, &mut nodes, &mut root).unwrap_err(),
            "nullifier already spent (or stale witness)",
            "replaying a across batches must fail"
        );
    }
}

/// Host-side sparse nullifier set mirroring the in-proof accumulator: produces, for each insert,
/// the sibling witness the guest verifies. (An L2 node keeps one of these per pool.)
#[derive(Clone, Debug, Default)]
pub struct SparseNfSet {
    nodes: std::collections::HashMap<(usize, Vec<u8>), [u8; 32]>,
    root: Option<[u8; 32]>,
}

impl SparseNfSet {
    fn prefix(nf: &[u8; 32], bits: usize) -> Vec<u8> {
        let mut p = nf[..bits.div_ceil(8)].to_vec();
        if bits % 8 != 0 {
            let last = p.len() - 1;
            p[last] &= 0xFFu8 << (8 - bits % 8);
        }
        p
    }

    pub fn root(&self) -> [u8; 32] {
        self.root.unwrap_or_else(|| nf_default_ladder()[NF_DEPTH])
    }

    /// Insert `nf`, returning the sibling witness valid for the accumulator state BEFORE the
    /// insert. Errors on a replay.
    pub fn insert(&mut self, nf: &[u8; 32]) -> Result<Vec<[u8; 32]>, &'static str> {
        let ladder = nf_default_ladder();
        let mut sibs = Vec::with_capacity(NF_DEPTH);
        for l in 0..NF_DEPTH {
            let bits = NF_DEPTH - l;
            let mut sib_key = *nf;
            sib_key[(bits - 1) / 8] ^= 1 << (7 - ((bits - 1) % 8));
            let pfx = Self::prefix(&sib_key, bits);
            sibs.push(*self.nodes.get(&(l, pfx)).unwrap_or(&ladder[l]));
        }
        let root = self.root();
        let new_root = nf_verify_and_insert(&root, nf, &sibs)?;
        let mut acc = nf_member_leaf();
        self.nodes.insert((0, Self::prefix(nf, NF_DEPTH)), acc);
        for l in 0..NF_DEPTH - 1 {
            let bits = NF_DEPTH - l;
            let right = {
                let i = bits - 1;
                (nf[i / 8] >> (7 - (i % 8))) & 1 == 1
            };
            acc = if right { node_hash(&sibs[l], &acc) } else { node_hash(&acc, &sibs[l]) };
            self.nodes.insert((l + 1, Self::prefix(nf, bits - 1)), acc);
        }
        self.root = Some(new_root);
        Ok(sibs)
    }
}
