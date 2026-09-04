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
