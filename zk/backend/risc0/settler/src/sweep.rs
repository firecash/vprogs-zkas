//! Withdrawal sweep: the host-side builder for spending a settlement's **permission output**
//! together with delegate-entry deposit UTXOs, paying an exit's recipient real L1 value.
//!
//! This is the last hop of a peg-out/withdrawal: the covenant's settlement carved a permission
//! UTXO committing the exit tree; sweeping it is proofless (the sig_script carries only public
//! withdrawal data — the leaf, its Merkle proof, and the deduct amount), so **anyone** can build
//! this transaction for a recipient. The permission redeem script enforces that output 0 pays at
//! least the deduct to the leaf's SPK (#77) and that the claimed tree matches the committed root
//! (#78); the value itself is funded by delegate-entry inputs.

use kaspa_consensus_core::{
    constants::TX_VERSION_TOCCATA,
    subnets::SUBNETWORK_ID_NATIVE,
    tx::{
        CovenantBinding, ScriptPublicKey, Transaction, TransactionInput, TransactionOutpoint,
        TransactionOutput,
    },
};
use kaspa_hashes::Hash;
use kaspa_txscript::{
    EngineFlags, script_builder::ScriptBuilder, standard::pay_to_script_hash_script,
};
use vprogs_zk_abi::withdrawal::StandardSpk;
use vprogs_zk_backend_risc0_api::{PermissionTreeAccumulator, build_permission_redeem_script};

/// One exit owed by the pool: `amount` to the P2PK holder of `recipient_pk`.
#[derive(Clone, Copy, Debug)]
pub struct ExitLeafSpec {
    pub recipient_pk: [u8; 32],
    pub amount: u64,
}

/// A dense permission tree over the exits of one settlement, hashed with the accumulator's own
/// tag domains so the host root equals the in-guest/on-chain root byte-for-byte.
pub struct PermissionTree {
    leaves: Vec<([u8; 34], u64)>,
    depth: usize,
}

impl PermissionTree {
    pub fn new(exits: &[ExitLeafSpec]) -> Self {
        let leaves = exits
            .iter()
            .map(|e| {
                let bytes = StandardSpk::PubKey(&e.recipient_pk).to_script_bytes();
                let spk: [u8; 34] =
                    bytes.as_slice().try_into().expect("P2PK script bytes are 34 bytes");
                (spk, e.amount)
            })
            .collect::<Vec<_>>();
        let depth = PermissionTreeAccumulator::required_depth(leaves.len());
        PermissionTree { leaves, depth }
    }

    fn leaf_hash(spk: &[u8; 34], amount: u64) -> [u8; 32] {
        let pk: &[u8; 32] = spk[1..33].try_into().unwrap();
        PermissionTreeAccumulator::hash_leaf(StandardSpk::PubKey(pk), amount)
    }

    /// All levels bottom-up; `levels[0]` is the padded leaf level, `levels[depth]` the root.
    fn levels(&self) -> Vec<Vec<[u8; 32]>> {
        let capacity = 1usize << self.depth;
        let mut level: Vec<[u8; 32]> = vec![PermissionTreeAccumulator::hash_empty(); capacity];
        for (i, (spk, amount)) in self.leaves.iter().enumerate() {
            level[i] = Self::leaf_hash(spk, *amount);
        }
        let mut levels = vec![level];
        for _ in 0..self.depth {
            let below = levels.last().unwrap();
            let mut up = Vec::with_capacity(below.len() / 2);
            for pair in below.chunks(2) {
                up.push(PermissionTreeAccumulator::hash_branch(&pair[0], &pair[1]));
            }
            levels.push(up);
        }
        levels
    }

    pub fn root(&self) -> [u8; 32] {
        self.levels()[self.depth][0]
    }

    fn siblings(&self, index: usize) -> Vec<[u8; 32]> {
        let levels = self.levels();
        (0..self.depth).map(|d| levels[d][(index >> d) ^ 1]).collect()
    }

    pub fn unclaimed(&self) -> u64 {
        self.leaves.len() as u64
    }

    pub fn redeem(&self) -> Vec<u8> {
        build_permission_redeem_script(&self.root(), self.unclaimed(), self.depth)
    }

    /// The 32-byte script hash the settlement's permission output commits
    /// (`permission_spk(hash)` — bytes `[2..34]` of the 35-byte P2SH script, per the locked layout).
    pub fn spk_hash(&self) -> [u8; 32] {
        let spk = pay_to_script_hash_script(&self.redeem());
        spk.script()[2..34].try_into().unwrap()
    }
}

/// A `ScriptBuilder` with covenant flags so >520-byte redeem pushes are allowed post-Toccata.
fn cov_builder() -> ScriptBuilder {
    ScriptBuilder::with_flags(EngineFlags { covenants_enabled: true, ..Default::default() })
}

/// The permission sig_script: new-root walk, old-root walk, leaf spk, amount (8 LE), deduct,
/// then the redeem script (P2SH pops it last).
fn permission_sig_script(
    spk: &[u8; 34],
    amount: u64,
    deduct: u64,
    index: usize,
    siblings: &[[u8; 32]],
    redeem: &[u8],
) -> Vec<u8> {
    let mut b = cov_builder();
    for level in (0..siblings.len()).rev() {
        b.add_data(&siblings[level]).unwrap();
        b.add_i64(((index >> level) & 1) as i64).unwrap();
    }
    for level in (0..siblings.len()).rev() {
        b.add_data(&siblings[level]).unwrap();
        b.add_i64(((index >> level) & 1) as i64).unwrap();
    }
    b.add_data(spk).unwrap();
    b.add_data(&amount.to_le_bytes()).unwrap();
    b.add_i64(deduct as i64).unwrap();
    b.add_data(redeem).unwrap();
    b.drain()
}

/// Everything the sweep needs to know about the on-chain state it spends.
pub struct SweepInput<'a> {
    pub tree: &'a PermissionTree,
    /// Which exit leaf is being claimed.
    pub leaf_index: usize,
    /// Amount claimed now (full claim: the leaf's amount).
    pub deduct: u64,
    /// The settlement's permission output (index 1 of the settlement tx).
    pub permission_outpoint: TransactionOutpoint,
    /// Value the permission UTXO holds (the covenant's `permission_output_value`, i.e. rent).
    pub permission_value: u64,
    /// Delegate-entry deposit UTXO(s) funding exactly `deduct` in total.
    pub delegate_outpoints: &'a [(TransactionOutpoint, u64)],
    /// The delegate-entry redeem script for this covenant (`build_delegate_entry_script`).
    pub delegate_redeem: &'a [u8],
    pub covenant_id: Hash,
    /// Compute budget for the permission input's script run.
    pub permission_budget: u16,
}

/// Build the withdrawal-sweep transaction. Output 0 pays the recipient; when other exits remain
/// unclaimed, output 1 re-commits the continuation permission UTXO carrying the rent forward
/// (a full final claim folds the rent into the payout instead).
pub fn build_withdrawal_sweep(input: &SweepInput<'_>) -> Transaction {
    let tree = input.tree;
    let (spk, amount) = tree.leaves[input.leaf_index];
    assert!(input.deduct <= amount, "deduct exceeds the leaf's owed amount");
    let delegate_total: u64 = input.delegate_outpoints.iter().map(|(_, v)| v).sum();
    assert_eq!(delegate_total, input.deduct, "delegate inputs must fund exactly the deduct");

    let new_amount = amount - input.deduct;
    let is_zero = new_amount == 0;
    let new_unclaimed = if is_zero { tree.unclaimed() - 1 } else { tree.unclaimed() };
    let is_done = new_unclaimed == 0;

    let old_redeem = tree.redeem();

    // Output 0: the payout. A final full claim folds the rent in.
    let honest_out0 = if is_done { input.deduct + input.permission_value } else { input.deduct };
    let withdrawal_spk = ScriptPublicKey::new(0, spk.to_vec().into());
    let mut outputs = vec![TransactionOutput::with_covenant(honest_out0, withdrawal_spk, None)];

    // Output 1: the continuation permission UTXO when exits remain.
    if !is_done {
        let new_leaf = if is_zero {
            PermissionTreeAccumulator::hash_empty()
        } else {
            PermissionTree::leaf_hash(&spk, new_amount)
        };
        let mut levels = tree.levels();
        levels[0][input.leaf_index] = new_leaf;
        for d in 0..tree.depth {
            let below = std::mem::take(&mut levels[d]);
            let mut up = Vec::with_capacity(below.len() / 2);
            for pair in below.chunks(2) {
                up.push(PermissionTreeAccumulator::hash_branch(&pair[0], &pair[1]));
            }
            levels[d + 1] = up;
        }
        let new_root = levels[tree.depth][0];
        let new_redeem = build_permission_redeem_script(&new_root, new_unclaimed, tree.depth);
        outputs.push(TransactionOutput::with_covenant(
            input.permission_value,
            pay_to_script_hash_script(&new_redeem),
            Some(CovenantBinding::new(0, input.covenant_id)),
        ));
    }

    let mut inputs = vec![TransactionInput::new_with_compute_budget(
        input.permission_outpoint,
        permission_sig_script(
            &spk,
            amount,
            input.deduct,
            input.leaf_index,
            &tree.siblings(input.leaf_index),
            &old_redeem,
        ),
        0,
        input.permission_budget,
    )];
    // Delegate inputs run only a redeem push + hash compare - a small fixed budget suffices,
    // and compute budget is priced into block mass, so oversizing it can burst the block limit.
    const DELEGATE_BUDGET: u16 = 50;
    let delegate_sig = cov_builder().add_data(input.delegate_redeem).unwrap().drain();
    for (outpoint, _) in input.delegate_outpoints {
        inputs.push(TransactionInput::new_with_compute_budget(
            *outpoint,
            delegate_sig.clone(),
            0,
            DELEGATE_BUDGET,
        ));
    }

    Transaction::new(TX_VERSION_TOCCATA, inputs, outputs, 0, SUBNETWORK_ID_NATIVE, 0, vec![])
}
