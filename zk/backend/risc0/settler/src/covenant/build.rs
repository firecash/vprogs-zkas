use kaspa_consensus_core::{
    mass::units::ComputeBudget,
    tx::{ScriptPublicKey, TransactionOutpoint},
};
use kaspa_hashes::Hash;
use kaspa_rpc_core::api::rpc::RpcApi;
use kaspa_txscript::standard::pay_to_script_hash_script;
use vprogs_core_smt::EMPTY_HASH;
use vprogs_l1_types::SettlementInfo;
use vprogs_l1_wallet::Wallet;
use vprogs_zk_aggregate_prover::SettlementArtifact;
use vprogs_zk_backend_risc0_api::{Backend, OwnedSuccinctWitness, Receipt};
use vprogs_zk_backend_risc0_covenant::{
    CommonPins, DEFAULT_PERMISSION_OUTPUT_VALUE, RedeemPins, SeqCommitAccessor, Settlement,
    SettlementDevInput, SettlementInput, SuccinctPins, build_dev_redeem_script,
    build_redeem_script, dev_redeem_script_len, redeem_script_len,
};

/// Covenant-input compute budget for a dev settlement.
pub const DEV_COVENANT_BUDGET: ComputeBudget = ComputeBudget(100);

use super::{BuiltSettlement, CovenantAdvance, CovenantState};
use crate::worker::SettlementMode;

/// Bootstraps a fresh production-pins covenant bound to `lane_key` and returns its initial state
/// plus bootstrap txid.
pub async fn bootstrap_real_covenant<C: RpcApi + ?Sized>(
    wallet: &Wallet<'_, C>,
    backend: &Backend,
    lane_key: Hash,
    value: u64,
) -> (CovenantState, Hash) {
    let (redeem, spk) = bootstrap_redeem(backend, &lane_key);

    let (tx, covenant_id) = wallet.build_covenant_bootstrap_transaction(&redeem, value).await;
    let txid = wallet.submit_transaction(&tx).await.expect("bootstrap submission failed");

    let covenant = CovenantState {
        covenant_id,
        state: EMPTY_HASH,
        lane_tip: Hash::default(),
        outpoint: TransactionOutpoint::new(txid, 0),
        spk,
        value,
        daa_score: 0,
    };
    (covenant, txid)
}

/// Returns the production redeem script and P2SH `ScriptPublicKey` for a fresh covenant.
pub fn bootstrap_redeem(backend: &Backend, lane_key: &Hash) -> (Vec<u8>, ScriptPublicKey) {
    let state = EMPTY_HASH;
    let lane_tip = Hash::default();
    let pins = redeem_pins(backend, lane_key);
    let redeem_len = redeem_script_len(&state, &pins);
    let redeem = build_redeem_script(&state, &lane_tip, redeem_len, &pins);
    let spk = pay_to_script_hash_script(&redeem);
    (redeem, spk)
}

/// Bootstraps a fresh dev-pins covenant bound to `lane_key` and returns its initial state plus
/// bootstrap txid.
pub async fn bootstrap_dev_covenant<C: RpcApi + ?Sized>(
    wallet: &Wallet<'_, C>,
    lane_key: Hash,
    value: u64,
) -> (CovenantState, Hash) {
    let (redeem, spk) = dev_bootstrap_redeem(&lane_key);

    let (tx, covenant_id) = wallet.build_covenant_bootstrap_transaction(&redeem, value).await;
    let txid = wallet.submit_transaction(&tx).await.expect("dev bootstrap submission failed");

    let covenant = CovenantState {
        covenant_id,
        state: EMPTY_HASH,
        lane_tip: Hash::default(),
        outpoint: TransactionOutpoint::new(txid, 0),
        spk,
        value,
        daa_score: 0,
    };
    (covenant, txid)
}

/// Returns the dev redeem script and P2SH `ScriptPublicKey` for a fresh covenant.
pub fn dev_bootstrap_redeem(lane_key: &Hash) -> (Vec<u8>, ScriptPublicKey) {
    let state = EMPTY_HASH;
    let lane_tip = Hash::default();
    let redeem_len = dev_redeem_script_len(&state, lane_key, DEFAULT_PERMISSION_OUTPUT_VALUE);
    let redeem = build_dev_redeem_script(
        &state,
        &lane_tip,
        lane_key,
        redeem_len,
        DEFAULT_PERMISSION_OUTPUT_VALUE,
    );
    let spk = pay_to_script_hash_script(&redeem);
    (redeem, spk)
}

/// Builds the settlement for one proven bundle in the configured [`SettlementMode`].
pub fn build_settlement_for_mode(
    mode: SettlementMode,
    backend: &Backend,
    lane_key: &Hash,
    cov: &CovenantState,
    artifact: &SettlementArtifact<Receipt>,
) -> BuiltSettlement {
    match mode {
        SettlementMode::Production => build_settlement(backend, lane_key, cov, artifact),
        SettlementMode::Dev => build_dev_settlement(lane_key, cov, artifact),
    }
}

/// Builds the production settlement for one proven bundle against the live covenant `cov`.
///
/// Panics if the artifact does not chain from `cov`.
pub fn build_settlement(
    backend: &Backend,
    lane_key: &Hash,
    cov: &CovenantState,
    artifact: &SettlementArtifact<Receipt>,
) -> BuiltSettlement {
    assert_eq!(
        artifact.prev_state, cov.state,
        "settlement prev_state must chain from the live covenant state",
    );
    assert_eq!(
        artifact.prev_lane_tip, cov.lane_tip,
        "settlement prev_lane_tip must match the spent covenant's redeem prefix",
    );
    assert_eq!(
        Hash::from_bytes(artifact.covenant_id),
        cov.covenant_id,
        "settlement covenant_id must match the live covenant",
    );

    let owned_witness =
        OwnedSuccinctWitness::from_receipt(&artifact.receipt, artifact.deposit_spk_hash);
    let settlement = Settlement::build(&SettlementInput {
        covenant_id: cov.covenant_id,
        pins: redeem_pins(backend, lane_key),
        prev_state: &artifact.prev_state,
        prev_lane_tip: &artifact.prev_lane_tip,
        new_state: &artifact.new_state,
        new_lane_tip: &artifact.new_lane_tip,
        block_prove_to: artifact.block_prove_to,
        canonical_kaspa_block: artifact.canonical_kaspa_block,
        prev_outpoint: cov.outpoint,
        value: cov.value,
        witness: owned_witness.as_witness(),
        permission_spk_hash: &artifact.permission_spk_hash,
    });
    let continuation_spk = pay_to_script_hash_script(&settlement.next_redeem);

    // The script engine anchors `new_seq_commit` to `block_prove_to` and, on the peg-out path, the
    // journal's `canonical_seq_commit` to `canonical_kaspa_block`; feed it both mappings and the
    // bundle's value so the budget covers exactly the units the covenant input consumes.
    let accessor = AnchorSeqCommit {
        block: artifact.block_prove_to,
        seq_commit: artifact.new_seq_commit,
        canonical_block: artifact.canonical_kaspa_block,
        canonical_seq_commit: Hash::from_bytes(artifact.canonical_seq_commit),
    };
    let compute_budget = settlement.covenant_compute_budget(cov.covenant_id, &accessor);

    // The continuation UTXO's value is what output 0 actually carries: the full covenant value,
    // minus the permission output when this settlement carved exits. Tracking `cov.value` here
    // unconditionally made the NEXT settlement build against a wrong input value after any
    // exits settlement.
    let continuation_value = settlement.transaction.outputs[0].value;
    BuiltSettlement {
        transaction: settlement.transaction,
        compute_budget,
        advance: CovenantAdvance {
            covenant_id: cov.covenant_id,
            new_state: artifact.new_state,
            new_lane_tip: artifact.new_lane_tip,
            continuation_spk,
            value: continuation_value,
        },
    }
}

/// Builds a dev settlement for one proven bundle against the live dev covenant `cov`.
///
/// Panics if the artifact does not chain from `cov`. Exits are supported: a non-zero
/// `permission_spk_hash` produces the two-output layout (continuation + permission exit), the
/// same as the production redeem.
pub fn build_dev_settlement<R>(
    lane_key: &Hash,
    cov: &CovenantState,
    artifact: &SettlementArtifact<R>,
) -> BuiltSettlement {
    assert_eq!(
        artifact.prev_state, cov.state,
        "dev settlement prev_state must chain from the live covenant state",
    );
    assert_eq!(
        artifact.prev_lane_tip, cov.lane_tip,
        "dev settlement prev_lane_tip must match the spent covenant's redeem prefix",
    );
    assert_eq!(
        Hash::from_bytes(artifact.covenant_id),
        cov.covenant_id,
        "dev settlement covenant_id must match the live covenant",
    );
    let settlement = Settlement::build_dev(&SettlementDevInput {
        deposit_spk_hash: &artifact.deposit_spk_hash,
        covenant_id: cov.covenant_id,
        prev_state: &artifact.prev_state,
        prev_lane_tip: &artifact.prev_lane_tip,
        lane_key,
        new_state: &artifact.new_state,
        new_lane_tip: &artifact.new_lane_tip,
        block_prove_to: artifact.block_prove_to,
        claimed_seq_commit: artifact.new_seq_commit,
        prev_outpoint: cov.outpoint,
        value: cov.value,
        permission_spk_hash: &artifact.permission_spk_hash,
        permission_output_value: DEFAULT_PERMISSION_OUTPUT_VALUE,
    });
    let continuation_spk = pay_to_script_hash_script(&settlement.next_redeem);

    // See build_settlement: the continuation carries output 0's actual value, which is
    // `cov.value - permission_output_value` when this settlement carved exits.
    let continuation_value = settlement.transaction.outputs[0].value;
    BuiltSettlement {
        transaction: settlement.transaction,
        compute_budget: DEV_COVENANT_BUDGET,
        advance: CovenantAdvance {
            covenant_id: cov.covenant_id,
            new_state: artifact.new_state,
            new_lane_tip: artifact.new_lane_tip,
            continuation_spk,
            value: continuation_value,
        },
    }
}

/// Rebuilds the live [`CovenantState`] from an external settlement `s` that advanced the covenant.
pub fn covenant_from_settlement(
    mode: SettlementMode,
    backend: &Backend,
    lane_key: &Hash,
    cov: &CovenantState,
    s: &SettlementInfo,
) -> CovenantState {
    let spk = match mode {
        SettlementMode::Dev => {
            let len =
                dev_redeem_script_len(&s.new_state, lane_key, DEFAULT_PERMISSION_OUTPUT_VALUE);
            let redeem = build_dev_redeem_script(
                &s.new_state,
                &s.new_lane_tip,
                lane_key,
                len,
                DEFAULT_PERMISSION_OUTPUT_VALUE,
            );
            pay_to_script_hash_script(&redeem)
        }
        SettlementMode::Production => {
            let pins = redeem_pins(backend, lane_key);
            let len = redeem_script_len(&s.new_state, &pins);
            let redeem = build_redeem_script(&s.new_state, &s.new_lane_tip, len, &pins);
            pay_to_script_hash_script(&redeem)
        }
    };
    CovenantState {
        covenant_id: cov.covenant_id,
        state: s.new_state,
        lane_tip: s.new_lane_tip,
        outpoint: TransactionOutpoint::new(s.tx_id, 0),
        spk,
        value: cov.value,
        daa_score: s.daa_score.get(),
    }
}

/// Returns the production redeem pins for this covenant.
fn redeem_pins<'a>(backend: &'a Backend, lane_key: &'a Hash) -> RedeemPins<'a> {
    RedeemPins::Succinct(SuccinctPins {
        common: CommonPins {
            program_id: &backend.aggregator.id,
            tx_image_id: &backend.transaction_processor.id,
            batch_image_id: &backend.batch_processor.id,
            lane_key,
            permission_output_value: DEFAULT_PERMISSION_OUTPUT_VALUE,
        },
    })
}

/// Two-block [`SeqCommitAccessor`] for sizing the covenant input's compute budget off chain: the
/// bundle's `block_prove_to` (anchoring `new_seq_commit`) and, on the peg-out path, the
/// `canonical_kaspa_block` (anchoring the journal's `canonical_seq_commit`). A zero
/// `canonical_block` (no peg-out) never matches, so the covenant's zero-sentinel branch does not
/// query the accessor.
struct AnchorSeqCommit {
    block: Hash,
    seq_commit: Hash,
    canonical_block: Hash,
    canonical_seq_commit: Hash,
}

impl AnchorSeqCommit {
    fn lookup(&self, block_hash: Hash) -> Option<Hash> {
        if block_hash == self.block {
            Some(self.seq_commit)
        } else if block_hash == self.canonical_block {
            Some(self.canonical_seq_commit)
        } else {
            None
        }
    }
}

impl SeqCommitAccessor for AnchorSeqCommit {
    fn is_chain_ancestor_from_pov(&self, block_hash: Hash) -> Option<bool> {
        self.lookup(block_hash).map(|_| true)
    }

    fn seq_commitment_within_depth(&self, block_hash: Hash) -> Option<Hash> {
        self.lookup(block_hash)
    }
}
