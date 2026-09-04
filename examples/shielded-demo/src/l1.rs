//! The L1 custody leg: everything the pool demo claims, made real on an in-process Kaspa simnet
//! (real kaspad, covenants active).
//!
//! 1. Bootstrap the dev covenant (the pool's on-chain anchor + rent).
//! 2. Deposits: real transactions paying the covenant's delegate-entry P2SH address.
//! 3. Settlement: advance the covenant to the pool's state root AND carve the permission output
//!    committing Bob's exit — a real 2-output settlement tx in a real block, seq-commit-anchored.
//! 4. Sweep: spend the permission output + a delegate deposit, paying Bob's L1 address real KAS.

use std::time::Duration;

use kaspa_consensus_core::{
    network::{NetworkId, NetworkType},
    tx::{ScriptPublicKey, TransactionOutpoint, UtxoEntry},
};
use kaspa_hashes::Hash;
use kaspa_rpc_core::api::rpc::RpcApi;
use kaspa_txscript::standard::{extract_script_pub_key_address, pay_to_script_hash_script};
use vprogs_node_test_utils::L1Node;
use vprogs_zk_aggregate_prover::SettlementArtifact;
use vprogs_zk_backend_risc0_api::build_delegate_entry_script;
use vprogs_zk_backend_risc0_settler::{
    build_dev_settlement,
    sweep::{build_withdrawal_sweep, ExitLeafSpec, PermissionTree, SweepInput},
};
use vprogs_zk_backend_risc0_test_suite::{force_covenant_forks, test_lane_key};

const SOMPI: u64 = 100_000_000;
/// Generous script budget for the proofless permission/delegate inputs.
const SWEEP_BUDGET: u16 = 3_000;

fn short(b: &[u8]) -> String {
    format!("{}…", hex::encode(&b[..4]))
}

/// Runs the custody loop for one exit. `pool_root` is the shielded pool's final tree root;
/// `exit` is (recipient_pk, amount) from the proven exit journal.
pub async fn run_custody_leg(pool_root: [u8; 32], exit_recipient: [u8; 32], exit_amount: u64) {
    println!("\n■ L1 custody leg — real kaspad simnet, covenants active");

    let l1 = L1Node::new(
        NetworkId::new(NetworkType::Simnet),
        Some(|p| {
            p.blockrate.coinbase_maturity = 1;
            force_covenant_forks(p);
        }),
    )
    .await;
    l1.mine_utxos(6).await;
    let wallet = l1.wallet();
    let lane_key = test_lane_key();

    // 1. Bootstrap: the covenant UTXO carries the state anchor + the permission rent.
    let (mut cov, boot_txid) =
        vprogs_zk_backend_risc0_settler::bootstrap_dev_covenant(&wallet, lane_key, SOMPI).await;
    l1.mine_blocks(2).await;
    println!("   covenant bootstrapped: id {} (tx {})", short(&cov.covenant_id.as_bytes()), short(&boot_txid.as_bytes()));

    // 2. Deposits to the delegate-entry address — REAL on-chain deposits.
    let cov_id_bytes: [u8; 32] = cov.covenant_id.as_bytes();
    let delegate_redeem = build_delegate_entry_script(&cov_id_bytes);
    let delegate_spk = pay_to_script_hash_script(&delegate_redeem);
    let delegate_addr = extract_script_pub_key_address(&delegate_spk, kaspa_addresses::Prefix::Simnet)
        .expect("delegate P2SH address");
    // The exit-funding UTXO must equal the deduct exactly; the rest of the pool's custody sits in
    // further delegate UTXOs.
    for (label, amount) in [("exit-funding", exit_amount), ("pool custody", 50 * SOMPI)] {
        let tx = wallet.pay_to_address(&delegate_addr, amount, 1).await;
        let txid = wallet.submit_transaction(&tx).await.expect("deposit submit");
        l1.mine_blocks(2).await;
        println!("   deposit ({label}): {}.{:08} KAS → {} (tx {})", amount / SOMPI, amount % SOMPI, delegate_addr, short(&txid.as_bytes()));
    }
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Locate the exit-funding delegate UTXO.
    let utxos = l1
        .grpc_client()
        .get_utxos_by_addresses(vec![delegate_addr.clone()])
        .await
        .expect("delegate utxos");
    let funding = utxos
        .iter()
        .find(|u| u.utxo_entry.amount == exit_amount)
        .expect("exit-funding delegate UTXO");
    let delegate_outpoint =
        TransactionOutpoint::new(funding.outpoint.transaction_id, funding.outpoint.index);

    // 3. Settlement: pool root + Bob's exit, anchored to a real buried block's seq-commit.
    let anchor_hashes = l1.mine_blocks(1).await;
    let anchor_block = anchor_hashes[0];
    l1.mine_blocks(5).await; // bury it
    let anchor_header =
        l1.grpc_client().get_block(anchor_block, false).await.expect("anchor block").header;
    let claimed_seq_commit = anchor_header.accepted_id_merkle_root;

    let tree = PermissionTree::new(&[ExitLeafSpec { recipient_pk: exit_recipient, amount: exit_amount }]);
    let artifact: SettlementArtifact<()> = SettlementArtifact {
        receipt: (),
        block_prove_to: anchor_block,
        prev_state: cov.state,
        prev_lane_tip: cov.lane_tip,
        new_state: pool_root,
        new_lane_tip: Hash::from_u64_word(1),
        new_seq_commit: claimed_seq_commit,
        permission_spk_hash: tree.spk_hash(),
        deposit_spk_hash: [0u8; 32],
        canonical_seq_commit: [0u8; 32],
        canonical_kaspa_block: Hash::default(),
        covenant_id: cov_id_bytes,
    };
    let built = build_dev_settlement(&lane_key, &cov, &artifact);
    let continuation_value = built.transaction.outputs[0].value;
    // v1 transactions carry compute budgets, not sig-op counts; the wallet's settlement
    // preparation sets the covenant input's budget and funds the fee.
    let covenant_entry = UtxoEntry::new(cov.value, cov.spk.clone(), 0, false, Some(cov.covenant_id));
    let funded = wallet
        .prepare_settlement_transaction(built.transaction.clone(), covenant_entry, built.compute_budget)
        .await;
    let settle_txid = wallet.submit_transaction(&funded).await.expect("settlement submit");
    let settle_block = l1.mine_blocks(2).await[0];
    l1.mine_blocks(1).await;
    println!(
        "   settlement mined in block {}: tx {} — output 0 = covenant continuation ({}.{:08} KAS, state root {}), output 1 = permission exit ({}.{:08} KAS)",
        short(&settle_block.as_bytes()),
        short(&settle_txid.as_bytes()),
        continuation_value / SOMPI,
        continuation_value % SOMPI,
        short(&pool_root),
        built.transaction.outputs[1].value / SOMPI,
        built.transaction.outputs[1].value % SOMPI,
    );
    cov.state = artifact.new_state;
    cov.lane_tip = artifact.new_lane_tip;
    cov.value = continuation_value;
    cov.outpoint = TransactionOutpoint::new(settle_txid, 0);
    cov.spk = built.advance.continuation_spk().clone();

    // 4. Sweep: pay Bob real KAS from the permission output + the delegate deposit.
    let permission_value = built.transaction.outputs[1].value;
    let sweep_tx = build_withdrawal_sweep(&SweepInput {
        tree: &tree,
        leaf_index: 0,
        deduct: exit_amount,
        permission_outpoint: TransactionOutpoint::new(settle_txid, 1),
        permission_value,
        delegate_outpoints: &[(delegate_outpoint, exit_amount)],
        delegate_redeem: &delegate_redeem,
        covenant_id: cov.covenant_id,
        permission_budget: SWEEP_BUDGET,
    });
    let sweep_txid = sweep_tx.id();
    let payout = sweep_tx.outputs[0].clone();
    let sweep_block = l1.mine_block(&[sweep_tx]).await;
    l1.mine_blocks(2).await;
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Verify Bob's payout UTXO exists on the live UTXO set.
    let bob_addr = extract_script_pub_key_address(
        &ScriptPublicKey::new(0, payout.script_public_key.script().to_vec().into()),
        kaspa_addresses::Prefix::Simnet,
    )
    .expect("bob payout address");
    let bob_utxos =
        l1.grpc_client().get_utxos_by_addresses(vec![bob_addr.clone()]).await.expect("bob utxos");
    let total: u64 = bob_utxos.iter().map(|u| u.utxo_entry.amount).sum();
    println!(
        "   sweep mined in block {}: tx {} pays {}.{:08} KAS to {} — live UTXO set confirms {}.{:08} KAS",
        short(&sweep_block.as_bytes()),
        short(&sweep_txid.as_bytes()),
        payout.value / SOMPI,
        payout.value % SOMPI,
        bob_addr,
        total / SOMPI,
        total % SOMPI,
    );
    assert_eq!(total, payout.value, "recipient must hold the payout on the live UTXO set");
    println!("   ✔ real KAS moved: deposit → covenant custody → shielded exit → recipient, no keys anywhere in the path");

    l1.shutdown().await;
}
