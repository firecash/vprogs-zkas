//! ZKas⇄Kaspa bridge peg-out: end-to-end through the real proving pipeline.
//!
//! Drives the `zkas-burn-processor` guest with real burn attestations and asserts the exits it
//! emits are *exactly* the ones the burns authorise — by recomputing the permission-tree
//! commitment independently and requiring the proof's journal to match it byte-for-byte.
//!
//! That single equality is the peg-out's soundness statement: `permission_spk_hash` is what the
//! settlement covenant enforces on-chain (invariant 6), and the permission redeem script pays a
//! withdrawer only against a Merkle proof into that tree. So if the journal commits to the tree we
//! computed from the burns, then the set of payable exits is exactly the set of burns — no more,
//! no less, no substitutions.
//!
//! Everything here is conditional on the state root `r` the attestation names being a real ZKas
//! state root. See `vprogs_zk_abi::zkas_bridge`.

use kaspa_consensus_core::network::{NetworkId, NetworkType};
use kaspa_hashes::Hash;
use kaspa_rpc_core::api::rpc::RpcApi;
use tempfile::TempDir;
use vprogs_core_codec::Reader;
use vprogs_core_types::{AccessMetadata, ResourceId};
use vprogs_l1_types::{ChainBlockMetadata, L1Transaction};
use vprogs_node_test_utils::L1Node;
use vprogs_scheduling_scheduler::{ExecutionConfig, Scheduler};
use vprogs_storage_manager::StorageConfig;
use vprogs_storage_rocksdb_store::RocksDbStore;
use vprogs_zk_abi::{
    batch_aggregator::StateTransition,
    withdrawal::StandardSpk,
    zkas_bridge::{BurnAttestation, ExitReceipt, NODE_DOMAIN, frame_ix_data},
};

use vprogs_zk_backend_risc0_api::{
    Backend, Hasher, PermissionTreeAccumulator, ProofType, Sha256 as ApiSha256,
};
use vprogs_zk_backend_risc0_covenant::JOURNAL_SIZE;
use vprogs_zk_backend_risc0_test_suite::{
    L1TransactionExt, aggregate_batches, batch_aggregator_elf, batch_processor_elf,
    canonical_r_witness_for, test_lane_key, zkas_burn_processor_elf,
};
// `Backend as _` brings the batch-prover trait's `journal_bytes` into scope.
use vprogs_zk_batch_prover::{Backend as _, BatchProverConfig};
use vprogs_zk_vm::{ProvingPipeline, Vm};

/// The shielded state the test burns are declared against. Real values come from the ZKas
/// coinbase; here they only need to be consistent between the encoder and the guest.
const ANCHOR: [u8; 32] = [0x11; 32];
const NULLROOT: [u8; 32] = [0x22; 32];
const COINBASE: u128 = 1_000_000_000;
const FEES: u128 = 12_345;

/// Encodes an `ix_data` the way the relayer will: the attestation (real shielded state, `r` derived
/// from it) framed together with a canonical-`R` witness proving `r` is committed by Kaspa's PoW.
fn encode_attestation(rec: &ExitReceipt, burn_root: &[u8; 32], idx: u32, branch: &[u8]) -> Vec<u8> {
    let r = BurnAttestation::state_root(&ANCHOR, &NULLROOT, COINBASE, FEES, burn_root);
    let attestation = BurnAttestation::encode(rec, &r, idx, &ANCHOR, &NULLROOT, COINBASE, FEES, branch);
    frame_ix_data(&attestation, &canonical_r_witness_for(&r))
}

async fn metadata_for_block(l1: &L1Node, block_hash: Hash) -> ChainBlockMetadata {
    let block = l1.grpc_client().get_block(block_hash, false).await.expect("get_block");
    let h = block.header;
    ChainBlockMetadata {
        hash: h.hash,
        blue_score: h.blue_score,
        daa_score: h.daa_score,
        timestamp: h.timestamp,
        seq_commit: h.accepted_id_merkle_root,
        ..Default::default()
    }
}

/// Two burn receipts and the two-leaf accumulator over them.
///
/// Returns `(receipts, burn_root, branches)` where `branches[i]` authenticates `receipts[i]`.
fn two_burn_tree() -> ([ExitReceipt; 2], [u8; 32], [[u8; 32]; 2]) {
    let a = ExitReceipt { v: 5_000_000, recipient: [0xA1; 32], n: [0x11; 32] };
    let b = ExitReceipt { v: 250_000, recipient: [0xB2; 32], n: [0x22; 32] };

    let la = a.leaf_hash::<ApiSha256>();
    let lb = b.leaf_hash::<ApiSha256>();
    let burn_root = ApiSha256::hash_parts_with_domain(&NODE_DOMAIN, [la.as_slice(), lb.as_slice()]);

    // Leaf 0's sibling is leaf 1, and vice versa.
    ([a, b], burn_root, [lb, la])
}

/// The peg-out happy path: two ZKas burns in, two exits out, committed exactly.
#[tokio::test(flavor = "multi_thread")]
async fn zkas_burns_produce_exactly_the_authorised_exits() {
    let transaction_elf = zkas_burn_processor_elf();
    let batch_elf = batch_processor_elf();
    let aggregator_elf = batch_aggregator_elf();

    let temp_dir = TempDir::new().expect("failed to create temp dir");
    let storage: RocksDbStore = RocksDbStore::open(temp_dir.path());
    let backend = Backend::new(&transaction_elf, &batch_elf, &aggregator_elf, ProofType::Succinct);

    let l1 = L1Node::new(NetworkId::new(NetworkType::Simnet), None).await;
    let block_hashes = l1.mine_blocks(1).await;

    let lane_key = test_lane_key();
    let config = BatchProverConfig {
        lane_key,
        covenant_id: Hash::default(),
        deposit_spk_hash: [0u8; 32],
    };
    let proving = ProvingPipeline::batch(backend.clone(), storage.clone(), config);
    let vm = Vm::new(backend.clone(), proving);
    let mut scheduler = Scheduler::new(
        ExecutionConfig::default().with_processor(vm),
        StorageConfig::default().with_store(storage.clone()),
    );

    let (receipts, burn_root, branches) = two_burn_tree();

    // Each peg-out transaction declares exactly one resource, keyed by the burn's nullifier —
    // the slot the guest requires to be new. This is what makes the exit single-use.
    let txs: Vec<L1Transaction> = receipts
        .iter()
        .zip(branches.iter())
        .enumerate()
        .map(|(i, (rec, branch))| {
            let ix_data = encode_attestation(rec, &burn_root, i as u32, branch);
            L1Transaction::for_l2_test(
                &[AccessMetadata::write(ResourceId::from(rec.n))],
                &ix_data,
            )
        })
        .collect();

    let metadata = metadata_for_block(&l1, block_hashes[0]).await;
    let batch = scheduler.schedule(
        metadata,
        txs.iter().enumerate().map(|(i, tx)| tx.clone().into_scheduler_tx(i as u32)).collect(),
    );
    batch.wait_committed_blocking();
    batch.wait_artifact_published_blocking();

    let batch_receipt = (*batch.artifact()).clone();
    let settlement_receipt =
        aggregate_batches(&backend, l1.grpc_client(), &lane_key, block_hashes[0], vec![
            batch_receipt,
        ])
        .await;

    let journal = Backend::journal_bytes(&settlement_receipt);
    assert_eq!(journal.len(), JOURNAL_SIZE);
    let parsed =
        (&mut &journal[..]).array_as::<StateTransition>("state_transition").unwrap();

    // Independently rebuild the permission tree the burns authorise.
    let mut expected = PermissionTreeAccumulator::new();
    for rec in &receipts {
        expected.add_exit(StandardSpk::PubKey(&rec.recipient), rec.v);
    }
    let expected_hash = expected.finalize();

    assert_ne!(
        parsed.permission_spk_hash, [0u8; 32],
        "the guest emitted no exits — burns did not turn into peg-outs",
    );
    assert_eq!(
        parsed.permission_spk_hash, expected_hash,
        "the proof commits to a different exit set than the burns authorise",
    );
}

/// A tampered attestation must not produce any exit.
///
/// The relayer is untrusted: it chooses the `ix_data`. Here it inflates a real 250_000-sompi burn
/// into a 5_000_000-sompi claim while keeping the honest Merkle branch. The leaf hash changes, the
/// recomputed root no longer binds to `r`, and the guest rejects — so the batch commits the
/// no-exit sentinel rather than an inflated payout.
#[tokio::test(flavor = "multi_thread")]
async fn inflated_burn_amount_yields_no_exit() {
    let transaction_elf = zkas_burn_processor_elf();
    let batch_elf = batch_processor_elf();
    let aggregator_elf = batch_aggregator_elf();

    let temp_dir = TempDir::new().expect("failed to create temp dir");
    let storage: RocksDbStore = RocksDbStore::open(temp_dir.path());
    let backend = Backend::new(&transaction_elf, &batch_elf, &aggregator_elf, ProofType::Succinct);

    let l1 = L1Node::new(NetworkId::new(NetworkType::Simnet), None).await;
    let block_hashes = l1.mine_blocks(1).await;

    let lane_key = test_lane_key();
    let config = BatchProverConfig {
        lane_key,
        covenant_id: Hash::default(),
        deposit_spk_hash: [0u8; 32],
    };
    let proving = ProvingPipeline::batch(backend.clone(), storage.clone(), config);
    let vm = Vm::new(backend.clone(), proving);
    let mut scheduler = Scheduler::new(
        ExecutionConfig::default().with_processor(vm),
        StorageConfig::default().with_store(storage.clone()),
    );

    let (receipts, burn_root, branches) = two_burn_tree();

    // Honest branch, dishonest amount.
    let mut inflated = receipts[1];
    inflated.v = 5_000_000;
    let ix_data = encode_attestation(&inflated, &burn_root, 1, &branches[1]);
    let tx = L1Transaction::for_l2_test(
        &[AccessMetadata::write(ResourceId::from(inflated.n))],
        &ix_data,
    );

    let metadata = metadata_for_block(&l1, block_hashes[0]).await;
    let batch = scheduler.schedule(metadata, vec![tx.into_scheduler_tx(0)]);
    batch.wait_committed_blocking();
    batch.wait_artifact_published_blocking();

    let batch_receipt = (*batch.artifact()).clone();
    let settlement_receipt =
        aggregate_batches(&backend, l1.grpc_client(), &lane_key, block_hashes[0], vec![
            batch_receipt,
        ])
        .await;

    let journal = Backend::journal_bytes(&settlement_receipt);
    let parsed =
        (&mut &journal[..]).array_as::<StateTransition>("state_transition").unwrap();

    assert_eq!(
        parsed.permission_spk_hash, [0u8; 32],
        "an inflated burn claim must yield no payable exit",
    );
}
