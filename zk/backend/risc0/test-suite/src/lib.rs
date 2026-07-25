use kaspa_consensus_core::{
    config::params::{ForkActivation, Params},
    hashing::tx::id as kaspa_tx_id,
    subnets::SubnetworkId,
};
use kaspa_hashes::Hash;
use kaspa_seq_commit::{
    hashing::{
        ActivityDigestBuilder, activity_leaf, lane_key, lane_tip_next, mergeset_context_hash,
    },
    types::{LaneTipInput, MergesetContext},
};
use vprogs_core_types::ResourceId;
use vprogs_l1_types::{ChainBlockMetadata, L1Transaction};
use vprogs_scheduling_scheduler::{ExecutionConfig, Processor, Scheduler};
use vprogs_state_version::StateVersion;
use vprogs_storage_manager::StorageConfig;
use vprogs_storage_types::{ReadStore, Store};
use vprogs_zk_abi::batch_aggregator::Inputs as AggregatorInputs;
use vprogs_zk_aggregate_prover::Backend as AggregateBackend;
use vprogs_zk_backend_risc0_api::{Backend, Receipt};
use vprogs_zk_batch_prover::{LaneProofRequest, LaneProofSource};

mod l1_transaction_ext;
pub mod runtime_flow;

pub use l1_transaction_ext::L1TransactionExt;

/// Subnetwork id the e2e fixtures bind to (the lane the batch proves and settles). Built from a
/// non-reserved namespace so it passes L1's subnetwork-shape check.
pub const TEST_SUBNETWORK_ID: SubnetworkId = SubnetworkId::from_namespace(4444u32.to_be_bytes());

/// Lane key for [`TEST_SUBNETWORK_ID`]: the value the guest commits and the covenant SPK pins.
pub fn test_lane_key() -> Hash {
    lane_key(TEST_SUBNETWORK_ID.as_bytes())
}

/// Runs the aggregator on a sequence of per-batch receipts and returns the resulting bundle
/// receipt.
///
/// The returned receipt's journal is a `vprogs_zk_abi::batch_aggregator::StateTransition`, ready
/// for the settlement covenant.
pub async fn aggregate_batches<L: LaneProofSource>(
    backend: &Backend,
    lane_source: &L,
    lane_key: &Hash,
    last_block_hash: Hash,
    batch_receipts: Vec<Receipt>,
) -> Receipt {
    // Fetch the lane proof for the bundle's final block from L1.
    let lane_proof = lane_source
        .fetch_lane_proof(LaneProofRequest { block: last_block_hash, lane_key: *lane_key })
        .await;

    // Encode the aggregator inputs over the per-batch journal bytes.
    let journals: Vec<Vec<u8>> = batch_receipts.iter().map(|r| r.journal.bytes.clone()).collect();
    let inputs = AggregatorInputs::encode(
        &backend.batch_processor.id,
        &lane_proof,
        journals.iter().map(|j| j.as_slice()),
    );

    // Prove the aggregator with the per-batch receipts as composition assumptions.
    backend.prove_aggregator(&inputs, batch_receipts).await
}

/// Builds a self-consistent canonical-`R` witness committing state root `r`, encoded to the wire
/// bytes the peg-out guest expects as the second `ix_data` section (see
/// [`vprogs_zk_abi::zkas_bridge::frame_ix_data`]).
///
/// This is the test analogue of what the ZKas relayer assembles from real chain data on the
/// two-chain (Kaspa-custody) deployment: a ZKas block whose coinbase payload commits `r` at offset
/// 16 and whose header hashes to `H_fc`, merge-mined into a Kaspa block whose coinbase payload
/// embeds `ZKMM ‖ hex(H_fc)`; that Kaspa block's KIP-21 seq_commit is the value the covenant reads
/// on-chain via `OpChainblockSeqCommit`. Every hash is produced by the same functions the guest
/// verifies with, so [`OwnedCanonicalRWitness::verify`] accepts it and returns the Kaspa block's
/// `seq_commit`: the value the guest journals and the covenant binds on-chain.
pub fn canonical_r_witness_for(r: &[u8; 32]) -> Vec<u8> {
    use kaspa_seq_commit::{
        hashing::{
            miner_payload_leaf, miner_payload_root, payload_and_context_digest, seq_commit,
            seq_state_root,
        },
        types::{MinerPayloadLeafInput, SeqCommitInput, SeqState},
    };
    use vprogs_zk_abi::{
        canonical_r::OwnedCanonicalRWitness,
        kaspa_hashing::{CoinbaseOutput, HeaderFields, coinbase_tx_hash_v0, header_hash},
        seq_commit_witness::MERGE_MINE_MAGIC,
    };

    // ZKas coinbase: payload commits `r` at [16..48] (blue_score(8) + subsidy(8)), pre-Toccata v0.
    let mut cb_payload = Vec::new();
    cb_payload.extend_from_slice(&7u64.to_le_bytes());
    cb_payload.extend_from_slice(&8u64.to_le_bytes());
    cb_payload.extend_from_slice(r);
    let mut cb_subnet = [0u8; 20];
    cb_subnet[0] = 1;
    let outputs = [CoinbaseOutput { value: 50, spk_version: 0, spk_script: &[0xaa] }];
    let tx = coinbase_tx_hash_v0(0, &outputs, 0, &cb_subnet, 0, &cb_payload);

    // ZKas header → H_fc (the merge-mined block hash Kaspa's coinbase commits).
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

    // Kaspa side: a block whose coinbase payload embeds `ZKMM ‖ hex(H_fc)` (the AuxPoW transport),
    // and that Kaspa block's KIP-21 seq_commit.
    let kaspa_payload = {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut out = Vec::new();
        out.extend_from_slice(b"kaspa-cb");
        out.extend_from_slice(&MERGE_MINE_MAGIC);
        for b in hfc.as_bytes() {
            out.push(HEX[(b >> 4) as usize]);
            out.push(HEX[(b & 0x0f) as usize]);
        }
        out
    };
    let kaspa_block = Hash::from_bytes([0x33; 32]);
    let blue_work_be = [0x01u8, 0x02];
    let activity_root = Hash::from_bytes([0x44; 32]);
    let context_hash = Hash::from_bytes([0x55; 32]);
    let parent_seq_commit = Hash::from_bytes([0x66; 32]);
    let other = Hash::from_bytes([0xA0; 32]);

    let our_leaf = miner_payload_leaf(MinerPayloadLeafInput {
        block_hash: &kaspa_block,
        blue_work_be_bytes: &blue_work_be,
        payload: &kaspa_payload,
    });
    let payload_root = miner_payload_root([our_leaf, other].into_iter());
    let pd = payload_and_context_digest(&context_hash, &payload_root);
    let sr = seq_state_root(&SeqState { activity_root: &activity_root, payload_and_ctx_digest: &pd });
    let expected_seq_commit =
        seq_commit(&SeqCommitInput { parent_seq_commit: &parent_seq_commit, state_root: &sr });

    let owned = OwnedCanonicalRWitness {
        coinbase_version: 0,
        coinbase_outputs: vec![(50u64, 0u16, vec![0xaa])],
        coinbase_lock_time: 0,
        coinbase_subnetwork: cb_subnet,
        coinbase_gas: 0,
        coinbase_payload: cb_payload,
        coinbase_branch: vec![],
        header_version: 1,
        header_parents: vec![vec![[0x01; 32]]],
        hash_merkle_root: tx.as_bytes(),
        accepted_id_merkle_root: [0x02; 32],
        utxo_commitment: [0x03; 32],
        timestamp: 111,
        bits: 22,
        nonce: 333,
        daa_score: 44,
        blue_score: 55,
        header_blue_work_be: vec![9],
        pruning_point: [0x04; 32],
        kaspa_payload,
        // Two-chain: the queried block IS the Kaspa block that merge-mined `H_fc`; its own
        // seq_commit is what the covenant reads on-chain. `member_block_hash` is unused on this path.
        kaspa_block_hash: kaspa_block.as_bytes(),
        kaspa_blue_work_be: vec![0x01, 0x02],
        other_leaves: vec![[0xA0; 32]],
        leaf_index: 0,
        activity_root: [0x44; 32],
        context_hash: [0x55; 32],
        parent_seq_commit: [0x66; 32],
        seq_commit: expected_seq_commit.as_bytes(),
        member_block_hash: kaspa_block.as_bytes(),
    };
    // Self-check: the relayer never ships a witness the guest would reject.
    owned.verify(r).expect("test canonical-R witness must verify");
    owned.encode()
}

/// Returns `true` when risc0 dev mode is active (env var `RISC0_DEV_MODE` is set to anything
/// other than `0`). In dev mode the prover emits fake receipts, so any code path that
/// cryptographically depends on the proof being real (receipt verification, on-chain script
/// engine checks of the covenant precompile) must be gated on this returning `false`.
pub fn dev_mode_enabled() -> bool {
    !matches!(std::env::var("RISC0_DEV_MODE").as_deref(), Err(_) | Ok("0"))
}

/// Loads the pre-built transaction processor ELF from the repository.
pub fn transaction_processor_elf() -> Vec<u8> {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let elf_path = format!("{manifest_dir}/../transaction-processor/compiled/program.elf");
    std::fs::read(&elf_path).unwrap_or_else(|e| {
        panic!(
            "transaction processor ELF not found at {elf_path}: {e}\n\
             Run `./zk/backend/risc0/build-guests.sh transaction-processor` to rebuild it."
        )
    })
}

/// Loads the pre-built transaction-processor variant that emits one L2→L1 exit per tx.
///
/// Use this in tests that need to exercise the settlement covenant's `count == 2` branch:
/// the resulting batch journal carries a non-zero `permission_spk_hash`, the host
/// `Settlement::build` emits two covenant-bound outputs, and `TxScriptEngine` runs the
/// permission-output validation path. See `settlement_e2e.rs` for the end-to-end test.
pub fn transaction_processor_with_exits_elf() -> Vec<u8> {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let elf_path =
        format!("{manifest_dir}/../transaction-processor-with-exits/compiled/program.elf");
    std::fs::read(&elf_path).unwrap_or_else(|e| {
        panic!(
            "transaction-processor-with-exits ELF not found at {elf_path}: {e}\n\
             Run `./zk/backend/risc0/build-guests.sh transaction-processor-with-exits` to rebuild it."
        )
    })
}

/// Loads the pre-built ZKas⇄Kaspa bridge peg-out guest ELF from the repository.
///
/// Each transaction carries a ZKas burn attestation in its `ix_data`; the guest verifies
/// inclusion under the claimed state root, consumes the burn's nullifier exactly once, and emits
/// the matching exit. See `zkas_bridge_e2e.rs`.
pub fn zkas_burn_processor_elf() -> Vec<u8> {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let elf_path = format!("{manifest_dir}/../zkas-burn-processor/compiled/program.elf");
    std::fs::read(&elf_path).unwrap_or_else(|e| {
        panic!(
            "zkas-burn-processor ELF not found at {elf_path}: {e}\n\
             Run `./zk/backend/risc0/build-guests.sh zkas-burn-processor` to rebuild it."
        )
    })
}

/// Loads the pre-built deposit/transfer/withdraw runtime-processor ELF from the repository.
///
/// This is the real L2 program (config Init, Deposit, Transfer, Withdraw, lock rotation), as
/// opposed to the dummy counter [`transaction_processor_elf`]. Pass it as the `tx_elf` to
/// [`Backend::new`] to drive the runtime through the scheduler.
pub fn runtime_processor_elf() -> Vec<u8> {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let elf_path = format!("{manifest_dir}/../runtime-processor/compiled/program.elf");
    std::fs::read(&elf_path).unwrap_or_else(|e| {
        panic!(
            "runtime processor ELF not found at {elf_path}: {e}\n\
             Run `./zk/backend/risc0/build-guests.sh runtime-processor` to rebuild it."
        )
    })
}

/// Loads the pre-built batch processor ELF from the repository.
pub fn batch_processor_elf() -> Vec<u8> {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let elf_path = format!("{manifest_dir}/../batch-processor/compiled/program.elf");
    std::fs::read(&elf_path).unwrap_or_else(|e| {
        panic!(
            "batch processor ELF not found at {elf_path}: {e}\n\
             Run `./zk/backend/risc0/build-guests.sh batch-processor` to rebuild it."
        )
    })
}

/// Loads the pre-built batch aggregator ELF from the repository.
pub fn batch_aggregator_elf() -> Vec<u8> {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let elf_path = format!("{manifest_dir}/../batch-aggregator/compiled/program.elf");
    std::fs::read(&elf_path).unwrap_or_else(|e| {
        panic!(
            "batch aggregator ELF not found at {elf_path}: {e}\n\
             Run `./zk/backend/risc0/build-guests.sh batch-aggregator` to rebuild it."
        )
    })
}

/// Empirical check that the build-time succinct verifier-identity consts (used by the
/// covenant redeem script's `OpZkPrecompile` pin) still match what the live succinct prover
/// emits. The pin is baked into `succinct_consts::SUCCINCT_CONTROL_ID` at covenant build
/// time; if risc0 changes the recursion pipeline (or a different ProverOpts variant gets
/// used) the pin and the receipt would silently diverge and on-chain script validation
/// would fail at settle time. Catching it here in the test pipeline is the point.
///
/// kaspa only supports `poseidon2` for the succinct precompile, so the hashfn check is a
/// simple string-equality assertion (no mapping table needed).
///
/// Must be called only when [`dev_mode_enabled`] is false: dev-mode receipts are the `Fake`
/// variant and don't have succinct fields. See
/// [`vprogs_zk_backend_risc0_covenant::succinct_consts`].
pub fn assert_receipt_pins_match_succinct_consts(receipt: &Receipt) {
    use vprogs_zk_backend_risc0_covenant::succinct_consts::SUCCINCT_CONTROL_ID;

    let succinct = receipt.inner.succinct().expect("expected succinct receipt outside dev mode");
    let live_control_id: [u8; 32] = succinct.control_id.into();
    assert_eq!(
        live_control_id, SUCCINCT_CONTROL_ID,
        "batch receipt control_id must match SUCCINCT_CONTROL_ID; if this fires, risc0 \
         changed the recursion pipeline (or a different ProverOpts variant got used) and \
         the covenant pins are now stale",
    );
    assert_eq!(
        succinct.hashfn, "poseidon2",
        "kaspa only supports poseidon2 for the succinct precompile; receipt reports `{}`",
        succinct.hashfn,
    );
}

/// Computes `lane_tip_next` for a single batch's worth of activity.
pub fn compute_section_lane_tip(
    metadata: &ChainBlockMetadata,
    txs: &[(u32, &L1Transaction)],
    lane_key: &Hash,
) -> Hash {
    let context_hash = mergeset_context_hash(&MergesetContext {
        timestamp: metadata.prev_timestamp,
        daa_score: metadata.daa_score,
        blue_score: metadata.blue_score,
    });

    let mut activity = ActivityDigestBuilder::new();
    for (merge_idx, tx) in txs {
        let tx_id = kaspa_tx_id(tx);
        activity.add_leaf(activity_leaf(&tx_id, tx.version, *merge_idx));
    }

    let parent_ref =
        if metadata.lane_expired { metadata.prev_seq_commit } else { metadata.prev_lane_tip };

    lane_tip_next(&LaneTipInput {
        parent_ref: &parent_ref,
        lane_key,
        activity_digest: &activity.finalize(),
        context_hash: &context_hash,
    })
}

/// Forces the Toccata fork active on `params`. The covenant flow is only valid where Toccata is
/// live.
pub fn force_covenant_forks(params: &mut Params) {
    params.toccata_activation = ForkActivation::always();
}

/// Builds a scheduler over `processor` and `store` with default execution and storage config: the
/// construction the settlement-l1 test and the tn10 example share. They differ only in the
/// processor's proving pipeline, which is baked into `processor`.
pub fn build_scheduler<S: Store, P: Processor<S>>(processor: P, store: S) -> Scheduler<S, P> {
    Scheduler::new(
        ExecutionConfig::default().with_processor(processor),
        StorageConfig::default().with_store(store),
    )
}

/// Reads a resource's latest bytes and decodes the leading four as a little-endian u32 counter,
/// returning 0 when the resource has never been written. The transaction-processor guest stores
/// each accessed resource as a u32 it bumps once per tx, so this is the lane's state as a number.
/// Call only after the batch has committed.
pub fn read_resource_u32<S: ReadStore>(store: &S, id: ResourceId) -> u32 {
    let version = StateVersion::from_latest_data(store, id);
    let data = version.data();
    if data.len() >= 4 { u32::from_le_bytes(data[..4].try_into().expect("4 bytes")) } else { 0 }
}
