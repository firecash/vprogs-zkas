//! The on-chain canonical-`R` gate: the covenant clause that ties a peg-out to Kaspa's own
//! proof-of-work, so no operator is trusted to assert which ZKas state root is real.
//!
//! The peg-out guest journals `(seq_commit, kaspa_block)` after proving, inside the proof, that the
//! burned `R` is committed by a ZKas block whose hash is embedded in `kaspa_block`'s coinbase
//! payload, and that `kaspa_block`'s KIP-21 sequencing commitment equals `seq_commit`
//! (`vprogs_zk_abi::canonical_r`). This gate closes the loop **on-chain**: it requires the journal's
//! `seq_commit` to equal the sequencing commitment Kaspa itself recorded for `kaspa_block`, read via
//! [`OpChainblockSeqCommit`].
//!
//! [`OpChainblockSeqCommit`] does the finality work for us: it resolves a block hash to its
//! `seq_commit` **only if the block is a chain ancestor within the accessor's depth window**,
//! failing the script otherwise. So burying-depth (the SPV-style finality assumption) is enforced by
//! the opcode, not by hand.
//!
//! After this gate, `R` is canonical: Kaspa's PoW chain committed the ZKas block that produced it.

use kaspa_txscript::{
    opcodes::codes::{OpChainblockSeqCommit, OpEqualVerify},
    script_builder::ScriptBuilder,
};

/// Emit the canonical-`R` gate.
///
/// Stack (top→bottom): `[..., kaspa_block, claimed_seq_commit]`
/// →      `[...]`
///
/// `OpChainblockSeqCommit` pops `kaspa_block` and pushes the sequencing commitment Kaspa recorded
/// for it (or fails if the block is not a buried chain ancestor). `OpEqualVerify` then requires that
/// to equal the `claimed_seq_commit` the guest journaled. Both values are consumed.
pub fn emit_seq_commit_gate(b: &mut ScriptBuilder) {
    // Stack (top→bottom): [..., claimed_seq_commit, kaspa_block]
    // Bring the block to the top for the opcode.
    b.add_op(kaspa_txscript::opcodes::codes::OpSwap).unwrap();
    // Stack: [..., kaspa_block, claimed_seq_commit]  → after swap: block on top
    b.add_op(OpChainblockSeqCommit).unwrap();
    // Stack: [..., claimed_seq_commit, chain_seq_commit]
    b.add_op(OpEqualVerify).unwrap();
    // Stack: [...]
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use kaspa_consensus_core::{
        hashing::sighash::SigHashReusedValuesUnsync,
        tx::{
            PopulatedTransaction, Transaction, TransactionInput, TransactionOutpoint,
            TransactionOutput, UtxoEntry,
        },
    };
    use kaspa_hashes::Hash;
    use kaspa_txscript::{
        EngineFlags, TxScriptEngine, caches::Cache, covenants::CovenantsContext,
        engine_context::EngineContext, opcodes::codes::OpTrue, script_builder::ScriptBuilder,
        seq_commit_accessor::SeqCommitAccessor, standard::pay_to_script_hash_script,
    };

    use super::emit_seq_commit_gate;

    /// Map-backed `OpChainblockSeqCommit` accessor: a block resolves to its `seq_commit` only if
    /// present (i.e. a buried chain ancestor); absent ⇒ the opcode fails (unburied / unknown block).
    struct MockAccessor(HashMap<Hash, Hash>);
    impl SeqCommitAccessor for MockAccessor {
        fn is_chain_ancestor_from_pov(&self, block: Hash) -> Option<bool> {
            self.0.contains_key(&block).then_some(true)
        }
        fn seq_commitment_within_depth(&self, block: Hash) -> Option<Hash> {
            self.0.get(&block).copied()
        }
    }

    /// A P2SH redeem script that pushes `(kaspa_block, claimed_seq_commit)` and runs the gate,
    /// ending in `OpTrue`. In the real covenant these two values come from the witness/journal; a
    /// self-contained redeem lets us exercise the on-chain opcode mechanic in isolation.
    fn gate_redeem(kaspa_block: Hash, claimed_seq_commit: Hash) -> Vec<u8> {
        let mut b = ScriptBuilder::new();
        // `add_data` emits the correct push opcode itself. Push block, then claimed, so the stack
        // (top→bottom) is `[claimed_seq_commit, kaspa_block]` — the shape the gate's OpSwap expects.
        b.add_data(&kaspa_block.as_bytes()).unwrap();
        b.add_data(&claimed_seq_commit.as_bytes()).unwrap();
        emit_seq_commit_gate(&mut b);
        b.add_op(OpTrue).unwrap();
        b.drain()
    }

    /// Spend the P2SH-wrapped redeem through the real script engine with `accessor`, returning
    /// whether the script verified.
    fn run(redeem: &[u8], accessor: &dyn SeqCommitAccessor) -> bool {
        let spk = pay_to_script_hash_script(redeem);
        // Sig script reveals the redeem (P2SH pops it last).
        let sig = ScriptBuilder::new().add_data(redeem).unwrap().drain();

        let utxo = UtxoEntry::new(1000, spk.clone(), 0, false, None);
        let input = TransactionInput::new(
            TransactionOutpoint::new(Hash::from_bytes([0x01; 32]), 0),
            sig,
            0,
            0,
        );
        let output = TransactionOutput::new(1000, ScriptPublicKeyStub::spk());
        let tx = Transaction::new(0, vec![input], vec![output], 0, Default::default(), 0, vec![]);

        let sig_cache = Cache::new(10);
        let reused = SigHashReusedValuesUnsync::new();
        // `OpChainblockSeqCommit` is a Toccata opcode; the engine only enables it when covenants are
        // on (otherwise it's a disabled opcode and every run fails — which is what made the earlier
        // "reject" cases pass spuriously).
        let flags = EngineFlags { covenants_enabled: true, ..Default::default() };
        let populated = PopulatedTransaction::new(&tx, vec![utxo.clone()]);
        let cov_ctx = CovenantsContext::from_tx(&populated).expect("no covenant bindings ⇒ trivial context");
        let ctx = EngineContext::new(&sig_cache)
            .with_reused(&reused)
            .with_seq_commit_accessor(accessor)
            .with_covenants_ctx(&cov_ctx);
        let mut vm = TxScriptEngine::from_transaction_input(&populated, &tx.inputs[0], 0, &utxo, ctx, flags);
        vm.execute().is_ok()
    }

    struct ScriptPublicKeyStub;
    impl ScriptPublicKeyStub {
        fn spk() -> kaspa_consensus_core::tx::ScriptPublicKey {
            kaspa_consensus_core::tx::ScriptPublicKey::new(0, vec![0x51].into()) // OP_TRUE
        }
    }

    #[test]
    fn gate_accepts_matching_seq_commit() {
        let block = Hash::from_bytes([0x33; 32]);
        let seq_commit = Hash::from_bytes([0x44; 32]);
        let accessor = MockAccessor(HashMap::from([(block, seq_commit)]));
        assert!(run(&gate_redeem(block, seq_commit), &accessor), "matching seq_commit must verify");
    }

    #[test]
    fn gate_rejects_wrong_seq_commit() {
        let block = Hash::from_bytes([0x33; 32]);
        let real = Hash::from_bytes([0x44; 32]);
        let lie = Hash::from_bytes([0x99; 32]);
        let accessor = MockAccessor(HashMap::from([(block, real)]));
        // The guest claims `lie`, but Kaspa recorded `real` for the block ⇒ OpEqualVerify fails.
        assert!(!run(&gate_redeem(block, lie), &accessor), "a fabricated seq_commit must be rejected");
    }

    #[test]
    fn gate_rejects_unburied_block() {
        let block = Hash::from_bytes([0x33; 32]);
        let seq_commit = Hash::from_bytes([0x44; 32]);
        // Empty accessor: the block is not a buried chain ancestor ⇒ OpChainblockSeqCommit fails.
        let accessor = MockAccessor(HashMap::new());
        assert!(!run(&gate_redeem(block, seq_commit), &accessor), "an unburied block must be rejected");
    }
}
