use crate::{Error, Result};

/// Captures a transaction's canonical-`R` sequencing commitment during execution.
///
/// The canonical-`R` commitment is the KIP-21 `seq_commit` of the Kaspa block whose coinbase
/// merge-mines the ZKas block that committed the shielded state root `r` a peg-out was proven
/// against (see [`crate::canonical_r`]). A peg-out guest proves that binding inside its proof and
/// records the resulting `seq_commit` here; a non-peg-out tx leaves the zero sentinel.
///
/// Mechanically identical to [`DepositSink`](crate::withdrawal::DepositSink): the ABI constructs one
/// per `process_transaction` invocation, passes it `&mut` to the handler, and reads it into the
/// journal after the handler returns. The value is bundle-constant — the batch and bundle journals
/// carry it opaquely with a carry-or-panic fold, and the on-chain settlement redeem script requires
/// it to equal the `seq_commit` Kaspa itself recorded for a buried block (via `OpChainblockSeqCommit`
/// on a witnessed block hash). That on-chain check is what turns "the guest verified `r` is
/// PoW-committed" into "`r` is committed by a block Kaspa's own consensus buried", closing the
/// checkpoint-trust gap.
pub struct CanonicalSink {
    /// Canonical-`R` `seq_commit`, or `[0u8; 32]` when the tx settled no peg-out.
    seq_commit: [u8; 32],
}

impl CanonicalSink {
    /// Creates a sink seeded with the zero sentinel (no peg-out).
    pub(crate) fn new() -> Self {
        Self { seq_commit: [0u8; 32] }
    }

    /// Records the canonical-`R` `seq_commit` for this tx.
    ///
    /// Idempotent across repeats with the same value. Returns `Ok` on the first set or an identical
    /// re-set, or `Err` on a conflicting non-zero value: one transaction settles at most one peg-out,
    /// so it may not name two distinct canonical blocks.
    pub fn set(&mut self, seq_commit: &[u8; 32]) -> Result<()> {
        if self.seq_commit == [0u8; 32] {
            self.seq_commit = *seq_commit;
            Ok(())
        } else if &self.seq_commit == seq_commit {
            Ok(())
        } else {
            Err(Error::Decode("canonical_seq_commit set twice with differing values".into()))
        }
    }

    /// Returns the recorded canonical-`R` `seq_commit`, or `[0u8; 32]` when none was set.
    pub(crate) fn get(&self) -> [u8; 32] {
        self.seq_commit
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_to_zero_sentinel() {
        let sink = CanonicalSink::new();
        assert_eq!(sink.get(), [0u8; 32]);
    }

    #[test]
    fn set_records_value() {
        let mut sink = CanonicalSink::new();
        sink.set(&[0xAB; 32]).unwrap();
        assert_eq!(sink.get(), [0xAB; 32]);
    }

    #[test]
    fn set_is_idempotent_for_equal_value() {
        let mut sink = CanonicalSink::new();
        sink.set(&[0xAB; 32]).unwrap();
        sink.set(&[0xAB; 32]).unwrap();
        assert_eq!(sink.get(), [0xAB; 32]);
    }

    #[test]
    fn set_rejects_conflicting_value() {
        let mut sink = CanonicalSink::new();
        sink.set(&[0xAB; 32]).unwrap();
        assert!(matches!(sink.set(&[0xCD; 32]), Err(Error::Decode(_))));
    }
}
