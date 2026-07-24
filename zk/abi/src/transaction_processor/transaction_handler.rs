use kaspa_hashes::Hash;

use crate::{
    transaction_processor::{Resource, Transaction},
    withdrawal::{CanonicalSink, DepositSink, ExitSink},
};

/// Developer-provided transaction execution logic.
///
/// Receives the full parsed transaction, its merge_idx, context hash, mutable access to the
/// transaction's resources, an [`ExitSink`] to emit L2→L1 withdrawals, a [`DepositSink`] to
/// record the deposit-address commitment when the tx credits an L1 deposit, and a [`CanonicalSink`]
/// to record the canonical-`R` `seq_commit` when the tx settles a peg-out.
/// Returns `Ok(())` on success or an error that gets committed to the journal.
pub trait TransactionHandler:
    for<'a> FnOnce(
    &Transaction<'a>,
    u32,
    &'a Hash,
    &mut [Resource<'a>],
    &mut ExitSink,
    &mut DepositSink,
    &mut CanonicalSink,
) -> crate::Result<()>
{
}

impl<F> TransactionHandler for F where
    F: for<'a> FnOnce(
        &Transaction<'a>,
        u32,
        &'a Hash,
        &mut [Resource<'a>],
        &mut ExitSink,
        &mut DepositSink,
        &mut CanonicalSink,
    ) -> crate::Result<()>
{
}
