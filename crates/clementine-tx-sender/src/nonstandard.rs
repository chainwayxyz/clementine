use crate::{TxSender, TxSenderDatabase, TxSenderSigner, TxSenderTxBuilder};
use bitcoin::Transaction;

impl<S, D, B> TxSender<S, D, B>
where
    S: TxSenderSigner,
    D: TxSenderDatabase,
    B: TxSenderTxBuilder,
{
    /// Checks if a bridge transaction is nonstandard. Keep in mind that these are not all cases where a transaction is nonstandard.
    /// We only check non-standard types that clementine generates by default in non-standard mode.
    /// Currently checks these cases:
    /// 1. The transaction contains 0 sat non-anchor (only checks our specific anchor address)
    ///    and non-op return output.
    /// 2. The transaction weight is bigger than 400k
    ///
    /// Arguments:
    /// * `tx` - The transaction to check.
    ///
    /// Returns:
    /// * `true` if the transaction is nonstandard, `false` otherwise.
    pub fn is_bridge_tx_nonstandard(&self, tx: &Transaction) -> bool {
        tx.output.iter().any(|output| {
            output.value.to_sat() == 0
                && !self.is_p2a_anchor(output)
                && !output.script_pubkey.is_op_return()
        }) || tx.weight().to_wu() > 400_000
    }
}
