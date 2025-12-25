//! Fee paying type for transactions.

use serde::{Deserialize, Serialize};

/// Specifies the fee bumping strategy used for a transaction.
#[derive(
    Copy, Clone, Debug, Eq, Hash, PartialEq, PartialOrd, Ord, Serialize, Deserialize, sqlx::Type,
)]
#[sqlx(type_name = "fee_paying_type", rename_all = "lowercase")]
pub enum FeePayingType {
    /// Child-Pays-For-Parent: A new "child" transaction is created, spending an output
    /// from the original "parent" transaction. The child pays a high fee, sufficient
    /// to cover both its own cost and the parent's fee deficit, incentivizing miners
    /// to confirm both together. Specifically, we utilize "fee payer" UTXOs.
    CPFP,
    /// Replace-By-Fee: The original unconfirmed transaction is replaced with a new
    /// version that includes a higher fee. The original transaction must signal
    /// RBF enablement (e.g., via nSequence). Bitcoin Core's `bumpfee` RPC is often used.
    RBF,
    /// The transaction has already been funded and no fee is needed.
    /// Currently used for disprove tx as it has operator's collateral as input.
    NoFunding,
}
