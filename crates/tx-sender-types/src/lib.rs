//! Shared types for tx-sender JSON-RPC and related client helpers.

#[cfg(feature = "citrea")]
pub mod citrea;
#[cfg(feature = "clementine")]
pub mod clementine;

#[cfg(feature = "citrea")]
pub use citrea::CitreaTxRequest;

#[cfg(feature = "clementine")]
pub use clementine::{
    ActivatedWithTxid, FeePayingType, InsertTryToSendParams, RbfSigningInfo, RbfSigningSpendPath,
    TxMetadata,
};
