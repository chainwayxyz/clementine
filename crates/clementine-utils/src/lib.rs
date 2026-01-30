//! # Clementine Utils
//!
//! Utility types and traits for the clementine bridge.
//!
//! This crate contains helper types used across multiple modules for common operations.

pub mod address;
pub mod sign;
pub mod tracing;
pub mod traits;

pub use clementine_tx_sender_types::{FeePayingType, TxMetadata};
pub use sign::{RbfSigningInfo, RbfSigningSpendPath, TapTweakData};
pub use traits::{Last20Bytes, NamedEntity, ScriptBufExt, TryLast20Bytes};
