//! # Clementine Utils
//!
//! Utility types and traits for the clementine bridge.
//!
//! This crate contains helper types used across multiple modules for common operations.

pub mod fee;
pub mod metadata;
pub mod rbf;
pub mod traits;

pub use fee::FeePayingType;
pub use metadata::TxMetadata;
pub use rbf::RbfSigningInfo;
pub use traits::{Last20Bytes, NamedEntity, ScriptBufExt, TryLast20Bytes};
