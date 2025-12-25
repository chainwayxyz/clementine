//! # Clementine Config
//!
//! Configuration types for the clementine bridge.
//!
//! This crate contains protocol parameters and configuration structures
//! that are shared across clementine crates.

pub mod grpc;
pub mod protocol;
pub mod telemetry;
pub mod tx_sender;

pub use grpc::GrpcLimits;
pub use protocol::{
    ProtocolParamset, ProtocolParamsetName, BLOCKS_PER_HOUR, MIN_TAPROOT_AMOUNT,
    NON_EPHEMERAL_ANCHOR_AMOUNT, REGTEST_PARAMSET, WINTERNITZ_LOG_D,
};
pub use telemetry::TelemetryConfig;
pub use tx_sender::TxSenderLimits;
