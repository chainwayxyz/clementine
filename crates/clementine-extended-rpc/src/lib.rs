//! Extended Bitcoin RPC client with retry logic.
//!
//! This crate provides [`ExtendedBitcoinRpc`], a wrapper around the Bitcoin RPC client
//! that includes retry logic for transient errors and utility methods for common operations.

mod client;
mod retry;

pub use clementine_errors::BitcoinRPCError;
pub use client::{
    get_fee_rate_from_mempool_space, ExtendedBitcoinRpc, RetryConfig, RetryableError,
};
