//! # Bitcoin Transaction Builder for Clementine Bridge
//!
//! This module provides a helper struct TxHandler for constructing
//! the tx's needed for the bridge. TxHandler's purpose is to store additional
//! data compared to a normal Bitcoin transaction to facilitate easier signing as the
//! scripts used in bridge can be quite complex.
//!
//! Modules:
//! - address: Contains helper functions to create taproot addresses and deposit addresses.
//! - script: Contains all kinds of scripts that are used in the bridge. There is a struct for each kind of script to
//!   facilitate both easier script creation and easier signing.
//! - sighash: As its possible more than 100000 tx's can be signed in a single deposit (depends on number of round tx's, number of
//!   kickoff utxo's, and number of operators), the sighash functions create a stream that verifiers and operators consume to sign the tx's
//!   during a deposit.
//! - transaction: Contains the functions that create TxHandler's of every single tx needed for the bridge. For detailed information
//!   about the tx's see the [clementine whitepaper](https://citrea.xyz/clementine_whitepaper.pdf).
pub mod address;
pub mod script;
pub mod sighash;
pub mod transaction;
