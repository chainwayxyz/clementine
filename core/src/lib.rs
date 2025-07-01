//! # Clementine 🍊
//!
//! Clementine is Citrea's BitVM-based, trust-minimized two-way peg program.
//! Please refer to the [whitepaper](https://citrea.xyz/clementine_whitepaper.pdf)
//! to understand the design of Clementine.
//!
//! Clementine Core is the backbone of Clementine. As the name suggests, it
//! provides the core functionalities for Clementine to operate.
//!
//! Most of the modules are self-explanatory and documented. Please refer
//! to the documentation of each module for more information.
//!
//! ## Binaries and Using Clementine
//!
//! Clementine's architecture is designed so that every actor is a separate
//! server. They all communicate with each other via gRPC.
//!
//! For this reason, Clementine Core provides a single main binary,
//! `clementine-core`, which acts as a server starter for every actor. There is
//! also a helper binary, `clementine-core-cli`, which is a command-line
//! interface for communicating with these servers. It is located in
//! `bin/cli.rs`.
//!
//! The [`cli`](cli) module provides the command-line interface for Clementine.
//! It is used in every binary.
//!
//! The [`config`](config) module is also essential for Clementine to operate.
//! It specifies essential variables for the protocol as well as the user's
//! environment setup.
//!
//! ## Utilizing Actors
//!
//! The core behavior of Clementine's actors is defined in the respective
//! modules:
//!
//! - [`operator`](operator)
//! - [`verifier`](verifier)
//! - [`aggregator`](aggregator)
//!
//! For all these modules, the [`actor`] module provides common utilities.
//!
//! ### Servers
//!
//! An actor is only meaningful if its server is running. For each actor, there
//! is a server module, which provides the server implementation.
//!
//! The main server architecture is defined in the `rpc/clementine.proto` file.
//! It is compiled to Rust code by the `tonic` library. Server logic for each
//! actor is defined in the respective server module in the [`rpc`](rpc) module.
//!
//! ## Building Transactions and Managing Flow with Tasks
//!
//! Clementine operates on Bitcoin transactions. The [`builder`](builder) module
//! provides utilities for building Bitcoin transactions based on the
//! specification (detailed in the whitepaper). The [`builder`](builder) module
//! can create a transaction according to the specification with the required
//! signatures, addresses, and scripts.
//!
//! Clementine requires a few background tasks to be running in order to operate
//! properly. The task interface is defined in the [`task`](task) module. These
//! tasks are:
//!
//! - The [`bitcoin_syncer`](bitcoin_syncer) module syncs Bitcoin blocks and
//!   transactions.
//! - The [`tx_sender`](tx_sender) module sends transactions to the Bitcoin network
//!   depending on the transaction type.
//! - The [`states`](states) module provides state machine implementations for
//!   managing some of the steps in the specification.
//!
//! There are other modules that are not tasks, but they are used in the tasks
//! and are important for the flow of Clementine:
//!
//! - The [`header_chain_prover`](header_chain_prover) module accepts Bitcoin block headers
//!   and prepares proofs for them.
//!
//! ### Communicating with the Outside
//!
//! Some steps require communicating with external systems:
//!
//! - The [`extended_rpc`](extended_rpc) module provides a client that talks with
//!   the Bitcoin node.
//! - The [`citrea`](citrea) module provides a client for interacting with Citrea.
//! - The [`bitvm_client`](bitvm_client) module provides a client for BitVM.
//! - The [`database`](database) module provides a database interface for
//!   interacting with the PostgreSQL database.
//!
//! ## Development Guidelines
//!
//! ### Error Handling
//!
//! There are rules about error handling in Clementine. Please refer to the
//! [`errors`](errors) module for more information.
//!
//! ### Testing Clementine
//!
//! There are a few quirks about testing Clementine. One of the main ones is
//! that there is no `tests` directory for integration tests. Rather, there is a
//! [`test`](test) module, which is compiled only if `test` is enabled by Cargo
//! (when running `cargo test`). That module provides common utilities for unit
//! and integration testing, as well as integration tests themselves. This is a
//! workaround for having common test utilities between unit and integration
//! tests.
//!
//! Please refer to the [`test`](test) module to check what utilities are
//! available for testing and how to use them.
//!
//! Also, if a new integration test file is added, it should be guarded by the
//! `#[cfg(feature = "integration-tests")]` attribute. This ensures that the
//! integration and unit tests can be run separately.

#![allow(clippy::too_many_arguments)]
#![allow(warnings)]

use bitcoin::{OutPoint, Txid};
use serde::{Deserialize, Serialize};

pub mod actor;
pub mod aggregator;
pub mod bitcoin_syncer;
pub mod bitvm_client;
pub mod builder;
pub mod citrea;
pub mod cli;
pub mod config;
pub mod constants;
pub mod database;
pub mod deposit;
pub mod errors;
pub mod extended_rpc;
pub mod header_chain_prover;
pub mod musig2;
pub mod operator;
pub mod rpc;
pub mod servers;
#[cfg(feature = "automation")]
pub mod states;
pub mod task;
#[cfg(feature = "automation")]
pub mod tx_sender;
pub mod utils;
pub mod verifier;

#[cfg(test)]
pub mod test;

macro_rules! impl_try_from_vec_u8 {
    ($name:ident, $size:expr) => {
        impl TryFrom<Vec<u8>> for $name {
            type Error = &'static str;

            fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
                if value.len() == $size {
                    Ok($name(value.try_into().unwrap()))
                } else {
                    Err(concat!("Expected a Vec<u8> of length ", stringify!($size)))
                }
            }
        }
    };
}

pub type ConnectorUTXOTree = Vec<Vec<OutPoint>>;
// pub type HashTree = Vec<Vec<HashType>>;
// pub type PreimageTree = Vec<Vec<PreimageType>>;
pub type InscriptionTxs = (OutPoint, Txid);

/// Type alias for EVM address
#[derive(Copy, Clone, Debug, PartialOrd, Ord, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct EVMAddress(#[serde(with = "hex::serde")] pub [u8; 20]);

impl_try_from_vec_u8!(EVMAddress, 20);

#[derive(Clone, Debug, Eq, Hash, PartialEq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct UTXO {
    pub outpoint: OutPoint,
    pub txout: bitcoin::TxOut,
}

#[derive(Clone, Debug, Copy, Serialize, Deserialize, PartialEq, sqlx::Type)]
#[sqlx(type_name = "bytea")]
pub struct ByteArray66(#[serde(with = "hex::serde")] pub [u8; 66]);

impl_try_from_vec_u8!(ByteArray66, 66);

#[derive(Clone, Debug, Copy, Serialize, Deserialize, PartialEq, sqlx::Type)]
#[sqlx(type_name = "bytea")]
pub struct ByteArray32(#[serde(with = "hex::serde")] pub [u8; 32]);

impl_try_from_vec_u8!(ByteArray32, 32);

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, sqlx::Type)]
#[sqlx(type_name = "bytea")]
pub struct ByteArray64(#[serde(with = "hex::serde")] pub [u8; 64]);

impl_try_from_vec_u8!(ByteArray64, 64);
