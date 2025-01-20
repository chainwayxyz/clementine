use crate::builder::transaction::TxHandler;
use crate::cli::Args;
use crate::config::BridgeConfig;
use crate::errors::BridgeError;
use bitcoin;
use bitcoin::sighash::SighashCache;
use bitcoin::taproot::LeafVersion;
use bitcoin::XOnlyPublicKey;
use bitvm::chunker::assigner::BridgeAssigner;
use std::borrow::BorrowMut;
use std::collections::BTreeMap;
use std::process::exit;
use std::str::FromStr;
use tracing::level_filters::LevelFilter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::{fmt, EnvFilter, Registry};

lazy_static::lazy_static! {
    /// Global secp context.
    pub static ref SECP: bitcoin::secp256k1::Secp256k1<bitcoin::secp256k1::All> = bitcoin::secp256k1::Secp256k1::new();
}

lazy_static::lazy_static! {
    /// This is an unspendable pubkey.
    ///
    /// See https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki#constructing-and-spending-taproot-outputs
    pub static ref UNSPENDABLE_PUBKEY: bitcoin::secp256k1::PublicKey =
        "93c7378d96518a75448821c4f7c8f4bae7ce60f804d03d1f0628dd5dd0f5de51".parse().unwrap();
}

lazy_static::lazy_static! {
    /// This is an unspendable pubkey.
    ///
    /// See https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki#constructing-and-spending-taproot-outputs
    pub static ref UNSPENDABLE_XONLY_PUBKEY: bitcoin::secp256k1::XOnlyPublicKey =
        XOnlyPublicKey::from_str("93c7378d96518a75448821c4f7c8f4bae7ce60f804d03d1f0628dd5dd0f5de51").unwrap();
}

lazy_static::lazy_static! {
    pub static ref NETWORK : bitcoin::Network = bitcoin::Network::Regtest;
}

lazy_static::lazy_static! {
    pub static ref ALL_BITVM_INTERMEDIATE_VARIABLES: BTreeMap<String, usize> = BridgeAssigner::default().all_intermediate_variable();
}

/// Gets configuration from CLI, for binaries. If there are any errors, print
/// error to stderr and exit program.
///
/// Steps:
///
/// 1. Get CLI arguments
/// 2. Initialize logger
/// 3. Get configuration file
///
/// These steps are pretty standard and binaries can use this to get a
/// `BridgeConfig`.
///
/// # Returns
///
/// A tuple, containing:
///
/// - [`BridgeConfig`] from CLI argument
/// - [`Args`] from CLI options
pub fn get_configuration_for_binaries() -> (BridgeConfig, Args) {
    let args = match crate::cli::parse() {
        Ok(args) => args,
        Err(e) => {
            eprintln!("{e}");
            exit(1);
        }
    };
    match crate::utils::initialize_logger(args.verbose) {
        Ok(args) => args,
        Err(e) => {
            eprintln!("{e}");
            exit(1);
        }
    };
    let config = match crate::cli::get_configuration_from(args.clone()) {
        Ok(config) => config,
        Err(e) => {
            eprintln!("{e}");
            exit(1);
        }
    };

    (config, args)
}

pub fn usize_to_var_len_bytes(x: usize) -> Vec<u8> {
    let usize_bytes = (usize::BITS / 8) as usize;
    let bits = x.max(1).ilog2() + 1;
    let len = ((bits + 7) / 8) as usize;
    let empty = usize_bytes - len;
    let op_idx_bytes = x.to_be_bytes();
    let op_idx_bytes = &op_idx_bytes[empty..];
    op_idx_bytes.to_vec()
}

pub fn handle_taproot_witness_new<T: AsRef<[u8]>>(
    tx: &mut TxHandler,
    witness_elements: &[T],
    txin_index: usize,
    script_index: Option<usize>,
) -> Result<(), BridgeError> {
    let mut sighash_cache = SighashCache::new(tx.tx.borrow_mut());

    let witness = sighash_cache
        .witness_mut(txin_index)
        .ok_or(BridgeError::TxInputNotFound)?;

    witness_elements
        .iter()
        .for_each(|element| witness.push(element));
    if let Some(index) = script_index {
        let script = &tx.prev_scripts[txin_index][index];
        let spend_control_block = tx.prev_taproot_spend_infos[txin_index]
            .clone()
            .ok_or(BridgeError::TaprootScriptError)?
            .control_block(&(script.clone(), LeafVersion::TapScript))
            .ok_or(BridgeError::ControlBlockError)?;

        witness.push(script.clone());
        witness.push(spend_control_block.serialize());
    }
    Ok(())
}

pub fn get_claim_reveal_indices(depth: usize, count: u32) -> Vec<(usize, usize)> {
    assert!(count <= 2u32.pow(depth as u32));

    if count == 0 {
        return vec![(0, 0)];
    }

    let mut indices: Vec<(usize, usize)> = Vec::new();
    if count == 2u32.pow(depth as u32) {
        return indices;
    }

    if count % 2 == 1 {
        indices.push((depth, count as usize));
        indices.extend(get_claim_reveal_indices(depth - 1, (count + 1) / 2));
    } else {
        indices.extend(get_claim_reveal_indices(depth - 1, count / 2));
    }

    indices
}

/// Initializes `tracing` as the logger.
///
/// # Parameters
///
/// - `level`: Level ranges from 0 to 5. 0 defaults to no logs but can be
///   overwritten with `RUST_LOG` env var. While other numbers sets log level from
///   lowest level (1) to highest level (5). Is is advised to use 0 on tests and
///   other values for binaries (get value from user).
///
/// # Returns
///
/// Returns `Err` if `tracing` can't be initialized. Multiple subscription error
/// is emmitted and will return `Ok(())`.
pub fn initialize_logger(level: u8) -> Result<(), BridgeError> {
    let level = match level {
        0 => None,
        1 => Some(LevelFilter::ERROR),
        2 => Some(LevelFilter::WARN),
        3 => Some(LevelFilter::INFO),
        4 => Some(LevelFilter::DEBUG),
        5 => Some(LevelFilter::TRACE),
        _ => {
            return Err(BridgeError::ConfigError(format!(
                "Verbosity level can only be between 0 and 5 (given {level})!"
            )))
        }
    };

    // Standard layer that will output human readable logs.
    let layer = fmt::layer().with_test_writer();
    // JSON layer that will output JSON formatted logs.
    let json_layer = fmt::layer::<Registry>().with_test_writer().json();

    let filter = match level {
        Some(level) => EnvFilter::builder()
            .with_default_directive(level.into())
            .from_env_lossy(),
        None => EnvFilter::from_default_env(),
    };

    // Try to initialize tracing, depending on the `JSON_LOGS` env var,
    let res = if std::env::var("JSON_LOGS").is_ok() {
        tracing_subscriber::util::SubscriberInitExt::try_init(
            tracing_subscriber::registry().with(json_layer).with(filter),
        )
    } else {
        tracing_subscriber::util::SubscriberInitExt::try_init(
            tracing_subscriber::registry().with(layer).with(filter),
        )
    };

    if let Err(e) = res {
        // If it failed because of a re-initialization, do not care about
        // the error.
        if e.to_string() != "a global default trace dispatcher has already been set" {
            return Err(BridgeError::ConfigError(e.to_string()));
        }

        tracing::trace!("Tracing is already initialized, skipping without errors...");
    };

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_indices() {
        let test_cases = vec![
            ((0, 0), vec![(0, 0)]),
            ((0, 1), vec![]),
            ((1, 0), vec![(0, 0)]),
            ((1, 1), vec![(1, 1)]),
            ((1, 2), vec![]),
            ((2, 0), vec![(0, 0)]),
            ((2, 1), vec![(2, 1), (1, 1)]),
            ((2, 2), vec![(1, 1)]),
            ((2, 3), vec![(2, 3)]),
            ((2, 4), vec![]),
            ((3, 0), vec![(0, 0)]),
            ((3, 1), vec![(3, 1), (2, 1), (1, 1)]),
            ((3, 2), vec![(2, 1), (1, 1)]),
            ((3, 3), vec![(3, 3), (1, 1)]),
            ((3, 4), vec![(1, 1)]),
            ((3, 5), vec![(3, 5), (2, 3)]),
            ((3, 6), vec![(2, 3)]),
            ((3, 7), vec![(3, 7)]),
            ((3, 8), vec![]),
        ];

        for ((depth, index), expected) in test_cases {
            let indices = get_claim_reveal_indices(depth, index);
            assert_eq!(
                indices, expected,
                "Failed at get_indices({}, {})",
                depth, index
            );
        }
    }
}
