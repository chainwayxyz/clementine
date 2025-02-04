use crate::cli::Args;
use crate::config::BridgeConfig;
use crate::errors::BridgeError;
use bitcoin::{self};
use bitcoin::{ScriptBuf, XOnlyPublicKey};
use bitvm::chunker::assigner::BridgeAssigner;
use bitvm::chunker::chunk_groth16_verifier::groth16_verify_to_segments;
use bitvm::chunker::disprove_execution::RawProof;
use bitvm::signatures::signing_winternitz::WinternitzPublicKey;
use bitvm::signatures::winternitz;
use sha2::digest::consts::U8;
use tracing::Level;
//use bitvm::chunker::assigner::BridgeAssigner;
use borsh::{BorshDeserialize, BorshSerialize};
use ctor::ctor;
use std::collections::BTreeMap;
use std::collections::HashMap;
use std::fs;
use std::process::exit;
use std::str::FromStr;
use std::sync::OnceLock;
use std::time::Instant;
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
        "93c7378d96518a75448821c4f7c8f4bae7ce60f804d03d1f0628dd5dd0f5de51".parse().expect("this key is valid");
}

lazy_static::lazy_static! {
    /// This is an unspendable pubkey.
    ///
    /// See https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki#constructing-and-spending-taproot-outputs
    pub static ref UNSPENDABLE_XONLY_PUBKEY: bitcoin::secp256k1::XOnlyPublicKey =
        XOnlyPublicKey::from_str("93c7378d96518a75448821c4f7c8f4bae7ce60f804d03d1f0628dd5dd0f5de51").expect("this key is valid");
}

lazy_static::lazy_static! {
    pub static ref NETWORK : bitcoin::Network = bitcoin::Network::Regtest;
}

// lazy_static::lazy_static! {
//     pub static ref ALL_BITVM_INTERMEDIATE_VARIABLES: BTreeMap<String, usize> = BridgeAssigner::default().all_intermediate_variable();
// }

pub static BITVM_CACHE_LOCK: OnceLock<BitvmCache> = OnceLock::new();

#[derive(BorshSerialize, BorshDeserialize, Debug)]
pub struct BitvmCache {
    pub intermediate_variables: BTreeMap<String, usize>,
    pub disprove_scripts: Vec<Vec<u8>>,
}

impl BitvmCache {
    fn save_to_file(&self, path: &str) -> bool {
        match borsh::to_vec(self) {
            Ok(serialized) => match fs::write(path, serialized) {
                Ok(_) => {
                    println!("Saved BitVM cache to file");
                    true
                }
                Err(e) => {
                    println!("Failed to save BitVM cache: {}", e);
                    false
                }
            },
            Err(e) => {
                println!("Failed to serialize BitVM cache: {}", e);
                false
            }
        }
    }

    fn load_from_file(path: &str) -> Option<Self> {
        match fs::read(path) {
            Ok(bytes) => match Self::try_from_slice(&bytes) {
                Ok(cache) => {
                    println!("Loaded BitVM cache from file");
                    Some(cache)
                }
                Err(e) => {
                    println!("Failed to deserialize BitVM cache: {}", e);
                    None
                }
            },
            Err(_) => {
                println!("No BitVM cache found");
                None
            }
        }
    }
}

#[ctor]
fn init_all_bitvm_intermediate_variables() {
    let start = Instant::now();
    let cache_path = "bitvm_cache.bin";

    let bitvm_cache = BitvmCache::load_from_file(cache_path).unwrap_or_else(|| {
        let fresh_data = generate_fresh_data();
        fresh_data.save_to_file(cache_path);
        fresh_data
    });

    BITVM_CACHE_LOCK.set(bitvm_cache).unwrap();
    println!("BitVM initialization took: {:?}", start.elapsed());
}

fn generate_fresh_data() -> BitvmCache {
    println!("Generating fresh BitVM data...");
    let map = BridgeAssigner::default().all_intermediate_variables();

    let commits_publickeys = map
        .iter()
        .enumerate()
        .map(|(idx, (intermediate_step, intermediate_step_size))| {
            let mut dummy_pk = [31u8; 20];
            dummy_pk[..8].copy_from_slice(&idx.to_le_bytes());
            let parameters = winternitz::Parameters::new(*intermediate_step_size as u32 * 2, 4);

            let digit_count = parameters.total_digit_count() as usize;
            let mut winternitz_pk = Vec::with_capacity(digit_count);

            for i in 0..digit_count {
                let mut new_pk = dummy_pk;
                new_pk[12..20].copy_from_slice(&i.to_le_bytes());
                winternitz_pk.push(new_pk);
            }

            let winternitz_pk = WinternitzPublicKey {
                public_key: winternitz_pk,
                parameters,
            };
            Ok((intermediate_step.clone(), winternitz_pk))
        })
        .collect::<Result<BTreeMap<_, _>, BridgeError>>()
        .unwrap();

    let mut bridge_assigner = BridgeAssigner::new_watcher(commits_publickeys);
    let proof = RawProof::default();
    let segments =
        groth16_verify_to_segments(&mut bridge_assigner, &proof.public, &proof.proof, &proof.vk);

    let scripts = segments
        .iter()
        .map(|s| s.script.clone().compile().to_bytes())
        .collect();

    BitvmCache {
        intermediate_variables: map,
        disprove_scripts: scripts,
    }
}

pub fn replace_disprove_scripts(winternitz_pk: &[Vec<[u8; 20]>]) -> Vec<ScriptBuf> {
    let start = Instant::now();

    // Get the initial scripts.
    let cache = BITVM_CACHE_LOCK.get().expect("BitVM cache not initialized");
    let mut disprove_scripts = cache.disprove_scripts.clone();
    // Process each intermediate variable one at a time.
    for (idx, (_intermediate_step, intermediate_step_size)) in
        cache.intermediate_variables.iter().enumerate()
    {
        if idx >= winternitz_pk.len() {
            panic!(
                "idx out of bounds, this should never happen, winternitz_pk.len() = {}, idx = {}",
                winternitz_pk.len(),
                idx
            );
            break;
        }

        // Build a dummy base public key.
        let mut dummy_base = [31u8; 20];
        dummy_base[..8].copy_from_slice(&idx.to_le_bytes());

        // Compute the parameters and determine the number of digits.
        let parameters = winternitz::Parameters::new((*intermediate_step_size as u32) * 2, 4);
        let digit_count = parameters.total_digit_count() as usize;

        // Build a mapping of dummy key -> actual replacement key.
        let mut mapping = HashMap::<[u8; 20], [u8; 20]>::with_capacity(digit_count);
        for digit in 0..digit_count {
            if digit >= winternitz_pk[idx].len() {
                panic!("digit out of bounds, this should never happen, winternitz_pk[idx].len() = {}, digit = {}", winternitz_pk[idx].len(), digit);
                break;
            }
            let mut dummy = dummy_base;
            dummy[12..20].copy_from_slice(&digit.to_le_bytes());
            mapping.insert(dummy, winternitz_pk[idx][digit]);
        }

        // For each script, scan through the bytes and do a one‐pass replacement.
        for script in disprove_scripts.iter_mut() {
            let mut new_bytes = Vec::with_capacity(script.len());
            let mut pos = 0;
            while pos < script.len() {
                if pos + 20 <= script.len() {
                    if let Ok(candidate_arr) = <[u8; 20]>::try_from(&script[pos..pos + 20]) {
                        if let Some(&replacement) = mapping.get(&candidate_arr) {
                            new_bytes.extend_from_slice(&replacement);
                            pos += 20;
                            continue;
                        }
                    }
                }
                new_bytes.push(script[pos]);
                pos += 1;
            }
            *script = new_bytes
        }
    }
    println!("BitVM script replacement took: {:?}", start.elapsed());
    let mut new_disprove_scripts = Vec::with_capacity(disprove_scripts.len());
    for script in disprove_scripts {
        new_disprove_scripts.push(ScriptBuf::from_bytes(script));
    }
    new_disprove_scripts
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

    let level_filter = match args.verbose {
        0 => None,
        other => Some(LevelFilter::from_level(
            Level::from_str(&other.to_string()).unwrap_or(Level::INFO),
        )),
    };

    match crate::utils::initialize_logger(level_filter) {
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
pub fn initialize_logger(level: Option<LevelFilter>) -> Result<(), BridgeError> {
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
