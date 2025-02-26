use crate::cli::Args;
use crate::config::protocol::ProtocolParamset;
use crate::config::BridgeConfig;
use crate::errors::BridgeError;
use bitcoin::key::Parity;
use bitcoin::{self, Txid};
use bitcoin::{ScriptBuf, XOnlyPublicKey};

use tracing::Level;
//use bitvm::chunker::assigner::BridgeAssigner;
use crate::actor::WinternitzDerivationPath;
#[cfg(not(debug_assertions))]
use bitvm::{
    chunker::{
        assigner::BridgeAssigner, chunk_groth16_verifier::groth16_verify_to_segments,
        disprove_execution::RawProof,
    },
    signatures::{signing_winternitz::WinternitzPublicKey, winternitz},
};
use borsh::{BorshDeserialize, BorshSerialize};
use std::collections::BTreeMap;
use std::collections::HashMap;
#[cfg(not(debug_assertions))]
use std::fs;
use std::process::exit;
use std::str::FromStr;
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
        "93c7378d96518a75448821c4f7c8f4bae7ce60f804d03d1f0628dd5dd0f5de51".parse::<bitcoin::secp256k1::XOnlyPublicKey>().expect("this key is valid").public_key(Parity::Even);
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
lazy_static::lazy_static! {
    pub static ref BITVM_CACHE: BitvmCache = {
        let start = Instant::now();

        #[cfg(debug_assertions)]
        let bitvm_cache = {
            println!("Debug mode: Using dummy BitVM cache");
            // Create minimal dummy data for faster development
            BitvmCache {
                intermediate_variables: {
                    let mut map = BTreeMap::new();
                    map.insert("dummy_var_1".to_string(), 4);
                    map.insert("dummy_var_2".to_string(), 4);
                    map.insert("dummy_var_3".to_string(), 4);
                    map.insert("dummy_var_4".to_string(), 4);
                    map.insert("dummy_var_5".to_string(), 4);
                    map.insert("dummy_var_6".to_string(), 4);
                    map.insert("dummy_var_7".to_string(), 4);
                    map.insert("dummy_var_8".to_string(), 4);
                    map.insert("dummy_var_9".to_string(), 4);
                    map.insert("dummy_var_10".to_string(), 4);
                    map.insert("dummy_var_11".to_string(), 4);
                    map.insert("dummy_var_12".to_string(), 4);
                    map.insert("dummy_var_13".to_string(), 4);
                    map.insert("dummy_var_14".to_string(), 4);
                    map.insert("dummy_var_15".to_string(), 4);
                    map.insert("dummy_var_16".to_string(), 4);
                    map
                },
                disprove_scripts: vec![
                    vec![31u8; 1000], // Dummy script 1
                    vec![31u8; 1000], // Dummy script 2
                ],
                replacement_places: {
                    let mut map = HashMap::new();
                    // Add some dummy replacement places
                    map.insert((0, 0), vec![(0, 0)]);
                    map.insert((0, 1), vec![(1, 0)]);
                    map
                },
            }
        };

        #[cfg(not(debug_assertions))]
        let bitvm_cache = {
            let cache_path = "bitvm_cache.bin";
            match BitvmCache::load_from_file(cache_path) {
                Ok(cache) => {
                    tracing::info!("Loaded BitVM cache from file");
                    cache
                }
                Err(_) => {
                    let fresh_data = generate_fresh_data();
                    if let Err(e) = fresh_data.save_to_file(cache_path) {
                        tracing::error!("Failed to save BitVM cache to file: {}", e);
                    }
                    fresh_data
                }
            }
        };
        println!("BitVM initialization took: {:?}", start.elapsed());
        bitvm_cache
    };

    pub static ref COMBINED_ASSERT_DATA: CombinedAssertData = {
        let mut current_length = 0;
        let mut cur_steps = 0;
        let mut last_steps = 0;
        let mut num_steps = Vec::new();
        for (_, step_size) in BITVM_CACHE.intermediate_variables.iter() {
            // store at most 190 bytes in one assert, to fit in a v3 tx
            if current_length + step_size > 190 {
                num_steps.push((last_steps, last_steps + cur_steps));
                last_steps += cur_steps;
                current_length = 0;
                cur_steps = 0;
            }
            current_length += step_size;
            cur_steps += 1;
        }
        if cur_steps > 0 {
            num_steps.push((last_steps, last_steps + cur_steps));
        }
        CombinedAssertData {
            num_steps
        }
    };
}

#[derive(BorshSerialize, BorshDeserialize, Debug)]
pub struct BitvmCache {
    pub intermediate_variables: BTreeMap<String, usize>,
    pub disprove_scripts: Vec<Vec<u8>>,
    pub replacement_places: HashMap<(usize, usize), Vec<(usize, usize)>>,
}

#[derive(Debug, Clone)]
pub struct CombinedAssertData {
    pub num_steps: Vec<(usize, usize)>,
}

impl CombinedAssertData {
    pub fn get_paths(
        &self,
        assert_idx: usize,
        txid: Txid,
        paramset: &'static ProtocolParamset,
    ) -> Vec<WinternitzDerivationPath> {
        BITVM_CACHE
            .intermediate_variables
            .iter()
            .skip(self.num_steps[assert_idx].0)
            .take(self.num_steps[assert_idx].1)
            .map(|(step_name, step_size)| {
                WinternitzDerivationPath::BitvmAssert(
                    *step_size as u32 * 2,
                    step_name.to_owned(),
                    txid,
                    paramset,
                )
            })
            .collect()
    }

    pub fn get_paths_and_sizes(
        &self,
        assert_idx: usize,
        txid: Txid,
        paramset: &'static ProtocolParamset,
    ) -> Vec<(WinternitzDerivationPath, u32)> {
        BITVM_CACHE
            .intermediate_variables
            .iter()
            .skip(self.num_steps[assert_idx].0)
            .take(self.num_steps[assert_idx].1)
            .map(|(step_name, step_size)| {
                (
                    WinternitzDerivationPath::BitvmAssert(
                        *step_size as u32 * 2,
                        step_name.to_owned(),
                        txid,
                        paramset,
                    ),
                    *step_size as u32 * 2,
                )
            })
            .collect::<Vec<_>>()
    }
}

#[cfg(not(debug_assertions))]
impl BitvmCache {
    fn save_to_file(&self, path: &str) -> Result<(), BridgeError> {
        let serialized = borsh::to_vec(self).map_err(|e| {
            tracing::error!("Failed to serialize BitVM cache: {}", e);
            BridgeError::ConfigError("Failed to serialize BitVM cache".to_string())
        })?;

        fs::write(path, serialized).map_err(|e| {
            tracing::error!("Failed to save BitVM cache: {}", e);
            BridgeError::ConfigError("Failed to save BitVM cache".to_string())
        })
    }

    fn load_from_file(path: &str) -> Result<Self, BridgeError> {
        let bytes = fs::read(path).map_err(|e| {
            tracing::error!("Failed to read BitVM cache: {}", e);
            BridgeError::ConfigError("No BitVM cache found".to_string())
        })?;

        Self::try_from_slice(&bytes).map_err(|e| {
            tracing::error!("Failed to deserialize BitVM cache: {}", e);
            BridgeError::ConfigError("Failed to deserialize BitVM cache".to_string())
        })
    }
}

#[cfg(not(debug_assertions))]
fn generate_fresh_data() -> BitvmCache {
    let intermediate_variables = BridgeAssigner::default().all_intermediate_variables();

    let commits_publickeys = intermediate_variables
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
            (intermediate_step.clone(), winternitz_pk)
        })
        .collect::<BTreeMap<_, _>>();

    let mut bridge_assigner = BridgeAssigner::new_watcher(commits_publickeys);
    let proof = RawProof::default();
    let segments =
        groth16_verify_to_segments(&mut bridge_assigner, &proof.public, &proof.proof, &proof.vk);

    let scripts: Vec<Vec<u8>> = segments
        .iter()
        .map(|s| s.script.clone().compile().to_bytes())
        .collect();

    // Build mapping of dummy keys to their positions
    let mut replacement_places: HashMap<(usize, usize), Vec<(usize, usize)>> = HashMap::new();

    // For each script
    for (script_idx, script) in scripts.iter().enumerate() {
        let mut pos = 0;
        while pos + 20 <= script.len() {
            // Check if this window matches our pattern (31u8 in middle bytes)
            if &script[pos + 8..pos + 12] == &[31u8; 4] {
                // Try to extract the index and digit from the window
                let window = &script[pos..pos + 20];
                if let Ok(window_arr) = <[u8; 20]>::try_from(window) {
                    // Extract idx from first 8 bytes
                    let mut idx_bytes = [0u8; 8];
                    idx_bytes.copy_from_slice(&window_arr[..8]);
                    let idx = usize::from_le_bytes(idx_bytes);

                    // Extract digit from last 8 bytes
                    let mut digit_bytes = [0u8; 8];
                    digit_bytes.copy_from_slice(&window_arr[12..20]);
                    let digit = usize::from_le_bytes(digit_bytes);

                    // If this is a valid index for our intermediate variables
                    if idx < intermediate_variables.len() {
                        let entry = replacement_places.entry((idx, digit)).or_default();
                        entry.push((script_idx, pos));
                    }
                }
            }
            pos += 1;
        }
    }

    BitvmCache {
        intermediate_variables,
        disprove_scripts: scripts,
        replacement_places,
    }
}

pub fn replace_disprove_scripts(winternitz_pk: &[Vec<[u8; 20]>]) -> Vec<ScriptBuf> {
    let start = Instant::now();
    tracing::info!(
        "Starting script replacement with {} keys",
        winternitz_pk.len()
    );

    let cache = &*BITVM_CACHE;
    let mut result: Vec<Vec<u8>> = cache.disprove_scripts.clone();

    winternitz_pk.iter().enumerate().for_each(|(idx, digits)| {
        digits.iter().enumerate().for_each(|(digit, replacement)| {
            if let Some(places) = cache.replacement_places.get(&(idx, digit)) {
                for &(script_idx, pos) in places {
                    result[script_idx][pos..pos + 20].copy_from_slice(replacement);
                }
            }
        });
    });

    let result: Vec<ScriptBuf> = result.into_iter().map(ScriptBuf::from_bytes).collect();

    let elapsed = start.elapsed();
    tracing::info!("Script replacement completed in {:?}", elapsed);

    result
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
    // Configure JSON formatting with additional fields
    let json_layer = fmt::layer::<Registry>()
        .with_test_writer()
        // .with_timer(time::UtcTime::rfc_3339())
        .with_file(true)
        .with_line_number(true)
        .with_thread_ids(true)
        .with_thread_names(true)
        .with_target(true)
        // .with_current_span(true)
        // .with_span_list(true)
        .json();

    // Standard human-readable layer for non-JSON output
    let standard_layer = fmt::layer()
        .with_test_writer()
        // .with_timer(time::UtcTime::rfc_3339())
        .with_target(true)
        .with_thread_ids(true);

    let filter = match level {
        Some(level) => EnvFilter::builder()
            .with_default_directive(level.into())
            .from_env_lossy(),
        None => EnvFilter::from_default_env(),
    };

    // Try to initialize tracing, depending on the `JSON_LOGS` env var
    let res = if std::env::var("JSON_LOGS").is_ok() {
        tracing_subscriber::util::SubscriberInitExt::try_init(
            tracing_subscriber::registry().with(json_layer).with(filter),
        )
    } else {
        tracing_subscriber::util::SubscriberInitExt::try_init(
            tracing_subscriber::registry()
                .with(standard_layer)
                .with(filter),
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

/// Monitors a JoinHandle and aborts the process if the task completes with an error.
/// Returns a handle to the monitoring task that can be used to cancel it.
pub fn monitor_task_with_abort<T: Send + 'static>(
    task_handle: tokio::task::JoinHandle<Result<T, crate::errors::BridgeError>>,
    task_name: &str,
) -> tokio::task::JoinHandle<()> {
    let task_name = task_name.to_string();

    // Move task_handle into the spawned task to make it Send
    tokio::spawn(async move {
        match task_handle.await {
            Ok(Ok(_)) => {
                // Task completed successfully
                tracing::debug!("Task {} completed successfully", task_name);
            }
            Ok(Err(e)) => {
                // Task returned an error
                tracing::error!("Task {} failed with error: {:?}", task_name, e);
                std::process::abort();
            }
            Err(e) => {
                if e.is_cancelled() {
                    // Task was cancelled, which is expected during cleanup
                    tracing::debug!("Task {} was cancelled", task_name);
                    return;
                }
                // Task panicked or was aborted
                tracing::error!("Task {} panicked: {:?}", task_name, e);
                std::process::abort();
            }
        }
    })
}
