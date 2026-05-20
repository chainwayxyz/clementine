//! # Testing Utilities

use crate::citrea::CitreaClientT;
use crate::constants::NON_STANDARD_V3;
use crate::protocol::ids::TransactionType;
use crate::protocol::tx::payout::{PayoutInput, PayoutOutput};
use crate::utils::initialize_logger;
use crate::utils::NamedEntity;
use crate::{
    actor::Actor, builder, config::BridgeConfig, database::Database,
    extended_bitcoin_rpc::ExtendedBitcoinRpc, musig2::AggregateFromPublicKeys,
};
use bitcoin::{sighash, taproot};
use citrea_e2e::bitcoin::DEFAULT_FINALITY_DEPTH;
use clementine_errors::BridgeError;
use clementine_primitives::{EVMAddress, UTXO};
use secrecy::ExposeSecret;
use std::net::TcpListener;

use super::test_actors::TestActors;

pub struct WithProcessCleanup(
    /// Handle to the bitcoind process
    pub Option<std::process::Child>,
    /// RPC client
    pub ExtendedBitcoinRpc,
    /// Path to the bitcoind debug log file
    pub std::path::PathBuf,
    /// Whether to wait indefinitely after test finishes before cleanup (for RPC debugging)
    pub bool,
);
impl WithProcessCleanup {
    pub fn rpc(&self) -> &ExtendedBitcoinRpc {
        &self.1
    }
}

impl Drop for WithProcessCleanup {
    fn drop(&mut self) {
        tracing::info!(
            "Test bitcoin regtest logs can be found at: {}",
            self.2.display()
        );

        if self.3 {
            tracing::warn!(
                "Suspending the test to allow inspection of bitcoind. Ctrl-C to exit. {}",
                self.2.display()
            );
            std::thread::sleep(std::time::Duration::from_secs(u64::MAX));
        }
        if let Some(ref mut child) = self.0.take() {
            let _ = child.kill();
        }
    }
}

/// Creates a Bitcoin regtest node for testing, waits for it to start and returns an RPC client.
///
/// # Environment Variables
/// - `BITCOIN_RPC_DEBUG`: If set to a non-empty value, will use port 18443 and connect to an existing
///   bitcoind instance when available.
///
/// # Returns
/// Returns a `WithProcessCleanup` which contains:
/// - The bitcoind process handle (if a new instance was started)
/// - An RPC client connected to the node
/// - Path to the debug log file
/// - A flag indicating whether to pause before cleanup
///
/// # Important
/// The returned value MUST NOT be dropped until the test is complete, as dropping it will terminate
/// the bitcoind process and invalidate the RPC connection. The cleanup is handled automatically when
/// the returned value is dropped.
pub async fn create_regtest_rpc(config: &mut BridgeConfig) -> WithProcessCleanup {
    let bitcoin_rpc_debug = std::env::var("BITCOIN_RPC_DEBUG").map(|d| !d.is_empty()) == Ok(true);
    let max_attempts = 5;
    let mut last_error = String::new();

    for attempt in 1..=max_attempts {
        match try_create_regtest_rpc(config, bitcoin_rpc_debug).await {
            Ok(regtest) => return regtest,
            Err(error) => {
                last_error = error;
                if attempt < max_attempts {
                    tracing::warn!(
                        attempt,
                        max_attempts,
                        error = %last_error,
                        "Failed to create Bitcoin regtest RPC; retrying with a fresh datadir and port"
                    );
                    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                }
            }
        }
    }

    panic!("Failed to create Bitcoin regtest RPC after {max_attempts} attempts: {last_error}");
}

async fn try_create_regtest_rpc(
    config: &mut BridgeConfig,
    bitcoin_rpc_debug: bool,
) -> Result<WithProcessCleanup, String> {
    use bitcoincore_rpc::RpcApi;
    use tempfile::TempDir;

    // Create temporary directory for bitcoin data
    let data_dir = TempDir::new()
        .map_err(|e| format!("Failed to create temporary directory: {e}"))?
        .keep();

    // Use per-attempt credentials in normal tests so an RPC port collision cannot
    // authenticate against another test's bitcoind.
    if !bitcoin_rpc_debug {
        let nonce = data_dir
            .file_name()
            .and_then(|name| name.to_str())
            .map(|name| {
                name.chars()
                    .filter(|ch| ch.is_ascii_alphanumeric())
                    .collect::<String>()
            })
            .filter(|name| !name.is_empty())
            .unwrap_or_else(|| std::process::id().to_string());
        config.bitcoin_rpc_user = format!("admin{nonce}").into();
        config.bitcoin_rpc_password = format!("admin{nonce}").into();
    }

    // Get available ports for RPC
    let rpc_port = if bitcoin_rpc_debug {
        18443
    } else {
        get_available_port()
    };

    config.bitcoin_rpc_url = format!("http://127.0.0.1:{rpc_port}");

    if bitcoin_rpc_debug && TcpListener::bind(format!("127.0.0.1:{rpc_port}")).is_err() {
        // Bitcoind is already running on port 18443, use existing port.
        return Ok(WithProcessCleanup(
            None,
            ExtendedBitcoinRpc::connect(
                "http://127.0.0.1:18443".into(),
                config.bitcoin_rpc_user.clone(),
                config.bitcoin_rpc_password.clone(),
                None,
            )
            .await
            .map_err(|e| format!("Failed to connect to existing debug bitcoind: {e:?}"))?,
            data_dir.join("debug.log"),
            false, // no need to wait after test
        ));
    }
    // Bitcoin node configuration
    // Construct args for bitcoind
    let mut args = vec![
        "-regtest".to_string(),
        format!("-datadir={}", data_dir.display()),
        "-listen=0".to_string(),
        format!("-rpcport={}", rpc_port),
        format!("-rpcuser={}", config.bitcoin_rpc_user.expose_secret()),
        format!(
            "-rpcpassword={}",
            config.bitcoin_rpc_password.expose_secret()
        ),
        "-wallet=admin".to_string(),
        "-txindex=1".to_string(),
        "-fallbackfee=0.00001".to_string(),
        "-rpcallowip=0.0.0.0/0".to_string(),
        "-maxtxfee=5".to_string(),
    ];

    if config.protocol_paramset().bridge_nonstandard {
        // allow 0 sat non-ephemeral outputs in regtest by not considering them as dust
        // https://github.com/bitcoin/bitcoin/blob/master/src/policy/policy.cpp
        args.push("-dustrelayfee=0".to_string());
    }

    if config.test_params.mine_0_fee_txs {
        // allow mining of 0-fee transactions
        args.push("-minrelaytxfee=0".to_string());
        args.push("-acceptnonstdtxn=1".to_string());
        args.push("-blockmintxfee=0".to_string());
    }

    // Create log file in temp directory
    let log_file = data_dir.join("debug.log");
    let log_file_path = log_file
        .to_str()
        .expect("Failed to convert log file path to string");

    // Start bitcoind process with log redirection
    let process = std::process::Command::new("bitcoind")
        .args(&args)
        .arg(format!("-debuglogfile={log_file_path}"))
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .map_err(|e| format!("Failed to start bitcoind: {e}"))?;

    struct AttemptCleanup {
        child: Option<std::process::Child>,
        data_dir: Option<std::path::PathBuf>,
    }

    impl Drop for AttemptCleanup {
        fn drop(&mut self) {
            if let Some(mut child) = self.child.take() {
                let _ = child.kill();
                let _ = child.wait();
            }
            if let Some(data_dir) = self.data_dir.take() {
                let _ = std::fs::remove_dir_all(data_dir);
            }
        }
    }

    let mut attempt_cleanup = AttemptCleanup {
        child: Some(process),
        data_dir: Some(data_dir.clone()),
    };

    if bitcoin_rpc_debug {
        tracing::warn!("Bitcoind logs are available at {}", log_file_path);
    }

    // Create RPC client
    let rpc_url = format!("http://127.0.0.1:{rpc_port}");

    // Wait for node to be ready
    let mut attempts = 0;
    let retry_count = 30;
    let client = loop {
        match ExtendedBitcoinRpc::connect(
            rpc_url.clone(),
            config.bitcoin_rpc_user.clone(),
            config.bitcoin_rpc_password.clone(),
            None,
        )
        .await
        {
            Ok(client) => break client,
            Err(_) => {
                if let Some(child) = attempt_cleanup.child.as_mut() {
                    match child.try_wait() {
                        Ok(Some(status)) => {
                            return Err(format!(
                                "Bitcoin node exited before RPC became ready: {status}"
                            ));
                        }
                        Ok(None) => {}
                        Err(e) => {
                            return Err(format!("Failed to check bitcoind process status: {e}"));
                        }
                    }
                }
                attempts += 1;
                if attempts >= retry_count {
                    return Err(format!(
                        "Bitcoin node failed to start in {retry_count} seconds"
                    ));
                }
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            }
        }
    };

    // Get and print bitcoind version
    let network_info = client
        .get_network_info()
        .await
        .map_err(|e| format!("Failed to get network info: {e:?}"))?;
    tracing::info!("Using bitcoind version: {}", network_info.version);

    // // Create wallet
    client
        .create_wallet("admin", None, None, None, None)
        .await
        .map_err(|e| format!("Failed to create wallet: {e:?}"))?;

    // Generate blocks
    let address = client
        .get_new_address(None, None)
        .await
        .map_err(|e| format!("Failed to get new address: {e:?}"))?;

    if config.test_params.generate_to_address {
        client
            .generate_to_address(201, address.assume_checked_ref())
            .await
            .map_err(|e| format!("Failed to generate blocks: {e:?}"))?;
    }

    let process = attempt_cleanup.child.take();
    attempt_cleanup.data_dir.take();

    Ok(WithProcessCleanup(
        process,
        client.clone(),
        log_file,
        bitcoin_rpc_debug,
    ))
}

/// Creates a temporary database for testing, using current thread's name as the
/// database name.
///
/// # Parameters
///
/// - `suffix`: Optional suffix added to the thread handle in `Option<str>`
///   type.
///
/// # Returns
///
/// - [`BridgeConfig`]: Modified configuration struct
pub async fn create_test_config_with_thread_name() -> BridgeConfig {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let handle = std::thread::current()
        .name()
        .expect("Failed to get thread name")
        .split(':')
        .next_back()
        .expect("Failed to get thread name")
        .to_owned();

    // Use maximum log level for tests.
    initialize_logger(Some(::tracing::level_filters::LevelFilter::DEBUG))
        .expect("Failed to initialize logger");

    let mut config = BridgeConfig {
        db_name: handle.to_string(),
        citrea_rpc_url: handle.to_string(),
        ..Default::default()
    };

    let mut new_paramset = config.protocol_paramset().clone();
    new_paramset.finality_depth = DEFAULT_FINALITY_DEPTH as u32;
    config.protocol_paramset = Box::leak(Box::new(new_paramset));

    initialize_database(&config).await;

    config
}

/// Initializes a new database with given configuration. If the database is
/// already initialized, it will be dropped before initialization. Meaning,
/// a clean state is guaranteed.
///
/// [`Database::new`] must be called after this to connect to the
/// initialized database.
///
/// # Parameters
///
/// - `config`: Configuration options in `BridgeConfig` type.
pub async fn initialize_database(config: &BridgeConfig) {
    // use a temporary config to connect to postgres maintenance db to drop and create the database
    let mut temp_config = config.clone();
    temp_config.db_name = "postgres".to_string();
    let db = Database::new(&temp_config).await.unwrap();
    let conn = db.get_pool();

    sqlx::query(&format!("DROP DATABASE IF EXISTS {}", &config.db_name))
        .execute(&conn)
        .await
        .expect("Failed to drop database");

    sqlx::query(&format!(
        "CREATE DATABASE {} WITH OWNER {}",
        config.db_name,
        config.db_user.expose_secret()
    ))
    .execute(&conn)
    .await
    .expect("Failed to create database");

    conn.close().await;

    Database::run_schema_script(config, true)
        .await
        .expect("Failed to run schema script");
}

/// Starts operators, verifiers, aggregator and watchtower servers.
///
/// Uses Unix sockets with temporary files for communication between services.
///
/// # Returns
///
/// Returns a tuple of vectors of clients, handles, and socket paths for the
/// verifiers, operators, aggregator and watchtowers, along with shutdown channels.
pub async fn create_actors<C: CitreaClientT>(config: &BridgeConfig) -> TestActors<C> {
    TestActors::new(config)
        .await
        .expect("Failed to create actors")
}

/// Gets the the deposit address for the user.
///
/// # Returns
///
/// - [`Address`]: Deposit address of the user
pub fn get_deposit_address(
    config: &BridgeConfig,
    evm_address: EVMAddress,
    verifiers_public_keys: Vec<bitcoin::secp256k1::PublicKey>,
) -> Result<(bitcoin::Address, bitcoin::taproot::TaprootSpendInfo), BridgeError> {
    let signer = Actor::new(config.secret_key, config.protocol_paramset().network);

    let nofn_xonly_pk = bitcoin::XOnlyPublicKey::from_musig2_pks(verifiers_public_keys, None)
        .expect("Failed to create xonly pk");

    crate::deposit::DepositSpendTree::from_base_deposit(
        nofn_xonly_pk,
        signer.address.as_unchecked(),
        evm_address,
        config.protocol_paramset().user_takes_after,
    )
    .and_then(|tree| tree.taproot_address(config.protocol_paramset().network))
}

/// Generates withdrawal transaction and signs it with `SinglePlusAnyoneCanPay`.
///
/// # Returns
///
/// A tuple of:
///
/// - [`UTXO`]: Dust UTXO used as the input of the withdrawal transaction
/// - [`TxOut`]: Txout of the withdrawal transaction
/// - [`Signature`]: Signature of the withdrawal transaction
pub async fn generate_withdrawal_transaction_and_signature(
    config: &BridgeConfig,
    rpc: &ExtendedBitcoinRpc,
    withdrawal_address: &bitcoin::Address,
    withdrawal_amount: bitcoin::Amount,
) -> (UTXO, bitcoin::TxOut, taproot::Signature) {
    let dust_utxo = generate_withdrawal_utxo(config, rpc).await;
    let (txout, sig) =
        sign_withdrawal_output(config, &dust_utxo, withdrawal_address, withdrawal_amount);
    (dust_utxo, txout, sig)
}

/// Optimistic payout registration must use the contract-accepted fee amount,
/// while operator payouts use the configured operator fee.
pub async fn generate_withdrawal_transaction_and_signatures(
    config: &BridgeConfig,
    rpc: &ExtendedBitcoinRpc,
    withdrawal_address: &bitcoin::Address,
    operator_amount: bitcoin::Amount,
    optimistic_amount: bitcoin::Amount,
) -> (
    UTXO,
    bitcoin::TxOut,
    taproot::Signature,
    bitcoin::TxOut,
    taproot::Signature,
) {
    let dust_utxo = generate_withdrawal_utxo(config, rpc).await;
    let (operator_txout, operator_sig) =
        sign_withdrawal_output(config, &dust_utxo, withdrawal_address, operator_amount);
    let (optimistic_txout, optimistic_sig) =
        sign_withdrawal_output(config, &dust_utxo, withdrawal_address, optimistic_amount);
    (
        dust_utxo,
        operator_txout,
        operator_sig,
        optimistic_txout,
        optimistic_sig,
    )
}

async fn generate_withdrawal_utxo(config: &BridgeConfig, rpc: &ExtendedBitcoinRpc) -> UTXO {
    let signer = Actor::new(config.secret_key, config.protocol_paramset().network);

    const WITHDRAWAL_EMPTY_UTXO_SATS: bitcoin::Amount = bitcoin::Amount::from_sat(550);

    let dust_outpoint = rpc
        .send_to_address(&signer.address, WITHDRAWAL_EMPTY_UTXO_SATS)
        .await
        .expect("Failed to send to address");

    UTXO {
        outpoint: dust_outpoint,
        txout: bitcoin::TxOut {
            value: WITHDRAWAL_EMPTY_UTXO_SATS,
            script_pubkey: signer.address.script_pubkey(),
        },
    }
}

fn sign_withdrawal_output(
    config: &BridgeConfig,
    dust_utxo: &UTXO,
    withdrawal_address: &bitcoin::Address,
    withdrawal_amount: bitcoin::Amount,
) -> (bitcoin::TxOut, taproot::Signature) {
    let signer = Actor::new(config.secret_key, config.protocol_paramset().network);
    let txin = builder::transaction::SpendableTxIn::new(
        dust_utxo.outpoint,
        dust_utxo.txout.clone(),
        vec![],
        vec![],
        None,
    );
    let txout = bitcoin::TxOut {
        value: withdrawal_amount,
        script_pubkey: withdrawal_address.script_pubkey(),
    };
    let unspent_txout = builder::transaction::UnspentTxOut::from_partial(txout.clone());

    let tx = builder::transaction::TxHandlerBuilder::new(TransactionType::Payout)
        .with_version(NON_STANDARD_V3)
        .add_input(
            PayoutInput::WithdrawalUtxo,
            txin,
            builder::transaction::DEFAULT_SEQUENCE,
            builder::transaction::input_descriptor(
                crate::protocol::spec::SpendSpec::key_spend()
                    .with_metadata(None, Some(sighash::TapSighashType::SinglePlusAnyoneCanPay)),
            ),
        )
        .add_output(PayoutOutput::User, unspent_txout.clone())
        .finalize();

    let sighash = tx
        .tap_sighash_for_input(PayoutInput::WithdrawalUtxo)
        .expect("Failed to calculate sighash");

    let sig = signer
        .sign_with_tweak_data(sighash, builder::sighash::TapTweakData::KeyPath(None), None)
        .expect("Failed to sign");

    let sig = taproot::Signature {
        signature: sig,
        sighash_type: sighash::TapSighashType::SinglePlusAnyoneCanPay,
    };

    (txout, sig)
}

/// Helper to get a dynamically assigned free port.
pub fn get_available_port() -> u16 {
    use std::net::TcpListener;
    TcpListener::bind("127.0.0.1:0")
        .expect("Could not bind to an available port")
        .local_addr()
        .expect("Could not get local address")
        .port()
}

// Mock implementation of the Owner trait for testing
#[derive(Debug, Clone, Default)]
pub struct MockOwner {
    #[cfg(feature = "automation")]
    cached_duties: std::sync::Arc<tokio::sync::Mutex<Vec<crate::states::Duty>>>,
}

#[allow(unused_variables)]
impl PartialEq for MockOwner {
    fn eq(&self, other: &Self) -> bool {
        true // all mock owners are equal
    }
}

impl NamedEntity for MockOwner {
    const ENTITY_NAME: &'static str = "test_owner";
    const LCP_SYNCER_CONSUMER_ID: &'static str = "test_lcp_syncer";
    const FINALIZED_BLOCK_CONSUMER_ID_AUTOMATION: &'static str = "test_finalized_block_automation";
}

#[cfg(feature = "automation")]
mod states {
    use super::MockOwner;
    use crate::database::Database;
    use crate::database::DatabaseTransaction;
    use crate::states::context::DutyResult;
    use crate::states::{Duty, Owner};
    use clementine_errors::BridgeError;
    use tonic::async_trait;

    // Implement the Owner trait for MockOwner
    #[async_trait]
    impl Owner for MockOwner {
        async fn handle_duty(
            &self,
            _dbtx: DatabaseTransaction<'_>,
            duty: Duty,
        ) -> Result<DutyResult, BridgeError> {
            self.cached_duties.lock().await.push(duty);
            Ok(DutyResult::Handled)
        }

        fn database(&self) -> Database {
            unreachable!("mock owner should not request a database in setup_utils tests")
        }
    }
}
