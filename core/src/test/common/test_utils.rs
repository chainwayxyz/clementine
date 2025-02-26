//! # Testing Utilities
//!
//! This crate provides testing utilities, which are not possible to be included
//! in binaries.
use std::net::TcpListener;
use std::str::FromStr;

use bitcoin::consensus::serde::With;
use bitcoin::secp256k1::schnorr;
use tokio::sync::oneshot;
use tonic::transport::Channel;

use crate::builder::script::SpendPath;
use crate::builder::transaction::output::UnspentTxOut;
use crate::builder::transaction::TransactionType;
use crate::rpc::clementine::clementine_aggregator_client::ClementineAggregatorClient;
use crate::rpc::clementine::clementine_operator_client::ClementineOperatorClient;
use crate::rpc::clementine::clementine_verifier_client::ClementineVerifierClient;
use crate::rpc::clementine::clementine_watchtower_client::ClementineWatchtowerClient;
use crate::rpc::clementine::NormalSignatureKind;
use crate::rpc::get_clients;
use crate::servers::{
    create_aggregator_unix_server, create_operator_unix_server, create_verifier_unix_server,
    create_watchtower_unix_server,
};
use crate::utils::initialize_logger;
use crate::verifier::Verifier;
use crate::{
    actor::Actor,
    builder,
    config::BridgeConfig,
    database::Database,
    errors::BridgeError,
    extended_rpc::ExtendedRpc,
    musig2::AggregateFromPublicKeys,
    servers::{
        create_aggregator_grpc_server, create_operator_grpc_server, create_verifier_grpc_server,
        create_watchtower_grpc_server,
    },
};
use crate::{EVMAddress, UTXO};

pub struct WithProcessCleanup(
    /// Handle to the bitcoind process
    pub Option<std::process::Child>,
    /// RPC client
    pub ExtendedRpc,
    /// Path to the bitcoind debug log file
    pub std::path::PathBuf,
    /// Whether to wait indefinitely after test finishes before cleanup (for RPC debugging)
    pub bool,
);
impl WithProcessCleanup {
    pub fn rpc(&self) -> &ExtendedRpc {
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
    use bitcoincore_rpc::RpcApi;
    use tempfile::TempDir;

    // Create temporary directory for bitcoin data
    let data_dir = TempDir::new()
        .expect("Failed to create temporary directory")
        .into_path();
    let bitcoin_rpc_debug = std::env::var("BITCOIN_RPC_DEBUG").map(|d| !d.is_empty()) == Ok(true);

    // Get available ports for RPC
    let rpc_port = if bitcoin_rpc_debug {
        18443
    } else {
        get_available_port()
    };

    config.bitcoin_rpc_url = format!("http://127.0.0.1:{}/wallet/admin", rpc_port);

    if bitcoin_rpc_debug && TcpListener::bind(format!("127.0.0.1:{}", rpc_port)).is_err() {
        // Bitcoind is already running on port 18443, use existing port.
        return WithProcessCleanup(
            None,
            ExtendedRpc::connect(
                "http://127.0.0.1:18443".into(),
                config.bitcoin_rpc_user.clone(),
                config.bitcoin_rpc_password.clone(),
            )
            .await
            .unwrap(),
            data_dir.join("debug.log"),
            false, // no need to wait after test
        );
    }
    // Bitcoin node configuration
    // Construct args for bitcoind
    let args = vec![
        "-regtest".to_string(),
        format!("-datadir={}", data_dir.display()),
        "-listen=0".to_string(),
        format!("-rpcport={}", rpc_port),
        format!("-rpcuser={}", config.bitcoin_rpc_user),
        format!("-rpcpassword={}", config.bitcoin_rpc_password),
        "-wallet=admin".to_string(),
        "-txindex=1".to_string(),
        "-fallbackfee=0.00001".to_string(),
        "-rpcallowip=0.0.0.0/0".to_string(),
    ];

    // Create log file in temp directory
    let log_file = data_dir.join("debug.log");
    let log_file_path = log_file
        .to_str()
        .expect("Failed to convert log file path to string");

    // Start bitcoind process with log redirection
    let process = std::process::Command::new("bitcoind")
        .args(&args)
        .arg(format!("-debuglogfile={}", log_file_path))
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("Failed to start bitcoind");

    if bitcoin_rpc_debug {
        tracing::warn!("Bitcoind logs are available at {}", log_file_path);
    }

    // Create RPC client
    let rpc_url = format!("http://127.0.0.1:{}", rpc_port);

    let client = ExtendedRpc::connect(
        rpc_url,
        config.bitcoin_rpc_user.clone(),
        config.bitcoin_rpc_password.clone(),
    )
    .await
    .expect("Failed to create RPC client");

    // Wait for node to be ready
    let mut attempts = 0;
    let retry_count = 30;
    while attempts < retry_count {
        if client.client.get_blockchain_info().await.is_ok() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        attempts += 1;
    }
    if attempts == retry_count {
        panic!("Bitcoin node failed to start in {} seconds", retry_count);
    }

    // Get and print bitcoind version
    let network_info = client
        .client
        .get_network_info()
        .await
        .expect("Failed to get network info");
    tracing::info!("Using bitcoind version: {}", network_info.version);

    // // Create wallet
    client
        .client
        .create_wallet("admin", None, None, None, None)
        .await
        .expect("Failed to create wallet");

    // Generate blocks
    let address = client
        .client
        .get_new_address(None, None)
        .await
        .expect("Failed to get new address");
    client
        .client
        .generate_to_address(101, address.assume_checked_ref())
        .await
        .expect("Failed to generate blocks");

    WithProcessCleanup(Some(process), client.clone(), log_file, bitcoin_rpc_debug)
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
pub async fn create_test_config_with_thread_name(suffix: Option<&str>) -> BridgeConfig {
    let suffix = suffix.unwrap_or_default().to_string();

    let handle = std::thread::current()
        .name()
        .expect("Failed to get thread name")
        .split(':')
        .last()
        .expect("Failed to get thread name")
        .to_owned()
        + &suffix;

    // Use maximum log level for tests.
    initialize_logger(Some(::tracing::level_filters::LevelFilter::DEBUG))
        .expect("Failed to initialize logger");

    let mut config = BridgeConfig::default();

    // Check environment for an overwrite config. TODO: Convert this to env vars.
    let env_config: Option<BridgeConfig> =
        if let Ok(config_file_path) = std::env::var("TEST_CONFIG") {
            Some(
                BridgeConfig::try_parse_file(config_file_path.into())
                    .expect("Failed to parse config file"),
            )
        } else {
            None
        };

    config.db_name = handle.to_string();

    // Overwrite user's environment to test's hard coded data if environment
    // file is specified.
    if let Some(env_config) = env_config {
        config.db_host = env_config.db_host;
        config.db_port = env_config.db_port;
        config.db_user = env_config.db_user;
        config.db_password = env_config.db_password;
        config.db_name = env_config.db_name;
    };

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
    let url = Database::get_postgresql_url(config);
    let conn = sqlx::PgPool::connect(url.as_str()).await.unwrap_or_else(|_| panic!("Failed to connect to database, please make sure a test Postgres DB is running at {}",
        url));

    sqlx::query(&format!("DROP DATABASE IF EXISTS {}", &config.db_name))
        .execute(&conn)
        .await
        .expect("Failed to drop database");

    sqlx::query(&format!(
        "CREATE DATABASE {} WITH OWNER {}",
        config.db_name, config.db_user
    ))
    .execute(&conn)
    .await
    .expect("Failed to create database");

    conn.close().await;

    Database::run_schema_script(config)
        .await
        .expect("Failed to run schema script");
}

pub struct ActorsCleanup(
    Vec<oneshot::Sender<()>>,
    tempfile::TempDir,
    WithProcessCleanup,
);

impl ActorsCleanup {
    pub fn rpc(&self) -> &ExtendedRpc {
        self.2.rpc()
    }
}

/// Starts operators, verifiers, aggregator and watchtower servers.
///
/// Uses Unix sockets with temporary files for communication between services.
///
/// # Returns
///
/// Returns a tuple of vectors of clients, handles, and socket paths for the
/// verifiers, operators, aggregator and watchtowers, along with shutdown channels.
pub async fn create_actors(
    config: &BridgeConfig,
) -> (
    Vec<ClementineVerifierClient<Channel>>,
    Vec<ClementineOperatorClient<Channel>>,
    ClementineAggregatorClient<Channel>,
    Vec<ClementineWatchtowerClient<Channel>>,
) {
    let all_verifiers_secret_keys = config.all_verifiers_secret_keys.clone().unwrap_or_else(|| {
        panic!("All secret keys of the verifiers are required for testing");
    });
    let all_watchtowers_secret_keys =
        config
            .all_watchtowers_secret_keys
            .clone()
            .unwrap_or_else(|| {
                panic!("All secret keys of the watchtowers are required for testing");
            });

    // Collect all shutdown channels
    let mut shutdown_channels = Vec::new();

    // Create temporary directory for Unix sockets
    let socket_dir = tempfile::tempdir().expect("Failed to create temporary directory for sockets");

    let verifier_futures = all_verifiers_secret_keys
        .iter()
        .enumerate()
        .map(|(i, sk)| {
            let socket_path = socket_dir.path().join(format!("verifier_{}.sock", i));
            let i = i.to_string();
            let mut config_with_new_db = config.clone();
            async move {
                config_with_new_db.db_name += &i;
                initialize_database(&config_with_new_db).await;

                let (socket_path, shutdown_tx) = create_verifier_unix_server(
                    BridgeConfig {
                        secret_key: *sk,
                        ..config_with_new_db.clone()
                    },
                    socket_path,
                )
                .await?;

                Ok::<((std::path::PathBuf, oneshot::Sender<()>), BridgeConfig), BridgeError>((
                    (socket_path, shutdown_tx),
                    config_with_new_db,
                ))
            }
        })
        .collect::<Vec<_>>();

    let verifier_results = futures::future::try_join_all(verifier_futures)
        .await
        .expect("Failed to join verifier futures");

    let (verifier_tmp, verifier_configs) =
        verifier_results.into_iter().unzip::<_, _, Vec<_>, Vec<_>>();
    let (verifier_paths, verifier_shutdown_channels) =
        verifier_tmp.into_iter().unzip::<_, _, Vec<_>, Vec<_>>();

    shutdown_channels.extend(verifier_shutdown_channels);

    let all_operators_secret_keys = config.all_operators_secret_keys.clone().unwrap_or_else(|| {
        panic!("All secret keys of the operators are required for testing");
    });

    // Create futures for operator Unix socket servers
    let operator_futures = all_operators_secret_keys
        .iter()
        .enumerate()
        .map(|(i, sk)| {
            let socket_path = socket_dir.path().join(format!("operator_{}.sock", i));
            let verifier_config = verifier_configs[i].clone();
            async move {
                let (socket_path, shutdown_tx) = create_operator_unix_server(
                    BridgeConfig {
                        secret_key: *sk,
                        ..verifier_config
                    },
                    socket_path,
                )
                .await?;

                Ok::<(std::path::PathBuf, oneshot::Sender<()>), BridgeError>((
                    socket_path,
                    shutdown_tx,
                ))
            }
        })
        .collect::<Vec<_>>();

    let operator_results = futures::future::try_join_all(operator_futures)
        .await
        .expect("Failed to join operator futures");

    let (operator_paths, operator_shutdown_channels) =
        operator_results.into_iter().unzip::<_, _, Vec<_>, Vec<_>>();

    shutdown_channels.extend(operator_shutdown_channels);

    let verifier_configs = verifier_configs.clone();

    let watchtower_futures = all_watchtowers_secret_keys
        .iter()
        .enumerate()
        .map(|(i, sk)| {
            let socket_path = socket_dir.path().join(format!("watchtower_{}.sock", i));
            create_watchtower_unix_server(
                BridgeConfig {
                    index: i as u32,
                    secret_key: *sk,
                    ..verifier_configs[i].clone()
                },
                socket_path,
            )
        })
        .collect::<Vec<_>>();

    let watchtower_results = futures::future::try_join_all(watchtower_futures)
        .await
        .expect("Failed to join watchtower futures");

    let (watchtower_paths, watchtower_shutdown_channels) = watchtower_results
        .into_iter()
        .unzip::<_, _, Vec<_>, Vec<_>>();

    shutdown_channels.extend(watchtower_shutdown_channels);

    let aggregator_socket_path = socket_dir.path().join("aggregator.sock");

    let (aggregator_path, aggregator_shutdown_tx) = create_aggregator_unix_server(
        BridgeConfig {
            verifier_endpoints: Some(
                verifier_paths
                    .iter()
                    .map(|path| format!("unix://{}", path.display()))
                    .collect(),
            ),
            operator_endpoints: Some(
                operator_paths
                    .iter()
                    .map(|path| format!("unix://{}", path.display()))
                    .collect(),
            ),
            watchtower_endpoints: Some(
                watchtower_paths
                    .iter()
                    .map(|path| format!("unix://{}", path.display()))
                    .collect(),
            ),
            ..verifier_configs[0].clone()
        },
        aggregator_socket_path,
    )
    .await
    .expect("Failed to create aggregator");

    // Add aggregator shutdown channel
    shutdown_channels.push(aggregator_shutdown_tx);

    (verifiers, operators, aggregator, watchtowers)
}

/// Gets the the deposit address for the user.
///
/// # Returns
///
/// - [`Address`]: Deposit address of the user
pub fn get_deposit_address(
    config: &BridgeConfig,
    evm_address: EVMAddress,
) -> Result<(bitcoin::Address, bitcoin::taproot::TaprootSpendInfo), BridgeError> {
    let signer = Actor::new(
        config.secret_key,
        config.winternitz_secret_key,
        config.protocol_paramset().network,
    );

    let nofn_xonly_pk =
        bitcoin::XOnlyPublicKey::from_musig2_pks(config.verifiers_public_keys.clone(), None)
            .expect("Failed to create xonly pk");

    builder::address::generate_deposit_address(
        nofn_xonly_pk,
        signer.address.as_unchecked(),
        evm_address,
        config.protocol_paramset().bridge_amount,
        config.protocol_paramset().network,
        config.protocol_paramset().user_takes_after,
    )
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
    rpc: &ExtendedRpc,
    withdrawal_address: &bitcoin::Address,
    withdrawal_amount: bitcoin::Amount,
) -> (UTXO, UnspentTxOut, schnorr::Signature) {
    let signer = Actor::new(
        config.secret_key,
        config.winternitz_secret_key,
        config.protocol_paramset().network,
    );

    const WITHDRAWAL_EMPTY_UTXO_SATS: bitcoin::Amount = bitcoin::Amount::from_sat(550);

    let dust_outpoint = rpc
        .send_to_address(&signer.address, WITHDRAWAL_EMPTY_UTXO_SATS)
        .await
        .expect("Failed to send to address");
    let dust_utxo = UTXO {
        outpoint: dust_outpoint,
        txout: bitcoin::TxOut {
            value: WITHDRAWAL_EMPTY_UTXO_SATS,
            script_pubkey: signer.address.script_pubkey(),
        },
    };

    let txin = builder::transaction::input::SpendableTxIn::new(
        dust_utxo.outpoint,
        dust_utxo.txout.clone(),
        vec![],
        None,
    );
    let txout = bitcoin::TxOut {
        value: withdrawal_amount,
        script_pubkey: withdrawal_address.script_pubkey(),
    };
    let txout = builder::transaction::output::UnspentTxOut::from_partial(txout.clone());

    let tx = builder::transaction::TxHandlerBuilder::new(TransactionType::Payout)
        .add_input(
            NormalSignatureKind::NotStored,
            txin,
            SpendPath::KeySpend,
            builder::transaction::DEFAULT_SEQUENCE,
        )
        .add_output(txout.clone())
        .finalize();

    let sighash = tx
        .calculate_sighash_txin(0, bitcoin::sighash::TapSighashType::SinglePlusAnyoneCanPay)
        .expect("Failed to calculate sighash");

    let sig = signer
        .sign_with_tweak(sighash, None)
        .expect("Failed to sign");

    (dust_utxo, txout, sig)
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
