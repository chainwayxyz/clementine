//! # Testing Utilities
//!
//! This crate provides testing utilities.

use crate::builder::script::SpendPath;
use crate::builder::transaction::{TransactionType, TxHandler};
use crate::rpc::clementine::clementine_aggregator_client::ClementineAggregatorClient;
use crate::rpc::clementine::clementine_operator_client::ClementineOperatorClient;
use crate::rpc::clementine::clementine_verifier_client::ClementineVerifierClient;
use crate::rpc::clementine::clementine_watchtower_client::ClementineWatchtowerClient;
use crate::rpc::clementine::NormalSignatureKind;
use crate::utils::initialize_logger;
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
use bitcoin::secp256k1::schnorr;
use std::net::TcpListener;
use tonic::transport::Channel;

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

    config.bitcoin_rpc_url = format!("http://127.0.0.1:{}", rpc_port);

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

/// Starts operators, verifiers, aggregator and watchtower servers.
///
/// Depends on create_regtest_rpc and get_available_port! for dynamic port allocation.
///
/// # Returns
///
/// Returns a tuple of vectors of clients, handles, and addresses for the
/// verifiers, operators, aggregator and watchtowers.
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
    let verifier_futures = all_verifiers_secret_keys
        .iter()
        .enumerate()
        .map(|(i, sk)| {
            let port = get_available_port();
            // println!("Port: {}", port);
            let i = i.to_string();
            let mut config_with_new_db = config.clone();
            async move {
                config_with_new_db.db_name += &i;
                initialize_database(&config_with_new_db).await;

                let verifier = create_verifier_grpc_server(BridgeConfig {
                    secret_key: *sk,
                    port,
                    ..config_with_new_db.clone()
                })
                .await?;
                Ok::<((std::net::SocketAddr,), BridgeConfig), BridgeError>((
                    verifier,
                    config_with_new_db,
                ))
            }
        })
        .collect::<Vec<_>>();
    let verifier_results = futures::future::try_join_all(verifier_futures)
        .await
        .expect("Failed to join verifier futures");
    let verifier_endpoints = verifier_results.iter().map(|(v, _)| *v).collect::<Vec<_>>();
    let verifier_configs = verifier_results
        .iter()
        .map(|(_, c)| c.clone())
        .collect::<Vec<_>>();

    let all_operators_secret_keys = config.all_operators_secret_keys.clone().unwrap_or_else(|| {
        panic!("All secret keys of the operators are required for testing");
    });

    // Create futures for operator gRPC servers
    let operator_futures = all_operators_secret_keys
        .iter()
        .enumerate()
        .map(|(i, sk)| {
            let port = get_available_port();
            let verifier_config = verifier_configs[i].clone();
            async move {
                let socket_addr = create_operator_grpc_server(BridgeConfig {
                    secret_key: *sk,
                    port,
                    ..verifier_config
                })
                .await?;
                Ok::<(std::net::SocketAddr,), BridgeError>(socket_addr)
            }
        })
        .collect::<Vec<_>>();

    let operator_endpoints = futures::future::try_join_all(operator_futures)
        .await
        .expect("Failed to join operator futures");

    let verifier_configs = verifier_configs.clone();

    let watchtower_futures = all_watchtowers_secret_keys
        .iter()
        .enumerate()
        .map(|(i, sk)| {
            let port = get_available_port();
            println!("Watchtower {i} start port: {port}");
            create_watchtower_grpc_server(BridgeConfig {
                index: i as u32,
                secret_key: *sk,
                port,
                ..verifier_configs[i].clone()
            })
        })
        .collect::<Vec<_>>();

    let watchtower_endpoints = futures::future::try_join_all(watchtower_futures)
        .await
        .expect("Failed to join watchtower futures");

    let port = get_available_port();
    println!("Aggregator port: {}", port);
    // + all_operators_secret_keys.len() as u16;
    let aggregator = create_aggregator_grpc_server(BridgeConfig {
        port,
        verifier_endpoints: Some(
            verifier_endpoints
                .iter()
                .map(|(socket_addr,)| format!("http://{}", socket_addr))
                .collect(),
        ),
        operator_endpoints: Some(
            operator_endpoints
                .iter()
                .map(|(socket_addr,)| format!("http://{}", socket_addr))
                .collect(),
        ),
        watchtower_endpoints: Some(
            watchtower_endpoints
                .iter()
                .map(|(socket_addr,)| format!("http://{}", socket_addr))
                .collect(),
        ),
        ..verifier_configs[0].clone()
    })
    .await
    .expect("Failed to create aggregator");

    let verifiers =
        futures_util::future::join_all(verifier_endpoints.iter().map(|verifier| async move {
            ClementineVerifierClient::connect(format!("http://{}", verifier.0))
                .await
                .expect("Failed to connect to verifier")
        }))
        .await;
    let operators =
        futures_util::future::join_all(operator_endpoints.iter().map(|operator| async move {
            ClementineOperatorClient::connect(format!("http://{}", operator.0))
                .await
                .expect("Failed to connect to operator")
        }))
        .await;
    let aggregator = ClementineAggregatorClient::connect(format!("http://{}", aggregator.0))
        .await
        .expect("Failed to connect to aggregator");
    let watchtowers =
        futures_util::future::join_all(watchtower_endpoints.iter().map(|watchtower| async move {
            ClementineWatchtowerClient::connect(format!("http://{}", watchtower.0))
                .await
                .expect("Failed to connect to watchtower")
        }))
        .await;

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
/// - [`TxHandler`]: Withdrawal transaction
/// - [`Signature`]: Signature of the withdrawal transaction
pub async fn generate_withdrawal_transaction_and_signature(
    config: &BridgeConfig,
    rpc: &ExtendedRpc,
    withdrawal_address: &bitcoin::Address,
    withdrawal_amount: bitcoin::Amount,
) -> (TxHandler, schnorr::Signature) {
    let signer = Actor::new(
        config.secret_key,
        config.winternitz_secret_key,
        config.protocol_paramset().network,
    );

    const WITHDRAWAL_EMPTY_UTXO_SATS: bitcoin::Amount = bitcoin::Amount::from_sat(550);

    let dust_outpoint = rpc
        .send_to_address(
            &signer.address,
            withdrawal_amount + WITHDRAWAL_EMPTY_UTXO_SATS,
        )
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

    let txhandler = builder::transaction::TxHandlerBuilder::new(TransactionType::Payout)
        .add_input(
            NormalSignatureKind::NotStored,
            txin,
            SpendPath::KeySpend,
            builder::transaction::DEFAULT_SEQUENCE,
        )
        .add_output(txout.clone())
        .finalize();

    let sighash = txhandler
        .calculate_sighash_txin(0, bitcoin::sighash::TapSighashType::SinglePlusAnyoneCanPay)
        .expect("Failed to calculate sighash");

    let sig = signer
        .sign_with_tweak(sighash, None)
        .expect("Failed to sign");

    (txhandler, sig)
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
