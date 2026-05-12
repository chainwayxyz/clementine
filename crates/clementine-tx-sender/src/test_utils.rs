//! Test utilities for clementine-tx-sender.

use std::net::TcpListener;

use bitcoin::secp256k1::SecretKey;
use clementine_config::TxSenderLimits;
use clementine_extended_rpc::ExtendedBitcoinRpc;
use clementine_utils::tracing::initialize_logger;
use secrecy::ExposeSecret;

use crate::config::{TxSenderBitcoinRpcConfig, TxSenderConfig, TxSenderPostgresConfig};
use crate::{MempoolConfig, TxSenderDb};

/// Creates a test environment with a unique database name and a regtest Bitcoin node specific to the test.
pub async fn create_test_environment(
    setup_db: bool,
    setup_rpc: bool,
) -> (
    TxSenderConfig,
    Option<TxSenderDb>,
    Option<WithProcessCleanup>,
) {
    initialize_logger(Some(::tracing::level_filters::LevelFilter::DEBUG))
        .expect("Failed to initialize logger");

    let mut config = TxSenderConfig {
        network: bitcoin::Network::Regtest,
        secret_key: SecretKey::new(&mut bitcoin::secp256k1::rand::thread_rng()),
        private_da_key: Some(SecretKey::new(&mut bitcoin::secp256k1::rand::thread_rng())),
        postgres: TxSenderPostgresConfig {
            host: "127.0.0.1".to_string(),
            port: 5432,
            user: "clementine".to_string().into(),
            password: "clementine".to_string().into(),
            dbname: get_current_test_name(),
        },
        bitcoin_rpc: TxSenderBitcoinRpcConfig {
            url: "http://127.0.0.1:18443".to_string(),
            user: "admin".to_string().into(),
            password: "admin".to_string().into(),
        },
        finality_depth: 1,
        poll_delay_ms: 500,
        input_unspent_max_retries: None,
        include_unsafe: true,
        jsonrpc: None,
        mempool: MempoolConfig {
            host: None,
            endpoint: None,
        },
        limits: TxSenderLimits::default(),
    };

    tracing::info!("Test txsender db name: {}", config.postgres.dbname);

    let rpc = if setup_rpc {
        Some(create_regtest_rpc(&mut config).await)
    } else {
        None
    };
    let db = if setup_db {
        Some(setup_txsender_test_db(&config).await)
    } else {
        None
    };

    (config, db, rpc)
}

/// Sets up a test database with a unique name based on the current test thread name.
///
/// This function follows the same pattern as `core::test::common::create_test_config_with_thread_name`:
/// it extracts the thread name, creates a unique database name, drops/creates the database,
/// and runs migrations.
///
/// # Panics
///
/// Panics if:
/// - The thread name cannot be retrieved
/// - Database connection fails
/// - Database operations fail
pub async fn setup_txsender_test_db(config: &TxSenderConfig) -> TxSenderDb {
    let db_name = config.postgres.dbname.clone();

    // Use same defaults as core test util
    let admin_config = TxSenderPostgresConfig {
        dbname: "postgres".to_string(),
        ..config.postgres.clone()
    };

    // Connect to postgres database to create/drop the test database
    let admin_db = TxSenderDb::connect(&admin_config)
        .await
        .expect("Failed to connect to postgres database");

    // Drop and create the test database
    let _ = sqlx::query(&format!("DROP DATABASE IF EXISTS {db_name}"))
        .execute(admin_db.pool())
        .await;

    let _ = sqlx::query(&format!(
        "CREATE DATABASE {} WITH OWNER {}",
        db_name,
        config.postgres.user.expose_secret()
    ))
    .execute(admin_db.pool())
    .await;

    admin_db.pool().close().await;

    // Connect to the test database
    let db = TxSenderDb::connect(&config.postgres)
        .await
        .expect("Failed to connect to test database");
    db.run_migrations().await.expect("Failed to run migrations");
    db
}

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
pub async fn create_regtest_rpc(config: &mut TxSenderConfig) -> WithProcessCleanup {
    use bitcoincore_rpc::RpcApi;
    use tempfile::TempDir;

    // Create temporary directory for bitcoin data
    let data_dir = TempDir::new()
        .expect("Failed to create temporary directory")
        .keep();
    let bitcoin_rpc_debug = std::env::var("BITCOIN_RPC_DEBUG").map(|d| !d.is_empty()) == Ok(true);

    // Get available ports for RPC
    let rpc_port = if bitcoin_rpc_debug {
        18443
    } else {
        get_available_port()
    };

    config.bitcoin_rpc.url = format!("http://127.0.0.1:{rpc_port}");

    if bitcoin_rpc_debug && TcpListener::bind(format!("127.0.0.1:{rpc_port}")).is_err() {
        // Bitcoind is already running on port 18443, use existing port.
        return WithProcessCleanup(
            None,
            ExtendedBitcoinRpc::connect(
                "http://127.0.0.1:18443".into(),
                config.bitcoin_rpc.user.clone(),
                config.bitcoin_rpc.password.clone(),
                None,
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
        format!("-rpcuser={}", config.bitcoin_rpc.user.expose_secret()),
        format!(
            "-rpcpassword={}",
            config.bitcoin_rpc.password.expose_secret()
        ),
        "-wallet=admin".to_string(),
        "-txindex=1".to_string(),
        "-whitelist=noban@127.0.0.1".to_string(),
        "-fallbackfee=0.00001".to_string(),
        "-rpcallowip=0.0.0.0/0".to_string(),
        "-maxtxfee=5".to_string(),
    ];

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
        .expect("Failed to start bitcoind");

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
            config.bitcoin_rpc.user.clone(),
            config.bitcoin_rpc.password.clone(),
            None,
        )
        .await
        {
            Ok(client) => break client,
            Err(_) => {
                attempts += 1;
                if attempts >= retry_count {
                    panic!("Bitcoin node failed to start in {retry_count} seconds");
                }
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            }
        }
    };

    // Get and print bitcoind version
    let network_info = client
        .get_network_info()
        .await
        .expect("Failed to get network info");
    tracing::info!("Using bitcoind version: {}", network_info.version);

    // // Create wallet
    client
        .create_wallet("admin", None, None, None, None)
        .await
        .expect("Failed to create wallet");

    // Generate blocks
    let address = client
        .get_new_address(None, None)
        .await
        .expect("Failed to get new address");

    // generate funds to wallet
    client
        .generate_to_address(201, address.assume_checked_ref())
        .await
        .expect("Failed to generate blocks");

    WithProcessCleanup(Some(process), client.clone(), log_file, bitcoin_rpc_debug)
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

pub fn get_current_test_name() -> String {
    // 1. Try the standard thread name (works for standard `cargo test`)
    let test_name = std::thread::current()
        .name()
        .unwrap_or("main")
        .split(':')
        .next_back()
        .unwrap_or("main")
        .to_string();

    // 2. If running via `cargo nextest`, the thread name is often "main".
    //    In this case, we parse the test name from the CLI arguments.
    if test_name == "main" {
        // Use the Process ID. It is unique for every parallel test.
        let pid = std::process::id();
        format!("tx_sender_{pid}")
    } else {
        test_name
    }
}
