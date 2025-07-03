//! # Testing Utilities

use crate::builder::script::SpendPath;
use crate::builder::transaction::TransactionType;
use crate::citrea::CitreaClientT;
use crate::rpc::clementine::clementine_aggregator_client::ClementineAggregatorClient;
use crate::rpc::clementine::clementine_operator_client::ClementineOperatorClient;
use crate::rpc::clementine::clementine_verifier_client::ClementineVerifierClient;
use crate::rpc::clementine::NormalSignatureKind;
use crate::rpc::get_clients;
use crate::servers::{
    create_aggregator_unix_server, create_operator_unix_server, create_verifier_unix_server,
};
use crate::utils::initialize_logger;
use crate::utils::NamedEntity;
use crate::{
    actor::Actor, builder, config::BridgeConfig, database::Database, errors::BridgeError,
    extended_rpc::ExtendedRpc, musig2::AggregateFromPublicKeys,
};
use crate::{EVMAddress, UTXO};
use bitcoin::secp256k1::schnorr;
use secrecy::ExposeSecret;
use std::net::TcpListener;

use tokio::sync::oneshot;
use tonic::transport::Channel;

#[must_use = "Servers will die if not used"]
pub struct ActorsCleanup(pub (Vec<oneshot::Sender<()>>, tempfile::TempDir));

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
        .keep();
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

    if config.test_params.generate_to_address {
        client
            .client
            .generate_to_address(201, address.assume_checked_ref())
            .await
            .expect("Failed to generate blocks");
    }

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
pub async fn create_test_config_with_thread_name() -> BridgeConfig {
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
    config.citrea_rpc_url = handle.to_string();

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
pub async fn create_actors<C: CitreaClientT>(
    config: &BridgeConfig,
) -> (
    Vec<ClementineVerifierClient<Channel>>,
    Vec<ClementineOperatorClient<Channel>>,
    ClementineAggregatorClient<Channel>,
    ActorsCleanup,
) {
    let all_verifiers_secret_keys = &config.test_params.all_verifiers_secret_keys;
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

            #[cfg(test)]
            {
                use crate::config::protocol::ProtocolParamset;

                if config.test_params.generate_diverse_total_works {
                    // Generate a new protocol paramset for each verifier
                    // to ensure diverse total works.
                    let mut paramset = config.protocol_paramset().clone();
                    paramset.time_to_send_watchtower_challenge = paramset
                        .time_to_send_watchtower_challenge
                        .checked_add(i.parse::<u16>().expect("Failed to parse i as u16") as u16)
                        .expect("Failed to add time to send watchtower challenge");
                    let paramset_ref: &'static ProtocolParamset = Box::leak(Box::new(paramset));

                    config_with_new_db.protocol_paramset = paramset_ref;
                }
            }

            async move {
                config_with_new_db.db_name += &i;
                initialize_database(&config_with_new_db).await;

                let (socket_path, shutdown_tx) = create_verifier_unix_server::<C>(
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

    let all_operators_secret_keys = &config.test_params.all_operators_secret_keys;

    // Create futures for operator Unix socket servers
    let operator_futures = all_operators_secret_keys
        .iter()
        .enumerate()
        .map(|(i, sk)| {
            let socket_path = socket_dir.path().join(format!("operator_{}.sock", i));
            let verifier_config = verifier_configs[i % verifier_configs.len()].clone();
            async move {
                let (socket_path, shutdown_tx) = create_operator_unix_server::<C>(
                    BridgeConfig {
                        secret_key: *sk,
                        ..verifier_config.clone()
                    },
                    socket_path,
                )
                .await?;

                Ok::<((std::path::PathBuf, oneshot::Sender<()>), BridgeConfig), BridgeError>((
                    (socket_path, shutdown_tx),
                    verifier_config,
                ))
            }
        })
        .collect::<Vec<_>>();

    let operator_results = futures::future::try_join_all(operator_futures)
        .await
        .expect("Failed to join operator futures");

    let (operator_tmp, operator_configs) =
        operator_results.into_iter().unzip::<_, _, Vec<_>, Vec<_>>();
    let (operator_paths, operator_shutdown_channels) =
        operator_tmp.into_iter().unzip::<_, _, Vec<_>, Vec<_>>();

    shutdown_channels.extend(operator_shutdown_channels);

    let verifier_configs = verifier_configs.clone();

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
            ..verifier_configs[0].clone()
        },
        aggregator_socket_path,
    )
    .await
    .expect("Failed to create aggregator");

    // Add aggregator shutdown channel
    shutdown_channels.push(aggregator_shutdown_tx);

    // Connect to the Unix socket servers
    let verifiers = get_clients(
        verifier_paths
            .iter()
            .map(|path| format!("unix://{}", path.display()))
            .collect::<Vec<_>>(),
        ClementineVerifierClient::new,
        &verifier_configs[0],
        false,
    )
    .await
    .expect("could not connect to verifiers");

    let operators = get_clients(
        operator_paths
            .iter()
            .map(|path| format!("unix://{}", path.display()))
            .collect::<Vec<_>>(),
        ClementineOperatorClient::new,
        &operator_configs[0],
        false,
    )
    .await
    .expect("could not connect to operators");

    let aggregator = get_clients(
        vec![format!("unix://{}", aggregator_path.display())],
        ClementineAggregatorClient::new,
        &verifier_configs[0],
        false,
    )
    .await
    .expect("could not connect to aggregator")
    .pop()
    .expect("could not connect to aggregator");

    (
        verifiers,
        operators,
        aggregator,
        ActorsCleanup((shutdown_channels, socket_dir)),
    )
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
    let signer = Actor::new(
        config.secret_key,
        config.winternitz_secret_key,
        config.protocol_paramset().network,
    );

    let nofn_xonly_pk = bitcoin::XOnlyPublicKey::from_musig2_pks(verifiers_public_keys, None)
        .expect("Failed to create xonly pk");

    builder::address::generate_deposit_address(
        nofn_xonly_pk,
        signer.address.as_unchecked(),
        evm_address,
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
) -> (UTXO, bitcoin::TxOut, schnorr::Signature) {
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
    let unspent_txout = builder::transaction::output::UnspentTxOut::from_partial(txout.clone());

    let tx = builder::transaction::TxHandlerBuilder::new(TransactionType::Payout)
        .add_input(
            NormalSignatureKind::NotStored,
            txin,
            SpendPath::KeySpend,
            builder::transaction::DEFAULT_SEQUENCE,
        )
        .add_output(unspent_txout.clone())
        .finalize();

    let sighash = tx
        .calculate_sighash_txin(0, bitcoin::sighash::TapSighashType::SinglePlusAnyoneCanPay)
        .expect("Failed to calculate sighash");

    let sig = signer
        .sign_with_tweak_data(sighash, builder::sighash::TapTweakData::KeyPath(None), None)
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
}

#[cfg(feature = "automation")]
mod states {
    use super::*;
    use crate::builder::block_cache;
    use crate::builder::transaction::{ContractContext, TransactionType, TxHandler};
    use crate::database::DatabaseTransaction;
    use crate::states::context::DutyResult;
    use crate::states::{Duty, Owner};
    use std::collections::BTreeMap;
    use std::sync::Arc;
    use tonic::async_trait;

    // Implement the Owner trait for MockOwner
    #[async_trait]
    impl Owner for MockOwner {
        async fn handle_duty(&self, duty: Duty) -> Result<DutyResult, BridgeError> {
            self.cached_duties.lock().await.push(duty);
            Ok(DutyResult::Handled)
        }

        async fn create_txhandlers(
            &self,
            _tx_type: TransactionType,
            _contract_context: ContractContext,
        ) -> Result<BTreeMap<TransactionType, TxHandler>, BridgeError> {
            Ok(BTreeMap::new())
        }

        async fn handle_finalized_block(
            &self,
            _dbtx: DatabaseTransaction<'_, '_>,
            _block_id: u32,
            _block_height: u32,
            _block_cache: Arc<block_cache::BlockCache>,
            _light_client_proof_wait_interval_secs: Option<u32>,
        ) -> Result<(), BridgeError> {
            Ok(())
        }
    }
}
