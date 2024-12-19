//! # Testing Utilities
//!
//! This crate provides testing utilities, which are not possible to be included
//! in binaries. There will be multiple prerequisites that these macros require.
//! Please check comments of each for more information.

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
///
/// # Required Imports
///
/// ## Unit Tests
///
/// ```rust
/// use crate::{
///     config::BridgeConfig, database::Database, initialize_database, utils::initialize_logger,
/// };
/// use std::{env, thread};
/// ```
///
/// ## Integration Tests And Binaries
///
/// ```rust
/// use clementine_core::{config::BridgeConfig, database::Database, utils::initialize_logger};
/// use std::{env, thread};
/// ```
#[macro_export]
macro_rules! create_test_config_with_thread_name {
    ($suffix:expr) => {{
        let suffix = $suffix.unwrap_or(&String::default()).to_string();

        let handle = thread::current()
            .name()
            .unwrap()
            .split(':')
            .last()
            .unwrap()
            .to_owned()
            + &suffix;

        // Use maximum log level for tests.
        initialize_logger(5).unwrap();

        let mut config = BridgeConfig::default();

        // Check environment for an overwrite config. TODO: Convert this to env vars.
        let env_config: Option<BridgeConfig> = if let Ok(config_file_path) = env::var("TEST_CONFIG")
        {
            Some(BridgeConfig::try_parse_file(config_file_path.into()).unwrap())
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

        initialize_database!(&config);

        config
    }};
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
///
/// # Required Imports
///
/// ## Unit Tests
///
/// ```rust
/// use crate::database::Database;
/// ```
///
/// ## Integration Tests And Binaries
///
/// ```rust
/// use clementine_core::database::Database;
/// ```
#[macro_export]
macro_rules! initialize_database {
    ($config:expr) => {{
        let url = Database::get_postgresql_url(&$config);
        let conn = sqlx::PgPool::connect(url.as_str()).await.unwrap();

        sqlx::query(&format!("DROP DATABASE IF EXISTS {}", &$config.db_name))
            .execute(&conn)
            .await
            .unwrap();

        sqlx::query(&format!(
            "CREATE DATABASE {} WITH OWNER {}",
            $config.db_name, $config.db_user
        ))
        .execute(&conn)
        .await
        .unwrap();

        conn.close().await;

        Database::run_schema_script($config).await.unwrap();
    }};
}

/// Starts operators, verifiers, aggregator and watchtower servers.
///
/// # Returns
///
/// Returns a tuple of vectors of clients, handles, and addresses for the
/// verifiers, operators, aggregator and watchtowers.
///
/// # Required Imports
///
/// ## Unit Tests
///
/// ```rust
/// use crate::{
///     config::BridgeConfig,
///     database::Database,
///     errors::BridgeError,
///     initialize_database,
///     extended_rpc::ExtendedRpc,
///     servers::{
///         create_aggregator_grpc_server, create_operator_grpc_server,
///         create_verifier_grpc_server, create_watchtower_grpc_server,
///     },
/// };
/// ```
///
/// ## Integration Tests And Binaries
///
/// ```rust
/// use clementine_core::servers::{
///     create_aggregator_grpc_server, create_operator_grpc_server, create_verifier_grpc_server,
///     create_watchtower_grpc_server,
/// };
/// ```
#[macro_export]
macro_rules! create_actors {
    ($config:expr, $number_of_watchtowers:expr) => {{
        let start_port = $config.port;
        let rpc = ExtendedRpc::new(
            $config.bitcoin_rpc_url.clone(),
            $config.bitcoin_rpc_user.clone(),
            $config.bitcoin_rpc_password.clone(),
        )
        .await;
        let all_verifiers_secret_keys =
            $config
                .all_verifiers_secret_keys
                .clone()
                .unwrap_or_else(|| {
                    panic!("All secret keys of the verifiers are required for testing");
                });
        let verifier_futures = all_verifiers_secret_keys
            .iter()
            .enumerate()
            .map(|(i, sk)| {
                let port = start_port + i as u16;
                // println!("Port: {}", port);
                let i = i.to_string();
                let rpc = rpc.clone();
                let mut config_with_new_db = $config.clone();
                async move {
                    config_with_new_db.db_name += &i;
                    initialize_database!(&config_with_new_db);

                    let verifier = create_verifier_grpc_server(
                        BridgeConfig {
                            secret_key: *sk,
                            port,
                            ..config_with_new_db.clone()
                        },
                        rpc,
                    )
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
            .unwrap();
        let verifier_endpoints = verifier_results.iter().map(|(v, _)| *v).collect::<Vec<_>>();
        let verifier_configs = verifier_results
            .iter()
            .map(|(_, c)| c.clone())
            .collect::<Vec<_>>();

        let all_operators_secret_keys =
            $config
                .all_operators_secret_keys
                .clone()
                .unwrap_or_else(|| {
                    panic!("All secret keys of the operators are required for testing");
                });

        // Create futures for operator gRPC servers
        let operator_futures = all_operators_secret_keys
            .iter()
            .enumerate()
            .map(|(i, sk)| {
                let port = start_port + i as u16 + all_verifiers_secret_keys.len() as u16;
                let rpc = rpc.clone();
                let verifier_config = verifier_configs[i].clone();
                async move {
                    let socket_addr = create_operator_grpc_server(
                        BridgeConfig {
                            secret_key: *sk,
                            port,
                            ..verifier_config
                        },
                        rpc,
                    )
                    .await?;
                    Ok::<(std::net::SocketAddr,), BridgeError>(socket_addr)
                }
            })
            .collect::<Vec<_>>();

        let operator_endpoints = futures::future::try_join_all(operator_futures)
            .await
            .unwrap();

        let port = start_port
            + all_verifiers_secret_keys.len() as u16
            + all_operators_secret_keys.len() as u16
            + 1;
        println!("Watchtower start port: {}", port);
        let watchtower_futures = (0..$number_of_watchtowers)
            .map(|i| {
                let verifier_configs = verifier_configs.clone();

                create_watchtower_grpc_server(BridgeConfig {
                    port: port + i as u16,
                    ..verifier_configs[0].clone()
                })
            })
            .collect::<Vec<_>>();
        let watchtower_endpoints = futures::future::try_join_all(watchtower_futures)
            .await
            .unwrap();

        let port = start_port
            + all_verifiers_secret_keys.len() as u16
            + all_operators_secret_keys.len() as u16
            + $number_of_watchtowers as u16
            + 1;
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
        .unwrap();

        (
            verifier_endpoints,
            operator_endpoints,
            aggregator,
            watchtower_endpoints,
        )
    }};
}
