//! # Testing Utilities
//!
//! This crate provides testing utilities, which are not possible to be included
//! in binaries. There will be multiple prerequisites that these macros require.
//! Please check comments of each for more information.

use pgtemp::PgTempDB;

use crate::{
    config::BridgeConfig,
    database::Database,
    errors::BridgeError,
    extended_rpc::ExtendedRpc,
    servers::{
        create_aggregator_grpc_server, create_operator_grpc_server, create_verifier_grpc_server,
        create_watchtower_grpc_server,
    },
};

/// Creates a temporary database for testing, using current thread's name as the
/// database name.
pub async fn create_test_setup() -> Result<(BridgeConfig, PgTempDB), BridgeError> {
    tracing_subscriber::fmt::try_init().ok();

    let db = PgTempDB::new();
    let config = BridgeConfig {
        db_port: db.db_port(),
        db_user: db.db_user().to_owned(),
        db_password: db.db_pass().to_owned(),
        db_name: "clementine_test".to_owned(),
        ..Default::default()
    };

    init_db(&config).await?;
    Ok((config, db))
}

pub async fn init_db(config: &BridgeConfig) -> Result<(), BridgeError> {
    let url = Database::get_postgresql_url(config);
    let conn = sqlx::PgPool::connect(&url).await?;

    sqlx::query(&format!("DROP DATABASE IF EXISTS {}", &config.db_name))
        .execute(&conn)
        .await
        .unwrap();

    sqlx::query(&format!(
        "CREATE DATABASE {} WITH OWNER {}",
        config.db_name, config.db_user
    ))
    .execute(&conn)
    .await?;

    conn.close().await;

    Database::run_schema_script(config).await?;
    Ok(())
}

/// Starts operators, verifiers, aggregator and watchtower servers.
pub async fn create_actors(
    config: &BridgeConfig,
) -> (
    Vec<(std::net::SocketAddr,)>,
    Vec<(std::net::SocketAddr,)>,
    (std::net::SocketAddr,),
    Vec<(std::net::SocketAddr,)>,
) {
    let start_port = config.port;
    let rpc = ExtendedRpc::new(
        config.bitcoin_rpc_url.clone(),
        config.bitcoin_rpc_user.clone(),
        config.bitcoin_rpc_password.clone(),
    )
    .await;
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
            let port = start_port + i as u16;
            // println!("Port: {}", port);
            let i = i.to_string();
            let rpc = rpc.clone();
            let mut config_with_new_db = config.clone();
            async move {
                config_with_new_db.db_name += &i;
                init_db(&config_with_new_db).await.expect("init db");

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

    let all_operators_secret_keys = config.all_operators_secret_keys.clone().unwrap_or_else(|| {
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
    let verifier_configs = verifier_configs.clone();

    let watchtower_futures = all_watchtowers_secret_keys
        .iter()
        .enumerate()
        .map(|(i, sk)| {
            create_watchtower_grpc_server(BridgeConfig {
                index: i as u32,
                secret_key: *sk,
                port: port + i as u16,
                ..verifier_configs[i].clone()
            })
        })
        .collect::<Vec<_>>();

    let watchtower_endpoints = futures::future::try_join_all(watchtower_futures)
        .await
        .unwrap();

    let port = start_port
        + all_verifiers_secret_keys.len() as u16
        + all_operators_secret_keys.len() as u16
        + all_watchtowers_secret_keys.len() as u16
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
}
