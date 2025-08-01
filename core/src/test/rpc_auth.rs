use crate::rpc::clementine::clementine_operator_client::ClementineOperatorClient;
use crate::rpc::clementine::Empty;
use crate::rpc::get_clients;
use crate::servers::create_operator_grpc_server;
use crate::test::common::citrea::MockCitreaClient;
use crate::test::common::create_regtest_rpc;
use crate::test::common::create_test_config_with_thread_name;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use tokio::net::TcpListener;

// Helper function to find an available port
async fn find_available_port() -> u16 {
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 0);
    let listener = TcpListener::bind(addr).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    port
}

#[tokio::test]
async fn test_mtls_connection() -> Result<(), eyre::Report> {
    let mut config = create_test_config_with_thread_name().await;
    let _rpc = create_regtest_rpc(&mut config).await;

    // Find an available port for the test
    let port = find_available_port().await;
    let host = "127.0.0.1";

    config.host = host.to_string();
    config.port = port;

    // Start the operator server
    let (_socket_addr, _shutdown_tx) =
        create_operator_grpc_server::<MockCitreaClient>(config.clone()).await?;

    // Connect to the server using mTLS
    let endpoint = format!("https://{}:{}", host, port);

    let clients =
        crate::rpc::get_clients::<ClementineOperatorClient<tonic::transport::Channel>, _>(
            vec![endpoint],
            crate::rpc::operator_client_builder(&config),
            &config,
            true,
        )
        .await?;

    // Verify that we have one client
    assert_eq!(clients.len(), 1);

    // Try to make a simple RPC call
    let mut client = clients[0].clone();
    let response = client.get_x_only_public_key(Empty {}).await;

    // We just want to verify that the connection works with mTLS
    println!("RPC response: {:?}", response);

    Ok(())
}

#[tokio::test]
async fn test_auth_interceptor() -> Result<(), eyre::Report> {
    let mut config = create_test_config_with_thread_name().await;
    let _rpc = create_regtest_rpc(&mut config).await;

    // Find an available port for the test
    let port = find_available_port().await;
    let host = "127.0.0.1";

    config.host = host.to_string();
    config.port = port;

    // Start the operator server
    let (_socket_addr, _shutdown_tx) =
        create_operator_grpc_server::<MockCitreaClient>(config.clone()).await?;

    // Connect to the server using mTLS
    let endpoint = format!("https://{}:{}", host, port);

    let mut agg_config = config.clone();
    agg_config.client_cert_path = PathBuf::from("certs/aggregator/aggregator.pem");
    agg_config.client_key_path = PathBuf::from("certs/aggregator/aggregator.key");

    let mut clients = get_clients(
        vec![endpoint.clone()],
        crate::rpc::operator_client_builder(&config),
        &agg_config,
        true,
    )
    .await?;

    clients[0]
        .get_x_only_public_key(Empty {})
        .await
        .expect("aggregator call succeeds");
    clients[0]
        .internal_end_round(Empty {})
        .await
        .expect_err("aggregator cannot call internal method");

    let mut bad_config = config.clone();
    // Server key is not recognized to be safe, all requests
    bad_config.client_cert_path = PathBuf::from("certs/server/server.pem");
    bad_config.client_key_path = PathBuf::from("certs/server/server.key");

    let mut clients = get_clients(
        vec![endpoint.clone()],
        crate::rpc::operator_client_builder(&config),
        &bad_config,
        true,
    )
    .await?;

    clients[0]
        .get_x_only_public_key(Empty {})
        .await
        .expect_err("unknown key should fail");
    clients[0]
        .internal_end_round(Empty {})
        .await
        .expect_err("unknown key should fail");

    let mut internal_client_config = config.clone();
    // Server key is not recognized to be safe, all requests
    internal_client_config.client_cert_path = PathBuf::from("certs/client/client.pem");
    internal_client_config.client_key_path = PathBuf::from("certs/client/client.key");

    let mut clients = get_clients(
        vec![endpoint.clone()],
        crate::rpc::operator_client_builder(&config),
        &internal_client_config,
        true,
    )
    .await?;

    clients[0]
        .get_x_only_public_key(Empty {})
        .await
        .expect("own key can call public method");
    clients[0]
        .internal_end_round(Empty {})
        .await
        .expect("own key can call internal method");

    Ok(())
}
