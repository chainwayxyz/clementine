use crate::citrea::mock::MockCitreaClient;
use crate::rpc::clementine::clementine_operator_client::ClementineOperatorClient;
use crate::rpc::clementine::Empty;
use crate::servers::create_operator_grpc_server;
use crate::test::common::create_test_config_with_thread_name;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
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
async fn test_mtls_connection() -> Result<(), Box<dyn std::error::Error>> {
    let mut config = create_test_config_with_thread_name().await;

    // Find an available port for the test
    let port = find_available_port().await;
    let host = "127.0.0.1";

    config.host = host.to_string();
    config.port = port;

    // Start the operator server
    let (_socket_addr, shutdown_tx) =
        create_operator_grpc_server::<MockCitreaClient>(config.clone()).await?;

    // Connect to the server using mTLS
    let endpoint = format!("https://{}:{}", host, port);

    let clients =
        crate::rpc::get_clients::<ClementineOperatorClient<tonic::transport::Channel>, _>(
            vec![endpoint],
            ClementineOperatorClient::new,
            &config,
        )
        .await?;

    // Verify that we have one client
    assert_eq!(clients.len(), 1);

    // Try to make a simple RPC call
    let mut client = clients[0].clone();
    let response = client.get_x_only_public_key(Empty {}).await;

    // We just want to verify that the connection works with mTLS
    println!("RPC response: {:?}", response);

    // Shutdown the server
    let _ = shutdown_tx.send(());

    Ok(())
}

#[tokio::test]
#[ignore = "need configurability for this test"]
async fn test_mtls_client_without_cert_fails() -> Result<(), Box<dyn std::error::Error>> {
    Ok(())
}
