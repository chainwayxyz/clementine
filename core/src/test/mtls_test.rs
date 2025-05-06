use crate::errors::BridgeError;
use crate::rpc::clementine::clementine_operator_client::ClementineOperatorClient;
use crate::rpc::clementine::Empty;
use crate::servers::create_operator_grpc_server;
use crate::test::common::create_test_config_with_thread_name;
use std::fmt::Debug;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use tokio::net::TcpListener;
use tonic::async_trait;

// Simple mock implementation of CitreaClientT
#[derive(Clone, Debug)]
pub struct MockCitreaClient;

#[async_trait]
impl crate::citrea::CitreaClientT for MockCitreaClient {
    async fn new(
        _citrea_rpc_url: String,
        _light_client_prover_url: String,
        _secret_key: Option<alloy::signers::local::PrivateKeySigner>,
    ) -> Result<Self, BridgeError> {
        Ok(MockCitreaClient)
    }

    async fn withdrawal_utxos(
        &self,
        _withdrawal_index: u64,
    ) -> Result<bitcoin::OutPoint, BridgeError> {
        unimplemented!()
    }

    async fn collect_deposit_move_txids(
        &self,
        _last_deposit_idx: Option<u32>,
        _to_height: u64,
    ) -> Result<Vec<(u64, bitcoin::Txid)>, BridgeError> {
        unimplemented!()
    }

    async fn collect_withdrawal_utxos(
        &self,
        _last_withdrawal_idx: Option<u32>,
        _to_height: u64,
    ) -> Result<Vec<(u64, bitcoin::OutPoint)>, BridgeError> {
        unimplemented!()
    }

    async fn get_light_client_proof(
        &self,
        _l1_height: u64,
    ) -> Result<Option<(u64, Vec<u8>)>, BridgeError> {
        unimplemented!()
    }

    async fn get_citrea_l2_height_range(
        &self,
        _block_height: u64,
        _timeout: std::time::Duration,
    ) -> Result<(u64, u64), BridgeError> {
        unimplemented!()
    }

    async fn get_replacement_deposit_move_txids(
        &self,
        _from_height: u64,
        _to_height: u64,
    ) -> Result<Vec<(bitcoin::Txid, bitcoin::Txid)>, BridgeError> {
        unimplemented!()
    }

    async fn check_nofn_correctness(
        &self,
        _nofn_xonly_pk: bitcoin::XOnlyPublicKey,
    ) -> Result<(), BridgeError> {
        unimplemented!()
    }
}

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
