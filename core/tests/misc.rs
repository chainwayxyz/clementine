use crate::common::run_single_deposit;
use bitcoincore_rpc::RpcApi;
use clementine_core::{
    config::BridgeConfig, database::Database, extended_rpc::ExtendedRpc, utils::initialize_logger,
};

mod common;

#[tokio::test]
async fn test_deposit() {
    let mut config = create_test_config_with_thread_name!(None);
    run_single_deposit(&mut config).await.unwrap();
}

//     #[ignore = "We are switching to gRPC"]
//     #[tokio::test]
//     async fn multiple_deposits_for_operator() {
//         run_multiple_deposits("test_config.toml").await;
//     }

#[tokio::test]
async fn create_regtest_rpc_macro() {
    let mut config = create_test_config_with_thread_name!(None);
    let regtest = create_regtest_rpc!(config);

    let macro_rpc = regtest.rpc();
    let rpc = ExtendedRpc::connect(
        config.bitcoin_rpc_url.clone(),
        config.bitcoin_rpc_user.clone(),
        config.bitcoin_rpc_password.clone(),
    )
    .await
    .unwrap();

    macro_rpc.mine_blocks(1).await.unwrap();
    let height = macro_rpc.client.get_block_count().await.unwrap();
    let new_rpc_height = rpc.client.get_block_count().await.unwrap();
    assert_eq!(height, new_rpc_height);

    rpc.mine_blocks(1).await.unwrap();
    let new_rpc_height = rpc.client.get_block_count().await.unwrap();
    let height = macro_rpc.client.get_block_count().await.unwrap();
    assert_eq!(height, new_rpc_height);
}
