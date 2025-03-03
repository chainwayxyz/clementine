use super::common::run_single_deposit;
use crate::extended_rpc::ExtendedRpc;
use bitcoincore_rpc::RpcApi;

use crate::test::common::*;

#[tokio::test]
async fn test_deposit() {
    let mut config = create_test_config_with_thread_name(None).await;
    let regtest = create_regtest_rpc(&mut config).await;
    let rpc = regtest.rpc().clone();
    let _ = run_single_deposit(&mut config, rpc, None).await.unwrap();
}

#[ignore = "We are switching to gRPC"]
#[tokio::test]
async fn multiple_deposits_for_operator() {
    let mut config = create_test_config_with_thread_name(None).await;
    let regtest = create_regtest_rpc(&mut config).await;
    let rpc = regtest.rpc().clone();
    let _ = run_multiple_deposits(&mut config, rpc, 2).await.unwrap();
}

#[tokio::test]
async fn create_regtest_rpc_macro() {
    let mut config = create_test_config_with_thread_name(None).await;

    let regtest = create_regtest_rpc(&mut config).await;

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
