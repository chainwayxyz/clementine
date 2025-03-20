//! # Common Utilities for Integration Tests

use crate::actor::Actor;
use crate::citrea::mock::MockCitreaClient;
use crate::citrea::CitreaClientT;
use crate::config::BridgeConfig;
use crate::errors::BridgeError;
use crate::extended_rpc::ExtendedRpc;
use crate::musig2::AggregateFromPublicKeys;
use crate::rpc::clementine::clementine_aggregator_client::ClementineAggregatorClient;
use crate::rpc::clementine::clementine_operator_client::ClementineOperatorClient;
use crate::rpc::clementine::clementine_verifier_client::ClementineVerifierClient;
use crate::rpc::clementine::clementine_watchtower_client::ClementineWatchtowerClient;
use crate::rpc::clementine::{DepositParams, Empty};
use crate::EVMAddress;
use bitcoin::{BlockHash, OutPoint, Txid};
use bitcoincore_rpc::RpcApi;
use eyre::Context;
pub use setup_utils::*;
use tonic::transport::Channel;
use tonic::Request;

pub mod citrea;
mod setup_utils;
pub mod tx_utils;

/// Wait for a transaction to be in the mempool and than mines a block to make
/// sure that it is included in the next block.
///
/// # Parameters
///
/// - `rpc`: The RPC client to use.
/// - `txid`: The txid to wait for.
/// - `tx_name`: The name of the transaction to wait for.
/// - `timeout`: The timeout in seconds.
pub async fn mine_once_after_in_mempool(
    rpc: &ExtendedRpc,
    txid: Txid,
    tx_name: Option<&str>,
    timeout: Option<u64>,
) -> Result<usize, BridgeError> {
    let timeout = timeout.unwrap_or(60);
    let start = std::time::Instant::now();
    let tx_name = tx_name.unwrap_or("Unnamed tx");

    loop {
        if start.elapsed() > std::time::Duration::from_secs(timeout) {
            panic!("{} did not land onchain within {timeout} seconds", tx_name);
        }

        if rpc.client.get_mempool_entry(&txid).await.is_ok() {
            break;
        };

        tracing::info!("Waiting for {} transaction to hit mempool...", tx_name);
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }

    rpc.mine_blocks(1).await?;

    let tx: bitcoincore_rpc::json::GetRawTransactionResult = rpc
        .client
        .get_raw_transaction_info(&txid, None)
        .await
        .map_err(|e| {
            BridgeError::Error(format!(
            "{} did not land onchain after in mempool and mining 1 block and rpc gave error: {}",
            tx_name,
            e
        ))
        })?;

    if tx.blockhash.is_none() {
        tracing::error!(
            "{} did not land onchain after in mempool and mining 1 block",
            tx_name
        );

        return Err(BridgeError::Error(format!(
            "{} did not land onchain after in mempool and mining 1 block",
            tx_name
        )));
    }

    let tx_block_height = rpc
        .client
        .get_block_info(&tx.blockhash.unwrap())
        .await
        .wrap_err("Failed to get block info")?;

    Ok(tx_block_height.height)
}

pub async fn run_multiple_deposits<C: CitreaClientT>(
    config: &mut BridgeConfig,
    rpc: ExtendedRpc,
    count: usize,
) -> Result<
    (
        Vec<ClementineVerifierClient<Channel>>,
        Vec<ClementineOperatorClient<Channel>>,
        ClementineAggregatorClient<Channel>,
        Vec<ClementineWatchtowerClient<Channel>>,
        ActorsCleanup,
        Vec<OutPoint>,
        Vec<Txid>,
    ),
    BridgeError,
> {
    let (verifiers, operators, mut aggregator, watchtowers, cleanup) =
        create_actors::<C>(config).await;

    let evm_address = EVMAddress([1u8; 20]);
    let actor = Actor::new(
        config.secret_key,
        config.winternitz_secret_key,
        config.protocol_paramset().network,
    );
    let (deposit_address, _) = get_deposit_address(config, evm_address)?;

    aggregator
        .setup(Request::new(Empty {}))
        .await
        .wrap_err("Failed to setup aggregator")?;

    let mut deposit_outpoints = Vec::new();
    let mut move_txids = Vec::new();

    let nofn_xonly_pk =
        bitcoin::XOnlyPublicKey::from_musig2_pks(config.verifiers_public_keys.clone(), None)
            .unwrap();

    for _ in 0..count {
        let deposit_outpoint: OutPoint = rpc
            .send_to_address(&deposit_address, config.protocol_paramset().bridge_amount)
            .await?;
        rpc.mine_blocks(18).await?;

        let move_txid: Txid = aggregator
            .new_deposit(DepositParams {
                deposit_outpoint: Some(deposit_outpoint.into()),
                evm_address: evm_address.0.to_vec(),
                recovery_taproot_address: actor.address.to_string(),
                nofn_xonly_pk: nofn_xonly_pk.serialize().to_vec(),
            })
            .await
            .wrap_err("Failed to execute deposit")?
            .into_inner()
            .try_into()
            .wrap_err("Failed to convert between Txid types")?;
        rpc.mine_blocks(1).await?;

        let start = std::time::Instant::now();
        let timeout = 60;
        let _tx = loop {
            if start.elapsed() > std::time::Duration::from_secs(timeout) {
                panic!("MoveTx did not land onchain within {timeout} seconds");
            }
            rpc.mine_blocks(1).await?;

            let tx_result = rpc.client.get_raw_transaction_info(&move_txid, None).await;

            let tx_result = match tx_result {
                Ok(tx) => tx,
                Err(e) => {
                    tracing::info!("Waiting for transaction to be on-chain: {}", e);
                    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                    continue;
                }
            };

            break tx_result;
        };

        deposit_outpoints.push(deposit_outpoint);
        move_txids.push(move_txid);
    }

    Ok((
        verifiers,
        operators,
        aggregator,
        watchtowers,
        cleanup,
        deposit_outpoints,
        move_txids,
    ))
}

pub async fn run_single_deposit<C: CitreaClientT>(
    config: &mut BridgeConfig,
    rpc: ExtendedRpc,
    evm_address: Option<EVMAddress>,
) -> Result<
    (
        Vec<ClementineVerifierClient<Channel>>,
        Vec<ClementineOperatorClient<Channel>>,
        ClementineAggregatorClient<Channel>,
        Vec<ClementineWatchtowerClient<Channel>>,
        ActorsCleanup,
        DepositParams,
        Txid,
        BlockHash,
    ),
    BridgeError,
> {
    let (verifiers, operators, mut aggregator, watchtowers, cleanup) =
        create_actors::<C>(config).await;

    let evm_address = evm_address.unwrap_or(EVMAddress([1u8; 20]));
    let actor = Actor::new(
        config.secret_key,
        config.winternitz_secret_key,
        config.protocol_paramset().network,
    );
    let (deposit_address, _) = get_deposit_address(config, evm_address)?;

    let setup_start = std::time::Instant::now();
    aggregator
        .setup(Request::new(Empty {}))
        .await
        .wrap_err("Failed to setup aggregator")?;
    let setup_elapsed = setup_start.elapsed();
    tracing::info!("Setup completed in: {:?}", setup_elapsed);

    let deposit_outpoint = rpc
        .send_to_address(&deposit_address, config.protocol_paramset().bridge_amount)
        .await?;

    mine_once_after_in_mempool(&rpc, deposit_outpoint.txid, Some("Deposit outpoint"), None).await?;
    let deposit_blockhash = rpc.get_blockhash_of_tx(&deposit_outpoint.txid).await?;

    let nofn_xonly_pk =
        bitcoin::XOnlyPublicKey::from_musig2_pks(config.verifiers_public_keys.clone(), None)
            .unwrap();

    let deposit_params = DepositParams {
        deposit_outpoint: Some(deposit_outpoint.into()),
        evm_address: evm_address.0.to_vec(),
        recovery_taproot_address: actor.address.to_string(),
        nofn_xonly_pk: nofn_xonly_pk.serialize().to_vec(),
    };

    let move_txid: Txid = aggregator
        .new_deposit(deposit_params.clone())
        .await
        .wrap_err("Failed to execute deposit")?
        .into_inner()
        .try_into()
        .wrap_err("Failed to convert between Txid types")?;

    // sleep 3 seconds so that tx_sender can send the fee_payer_tx to the mempool
    tokio::time::sleep(std::time::Duration::from_secs(3)).await;
    // mine 1 block
    rpc.mine_blocks(1).await?;

    mine_once_after_in_mempool(&rpc, move_txid, Some("Move tx"), None).await?;

    Ok((
        verifiers,
        operators,
        aggregator,
        watchtowers,
        cleanup,
        deposit_params,
        move_txid,
        deposit_blockhash,
    ))
}

#[ignore = "Tested everywhere, no need to run again"]
#[tokio::test]
async fn test_deposit() {
    let mut config = create_test_config_with_thread_name(None).await;
    let regtest = create_regtest_rpc(&mut config).await;
    let rpc = regtest.rpc().clone();
    let _ = run_single_deposit::<MockCitreaClient>(&mut config, rpc, None)
        .await
        .unwrap();
}

#[ignore = "Tested everywhere, no need to run again"]
#[tokio::test]
async fn multiple_deposits_for_operator() {
    let mut config = create_test_config_with_thread_name(None).await;
    let regtest = create_regtest_rpc(&mut config).await;
    let rpc = regtest.rpc().clone();
    let _ = run_multiple_deposits::<MockCitreaClient>(&mut config, rpc, 2)
        .await
        .unwrap();
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
