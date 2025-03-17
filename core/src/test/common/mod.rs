//! # Common Utilities for Integration Tests

use crate::actor::Actor;
use crate::builder::transaction::{BaseDepositData, DepositData};
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
pub use test_utils::*;
use tonic::transport::Channel;
use tonic::Request;

pub mod citrea;
mod test_utils;

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
) -> Result<(), BridgeError> {
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

    Ok(())
}

pub async fn run_multiple_deposits(
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
    let (verifiers, operators, mut aggregator, watchtowers, cleanup) = create_actors(config).await;

    let evm_address = EVMAddress([1u8; 20]);
    let actor = Actor::new(
        config.secret_key,
        config.winternitz_secret_key,
        config.protocol_paramset().network,
    );
    let (deposit_address, _) = get_deposit_address(config, evm_address)?;

    aggregator.setup(Request::new(Empty {})).await?;

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

        let deposit_data = DepositData::BaseDeposit(BaseDepositData {
            deposit_outpoint,
            evm_address,
            recovery_taproot_address: actor.address.as_unchecked().to_owned(),
            nofn_xonly_pk,
        });

        let deposit_params: DepositParams = deposit_data.into();

        let move_txid: Txid = aggregator
            .new_deposit(deposit_params)
            .await?
            .into_inner()
            .try_into()?;
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

pub async fn run_single_deposit(
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
    let (verifiers, operators, mut aggregator, watchtowers, cleanup) = create_actors(config).await;

    let evm_address = evm_address.unwrap_or(EVMAddress([1u8; 20]));
    let actor = Actor::new(
        config.secret_key,
        config.winternitz_secret_key,
        config.protocol_paramset().network,
    );
    let (deposit_address, _) = get_deposit_address(config, evm_address)?;

    let setup_start = std::time::Instant::now();
    aggregator.setup(Request::new(Empty {})).await?;
    let setup_elapsed = setup_start.elapsed();
    tracing::info!("Setup completed in: {:?}", setup_elapsed);

    let deposit_outpoint = rpc
        .send_to_address(&deposit_address, config.protocol_paramset().bridge_amount)
        .await?;

    mine_once_after_in_mempool(&rpc, deposit_outpoint.txid, Some("Deposit outpoint"), None).await?;
    let deposit_blockhash = rpc.get_blockhash_of_deposit(&deposit_outpoint.txid).await?;

    let nofn_xonly_pk =
        bitcoin::XOnlyPublicKey::from_musig2_pks(config.verifiers_public_keys.clone(), None)
            .unwrap();

    let deposit_data = DepositData::BaseDeposit(BaseDepositData {
        deposit_outpoint,
        evm_address,
        recovery_taproot_address: actor.address.as_unchecked().to_owned(),
        nofn_xonly_pk,
    });

    let deposit_params: DepositParams = deposit_data.into();

    let move_txid: Txid = aggregator
        .new_deposit(deposit_params.clone())
        .await?
        .into_inner()
        .try_into()?;

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
