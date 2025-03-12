//! # Common Utilities for Integration Tests

use crate::actor::Actor;
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

        let move_txid: Txid = aggregator
            .new_deposit(DepositParams {
                deposit_outpoint: Some(deposit_outpoint.into()),
                evm_address: evm_address.0.to_vec(),
                recovery_taproot_address: actor.address.to_string(),
                nofn_xonly_pk: nofn_xonly_pk.serialize().to_vec(),
            })
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
    rpc.mine_blocks(18).await?;
    let deposit_blockhash = rpc.get_blockhash_of_deposit(&deposit_outpoint.txid).await?;

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

    tracing::info!("MoveTx landed onchain: Deposit successful");

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
