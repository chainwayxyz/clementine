//! # Common Utilities for Integration Tests

use crate::actor::Actor;
use crate::config::BridgeConfig;
use crate::errors::BridgeError;
use crate::extended_rpc::ExtendedRpc;
use crate::rpc::clementine::clementine_aggregator_client::ClementineAggregatorClient;
use crate::rpc::clementine::clementine_operator_client::ClementineOperatorClient;
use crate::rpc::clementine::clementine_verifier_client::ClementineVerifierClient;
use crate::rpc::clementine::clementine_watchtower_client::ClementineWatchtowerClient;
use crate::rpc::clementine::{DepositParams, Empty};
use crate::EVMAddress;
use bitcoin::{OutPoint, Txid};
use bitcoincore_rpc::RpcApi;
pub use test_utils::*;
use tonic::transport::Channel;
use tonic::Request;

pub mod citrea;
mod test_utils;

pub async fn run_multiple_deposits(
    config: &mut BridgeConfig,
    rpc: ExtendedRpc,
) -> Result<
    (
        Vec<ClementineVerifierClient<Channel>>,
        Vec<ClementineOperatorClient<Channel>>,
        ClementineAggregatorClient<Channel>,
        Vec<ClementineWatchtowerClient<Channel>>,
        Vec<OutPoint>,
        Vec<Txid>,
    ),
    BridgeError,
> {
    let (verifiers, operators, mut aggregator, watchtowers) = create_actors(config).await;

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
    // for _ in 0..config.operator_num_kickoff_utxos_per_tx + 1 {
    for _ in 0..1 {
        let deposit_outpoint: OutPoint = rpc
            .send_to_address(&deposit_address, config.protocol_paramset().bridge_amount)
            .await?;
        rpc.mine_blocks(18).await?;

        let move_txid: Txid = aggregator
            .new_deposit(DepositParams {
                deposit_outpoint: Some(deposit_outpoint.into()),
                evm_address: evm_address.0.to_vec(),
                recovery_taproot_address: actor.address.to_string(),
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
        deposit_outpoints,
        move_txids,
    ))

    // let withdrawal_address = Address::p2tr(
    //     &secp,
    //     secret_key.x_only_public_key(&secp).0,
    //     None,
    //     config.protocol_paramset().network,
    // );
    // let (user_utxo, user_txout, user_sig) = user
    //     .generate_withdrawal_transaction_and_signature(
    //         withdrawal_address.clone(),
    //         Amount::from_sat(
    //             config.protocol_paramset().bridge_amount.to_sat()
    //                 - 2 * config.operator_withdrawal_fee_sats.unwrap().to_sat(),
    //         ),
    //     )
    //     .await
    //     .unwrap(); This line needs to be converted into generate_withdrawal_transaction_and_signature
    // let withdrawal_provide_txid = operators[0]
    //     .0
    //     .new_withdrawal_sig_rpc(0, user_sig, user_utxo, user_txout)
    //     .await
    //     .unwrap();
    // println!("Withdrawal provide txid: {:?}", withdrawal_provide_txid);
    // let txs_to_be_sent_0 = operators[0]
    //     .0
    //     .withdrawal_proved_on_citrea_rpc(0, deposit_outpoints[0])
    //     .await
    //     .unwrap();
    // assert!(txs_to_be_sent_0.len() == 3);
    // let (user_utxo, user_txout, user_sig) = user
    //     .generate_withdrawal_transaction_and_signature(
    //         withdrawal_address.clone(),
    //         Amount::from_sat(
    //             config.protocol_paramset().bridge_amount.to_sat()
    //                 - 2 * config.operator_withdrawal_fee_sats.unwrap().to_sat(),
    //         ),
    //     )
    //     .await
    //     .unwrap(); This line needs to be converted into generate_withdrawal_transaction_and_signature
    // let withdrawal_provide_txid = operators[1]
    //     .0
    //     .new_withdrawal_sig_rpc(
    //         config.operator_num_kickoff_utxos_per_tx as u32 - 1,
    //         user_sig,
    //         user_utxo,
    //         user_txout,
    //     )
    //     .await
    //     .unwrap();
    // println!("Withdrawal provide txid: {:?}", withdrawal_provide_txid);
    // let txs_to_be_sent_penultimate = operators[1]
    //     .0
    //     .withdrawal_proved_on_citrea_rpc(
    //         config.operator_num_kickoff_utxos_per_tx as u32 - 1,
    //         deposit_outpoints[config.operator_num_kickoff_utxos_per_tx - 1],
    //     )
    //     .await
    //     .unwrap();
    // assert!(txs_to_be_sent_penultimate.len() == 3);
    // let (user_utxo, user_txout, user_sig) = user
    //     .generate_withdrawal_transaction_and_signature(
    //         withdrawal_address.clone(),
    //         Amount::from_sat(
    //             config.protocol_paramset().bridge_amount.to_sat()
    //                 - 2 * config.operator_withdrawal_fee_sats.unwrap().to_sat(),
    //         ),
    //     )
    //     .await
    //     .unwrap(); This line needs to be converted into generate_withdrawal_transaction_and_signature
    // let withdrawal_provide_txid = operators[0]
    //     .0
    //     .new_withdrawal_sig_rpc(2, user_sig, user_utxo, user_txout)
    //     .await
    //     .unwrap();
    // println!("Withdrawal provide txid: {:?}", withdrawal_provide_txid);
    // let txs_to_be_sent_last = operators[2]
    //     .0
    //     .withdrawal_proved_on_citrea_rpc(
    //         config.operator_num_kickoff_utxos_per_tx as u32,
    //         deposit_outpoints[config.operator_num_kickoff_utxos_per_tx],
    //     )
    //     .await
    //     .unwrap();
    // assert!(txs_to_be_sent_last.len() == 4);
}

pub async fn run_single_deposit(
    config: &mut BridgeConfig,
    rpc: ExtendedRpc,
) -> Result<
    (
        Vec<ClementineVerifierClient<Channel>>,
        Vec<ClementineOperatorClient<Channel>>,
        ClementineAggregatorClient<Channel>,
        Vec<ClementineWatchtowerClient<Channel>>,
        OutPoint,
        Txid,
    ),
    BridgeError,
> {
    let (verifiers, operators, mut aggregator, watchtowers) = create_actors(config).await;

    let evm_address = EVMAddress([1u8; 20]);
    let actor = Actor::new(
        config.secret_key,
        config.winternitz_secret_key,
        config.protocol_paramset().network,
    );
    let (deposit_address, _) = get_deposit_address(config, evm_address)?;

    aggregator.setup(Request::new(Empty {})).await?;

    let deposit_outpoint = rpc
        .send_to_address(&deposit_address, config.protocol_paramset().bridge_amount)
        .await?;
    rpc.mine_blocks(18).await?;

    let move_txid: Txid = aggregator
        .new_deposit(DepositParams {
            deposit_outpoint: Some(deposit_outpoint.into()),
            evm_address: evm_address.0.to_vec(),
            recovery_taproot_address: actor.address.to_string(),
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

    tracing::info!("MoveTx landed onchain: Deposit successful");

    Ok((
        verifiers,
        operators,
        aggregator,
        watchtowers,
        deposit_outpoint,
        move_txid,
    ))
}
