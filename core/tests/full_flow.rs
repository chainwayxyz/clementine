use std::time::Duration;

use bitcoin::consensus::Decodable as _;
use bitcoin::hashes::Hash;
use bitcoin::{Address, Amount, Transaction, Txid};
use bitcoincore_rpc::RpcApi;
use clementine_core::builder::script::SpendPath;
use clementine_core::builder::transaction::TransactionType;
use clementine_core::config::BridgeConfig;
use clementine_core::database::Database;
use clementine_core::errors::BridgeError;
use clementine_core::extended_rpc::ExtendedRpc;
use clementine_core::rpc::clementine::clementine_aggregator_client::ClementineAggregatorClient;
use clementine_core::rpc::clementine::clementine_operator_client::ClementineOperatorClient;
use clementine_core::rpc::clementine::clementine_verifier_client::ClementineVerifierClient;
use clementine_core::rpc::clementine::clementine_watchtower_client::ClementineWatchtowerClient;
use clementine_core::rpc::clementine::{self, NormalSignatureKind};
use clementine_core::rpc::clementine::{
    DepositParams, Empty, KickoffId, TransactionRequest, WithdrawParams,
};
use clementine_core::servers::{
    create_aggregator_grpc_server, create_operator_grpc_server, create_verifier_grpc_server,
    create_watchtower_grpc_server,
};
use clementine_core::utils::initialize_logger;
use clementine_core::utils::SECP;
use clementine_core::EVMAddress;
use clementine_core::UTXO;
use clementine_core::{actor::Actor, builder, musig2::AggregateFromPublicKeys};
use eyre::Result;
use secp256k1::rand::rngs::ThreadRng;
use tokio::time::sleep;
use tonic::Request;

mod common;

pub async fn run_happy_path(config: BridgeConfig) -> Result<()> {
    tracing::info!("Starting happy path test");

    // 1. Setup environment and actors
    tracing::info!("Setting up environment and actors");
    let (verifiers, mut operators, mut aggregator, _watchtowers, regtest) = create_actors!(config);
    let rpc: ExtendedRpc = regtest.rpc().clone();
    let keypair = bitcoin::key::Keypair::new(&SECP, &mut ThreadRng::default());

    let evm_address = EVMAddress([1u8; 20]);
    let (deposit_address, _) = get_deposit_address!(config, evm_address)?;
    tracing::info!("Generated deposit address: {}", deposit_address);

    let withdrawal_address =
        Address::p2tr(&SECP, keypair.x_only_public_key().0, None, config.network);
    let recovery_taproot_address = Actor::new(
        config.secret_key,
        config.winternitz_secret_key,
        config.network,
    )
    .address;

    let withdrawal_amount = config.bridge_amount_sats.to_sat()
        - (2 * config
            .operator_withdrawal_fee_sats
            .expect("exists in test config")
            .to_sat());
    tracing::info!("Withdrawal amount set to: {} sats", withdrawal_amount);

    let (empty_utxo, withdrawal_tx_out, user_sig) = generate_withdrawal_transaction_and_signature!(
        config,
        rpc,
        withdrawal_address,
        Amount::from_sat(withdrawal_amount)
    );

    // 2. Setup Aggregator
    tracing::info!("Setting up aggregator");
    aggregator.setup(Request::new(Empty {})).await?;

    // 3. Make Deposit
    tracing::info!("Making deposit transaction");
    let deposit_outpoint = rpc
        .send_to_address(&deposit_address, config.bridge_amount_sats)
        .await?;
    rpc.mine_blocks(18).await?;
    tracing::info!("Deposit transaction mined: {}", deposit_outpoint);

    let dep_params = DepositParams {
        deposit_outpoint: Some(deposit_outpoint.into()),
        evm_address: evm_address.0.to_vec(),
        recovery_taproot_address: recovery_taproot_address.to_string(),
    };

    tracing::info!("Creating move transaction");
    let _move_tx_response = aggregator
        .new_deposit(dep_params.clone())
        .await?
        .into_inner();

    let start = std::time::Instant::now();
    loop {
        let timeout = 2;
        if start.elapsed() > std::time::Duration::from_secs(timeout) {
            panic!("MoveTx did not land onchain within {timeout} seconds");
        }

        let tx_result = rpc
            .client
            .get_raw_transaction(&Txid::from_slice(&_move_tx_response.txid).unwrap(), None)
            .await;
        tracing::error!("sss {:?}", tx_result);

        if tx_result.is_ok() {
            break;
        }
        rpc.mine_blocks(1).await?;

        sleep(Duration::from_secs(1)).await;
    }

    // 4. Make Withdrawal
    tracing::info!("Starting withdrawal process");
    let request = Request::new(WithdrawParams {
        withdrawal_id: 0,
        input_signature: user_sig.serialize().to_vec(),
        input_outpoint: Some(empty_utxo.outpoint.into()),
        output_script_pubkey: withdrawal_tx_out.txout().script_pubkey.clone().into(),
        output_amount: withdrawal_amount,
    });

    let withdrawal_provide_txid = operators[0].withdraw(request).await?.into_inner();
    tracing::info!("Withdrawal transaction created");

    rpc.client
        .get_raw_transaction(
            &Txid::from_slice(&withdrawal_provide_txid.txid).expect("valid txid hash"),
            None,
        )
        .await?;

    // 5. Send Kickoff Transaction
    let base_tx_req = TransactionRequest {
        transaction_type: Some(TransactionType::AllNeededForOperatorDeposit.into()),
        kickoff_id: Some(KickoffId {
            operator_idx: 0,
            sequential_collateral_idx: 0,
            kickoff_idx: 0,
        }),
        deposit_params: Some(dep_params.clone()),
        ..Default::default()
    };

    tracing::info!("Sending sequential collateral transaction");
    let op_seq_collat = operators[0]
        .internal_create_signed_tx(TransactionRequest {
            transaction_type: Some(TransactionType::SequentialCollateral.into()),
            ..base_tx_req.clone()
        })
        .await?
        .into_inner();
    rpc.client
        .send_raw_transaction(&op_seq_collat.raw_tx)
        .await?;

    tracing::info!("Sending kickoff transaction");
    let kickoff_tx = operators[0]
        .internal_create_signed_tx(TransactionRequest {
            transaction_type: Some(TransactionType::Kickoff.into()),
            ..base_tx_req.clone()
        })
        .await?
        .into_inner();
    rpc.client.send_raw_transaction(&kickoff_tx.raw_tx).await?;
    rpc.mine_blocks(69).await?;

    // 6. Send Start Happy Reimburse Transaction
    tracing::info!("Sending start happy reimburse transaction");
    let start_happy_tx = operators[0]
        .internal_create_signed_tx(TransactionRequest {
            transaction_type: Some(TransactionType::StartHappyReimburse.into()),
            ..base_tx_req.clone()
        })
        .await?
        .into_inner();
    rpc.client
        .send_raw_transaction(&start_happy_tx.raw_tx)
        .await?;

    // 7. Send Happy Reimburse Transaction
    tracing::info!("Sending happy reimburse transaction");
    let happy_reimburse_tx = operators[0]
        .internal_create_signed_tx(TransactionRequest {
            transaction_type: Some(TransactionType::HappyReimburse.into()),
            ..base_tx_req.clone()
        })
        .await?
        .into_inner();
    rpc.client
        .send_raw_transaction(&happy_reimburse_tx.raw_tx)
        .await?;

    tracing::info!("Happy reimburse transaction sent successfully");
    tracing::info!("Happy path test completed successfully");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::create_test_config_with_thread_name;

    #[tokio::test(flavor = "multi_thread")]
    async fn test_happy_path() {
        let config = create_test_config_with_thread_name!(None);
        run_happy_path(config).await.unwrap();
    }
}

#[tokio::test]
async fn aggregator_deposit_movetx_lands_onchain() {
    let config = create_test_config_with_thread_name!(None);
    let (_verifiers, _operators, mut aggregator, _watchtowers, regtest) = create_actors!(config);
    let rpc = regtest.1.clone();

    let evm_address = EVMAddress([1u8; 20]);
    let signer = Actor::new(
        config.secret_key,
        config.winternitz_secret_key,
        config.network,
    );

    let nofn_xonly_pk =
        bitcoin::XOnlyPublicKey::from_musig2_pks(config.verifiers_public_keys.clone(), None)
            .unwrap();

    let deposit_address = builder::address::generate_deposit_address(
        nofn_xonly_pk,
        signer.address.as_unchecked(),
        evm_address,
        config.bridge_amount_sats,
        config.network,
        config.user_takes_after,
    )
    .unwrap()
    .0;

    let recovery_taproot_address = Actor::new(
        config.secret_key,
        config.winternitz_secret_key,
        config.network,
    )
    .address;

    let deposit_outpoint = rpc
        .send_to_address(&deposit_address, config.bridge_amount_sats)
        .await
        .unwrap();
    rpc.mine_blocks(18).await.unwrap();

    aggregator
        .setup(tonic::Request::new(clementine::Empty {}))
        .await
        .unwrap();

    let movetx_txid: Txid = aggregator
        .new_deposit(DepositParams {
            deposit_outpoint: Some(deposit_outpoint.into()),
            evm_address: evm_address.0.to_vec(),
            recovery_taproot_address: recovery_taproot_address.to_string(),
        })
        .await
        .unwrap()
        .into_inner()
        .try_into()
        .unwrap();

    let start = std::time::Instant::now();
    loop {
        let timeout = 2;
        if start.elapsed() > std::time::Duration::from_secs(timeout) {
            panic!("MoveTx did not land onchain within {timeout} seconds");
        }
        rpc.mine_blocks(1).await.unwrap();

        let tx_result = rpc.client.get_raw_transaction(&movetx_txid, None).await;

        match tx_result {
            Ok(_tx) => break,
            Err(e) => {
                tracing::error!("Error getting transaction: {:?}", e);
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                continue;
            }
        };
    }
}
