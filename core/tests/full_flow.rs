use bitcoin::consensus::encode::serialize;
use bitcoin::consensus::{self, Decodable as _, Encodable};
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::Message;
use bitcoin::sighash::SighashCache;
use bitcoin::{
    taproot, Address, Amount, Network, ScriptBuf, Sequence, TapTweakHash, Transaction, TxIn, TxOut,
    Txid, Witness,
};
use bitcoincore_rpc::RpcApi;
use clementine_core::builder::script::SpendPath;
use clementine_core::builder::transaction::TransactionType;
use clementine_core::config::BridgeConfig;
use clementine_core::constants::ANCHOR_AMOUNT;
use clementine_core::database::Database;
use clementine_core::errors::BridgeError;
use clementine_core::extended_rpc::ExtendedRpc;
use clementine_core::rpc::clementine::clementine_aggregator_client::ClementineAggregatorClient;
use clementine_core::rpc::clementine::clementine_operator_client::ClementineOperatorClient;
use clementine_core::rpc::clementine::clementine_verifier_client::ClementineVerifierClient;
use clementine_core::rpc::clementine::clementine_watchtower_client::ClementineWatchtowerClient;
use clementine_core::rpc::clementine::{
    DepositParams, Empty, KickoffId, TransactionRequest, WithdrawParams,
};
use clementine_core::rpc::clementine::{NormalSignatureKind, RawSignedTx};
use clementine_core::servers::{
    create_aggregator_grpc_server, create_operator_grpc_server, create_verifier_grpc_server,
    create_watchtower_grpc_server,
};
use clementine_core::utils::initialize_logger;
use clementine_core::utils::SECP;
use clementine_core::EVMAddress;
use clementine_core::UTXO;
use clementine_core::{actor::Actor, builder, musig2::AggregateFromPublicKeys};
use eyre::{Context, OptionExt, Result};
use secp256k1::rand::rngs::ThreadRng;
use tonic::Request;

mod common;

#[cfg(test)]
pub async fn run_happy_path(mut config: BridgeConfig) -> Result<()> {
    // use std::time::Duration;

    // use clementine_core::bitcoin_syncer;

    tracing::info!("Starting happy path test");

    // 1. Setup environment and actors
    tracing::info!("Setting up environment and actors");
    let (_verifiers, mut operators, mut aggregator, _watchtowers, regtest) = create_actors!(config);

    let rpc: ExtendedRpc = regtest.rpc().clone();
    let keypair = bitcoin::key::Keypair::new(&SECP, &mut ThreadRng::default());

    // let tx_sender = {
    //     let actor = Actor::new(keypair.secret_key(), None, config.network);
    //     let db = Database::new(&config)
    //         .await
    //         .expect("failed to create database");

    //     bitcoin_syncer::start_bitcoin_syncer(db.clone(), rpc.clone(), Duration::from_secs(1))
    //         .await
    //         .unwrap();

    //     let sender = TxSender::new(actor.clone(), rpc.clone(), db.clone(), config.network);
    //     sender
    //         .run("tx_sender", Duration::from_secs(0))
    //         .await
    //         .unwrap();
    //     sender
    // };

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
    let move_tx_response = aggregator
        .new_deposit(dep_params.clone())
        .await?
        .into_inner();

    tracing::info!("Move transaction sent: {:x?}", move_tx_response.txid);
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

    // Wait 1 week
    rpc.mine_blocks(7 * 24 * 6).await?;

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

    // 7. Send Ready to Reimburse Reimburse Transaction
    tracing::info!("Sending ready to reimburse reimburse transaction");
    let ready_to_reimburse = operators[0]
        .internal_create_signed_tx(TransactionRequest {
            transaction_type: Some(TransactionType::ReadyToReimburse.into()),
            ..base_tx_req.clone()
        })
        .await?
        .into_inner();
    send_confirm(&rpc, ready_to_reimburse)
        .await
        .context("failed to send ready to reimburse transaction")?;

    rpc.mine_blocks(6 * 24 + 1).await?;

    // 8. Send Reimburse Generator 1
    tracing::info!("Sending reimburse generator transaction");
    let reimburse_gen = operators[0]
        .internal_create_signed_tx(TransactionRequest {
            transaction_type: Some(TransactionType::ReimburseGenerator.into()),
            ..base_tx_req.clone()
        })
        .await?
        .into_inner();
    send_confirm(&rpc, reimburse_gen)
        .await
        .context("failed to send reimburse generator transaction")?;

    // 8. Send Happy Reimburse Transaction
    tracing::info!("Sending happy reimburse transaction");
    let happy_reimburse_tx = operators[0]
        .internal_create_signed_tx(TransactionRequest {
            transaction_type: Some(TransactionType::HappyReimburse.into()),
            ..base_tx_req.clone()
        })
        .await?
        .into_inner();
    send_confirm(&rpc, happy_reimburse_tx)
        .await
        .context("failed to send happy reimburse transaction")?;

    tracing::info!("Happy reimburse transaction sent successfully");
    tracing::info!("Happy path test completed successfully");
    Ok(())
}

async fn run_happy_path_2(mut config: BridgeConfig) -> Result<()> {
    tracing::info!("Starting happy path test");

    // 1. Setup environment and actors
    tracing::info!("Setting up environment and actors");
    let (_verifiers, mut operators, mut aggregator, mut watchtowers, regtest) =
        create_actors!(config);
    let rpc: ExtendedRpc = regtest.rpc().clone();
    let keypair = bitcoin::key::Keypair::new(&SECP, &mut ThreadRng::default());

    // let tx_sender = {
    //     let actor = Actor::new(keypair.secret_key(), None, config.network);
    //     let db = Database::new(&config)
    //         .await
    //         .expect("failed to create database");

    //     bitcoin_syncer::start_bitcoin_syncer(db.clone(), rpc.clone(), Duration::from_secs(1))
    //         .await
    //         .context("failed to start bitcoin syncer")?;

    //     let sender = TxSender::new(actor.clone(), rpc.clone(), db.clone(), config.network);
    //     sender
    //         .run("tx_sender", Duration::from_secs(0))
    //         .await
    //         .context("failed to start tx sender")?;
    //     sender
    // };

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

    let (_, _, _) = generate_withdrawal_transaction_and_signature!(
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
    let move_tx_response = aggregator
        .new_deposit(dep_params.clone())
        .await?
        .into_inner();

    // let move_tx: Transaction =
    //     Transaction::consensus_decode(&mut move_tx_response..as_slice())?;
    // rpc.client.send_raw_transaction(&move_tx).await?;
    tracing::info!("Move transaction sent: {:#?}", move_tx_response.txid);

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

    // 4. Send Kickoff Transaction
    tracing::info!("Sending kickoff transaction");
    let kickoff_tx = operators[0]
        .internal_create_signed_tx(TransactionRequest {
            transaction_type: Some(TransactionType::Kickoff.into()),
            ..base_tx_req.clone()
        })
        .await?
        .into_inner();
    send_confirm(&rpc, kickoff_tx)
        .await
        .context("failed to send kickoff transaction")?;

    // 5. Send Challenge Transaction
    tracing::info!("Sending challenge transaction");

    let challenge_txorig = operators[0]
        .internal_create_signed_tx(TransactionRequest {
            transaction_type: Some(TransactionType::Challenge.into()),
            ..base_tx_req.clone()
        })
        .await?
        .into_inner();
    let mut challenge_tx =
        Transaction::consensus_decode(&mut &challenge_txorig.raw_tx[..]).expect("valid");

    rpc.mine_blocks(1).await?;

    let amount = Amount::from_int_btc(2) + Amount::from_sat(10000);
    fund_tx(&rpc, keypair, &mut challenge_tx, amount).await?;

    let mut encoded_tx = vec![];
    tracing::info!(?challenge_tx);
    challenge_tx
        .consensus_encode(&mut encoded_tx)
        .expect("failed to encode");
    send_confirm(&rpc, RawSignedTx { raw_tx: encoded_tx })
        .await
        .context("failed to send challenge transaction")?;

    tracing::info!("Sending watchtower challenge kickoff transaction");
    let watchtower_challenge_kickoff = operators[0]
        .internal_create_signed_tx(TransactionRequest {
            transaction_type: Some(TransactionType::WatchtowerChallengeKickoff.into()),
            ..base_tx_req.clone()
        })
        .await?
        .into_inner();
    send_confirm(&rpc, watchtower_challenge_kickoff)
        .await
        .context("failed to send watchtower challenge kickoff transaction")?;

    // 6. Send Watchtower Challenge Transactions
    tracing::info!("Sending watchtower challenge transactions");
    for (i, watchtower) in watchtowers.iter_mut().enumerate() {
        let watchtower_challenge = watchtower
            .internal_create_signed_tx(TransactionRequest {
                transaction_type: Some(TransactionType::WatchtowerChallenge(i).into()),
                ..base_tx_req.clone()
            })
            .await?
            .into_inner();
        let wt_challenge_txid = rpc
            .client
            .send_raw_transaction(&watchtower_challenge.raw_tx)
            .await?;
        tracing::info!(?wt_challenge_txid);
    }

    // 7. Send Operator Challenge Acknowledgment Transaction
    tracing::info!("Sending operator challenge acknowledgment transaction");
    for i in watchtowers.iter().enumerate().map(|(i, _)| i) {
        let ack_tx = operators[0]
            .internal_create_signed_tx(TransactionRequest {
                transaction_type: Some(TransactionType::OperatorChallengeAck(i).into()),
                ..base_tx_req.clone()
            })
            .await?
            .into_inner();

        let mut ack_tx_parsed =
            Transaction::consensus_decode(&mut &ack_tx.raw_tx[..]).expect("valid tx");
        fund_tx(&rpc, keypair, &mut ack_tx_parsed, Amount::from_sat(10000)).await?;
        let encoded_tx = serialize(&ack_tx_parsed);

        rpc.client.send_raw_transaction(&encoded_tx).await?;
    }

    rpc.mine_blocks(3 * 24 * 6 * 7).await?;

    // 7. Send Operator Challenge Acknowledgment Transaction
    tracing::info!("Sending operator assert begin transaction");
    let ack_tx = operators[0]
        .internal_create_signed_tx(TransactionRequest {
            transaction_type: Some(TransactionType::AssertBegin.into()),
            ..base_tx_req.clone()
        })
        .await?
        .into_inner();
    send_confirm(&rpc, ack_tx)
        .await
        .context("failed to send operator assert begin transaction")?;

    // 8. Send Assert Transactions
    // tracing::info!("Sending assert transactions");
    // for (step_idx, (_, step_size)) in utils::BITVM_CACHE.intermediate_variables.iter().enumerate() {
    //     tracing::info!("Sending assert transaction {}", step_idx);
    //     let assert_txs = operators[0]
    //         .internal_create_signed_tx(TransactionRequest {
    //             transaction_type: Some(TransactionType::MiniAssert(step_idx).into()),
    //             commit_data: vec![0u8; *step_size],
    //             ..base_tx_req.clone()
    //         })
    //         .await?
    //         .into_inner();
    //     rpc.client.send_raw_transaction(&assert_txs.raw_tx).await?;
    // }

    // tracing::info!("Sending assert end transaction");
    // let assert_txs = operators[0]
    //     .internal_create_signed_tx(TransactionRequest {
    //         transaction_type: Some(TransactionType::AssertEnd.into()),
    //         ..base_tx_req.clone()
    //     })
    //     .await?
    //     .into_inner();
    // rpc.client.send_raw_transaction(&assert_txs.raw_tx).await?;

    // // 9. Send Disprove Timeout Transaction
    // tracing::info!("Sending disprove timeout transaction");
    // let disprove_timeout = operators[0]
    //     .internal_create_signed_tx(TransactionRequest {
    //         transaction_type: Some(TransactionType::DisproveTimeout.into()),
    //         ..base_tx_req.clone()
    //     })
    //     .await?
    //     .into_inner();
    // rpc.client
    //     .send_raw_transaction(&disprove_timeout.raw_tx)
    //     .await?;

    // // 7. Send Ready to Reimburse Reimburse Transaction
    // tracing::info!("Sending ready to reimburse reimburse transaction");
    // let ready_to_reimburse = operators[0]
    //     .internal_create_signed_tx(TransactionRequest {
    //         transaction_type: Some(TransactionType::ReadyToReimburse.into()),
    //         ..base_tx_req.clone()
    //     })
    //     .await?
    //     .into_inner();
    // rpc.client
    //     .send_raw_transaction(&ready_to_reimburse.raw_tx)
    //     .await?;

    // rpc.mine_blocks(6 * 24).await?;

    // // 8. Send Reimburse Generator 1
    // tracing::info!("Sending reimburse generator transaction");
    // let reimburse_gen = operators[0]
    //     .internal_create_signed_tx(TransactionRequest {
    //         transaction_type: Some(TransactionType::ReimburseGenerator.into()),
    //         ..base_tx_req.clone()
    //     })
    //     .await?
    //     .into_inner();
    // rpc.client
    //     .send_raw_transaction(&reimburse_gen.raw_tx)
    //     .await?;

    // // 10. Send Reimburse Transaction
    // tracing::info!("Sending reimburse transaction");
    // let reimburse_tx = operators[0]
    //     .internal_create_signed_tx(TransactionRequest {
    //         transaction_type: Some(TransactionType::Reimburse.into()),
    //         ..base_tx_req.clone()
    //     })
    //     .await?
    //     .into_inner();
    // rpc.client
    //     .send_raw_transaction(&reimburse_tx.raw_tx)
    //     .await?;

    tracing::info!("Happy path 2 test completed successfully");
    Ok(())
}

async fn fund_tx(
    rpc: &ExtendedRpc,
    keypair: bitcoin::key::Keypair,
    tx: &mut Transaction,
    amount: Amount,
) -> Result<()> {
    let some_addr = Address::p2tr(&SECP, keypair.x_only_public_key().0, None, Network::Regtest);
    let challenge_fund = rpc.send_to_address(&some_addr, amount).await?;
    rpc.mine_blocks(1).await?;

    tx.input.push(TxIn {
        previous_output: challenge_fund,
        script_sig: ScriptBuf::new(),
        sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
        witness: Witness::new(),
    });

    let mut sh = SighashCache::new(&*tx);
    let prevouts = {
        let mut v = Vec::new();
        for inp in &tx.input {
            let prevout = rpc
                .client
                .get_tx_out(
                    &inp.previous_output.txid,
                    inp.previous_output.vout,
                    Some(true),
                )
                .await?
                .ok_or_eyre("prevout should exist")?;
            v.push(TxOut {
                value: prevout.value,
                script_pubkey: prevout.script_pub_key.script().expect("..."),
            });
        }
        v
    };

    let sh = sh
        .taproot_key_spend_signature_hash(
            tx.input.len() - 1,
            &bitcoin::sighash::Prevouts::All(&prevouts),
            bitcoin::TapSighashType::Default,
        )
        .expect("...");
    tx.input.last_mut().expect("...").witness = Witness::p2tr_key_spend(
        &taproot::Signature::from_slice(
            &SECP
                .sign_schnorr(
                    &Message::from_digest(sh.to_byte_array()),
                    &keypair.add_xonly_tweak(
                        &SECP,
                        &TapTweakHash::from_key_and_tweak(keypair.x_only_public_key().0, None)
                            .to_scalar(),
                    )?,
                )
                .serialize(),
        )
        .expect("..."),
    );
    Ok(())
}
pub fn has_anchor_out(tx: &Transaction) -> bool {
    let anchor_sk = ScriptBuf::from_hex("51024e73").expect("...");
    tx.output
        .iter()
        .any(|out| out.value == ANCHOR_AMOUNT && out.script_pubkey == anchor_sk)
}

pub async fn send_confirm(
    rpc: &ExtendedRpc,
    raw_tx: RawSignedTx,
    // tx_sender: &TxSender,
) -> Result<()> {
    let tx: Transaction = consensus::deserialize(&raw_tx.raw_tx).context("expected valid tx")?;
    for (i, input) in tx.input.iter().enumerate() {
        let prevout = rpc
            .client
            .get_tx_out(
                &input.previous_output.txid,
                input.previous_output.vout,
                Some(true),
            )
            .await?;
        if prevout.is_none() {
            tracing::warn!("prevout not found for input {}", i);
        }
    }
    // if has_anchor_out(&tx) {
    //     tracing::info!("Sending with CPFP using tx sender");
    //     let txid = tx.compute_txid();
    //     let _outpoint = tx_sender.create_fee_payer_utxo(txid, tx.weight()).await?;
    //     tx_sender.save_tx(&tx).await.context("failed to save tx")?;

    //     rpc.mine_blocks(1).await?;
    //     rpc.mine_blocks(1).await?;
    //     let mut count = 1;
    //     loop {
    //         let res = rpc
    //             .client
    //             .get_raw_transaction_info(&tx.compute_txid(), None)
    //             .await;

    //         if let Ok(info) = res {
    //             if info.blockhash.is_some() {
    //                 break;
    //             }
    //         }
    //         count += 1;

    //         rpc.mine_blocks(1).await?;
    //         tokio::time::sleep(std::time::Duration::from_secs(3)).await;
    //         tracing::info!(?count, "waiting for tx to be in a block");

    //         if count > 20 {
    //             bail!("timeout while trying to send tx");
    //         }
    //     }

    //     Ok(())
    // } else
    {
        let txid = rpc.client.send_raw_transaction(&raw_tx.raw_tx).await?;
        rpc.mine_blocks(1).await?;
        let info = rpc.client.get_raw_transaction_info(&txid, None).await?;
        if info.blockhash.is_none() {
            tracing::warn!(
                ?txid,
                "transaction not in a block after one block was mined"
            );
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::create_test_config_with_thread_name;

    #[tokio::test(flavor = "multi_thread")]
    #[ignore = "Design changes in progress"]
    async fn test_happy_path_1() {
        let config = create_test_config_with_thread_name!(None);
        run_happy_path(config).await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    #[ignore = "Design changes in progress"]
    async fn test_happy_path_2() {
        let config = create_test_config_with_thread_name!(None);
        run_happy_path_2(config).await.unwrap();
    }
}
