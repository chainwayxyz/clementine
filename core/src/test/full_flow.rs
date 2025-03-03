use crate::actor::Actor;
use crate::builder::transaction::TransactionType;
use crate::config::BridgeConfig;
use crate::database::Database;
use crate::extended_rpc::ExtendedRpc;
use crate::rpc::clementine::{DepositParams, Empty, KickoffId, TransactionRequest};
use crate::test::common::*;
use crate::tx_sender::{FeePayingType, TxSender};
use crate::utils::SECP;
use crate::EVMAddress;
use bitcoin::consensus::{self};
use bitcoin::Transaction;
use bitcoincore_rpc::RpcApi;
use eyre::{bail, Context, Result};
use secp256k1::rand::rngs::ThreadRng;
use tonic::Request;

pub async fn run_happy_path(config: &mut BridgeConfig, rpc: ExtendedRpc) -> Result<()> {
    // use std::time::Duration;

    // use clementine_core::bitcoin_syncer;

    tracing::info!("Starting happy path test");

    // 1. Setup environment and actors
    tracing::info!("Setting up environment and actors");
    let (_verifiers, mut operators, mut aggregator, _watchtowers, _cleanup) =
        create_actors(config).await;

    let keypair = bitcoin::key::Keypair::new(&SECP, &mut ThreadRng::default());

    let verifier_0_config = {
        let mut config = config.clone();
        config.db_name += "0";
        config
    };

    tracing::info!("verifier_0_config: {:#?}", verifier_0_config);

    let tx_sender_db = Database::new(&verifier_0_config)
        .await
        .expect("failed to create database");
    let tx_sender = {
        let actor = Actor::new(
            keypair.secret_key(),
            None,
            config.protocol_paramset().network,
        );

        // This tx sender will be adding txs using verifier 0's tx sender loop
        TxSender::new(
            actor.clone(),
            rpc.clone(),
            tx_sender_db.clone(),
            "run_happy_path_1",
            config.protocol_paramset().network,
        )
    };

    let evm_address = EVMAddress([1u8; 20]);
    let (deposit_address, _) = get_deposit_address(config, evm_address)?;
    tracing::info!("Generated deposit address: {}", deposit_address);

    let recovery_taproot_address = Actor::new(
        config.secret_key,
        config.winternitz_secret_key,
        config.protocol_paramset().network,
    )
    .address;

    let withdrawal_amount = config.protocol_paramset().bridge_amount.to_sat()
        - (2 * config
            .operator_withdrawal_fee_sats
            .expect("exists in test config")
            .to_sat());
    tracing::info!("Withdrawal amount set to: {} sats", withdrawal_amount);

    // let (empty_utxo, withdrawal_tx_out, user_sig) = generate_withdrawal_transaction_and_signature(
    //     &config,
    //     &rpc,
    //     &withdrawal_address,
    //     Amount::from_sat(withdrawal_amount),
    // )
    // .await;

    // 2. Setup Aggregator
    tracing::info!("Setting up aggregator");
    aggregator.setup(Request::new(Empty {})).await?;

    // 3. Make Deposit
    tracing::info!("Making deposit transaction");
    let deposit_outpoint = rpc
        .send_to_address(&deposit_address, config.protocol_paramset().bridge_amount)
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
    // tracing::info!("Starting withdrawal process");
    // let request = Request::new(WithdrawParams {
    //     withdrawal_id: 0,
    //     input_signature: user_sig.serialize().to_vec(),
    //     input_outpoint: Some(empty_utxo.outpoint.into()),
    //     output_script_pubkey: withdrawal_tx_out.txout().script_pubkey.clone().into(),
    //     output_amount: withdrawal_amount,
    // });

    // let withdrawal_provide_txid = operators[0].withdraw(request).await?.into_inner();
    // tracing::info!("Withdrawal transaction created");

    // rpc.client
    //     .get_raw_transaction(
    //         &Txid::from_slice(&withdrawal_provide_txid.txid).expect("valid txid hash"),
    //         None,
    //     )
    //     .await?;

    let base_tx_req = TransactionRequest {
        transaction_type: Some(TransactionType::AllNeededForDeposit.into()),
        kickoff_id: Some(KickoffId {
            operator_idx: 0,
            round_idx: 0,
            kickoff_idx: 0,
        }),
        deposit_params: Some(dep_params.clone()),
    };

    let all_txs = operators[0]
        .internal_create_signed_txs(base_tx_req.clone())
        .await?
        .into_inner();

    tracing::info!("Sending round transaction");
    let round_tx = all_txs
        .signed_txs
        .iter()
        .find(|tx| tx.transaction_type == Some(TransactionType::Round.into()))
        .unwrap();
    send_tx(&tx_sender, &tx_sender_db, &rpc, round_tx.raw_tx.as_slice())
        .await
        .context("failed to send round transaction")?;

    tracing::info!("Sending kickoff transaction");
    let kickoff_tx = all_txs
        .signed_txs
        .iter()
        .find(|tx| tx.transaction_type == Some(TransactionType::Kickoff.into()))
        .unwrap();
    send_tx(
        &tx_sender,
        &tx_sender_db,
        &rpc,
        kickoff_tx.raw_tx.as_slice(),
    )
    .await
    .context("failed to send kickoff transaction")?;

    // Wait 1 week
    rpc.mine_blocks(7 * 24 * 6).await?;

    // 6. Send Start Happy Reimburse Transaction
    tracing::info!("Sending challenge timeout transaction");
    let challenge_timeout_tx = all_txs
        .signed_txs
        .iter()
        .find(|tx| tx.transaction_type == Some(TransactionType::ChallengeTimeout.into()))
        .unwrap();
    send_tx(
        &tx_sender,
        &tx_sender_db,
        &rpc,
        challenge_timeout_tx.raw_tx.as_slice(),
    )
    .await
    .context("failed to send challenge timeout transaction")?;

    // 7. Send Ready to Reimburse Reimburse Transaction
    tracing::info!("Sending ready to reimburse transaction");
    let ready_to_reimburse = all_txs
        .signed_txs
        .iter()
        .find(|tx| tx.transaction_type == Some(TransactionType::ReadyToReimburse.into()))
        .unwrap();
    send_tx(
        &tx_sender,
        &tx_sender_db,
        &rpc,
        ready_to_reimburse.raw_tx.as_slice(),
    )
    .await
    .context("failed to send ready to reimburse transaction")?;

    rpc.mine_blocks(6 * 24 * 2 + 1).await?;

    // 8. Send Reimburse Generator 1
    tracing::info!("Sending round 2 transaction");
    let all_txs_2 = operators[0]
        .internal_create_signed_txs(TransactionRequest {
            transaction_type: Some(TransactionType::Round.into()),
            kickoff_id: Some(KickoffId {
                operator_idx: 0,
                round_idx: 1,
                kickoff_idx: 0,
            }),
            ..base_tx_req.clone()
        })
        .await?
        .into_inner();

    let round_2 = all_txs_2
        .signed_txs
        .iter()
        .find(|tx| tx.transaction_type == Some(TransactionType::Round.into()))
        .unwrap();
    send_tx(&tx_sender, &tx_sender_db, &rpc, round_2.raw_tx.as_slice())
        .await
        .context("failed to send round 2 transaction")?;

    // 8. Send Happy Reimburse Transaction
    tracing::info!("Sending happy reimburse transaction");
    let reimburse_tx = all_txs
        .signed_txs
        .iter()
        .find(|tx| tx.transaction_type == Some(TransactionType::Reimburse.into()))
        .unwrap();
    send_tx(
        &tx_sender,
        &tx_sender_db,
        &rpc,
        reimburse_tx.raw_tx.as_slice(),
    )
    .await
    .context("failed to send reimburse transaction")?;

    tracing::info!("Reimburse transaction sent successfully");
    tracing::info!("Happy path test completed successfully");
    Ok(())
}

// async fn fund_tx(
//     rpc: &ExtendedRpc,
//     keypair: bitcoin::key::Keypair,
//     tx: &mut Transaction,
//     amount: Amount,
// ) -> Result<()> {
//     let some_addr = Address::p2tr(&SECP, keypair.x_only_public_key().0, None, Network::Regtest);
//     let challenge_fund = rpc.send_to_address(&some_addr, amount).await?;
//     rpc.mine_blocks(1).await?;

//     tx.input.push(TxIn {
//         previous_output: challenge_fund,
//         script_sig: ScriptBuf::new(),
//         sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
//         witness: Witness::new(),
//     });

//     let mut sh = SighashCache::new(&*tx);
//     let prevouts = {
//         let mut v = Vec::new();
//         for inp in &tx.input {
//             let prevout = rpc
//                 .client
//                 .get_tx_out(
//                     &inp.previous_output.txid,
//                     inp.previous_output.vout,
//                     Some(true),
//                 )
//                 .await?
//                 .ok_or_eyre("prevout should exist")?;
//             v.push(TxOut {
//                 value: prevout.value,
//                 script_pubkey: prevout.script_pub_key.script().expect("..."),
//             });
//         }
//         v
//     };

//     let sh = sh
//         .taproot_key_spend_signature_hash(
//             tx.input.len() - 1,
//             &bitcoin::sighash::Prevouts::All(&prevouts),
//             bitcoin::TapSighashType::Default,
//         )
//         .expect("...");
//     tx.input.last_mut().expect("...").witness = Witness::p2tr_key_spend(
//         &taproot::Signature::from_slice(
//             &SECP
//                 .sign_schnorr(
//                     &Message::from_digest(sh.to_byte_array()),
//                     &keypair.add_xonly_tweak(
//                         &SECP,
//                         &TapTweakHash::from_key_and_tweak(keypair.x_only_public_key().0, None)
//                             .to_scalar(),
//                     )?,
//                 )
//                 .serialize(),
//         )
//         .expect("..."),
//     );
//     Ok(())
// }
// // pub fn has_anchor_out(tx: &Transaction) -> bool {
// //     let anchor_sk = ScriptBuf::from_hex("51024e73").expect("...");
// //     tx.output
// //         .iter()
// //         .any(|out| out.value == ANCHOR_AMOUNT && out.script_pubkey == anchor_sk)
// // }
pub async fn send_tx(
    tx_sender: &TxSender,
    db: &Database,
    rpc: &ExtendedRpc,
    raw_tx: &[u8],
) -> Result<()> {
    let tx: Transaction = consensus::deserialize(raw_tx).context("expected valid tx")?;
    let mut dbtx = db.begin_transaction().await?;
    tx_sender
        .try_to_send(&mut dbtx, &tx, FeePayingType::CPFP, &[], &[], &[], &[])
        .await?;
    dbtx.commit().await?;
    rpc.mine_blocks(1).await?;
    let mut timeout_counter = 30;

    while rpc
        .client
        .get_raw_transaction_info(&tx.compute_txid(), None)
        .await
        .ok()
        .and_then(|s| s.blockhash)
        .is_none()
    {
        rpc.mine_blocks(1).await?;
        tokio::time::sleep(std::time::Duration::from_secs(3)).await;
        timeout_counter -= 1;

        if timeout_counter == 0 {
            bail!(
                "timeout while trying to send tx with txid {:?}",
                tx.compute_txid()
            );
        }
    }

    Ok(())
}
// pub async fn send_confirm(
//     rpc: &ExtendedRpc,
//     raw_tx: RawSignedTx,
//     // tx_sender: &TxSender,
// ) -> Result<()> {
//     let tx: Transaction = consensus::deserialize(&raw_tx.raw_tx).context("expected valid tx")?;
//     for (i, input) in tx.input.iter().enumerate() {
//         let prevout = rpc
//             .client
//             .get_tx_out(
//                 &input.previous_output.txid,
//                 input.previous_output.vout,
//                 Some(true),
//             )
//             .await?;
//         if prevout.is_none() {
//             tracing::warn!("prevout not found for input {}", i);
//         }
//     }
//     // if has_anchor_out(&tx) {
//     //     tracing::info!("Sending with CPFP using tx sender");
//     //     let txid = tx.compute_txid();
//     //     let _outpoint = tx_sender.create_fee_payer_utxo(txid, tx.weight()).await?;
//     //     tx_sender.save_tx(&tx).await.context("failed to save tx")?;

//     //     rpc.mine_blocks(1).await?;
//     //     rpc.mine_blocks(1).await?;
//     //     let mut count = 1;
//     //     loop {
//     //         let res = rpc
//     //             .client
//     //             .get_raw_transaction_info(&tx.compute_txid(), None)
//     //             .await;

//     //         if let Ok(info) = res {
//     //             if info.blockhash.is_some() {
//     //                 break;
//     //             }
//     //         }
//     //         count += 1;

//     //         rpc.mine_blocks(1).await?;
//     //         tokio::time::sleep(std::time::Duration::from_secs(3)).await;
//     //         tracing::info!(?count, "waiting for tx to be in a block");

//     //         if count > 20 {
//     //             bail!("timeout while trying to send tx");
//     //         }
//     //     }

//     //     Ok(())
//     // } else
//     {
//         let txid = rpc.client.send_raw_transaction(&raw_tx.raw_tx).await?;
//         rpc.mine_blocks(1).await?;
//         let info = rpc.client.get_raw_transaction_info(&txid, None).await?;
//         if info.blockhash.is_none() {
//             tracing::warn!(
//                 ?txid,
//                 "transaction not in a block after one block was mined"
//             );
//         }
//         Ok(())
//     }
// }

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(flavor = "multi_thread")]
    // #[ignore = "Design changes in progress"]
    async fn test_happy_path_1() {
        let mut config = create_test_config_with_thread_name(None).await;
        let regtest = create_regtest_rpc(&mut config).await;
        let rpc = regtest.rpc().clone();
        run_happy_path(&mut config, rpc).await.unwrap();
    }
}
