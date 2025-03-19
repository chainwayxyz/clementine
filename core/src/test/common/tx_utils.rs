use crate::builder::transaction::TransactionType as TxType;
use crate::extended_rpc::ExtendedRpc;
use crate::rpc::clementine::SignedTxsWithType;
use crate::tx_sender::{FeePayingType, TxMetadata, TxSenderClient};
use bitcoin::consensus::{self};
use bitcoin::{OutPoint, Transaction, Txid};
use bitcoincore_rpc::RpcApi;
use citrea_e2e::bitcoin::DEFAULT_FINALITY_DEPTH;
use citrea_e2e::config::LightClientProverConfig;
use citrea_e2e::node::Node;
use eyre::{bail, Context, Result};

pub async fn ensure_outpoint_spent_while_waiting_for_light_client_sync(
    rpc: &ExtendedRpc,
    lc_prover: &Node<LightClientProverConfig>,
    outpoint: OutPoint,
) -> Result<(), eyre::Error> {
    let mut timeout_counter = 1000;
    while rpc
        .client
        .get_tx_out(&outpoint.txid, outpoint.vout, Some(false))
        .await
        .unwrap()
        .is_some()
    {
        // Mine more blocks and wait longer between checks
        let block_count = rpc.client.get_blockchain_info().await?.blocks;
        lc_prover
            .wait_for_l1_height(block_count as u64 - DEFAULT_FINALITY_DEPTH, None)
            .await
            .unwrap();
        rpc.mine_blocks(1).await?;

        tokio::time::sleep(std::time::Duration::from_millis(1000)).await;
        timeout_counter -= 1;

        if timeout_counter == 0 {
            bail!(
                "timeout while waiting for outpoint {:?} to be spent",
                outpoint
            );
        }
    }
    rpc.client
        .get_tx_out(&outpoint.txid, outpoint.vout, Some(false))
        .await?;
    Ok(())
}

// Helper function to send a transaction and mine a block
pub async fn send_tx(
    tx_sender: &TxSenderClient,
    rpc: &ExtendedRpc,
    raw_tx: &[u8],
    tx_type: TxType,
) -> Result<()> {
    let tx: Transaction = consensus::deserialize(raw_tx).context("expected valid tx")?;
    let mut dbtx = tx_sender.test_dbtx().await.unwrap();

    // Try to send the transaction with CPFP first
    let send_result = tx_sender
        .insert_try_to_send(
            &mut dbtx,
            Some(TxMetadata {
                tx_type,
                deposit_outpoint: None,
                kickoff_idx: None,
                operator_idx: None,
                round_idx: None,
                verifier_idx: None,
            }),
            &tx,
            if matches!(tx_type, TxType::Challenge | TxType::WatchtowerChallenge(_)) {
                FeePayingType::RBF
            } else {
                FeePayingType::CPFP
            },
            &[],
            &[],
            &[],
            &[],
        )
        .await;

    // If CPFP fails, try with RBF
    if let Err(e) = send_result {
        tracing::warn!("Failed to send with CPFP, trying RBF: {}", e);
        tx_sender
            .insert_try_to_send(&mut dbtx, None, &tx, FeePayingType::RBF, &[], &[], &[], &[])
            .await?;
    }

    dbtx.commit().await?;

    // Mine blocks to confirm the transaction
    rpc.mine_blocks(3).await?;

    if matches!(tx_type, TxType::Challenge | TxType::WatchtowerChallenge(_)) {
        ensure_outpoint_spent(rpc, tx.input[0].previous_output).await?;
    } else {
        ensure_tx_onchain(rpc, tx.compute_txid()).await?;
    }

    Ok(())
}

pub async fn ensure_tx_onchain(rpc: &ExtendedRpc, tx: Txid) -> Result<(), eyre::Error> {
    let mut timeout_counter = 50;
    while rpc
        .client
        .get_raw_transaction_info(&tx, None)
        .await
        .ok()
        .and_then(|s| s.blockhash)
        .is_none()
    {
        // Mine more blocks and wait longer between checks
        rpc.mine_blocks(2).await?;
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        timeout_counter -= 1;

        if timeout_counter == 0 {
            bail!("timeout while trying to send tx with txid {:?}", tx);
        }
    }
    Ok(())
}

pub async fn ensure_outpoint_spent(
    rpc: &ExtendedRpc,
    outpoint: OutPoint,
) -> Result<(), eyre::Error> {
    let mut timeout_counter = 3000;
    while rpc
        .client
        .get_tx_out(&outpoint.txid, outpoint.vout, Some(false))
        .await
        .unwrap()
        .is_some()
    {
        // Mine more blocks and wait longer between checks
        rpc.mine_blocks(1).await?;
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        timeout_counter -= 1;

        if timeout_counter == 0 {
            bail!(
                "timeout while waiting for outpoint {:?} to be spent",
                outpoint
            );
        }
    }
    rpc.client
        .get_tx_out(&outpoint.txid, outpoint.vout, Some(false))
        .await?;
    Ok(())
}

pub async fn send_tx_with_type(
    rpc: &ExtendedRpc,
    tx_sender: &TxSenderClient,
    all_txs: &SignedTxsWithType,
    tx_type: TxType,
) -> Result<(), eyre::Error> {
    let round_tx = all_txs
        .signed_txs
        .iter()
        .find(|tx| tx.transaction_type == Some(tx_type.into()))
        .unwrap();
    send_tx(tx_sender, rpc, round_tx.raw_tx.as_slice(), tx_type)
        .await
        .context(format!("failed to send {:?} transaction", tx_type))?;
    Ok(())
}
