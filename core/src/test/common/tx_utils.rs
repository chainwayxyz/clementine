use std::time::Duration;

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

use super::{mine_once_after_in_mempool, poll_until_condition};

// Cannot use ensure_async due to `Send` requirement being broken upstream
pub async fn ensure_outpoint_spent_while_waiting_for_light_client_sync(
    rpc: &ExtendedRpc,
    lc_prover: &Node<LightClientProverConfig>,
    outpoint: OutPoint,
) -> Result<(), eyre::Error> {
    let mut timeout_counter = 300;
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
    if let TxType::WatchtowerChallenge(_) = tx_type {
        // Please manually insert it with the correct RBF spending info.
        tracing::error!("Attempting to send watchtower challenge tx with send_tx which does not support RBF with PSBT");
    }

    // Try to send the transaction with CPFP first
    tx_sender
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
            if tx_type == TxType::Challenge {
                FeePayingType::RBF
            } else {
                FeePayingType::CPFP
            },
            None,
            &[],
            &[],
            &[],
            &[],
        )
        .await
        .expect("failed to send tx");

    dbtx.commit().await?;

    if tx_type == TxType::Challenge {
        ensure_outpoint_spent(rpc, tx.input[0].previous_output).await?;
    } else {
        ensure_tx_onchain(rpc, tx.compute_txid()).await?;
    }

    Ok(())
}

/// Helper function that ensures that utxo is spent then gets the txid where it was spent
/// Be careful that this function will only work if utxo is not already spent.
pub async fn get_txid_where_utxo_is_spent(
    rpc: &ExtendedRpc,
    utxo: OutPoint,
) -> Result<Txid, eyre::Error> {
    ensure_outpoint_spent(rpc, utxo).await?;
    let current_height = rpc.client.get_block_count().await?;
    let hash = rpc.client.get_block_hash(current_height).await?;
    let block = rpc.client.get_block(&hash).await?;
    let tx = block
        .txdata
        .iter()
        .find(|txid| txid.input.iter().any(|input| input.previous_output == utxo))
        .ok_or(eyre::eyre!(
            "utxo not found in block where utxo was supposedly spent"
        ))?;
    Ok(tx.compute_txid())
}

pub async fn ensure_tx_onchain(rpc: &ExtendedRpc, tx: Txid) -> Result<(), eyre::Error> {
    poll_until_condition(
        async || {
            if rpc
                .client
                .get_raw_transaction_info(&tx, None)
                .await
                .ok()
                .and_then(|s| s.blockhash)
                .is_some()
            {
                return Ok(true);
            }

            // Mine more blocks and wait longer between checks - wait for fee payer tx to be sent to mempool
            rpc.mine_blocks(1).await?;
            // mine after tx is sent to mempool - with a timeout
            let _ = mine_once_after_in_mempool(rpc, tx, Some("ensure_tx_onchain"), Some(1)).await;
            Ok(false)
        },
        None,
        None,
    )
    .await
    .wrap_err("Timed out while waiting for tx to land onchain")?;
    Ok(())
}

pub async fn ensure_outpoint_spent(
    rpc: &ExtendedRpc,
    outpoint: OutPoint,
) -> Result<(), eyre::Error> {
    poll_until_condition(
        async || {
            rpc.mine_blocks(1).await?;
            rpc.is_utxo_spent(&outpoint).await.map_err(Into::into)
        },
        Some(Duration::from_secs(500)),
        None,
    )
    .await
    .wrap_err_with(|| {
        format!(
            "Timed out while waiting for outpoint {:?} to be spent",
            outpoint
        )
    })?;

    rpc.client
        .get_tx_out(&outpoint.txid, outpoint.vout, Some(false))
        .await
        .wrap_err("Failed to find txout in RPC after outpoint was spent")?;
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
