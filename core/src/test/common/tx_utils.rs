use std::time::Duration;

use crate::builder::transaction::TransactionType as TxType;
use crate::config::BridgeConfig;
use crate::database::Database;
use crate::extended_rpc::ExtendedRpc;
use crate::rpc::clementine::SignedTxsWithType;
use crate::utils::{FeePayingType, RbfSigningInfo, TxMetadata};
use bitcoin::consensus::{self};
use bitcoin::{block, OutPoint, Transaction, Txid};
use bitcoincore_rpc::RpcApi;
use citrea_e2e::bitcoin::DEFAULT_FINALITY_DEPTH;
use citrea_e2e::config::LightClientProverConfig;
use citrea_e2e::node::Node;
use eyre::{bail, Context, Result};
use tokio::time::sleep;

use super::{mine_once_after_in_mempool, poll_until_condition};

pub fn get_tx_from_signed_txs_with_type(
    txs: &SignedTxsWithType,
    tx_type: TxType,
) -> Result<bitcoin::Transaction> {
    let tx = txs
        .signed_txs
        .iter()
        .find(|tx| tx.transaction_type == Some(tx_type.into()))
        .to_owned()
        .unwrap_or_else(|| panic!("expected tx of type: {:?} not found", tx_type))
        .to_owned()
        .raw_tx;
    bitcoin::consensus::deserialize(&tx).context("expected valid tx")
}
// Cannot use ensure_async due to `Send` requirement being broken upstream
pub async fn ensure_outpoint_spent_while_waiting_for_light_client_sync(
    rpc: &ExtendedRpc,
    lc_prover: &Node<LightClientProverConfig>,
    outpoint: OutPoint,
) -> Result<(), eyre::Error> {
    let mut timeout_counter = 300;
    while match rpc
        .client
        .get_tx_out(&outpoint.txid, outpoint.vout, Some(false))
        .await
    {
        Err(_) => true,
        Ok(val) => val.is_some(),
    } {
        // Mine more blocks and wait longer between checks
        let block_count = retry_get_block_count(&rpc, 5, Duration::from_millis(300)).await?;

        let mut total_retry = 0;
        while let Err(e) = lc_prover
            .wait_for_l1_height(block_count as u64 - DEFAULT_FINALITY_DEPTH, None)
            .await
        {
            if total_retry > 10 {
                bail!("Failed to wait for l1 height: {:?}", e);
            }
            total_retry += 1;
            tokio::time::sleep(std::time::Duration::from_millis(1000)).await;
        }
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

/// Attempts to retrieve the current block count with retry logic.
///
/// This async function queries the blockchain info from the given RPC client,
/// retrying up to `retries` times with a fixed `delay` between attempts in case of failure.
///
/// # Parameters
/// - `rpc`: Reference to the `ExtendedRpc` containing the RPC client.
/// - `retries`: Maximum number of retry attempts.
/// - `delay`: Duration to wait between retries.
///
/// # Returns
/// - `Ok(u64)`: The current block count if successful.
/// - `Err`: The final error after exhausting all retries.
///
/// # Panics
/// This function will panic with `unreachable!()` if the retry loop completes without returning.
/// In practice, this should never happen due to the early return on success or final failure.
pub async fn retry_get_block_count(
    rpc: &ExtendedRpc,
    retries: usize,
    delay: Duration,
) -> Result<u64> {
    for attempt in 0..retries {
        match rpc.client.get_blockchain_info().await {
            Ok(info) => return Ok(info.blocks),
            Err(e) if attempt + 1 < retries => {
                tracing::warn!(
                    "Retry {}/{} failed to get block count: {}. Retrying after {:?}...",
                    attempt + 1,
                    retries,
                    e,
                    delay
                );
                sleep(delay).await;
            }
            Err(e) => return Err(eyre::Error::new(e).wrap_err("Failed to get block count")),
        }
    }

    unreachable!("retry loop should either return Ok or Err")
}

pub async fn get_txid_where_utxo_is_spent_while_waiting_for_light_client_sync(
    rpc: &ExtendedRpc,
    lc_prover: &Node<LightClientProverConfig>,
    utxo: OutPoint,
) -> Result<Txid, eyre::Error> {
    ensure_outpoint_spent_while_waiting_for_light_client_sync(rpc, lc_prover, utxo).await?;
    let remaining_block_count = 30;
    // look for the txid in the last 30 blocks
    for i in 0..remaining_block_count {
        let current_height = rpc.client.get_block_count().await?;
        if current_height < i {
            bail!(
                "Not enough blocks mined to look for the utxo in the last {} blocks",
                remaining_block_count
            );
        }
        let hash = rpc.client.get_block_hash(current_height - i).await?;
        let block: block::Block = rpc.client.get_block(&hash).await?;
        if let Some(tx) = block
            .txdata
            .iter()
            .find(|txid| txid.input.iter().any(|input| input.previous_output == utxo))
        {
            return Ok(tx.compute_txid());
        }
    }
    bail!(
        "utxo {:?} not found in the last {} blocks",
        utxo,
        remaining_block_count
    );
}

// Polls until a tx that spends the outpoint is in the mempool, without mining any blocks
// After outpoint is spent, mine once to spend the utxo on chain
pub async fn mine_once_after_outpoint_spent_in_mempool(
    rpc: &ExtendedRpc,
    outpoint: OutPoint,
) -> Result<(), eyre::Error> {
    let mut timeout_counter = 300;
    while rpc
        .client
        .get_tx_out(&outpoint.txid, outpoint.vout, Some(true))
        .await
        .unwrap()
        .is_some()
    {
        tokio::time::sleep(std::time::Duration::from_millis(1000)).await;
        timeout_counter -= 1;

        if timeout_counter == 0 {
            bail!(
                "timeout while waiting for outpoint {:?} to be spent in mempool",
                outpoint
            );
        }
    }
    rpc.mine_blocks(1).await?;
    if rpc
        .client
        .get_tx_out(&outpoint.txid, outpoint.vout, Some(false))
        .await?
        .is_some()
    {
        bail!("Outpoint {:?} was not spent after waiting until it was spent in mempool and mining once", outpoint);
    }

    Ok(())
}

#[cfg(feature = "automation")]
// Helper function to send a transaction and mine a block
pub async fn send_tx(
    tx_sender: &crate::tx_sender::TxSenderClient,
    rpc: &ExtendedRpc,
    raw_tx: &[u8],
    tx_type: TxType,
    rbf_info: Option<RbfSigningInfo>,
) -> Result<()> {
    let tx: Transaction = consensus::deserialize(raw_tx).context("expected valid tx")?;
    let mut dbtx = tx_sender.test_dbtx().await.unwrap();

    // Try to send the transaction with CPFP first
    tx_sender
        .insert_try_to_send(
            &mut dbtx,
            Some(TxMetadata {
                tx_type,
                deposit_outpoint: None,
                kickoff_idx: None,
                operator_xonly_pk: None,
                round_idx: None,
            }),
            &tx,
            if tx_type == TxType::Challenge || matches!(tx_type, TxType::WatchtowerChallenge(_)) {
                FeePayingType::RBF
            } else {
                FeePayingType::CPFP
            },
            rbf_info,
            &[],
            &[],
            &[],
            &[],
        )
        .await
        .expect("failed to send tx");

    dbtx.commit().await?;

    if matches!(tx_type, TxType::Challenge | TxType::WatchtowerChallenge(_)) {
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
    let mut timeout_counter = 500;
    while match rpc
        .client
        .get_tx_out(&outpoint.txid, outpoint.vout, Some(false))
        .await
    {
        Err(_) => true,
        Ok(val) => val.is_some(),
    } {
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

#[cfg(feature = "automation")]
pub async fn send_tx_with_type(
    rpc: &ExtendedRpc,
    tx_sender: &crate::tx_sender::TxSenderClient,
    all_txs: &SignedTxsWithType,
    tx_type: TxType,
) -> Result<(), eyre::Error> {
    let round_tx = all_txs
        .signed_txs
        .iter()
        .find(|tx| tx.transaction_type == Some(tx_type.into()))
        .unwrap();
    send_tx(tx_sender, rpc, round_tx.raw_tx.as_slice(), tx_type, None)
        .await
        .context(format!("failed to send {:?} transaction", tx_type))?;
    Ok(())
}

#[cfg(feature = "automation")]
pub async fn create_tx_sender(
    config: &BridgeConfig,
    verifier_index: u32,
) -> Result<(crate::tx_sender::TxSenderClient, Database)> {
    let verifier_config = {
        let mut config = config.clone();
        config.db_name += &verifier_index.to_string();
        config
    };
    let db = Database::new(&verifier_config).await?;
    let tx_sender = crate::tx_sender::TxSenderClient::new(
        db.clone(),
        format!("tx_sender_test_{}", verifier_index),
    );
    Ok((tx_sender, db))
}
