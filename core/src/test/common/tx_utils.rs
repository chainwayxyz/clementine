use super::test_actors::TestActors;
use super::{mine_once_after_in_mempool, poll_until_condition};
use crate::builder::transaction::TransactionType as TxType;
use crate::citrea::CitreaClientT;
use crate::config::BridgeConfig;
use crate::database::Database;
use crate::extended_rpc::ExtendedRpc;
use crate::rpc::clementine::SignedTxsWithType;
use crate::utils::{FeePayingType, RbfSigningInfo, TxMetadata};
use bitcoin::consensus::{self};
use bitcoin::{block, OutPoint, Transaction, Txid};
use bitcoincore_rpc::RpcApi;
use citrea_e2e::config::LightClientProverConfig;
use citrea_e2e::node::Node;
use eyre::{bail, Context, Result};
use std::time::Duration;
use tokio::time::sleep;

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
pub async fn ensure_outpoint_spent_while_waiting_for_state_mngr_sync<
    C: CitreaClientT,
>(
    rpc: &ExtendedRpc,
    _lc_prover: &Node<LightClientProverConfig>,
    outpoint: OutPoint,
    actors: &TestActors<C>,
) -> Result<(), eyre::Error> {
    let mut max_blocks_to_mine = 1000;
    while match rpc
        .client
        .get_tx_out(&outpoint.txid, outpoint.vout, Some(false))
        .await
    {
        Err(_) => true,
        Ok(val) => val.is_some(),
    } {
        rpc.mine_blocks_while_synced(1, actors).await?;
        max_blocks_to_mine -= 1;

        if max_blocks_to_mine == 0 {
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

pub async fn get_txid_where_utxo_is_spent_while_waiting_for_state_mngr_sync<
    C: CitreaClientT,
>(
    rpc: &ExtendedRpc,
    lc_prover: &Node<LightClientProverConfig>,
    utxo: OutPoint,
    actors: &TestActors<C>,
) -> Result<Txid, eyre::Error> {
    ensure_outpoint_spent_while_waiting_for_state_mngr_sync(
        rpc, lc_prover, utxo, actors,
    )
    .await?;
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

#[cfg(feature = "automation")]
pub async fn wait_for_fee_payer_utxos_to_be_in_mempool(
    rpc: &ExtendedRpc,
    db: Database,
    txid: Txid,
) -> Result<(), eyre::Error> {
    let rpc_clone = rpc.clone();
    poll_until_condition(
        async move || {
            let tx_id = db.get_id_from_txid(None, txid).await?.unwrap();
            tracing::debug!("Waiting for fee payer utxos for tx_id: {:?}", tx_id);
            let fee_payer_utxos = db.get_fee_payer_utxos_for_tx(None, tx_id).await?;
            tracing::debug!(
                "For TXID {:?}, fee payer utxos: {:?}",
                txid,
                fee_payer_utxos
            );

            if fee_payer_utxos.is_empty() {
                tracing::error!("No fee payer utxos found in db for txid {}", txid);
                return Ok(false);
            }

            for fee_payer in fee_payer_utxos.iter() {
                let entry = rpc_clone.client.get_mempool_entry(&fee_payer.0).await;

                if entry.is_err() {
                    tracing::error!(
                        "Fee payer utxo with txid of {} is not in mempool: {:?}",
                        fee_payer.0,
                        entry
                    );
                    return Ok(false);
                }
            }

            Ok(true)
        },
        None,
        None,
    )
    .await?;

    Ok(())
}
