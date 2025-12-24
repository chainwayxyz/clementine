use super::test_actors::TestActors;
use super::{mine_once_after_in_mempool, poll_until_condition};
use crate::actor::Actor;
#[cfg(feature = "automation")]
use crate::bitcoin_syncer::BitcoinSyncer;
use crate::builder;
use crate::builder::script::SpendPath;
use crate::builder::transaction::input::SpendableTxIn;
use crate::builder::transaction::output::UnspentTxOut;
use crate::builder::transaction::{TxHandlerBuilder, DEFAULT_SEQUENCE};
use crate::citrea::CitreaClientT;
#[cfg(feature = "automation")]
use crate::config::BridgeConfig;
use crate::constants::{MIN_TAPROOT_AMOUNT, NON_STANDARD_V3};
use crate::database::Database;
use crate::extended_bitcoin_rpc::{ExtendedBitcoinRpc, MINE_BLOCK_COUNT};
use crate::rpc::clementine::tagged_signature::SignatureId;
use crate::rpc::clementine::{NormalSignatureKind, NumberedSignatureKind, SignedTxsWithType};
use crate::task::{IntoTask, TaskExt};
use crate::test::common::citrea::CitreaE2EData;
#[cfg(feature = "automation")]
use crate::tx_sender::{TxSender, TxSenderClient};
use crate::utils::{FeePayingType, RbfSigningInfo, TxMetadata};
use bitcoin::consensus::{self};
use bitcoin::transaction::Version;
use bitcoin::{block, Amount, OutPoint, Transaction, TxOut, Txid};
use bitcoincore_rpc::RpcApi;
use clementine_errors::BridgeError;
use clementine_primitives::TransactionType;
use clementine_primitives::TransactionType as TxType;
use eyre::{bail, Context, Result};
use std::time::Duration;
use tokio::sync::oneshot;
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
        .unwrap_or_else(|| panic!("expected tx of type: {tx_type:?} not found"))
        .to_owned()
        .raw_tx;
    bitcoin::consensus::deserialize(&tx).context("expected valid tx")
}
// Cannot use ensure_async due to `Send` requirement being broken upstream
pub async fn ensure_outpoint_spent_while_waiting_for_state_mngr_sync<C: CitreaClientT>(
    rpc: &ExtendedBitcoinRpc,
    outpoint: OutPoint,
    actors: &TestActors<C>,
    e2e: Option<&CitreaE2EData<'_>>,
) -> Result<(), eyre::Error> {
    let mut max_blocks_to_mine = 1000;
    while match rpc
        .get_tx_out(&outpoint.txid, outpoint.vout, Some(false))
        .await
    {
        Err(_) => true,
        Ok(val) => val.is_some(),
    } {
        rpc.mine_blocks_while_synced(MINE_BLOCK_COUNT, actors, e2e)
            .await?;
        max_blocks_to_mine -= MINE_BLOCK_COUNT;

        if max_blocks_to_mine == 0 {
            bail!(
                "timeout while waiting for outpoint {:?} to be spent",
                outpoint
            );
        }
    }
    rpc.get_tx_out(&outpoint.txid, outpoint.vout, Some(false))
        .await?;

    Ok(())
}

/// Attempts to retrieve the current block count with retry logic.
///
/// This async function queries the blockchain info from the given RPC client,
/// retrying up to `retries` times with a fixed `delay` between attempts in case of failure.
///
/// # Parameters
/// - `rpc`: Reference to the `ExtendedBitcoinRpc` containing the RPC client.
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
    rpc: &ExtendedBitcoinRpc,
    retries: usize,
    delay: Duration,
) -> Result<u64> {
    for attempt in 0..retries {
        match rpc.get_blockchain_info().await {
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

pub async fn get_txid_where_utxo_is_spent_while_waiting_for_state_mngr_sync<C: CitreaClientT>(
    rpc: &ExtendedBitcoinRpc,
    utxo: OutPoint,
    actors: &TestActors<C>,
    e2e: Option<&CitreaE2EData<'_>>,
) -> Result<Txid, eyre::Error> {
    ensure_outpoint_spent_while_waiting_for_state_mngr_sync(rpc, utxo, actors, e2e).await?;
    let remaining_block_count = 30;
    // look for the txid in the last 30 blocks
    for i in 0..remaining_block_count {
        let current_height = rpc.get_block_count().await?;
        if current_height < i {
            bail!(
                "Not enough blocks mined to look for the utxo in the last {} blocks",
                remaining_block_count
            );
        }
        let hash = rpc.get_block_hash(current_height - i).await?;
        let block: block::Block = rpc.get_block(&hash).await?;
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
    rpc: &ExtendedBitcoinRpc,
    outpoint: OutPoint,
) -> Result<(), eyre::Error> {
    let mut timeout_counter = 600;
    while rpc
        .get_tx_out(&outpoint.txid, outpoint.vout, Some(true))
        .await
        .unwrap()
        .is_some()
    {
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
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
    rpc: &ExtendedBitcoinRpc,
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
    rpc: &ExtendedBitcoinRpc,
    utxo: OutPoint,
) -> Result<Txid, eyre::Error> {
    ensure_outpoint_spent(rpc, utxo).await?;
    let current_height = rpc.get_block_count().await?;
    for i in 0..MINE_BLOCK_COUNT * 2 {
        let hash = rpc.get_block_hash(current_height - i).await?;
        let block = rpc.get_block(&hash).await?;
        let tx = block
            .txdata
            .iter()
            .find(|txid| txid.input.iter().any(|input| input.previous_output == utxo));
        if let Some(tx) = tx {
            return Ok(tx.compute_txid());
        }
    }
    bail!(
        "utxo {:?} not found in the last {} blocks",
        utxo,
        MINE_BLOCK_COUNT * 2
    );
}

pub async fn ensure_tx_onchain(rpc: &ExtendedBitcoinRpc, tx: Txid) -> Result<(), eyre::Error> {
    poll_until_condition(
        async || {
            if rpc
                .get_raw_transaction_info(&tx, None)
                .await
                .ok()
                .and_then(|s| s.blockhash)
                .is_some()
            {
                return Ok(true);
            }

            // Mine more blocks and wait longer between checks - wait for fee payer tx to be sent to mempool
            rpc.mine_blocks(MINE_BLOCK_COUNT).await?;
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
    rpc: &ExtendedBitcoinRpc,
    outpoint: OutPoint,
) -> Result<(), eyre::Error> {
    poll_until_condition(
        async || {
            rpc.mine_blocks(MINE_BLOCK_COUNT).await?;
            match rpc.is_utxo_spent(&outpoint).await {
                Ok(spent) => Ok(spent),
                Err(e) => {
                    tracing::warn!("Error while checking if outpoint is spent: {e}");
                    Ok(false)
                }
            }
        },
        Some(Duration::from_secs(500)),
        None,
    )
    .await
    .wrap_err_with(|| format!("Timed out while waiting for outpoint {outpoint:?} to be spent"))?;

    rpc.get_tx_out(&outpoint.txid, outpoint.vout, Some(false))
        .await
        .wrap_err("Failed to find txout in RPC after outpoint was spent")?;
    Ok(())
}

#[cfg(feature = "automation")]
pub async fn send_tx_with_type(
    rpc: &ExtendedBitcoinRpc,
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
        .context(format!("failed to send {tx_type:?} transaction"))?;
    Ok(())
}

#[cfg(feature = "automation")]
pub async fn create_tx_sender(
    config: BridgeConfig,
    verifier_index: u32,
) -> (
    TxSender,
    BitcoinSyncer,
    ExtendedBitcoinRpc,
    Database,
    Actor,
    bitcoin::Network,
) {
    use crate::bitcoin_syncer::BitcoinSyncer;
    use bitcoin::secp256k1::SecretKey;

    let sk = SecretKey::new(&mut rand::thread_rng());
    let network = config.protocol_paramset().network;
    let actor: Actor = Actor::new(sk, network);

    let config = {
        let mut config = config.clone();
        config.db_name += &verifier_index.to_string();
        config
    };

    let rpc = ExtendedBitcoinRpc::connect(
        config.bitcoin_rpc_url.clone(),
        config.bitcoin_rpc_user.clone(),
        config.bitcoin_rpc_password.clone(),
        None,
    )
    .await
    .unwrap();

    let db = Database::new(&config).await.unwrap();

    let tx_sender = TxSender::new(
        actor.clone(),
        rpc.clone(),
        db.clone(),
        format!("tx_sender_test_{verifier_index}"),
        config.clone(),
    );

    (
        tx_sender,
        BitcoinSyncer::new(db.clone(), rpc.clone(), config.protocol_paramset())
            .await
            .unwrap(),
        rpc,
        db,
        actor,
        network,
    )
}

#[cfg(feature = "automation")]
pub async fn create_bg_tx_sender(
    config: BridgeConfig,
) -> (
    TxSenderClient,
    TxSender,
    Vec<oneshot::Sender<()>>,
    ExtendedBitcoinRpc,
    Database,
    Actor,
    bitcoin::Network,
) {
    use crate::test::common::initialize_database;

    // create the db for the tx sender
    let mut new_config = config.clone();
    new_config.db_name += "0";
    initialize_database(&new_config).await;
    let (tx_sender, syncer, rpc, db, actor, network) = create_tx_sender(config, 0).await;

    let sender_task = tx_sender.clone().into_task().cancelable_loop();
    sender_task.0.into_bg();

    let syncer_task = syncer.into_task().cancelable_loop();
    syncer_task.0.into_bg();

    (
        tx_sender.client(),
        tx_sender,
        vec![sender_task.1, syncer_task.1],
        rpc,
        db,
        actor,
        network,
    )
}

#[cfg(feature = "automation")]
pub async fn create_bumpable_tx(
    rpc: &ExtendedBitcoinRpc,
    signer: &Actor,
    network: bitcoin::Network,
    fee_paying_type: FeePayingType,
    requires_rbf_signing_info: bool,
) -> Result<Transaction, BridgeError> {
    let (address, spend_info) =
        builder::address::create_taproot_address(&[], Some(signer.xonly_public_key), network);

    let amount = Amount::from_sat(100000);
    let outpoint = rpc.send_to_address(&address, amount).await?;
    rpc.mine_blocks(1).await?;

    let version = match fee_paying_type {
        FeePayingType::CPFP => NON_STANDARD_V3,
        FeePayingType::RBF | FeePayingType::NoFunding => Version::TWO,
    };

    let mut txhandler = TxHandlerBuilder::new(TransactionType::Dummy)
        .with_version(version)
        .add_input(
            match fee_paying_type {
                FeePayingType::CPFP => {
                    SignatureId::from(NormalSignatureKind::OperatorSighashDefault)
                }
                FeePayingType::RBF if !requires_rbf_signing_info => {
                    NormalSignatureKind::Challenge.into()
                }
                FeePayingType::RBF => (NumberedSignatureKind::WatchtowerChallenge, 0i32).into(),
                FeePayingType::NoFunding => {
                    unreachable!("AlreadyFunded should not be used for bumpable txs")
                }
            },
            SpendableTxIn::new(
                outpoint,
                TxOut {
                    value: amount,
                    script_pubkey: address.script_pubkey(),
                },
                vec![],
                Some(spend_info),
            ),
            SpendPath::KeySpend,
            DEFAULT_SEQUENCE,
        )
        .add_output(UnspentTxOut::from_partial(TxOut {
            value: amount
                - match fee_paying_type {
                    FeePayingType::CPFP => Amount::from_sat(0), // for cpfp create a 0 fee tx
                    FeePayingType::RBF | FeePayingType::NoFunding => MIN_TAPROOT_AMOUNT * 3, // buffer so that rbf works without adding inputs
                },
            script_pubkey: address.script_pubkey(), // In practice, should be the wallet address, not the signer address
        }))
        .add_output(UnspentTxOut::from_partial(
            builder::transaction::anchor_output(Amount::from_sat(0)),
        ))
        .finalize();

    signer
        .tx_sign_and_fill_sigs(&mut txhandler, &[], None)
        .unwrap();

    let tx = txhandler.get_cached_tx().clone();
    Ok(tx)
}

#[cfg(feature = "automation")]
pub async fn wait_for_fee_payer_utxos_to_be_in_mempool(
    rpc: &ExtendedBitcoinRpc,
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
                let entry = rpc_clone.get_mempool_entry(&fee_payer.0).await;

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
