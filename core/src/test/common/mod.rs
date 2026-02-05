//! # Common Utilities for Tests
//!
//! This module provides all the common utilities needed in unit and integration
//! tests, including:
//!
//! - Setting up databases, servers
//! - Creating test configurations
//! - Making common operations like deposits
//! - Communicating with Citrea

use crate::actor::Actor;
use crate::bitvm_client::SECP;
use crate::builder::address::create_taproot_address;
use crate::builder::script::{CheckSig, Multisig, SpendableScript};
use crate::builder::sighash::TapTweakData;
use crate::builder::transaction::input::UtxoVout;
use crate::builder::transaction::{create_replacement_deposit_txhandler, TxHandler};
use crate::citrea::CitreaClientT;
use crate::config::BridgeConfig;
use crate::database::Database;
use crate::deposit::{BaseDepositData, DepositInfo, DepositType, ReplacementDepositData};
use crate::extended_bitcoin_rpc::{ExtendedBitcoinRpc, TestRpcExtensions as _, MINE_BLOCK_COUNT};
use crate::rpc::clementine::{
    entity_status_with_id, Deposit, Empty, GetEntityStatusesRequest, SendMoveTxRequest,
};
use crate::utils::FeePayingType;
use bitcoin::secp256k1::rand;
use bitcoin::secp256k1::PublicKey;
use bitcoin::XOnlyPublicKey;
use bitcoin::{taproot, BlockHash, OutPoint, Transaction, Txid};
use bitcoincore_rpc::RpcApi;
use citrea_e2e::bitcoin::DEFAULT_FINALITY_DEPTH;
use clementine_errors::BridgeError;
use clementine_primitives::EVMAddress;
use eyre::Context;
pub use setup_utils::*;
use std::path::Path;
use std::process::Command;
use std::sync::Mutex;
use std::time::Duration;
use test_actors::TestActors;
use tokio_retry::strategy::ExponentialBackoff;
use tokio_retry::Retry;
use tonic::Request;

pub mod citrea;
#[cfg(feature = "automation")]
pub mod clementine_utils;
mod setup_utils;
pub mod test_actors;
pub mod tx_utils;

#[cfg(feature = "automation")]
use crate::test::common::tx_utils::wait_for_fee_payer_utxos_to_be_in_mempool;
#[cfg(feature = "automation")]
use tx_utils::create_tx_sender;

/// Generate a random XOnlyPublicKey
pub fn generate_random_xonly_pk() -> XOnlyPublicKey {
    let (pubkey, _parity) = SECP
        .generate_keypair(&mut rand::thread_rng())
        .1
        .x_only_public_key();

    pubkey
}

/// Polls a closure until it returns true, or the timeout is reached. Exits
/// early if the closure throws an error.
///
/// Default timeout is 60 seconds, default poll interval is 500 milliseconds.
///
/// # Parameters
///
/// - `func`: The closure to poll.
/// - `timeout`: The timeout duration.
/// - `poll_interval`: The poll interval.
///
/// # Returns
///
/// - `Ok(())`: If the condition is met.
/// - `Err(eyre::eyre!("Timeout reached"))`: If the timeout is reached.
/// - `Err(e)`: If the closure returns an error.
pub async fn poll_until_condition(
    mut func: impl AsyncFnMut() -> Result<bool, eyre::Error>,
    timeout: Option<Duration>,
    poll_interval: Option<Duration>,
) -> Result<(), BridgeError> {
    poll_get(
        async move || {
            if func().await? {
                Ok(Some(()))
            } else {
                Ok(None)
            }
        },
        timeout,
        poll_interval,
    )
    .await
}

/// Polls a closure until it returns a value, or the timeout is reached. Exits
/// early if the closure throws an error.
///
/// Default timeout is 60 seconds, default poll interval is 500 milliseconds.
///
/// # Parameters
///
/// - `func`: The closure to poll.
/// - `timeout`: The timeout duration.
/// - `poll_interval`: The poll interval.
pub async fn poll_get<T>(
    mut func: impl AsyncFnMut() -> Result<Option<T>, eyre::Error>,
    timeout: Option<Duration>,
    poll_interval: Option<Duration>,
) -> Result<T, BridgeError> {
    let timeout = timeout.unwrap_or(Duration::from_secs(90));
    let poll_interval = poll_interval.unwrap_or(Duration::from_millis(500));

    let start = std::time::Instant::now();

    loop {
        if start.elapsed() > timeout {
            return Err(eyre::eyre!(
                "Timeout of {:?} seconds reached. Poll interval was {:?} seconds",
                timeout.as_secs_f32(),
                poll_interval.as_secs_f32()
            )
            .into());
        }

        if let Some(result) = func().await? {
            return Ok(result);
        }

        tokio::time::sleep(poll_interval).await;
    }
}

/// Checks if all clementine nodes are synced.
/// State managers must be synced to the last finalized height. (If they are running)
/// Tx senders must be synced to at least current height - some buffer.
/// LCPs must be synced to the last finalized height. (We add +1 internally because its not "next" height like state manager but last synced height)
pub async fn are_all_nodes_synced<C: CitreaClientT>(
    rpc: &ExtendedBitcoinRpc,
    actors: &TestActors<C>,
) -> eyre::Result<bool> {
    let mut aggregator = actors.get_aggregator();
    let entity_statuses = aggregator
        .get_entity_statuses(Request::new(GetEntityStatusesRequest {
            restart_tasks: false,
        }))
        .await?
        .into_inner();

    let finality_depth = actors.aggregator.config.protocol_paramset().finality_depth;
    let current_chain_height = rpc.get_current_chain_height().await?;
    let current_finalized_chain_height = current_chain_height.saturating_sub(finality_depth - 1);
    // tx sender doent have to be finalized but keep some buffer so that the requirement is not too strict, so tests are faster
    let tx_sender_threshold = current_chain_height.saturating_sub(MINE_BLOCK_COUNT as u32);

    let mut min_next_sync_height = u32::MAX;
    let mut all_tx_sender_synced = true;

    let state_manager_running = actors
        .aggregator
        .config
        .test_params
        .should_run_state_manager;

    for entity in &entity_statuses.entity_statuses {
        let Some(entity_status_with_id::StatusResult::Status(status)) = &entity.status_result
        else {
            return Err(eyre::eyre!(
                "Couldn't retrieve sync status from entity {:?}, status result: {:?}",
                entity.entity_id,
                entity.status_result
            ));
        };

        if status.automation {
            min_next_sync_height = min_next_sync_height.min(
                status
                    .state_manager_next_height
                    .unwrap_or(match state_manager_running {
                        true => 0,
                        false => u32::MAX,
                    })
                    .min(status.lcp_synced_height.map(|h| h + 1).unwrap_or(0)),
            );
            let tx_sender_height = status.tx_sender_synced_height.unwrap_or(0);
            if tx_sender_height < tx_sender_threshold {
                all_tx_sender_synced = false;
            }
        } else {
            min_next_sync_height =
                min_next_sync_height.min(status.lcp_synced_height.map(|h| h + 1).unwrap_or(0));
        }
    }

    Ok((min_next_sync_height > current_finalized_chain_height) && all_tx_sender_synced)
}

/// Wait for a transaction to be in the mempool and than mines a block to make
/// sure that it is included in the next block.
///
/// # Parameters
///
/// - `rpc`: The RPC client to use.
/// - `txid`: The txid to wait for.
/// - `tx_name`: The name of the transaction to wait for.
/// - `timeout`: The timeout in seconds.
pub async fn mine_once_after_in_mempool(
    rpc: &ExtendedBitcoinRpc,
    txid: Txid,
    tx_name: Option<&str>,
    timeout: Option<u64>,
) -> Result<usize, BridgeError> {
    let timeout = timeout.unwrap_or(90);
    let start = std::time::Instant::now();
    let tx_name = tx_name.unwrap_or("Unnamed tx");
    tracing::info!("Mine once after in mempool: {} txid: {:?}", tx_name, txid);

    loop {
        if start.elapsed() > std::time::Duration::from_secs(timeout) {
            return Err(
                eyre::eyre!("{} didn't hit mempool within {} seconds", tx_name, timeout).into(),
            );
        }

        // if already mined, break
        if rpc
            .get_raw_transaction_info(&txid, None)
            .await
            .is_ok_and(|tx| tx.blockhash.is_some())
        {
            break;
        };

        tracing::info!(
            "{} is not in mempool, mempool size: {}",
            tx_name,
            rpc.mempool_size().await?
        );

        // mine if there are some txs in mempool
        if rpc.mempool_size().await? > 0 {
            rpc.mine_blocks(1).await?;
        }

        tracing::info!("Waiting for {} transaction to hit mempool...", tx_name);
        tracing::info!(
            "Rpc info about tx {}: {:?}",
            tx_name,
            rpc.get_raw_transaction_info(&txid, None).await
        );
        tokio::time::sleep(std::time::Duration::from_millis(1000)).await;
    }

    let tx: bitcoincore_rpc::json::GetRawTransactionResult = rpc
        .get_raw_transaction_info(&txid, None)
        .await
        .map_err(|e| eyre::eyre!("Failed to get raw transaction {}: {}", tx_name, e))?;

    if tx.blockhash.is_none() {
        return Err(eyre::eyre!("{} did not get mined", tx_name).into());
    }

    let tx_block_height = rpc
        .get_block_info(&tx.blockhash.unwrap())
        .await
        .wrap_err("Failed to get block info")?;

    Ok(tx_block_height.height)
}

pub async fn run_multiple_deposits<C: CitreaClientT>(
    config: &mut BridgeConfig,
    rpc: ExtendedBitcoinRpc,
    count: usize,
    actors: &TestActors<C>,
) -> Result<(Vec<DepositInfo>, Vec<Txid>, Vec<BlockHash>, Vec<PublicKey>), BridgeError> {
    let mut aggregator = actors.get_aggregator();

    let evm_address = EVMAddress([1u8; 20]);
    let actor = Actor::new(config.secret_key, config.protocol_paramset().network);

    let verifiers_public_keys: Vec<PublicKey> = aggregator
        .setup(Request::new(Empty {}))
        .await
        .wrap_err("Can't setup aggregator")?
        .into_inner()
        .try_into()?;

    let (deposit_address, _) =
        get_deposit_address(config, evm_address, verifiers_public_keys.clone())?;
    let mut move_txids = Vec::new();
    let mut deposit_blockhashes = Vec::new();
    let mut deposit_infos = Vec::new();

    for _ in 0..count {
        let deposit_outpoint: OutPoint = rpc
            .send_to_address(&deposit_address, config.protocol_paramset().bridge_amount)
            .await?;
        rpc.mine_blocks_while_synced(DEFAULT_FINALITY_DEPTH + 1, actors, None)
            .await?;

        let deposit_info = DepositInfo {
            deposit_outpoint,
            deposit_type: DepositType::BaseDeposit(BaseDepositData {
                evm_address,
                recovery_taproot_address: actor.address.as_unchecked().to_owned(),
            }),
        };

        deposit_infos.push(deposit_info.clone());

        let deposit: Deposit = deposit_info.into();

        let movetx = aggregator
            .new_deposit(deposit)
            .await
            .wrap_err("Error while making a deposit")?
            .into_inner();
        let move_txid = aggregator
            .send_move_to_vault_tx(SendMoveTxRequest {
                deposit_outpoint: Some(deposit_outpoint.into()),
                raw_tx: Some(movetx),
            })
            .await
            .expect("failed to send movetx")
            .into_inner()
            .try_into()?;

        if !rpc.is_tx_on_chain(&move_txid).await? {
            mine_once_after_in_mempool(&rpc, move_txid, Some("Move tx"), Some(180)).await?;
        }

        let deposit_blockhash = rpc.get_blockhash_of_tx(&deposit_outpoint.txid).await?;
        deposit_blockhashes.push(deposit_blockhash);
        move_txids.push(move_txid);
    }

    Ok((
        deposit_infos,
        move_txids,
        deposit_blockhashes,
        verifiers_public_keys,
    ))
}

/// Creates a user deposit transaction and makes a new deposit call to
/// Clementine via aggregator.
///
/// # Parameters
///
/// - `config` [`BridgeConfig`]: The bridge configuration.
/// - `rpc` [`ExtendedBitcoinRpc`]: The RPC client to use.
/// - `evm_address` [`EVMAddress`]: Optional EVM address to use for the
///   deposit. If not provided, a default address is used.
/// - `actors` [`TestActors`]: Optional actors to use for the deposit. If not
///   provided, a new actors will be created.
/// - `deposit_outpoint` [`OutPoint`]: Optional deposit outpoint to use for the
///   deposit. If not provided, a new deposit outpoint will be created.
///
/// # Returns
///
/// A big tuple, containing:
///
/// - Server clients:
///    - [`TestActors`]: A helper struct holding all the verifiers, operators, and the aggregator.
/// - [`DepositInfo`]: Information about the deposit.
/// - [`Txid`]: TXID of the move transaction.
/// - [`BlockHash`]: Block hash of the block where the user deposit was mined.
/// - [`Vec<PublicKey>`]: Public keys of the verifiers used in the deposit.
pub async fn run_single_deposit<C: CitreaClientT>(
    config: &mut BridgeConfig,
    rpc: ExtendedBitcoinRpc,
    evm_address: Option<EVMAddress>,
    actors: &TestActors<C>,
    deposit_outpoint: Option<OutPoint>, // if a deposit outpoint is provided, it will be used instead of creating a new one
) -> Result<(DepositInfo, Txid, BlockHash, Vec<PublicKey>), BridgeError> {
    let evm_address = evm_address.unwrap_or(EVMAddress([1u8; 20]));
    let actor = Actor::new(config.secret_key, config.protocol_paramset().network);

    let setup_start = std::time::Instant::now();
    let strategy = ExponentialBackoff::from_millis(2).factor(500).take(3);
    let verifiers_public_keys: Vec<PublicKey> = Retry::spawn(strategy, || {
        let mut aggregator = actors.get_aggregator();
        async move {
            aggregator
                .setup(Request::new(Empty {}))
                .await
                .map_err(BridgeError::from)?
                .into_inner()
                .try_into()
                .map_err(|e| BridgeError::from(eyre::eyre!("Failed to convert response: {:?}", e)))
        }
    })
    .await?;
    let setup_elapsed = setup_start.elapsed();
    tracing::info!("Setup completed in: {:?}", setup_elapsed);

    let deposit_outpoint = match deposit_outpoint {
        Some(outpoint) => outpoint,
        None => {
            let (deposit_address, _) =
                get_deposit_address(config, evm_address, verifiers_public_keys.clone())?;
            let outpoint = rpc
                .send_to_address(&deposit_address, config.protocol_paramset().bridge_amount)
                .await?;
            match config.protocol_paramset().network {
                bitcoin::Network::Regtest => {
                    mine_once_after_in_mempool(&rpc, outpoint.txid, Some("Deposit outpoint"), None)
                        .await?;
                }
                bitcoin::Network::Testnet4 => loop {
                    tracing::info!("Deposit outpoint: {:?}", outpoint);
                    if rpc.is_tx_on_chain(&outpoint.txid).await? {
                        break;
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(1000)).await;
                },
                _ => {
                    return Err(eyre::eyre!(
                        "Unsupported network: {:?}",
                        config.protocol_paramset().network
                    )
                    .into())
                }
            }
            outpoint
        }
    };

    let deposit_blockhash = rpc.get_blockhash_of_tx(&deposit_outpoint.txid).await?;

    let deposit_info = DepositInfo {
        deposit_outpoint,
        deposit_type: DepositType::BaseDeposit(BaseDepositData {
            evm_address,
            recovery_taproot_address: actor.address.as_unchecked().to_owned(),
        }),
    };

    let deposit: Deposit = deposit_info.clone().into();

    let mut aggregator = actors.get_aggregator();

    let movetx = aggregator
        .new_deposit(deposit)
        .await
        .wrap_err("Error while making a deposit")?
        .into_inner();
    let move_txid;
    #[cfg(feature = "automation")]
    {
        move_txid = aggregator
            .send_move_to_vault_tx(SendMoveTxRequest {
                deposit_outpoint: Some(deposit_outpoint.into()),
                raw_tx: Some(movetx),
            })
            .await
            .expect("failed to send movetx")
            .into_inner()
            .try_into()?;

        match config.protocol_paramset().network {
            bitcoin::Network::Regtest => {
                if !rpc.is_tx_on_chain(&move_txid).await? {
                    let aggregator_db = Database::new(&actors.aggregator.config).await?;
                    // check if deposit outpoint is spent
                    let deposit_outpoint_spent = rpc.is_utxo_spent(&deposit_outpoint).await?;
                    if deposit_outpoint_spent {
                        return Err(eyre::eyre!(
                            "Deposit outpoint is spent but move tx is not in chain. In test_bridge_contract_change
                            this means move tx does not match the one in saved state"
                            )
                            .into());
                    }
                    wait_for_fee_payer_utxos_to_be_in_mempool(&rpc, aggregator_db, move_txid)
                        .await?;
                    rpc.mine_blocks_while_synced(1, actors, None).await?;
                    mine_once_after_in_mempool(&rpc, move_txid, Some("Move tx"), Some(180)).await?;
                }
            }
            bitcoin::Network::Testnet4 => {
                tracing::info!("Move txid: {:?}", move_txid);
                loop {
                    if rpc.is_tx_on_chain(&move_txid).await? {
                        break;
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(1000)).await;
                }
            }
            _ => {
                return Err(eyre::eyre!(
                    "Unsupported network: {:?}",
                    config.protocol_paramset().network
                )
                .into())
            }
        }

        // Uncomment below to debug the move tx.
        // let transaction = rpc
        //     .get_raw_transaction(&move_txid, None)
        //     .await
        //     .expect("a");
        // let tx_info: bitcoincore_rpc::json::GetRawTransactionResult = rpc
        //     .get_raw_transaction_info(&move_txid, None)
        //     .await
        //     .expect("a");
        // let block: bitcoincore_rpc::json::GetBlockResult = rpc
        //     .get_block_info(&tx_info.blockhash.unwrap())
        //     .await
        //     .expect("a");
        // let block_height = block.height;
        // let block = rpc
        //     .get_block(&tx_info.blockhash.unwrap())
        //     .await
        //     .expect("a");
        // let transaction_params = get_citrea_deposit_params(
        //     &rpc,
        //     transaction.clone(),
        //     block,
        //     block_height as u32,
        //     move_txid,
        // ).await?;
        // println!("Move tx Transaction params: {:?}", transaction_params);
        // println!(
        //     "Move tx: {:?}",
        //     hex::encode(bitcoin::consensus::serialize(&transaction))
        // );
    }

    #[cfg(not(feature = "automation"))]
    {
        let movetx: Transaction = bitcoin::consensus::deserialize(&movetx.raw_tx)
            .wrap_err("Failed to deserialize movetx")?;
        move_txid = rpc
            .send_raw_transaction(&movetx)
            .await
            .wrap_err("Failed to send movetx")?;

        while !rpc.is_tx_on_chain(&move_txid).await? {
            rpc.mine_blocks(1).await?;
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        }
    }

    Ok((
        deposit_info,
        move_txid,
        deposit_blockhash,
        verifiers_public_keys,
    ))
}

/// Runs a single replacement deposit transaction. It will replace the old movetx using the nofn path, so it needs
/// the nofn xonly public key and secret keys of the old signer set that signed the previous movetx.
///
/// # Parameters
///
/// - `config` [`BridgeConfig`]: The bridge configuration.
/// - `rpc` [`ExtendedBitcoinRpc`]: The RPC client to use.
/// - `old_move_txid` [`Txid`]: The TXID of the old move transaction.
/// - `current_actors` [`TestActors`]: The actors to use for the replacement deposit.
/// - `old_nofn_xonly_pk` [`XOnlyPublicKey`]: The nofn xonly public key of the old signer set that signed previous movetx.
/// - `old_secret_keys` [`Vec<SecretKey>`]: The secret keys of the old signer set that signed previous movetx.
///
/// # Returns
///
/// A big tuple, containing:
///
/// - Server clients:
///    - [`TestActors`]: A helper struct holding all the verifiers, operators, and the aggregator.
/// - [`DepositInfo`]: Information about the deposit.
/// - [`Txid`]: TXID of the move transaction.
/// - [`BlockHash`]: Block hash of the block where the user deposit was mined.
#[cfg(feature = "automation")]
pub async fn run_single_replacement_deposit<C: CitreaClientT>(
    config: &mut BridgeConfig,
    rpc: &ExtendedBitcoinRpc,
    old_move_txid: Txid,
    actors: &TestActors<C>,
    old_nofn_xonly_pk: XOnlyPublicKey,
) -> Result<(DepositInfo, Txid, BlockHash), BridgeError> {
    let aggregator_db = Database::new(&BridgeConfig {
        db_name: config.db_name.clone() + "0",
        ..config.clone()
    })
    .await?;

    // create a replacement deposit tx, we will sign it using nofn
    let replacement_deposit_txid =
        send_replacement_deposit_tx(config, rpc, old_move_txid, actors, old_nofn_xonly_pk).await?;

    let deposit_outpoint = OutPoint {
        txid: replacement_deposit_txid,
        vout: 0,
    };

    let setup_start = std::time::Instant::now();
    let mut aggregator = actors.get_aggregator();
    tracing::info!(
        "Current chain height before aggregator setup: {:?}",
        rpc.get_current_chain_height().await?
    );
    aggregator
        .setup(Request::new(Empty {}))
        .await
        .wrap_err("Failed to setup aggregator")?;

    let setup_elapsed = setup_start.elapsed();
    tracing::info!("Setup completed in: {:?}", setup_elapsed);

    let deposit_blockhash = rpc.get_blockhash_of_tx(&deposit_outpoint.txid).await?;

    let deposit_info = DepositInfo {
        deposit_outpoint,
        deposit_type: DepositType::ReplacementDeposit(ReplacementDepositData { old_move_txid }),
    };

    let deposit: Deposit = deposit_info.clone().into();

    let movetx = aggregator
        .new_deposit(deposit)
        .await
        .wrap_err("Error while making a replacement deposit")?
        .into_inner();
    let move_txid = aggregator
        .send_move_to_vault_tx(SendMoveTxRequest {
            deposit_outpoint: Some(deposit_outpoint.into()),
            raw_tx: Some(movetx),
        })
        .await
        .expect("failed to send movetx")
        .into_inner()
        .try_into()?;

    if !rpc.is_tx_on_chain(&move_txid).await? {
        wait_for_fee_payer_utxos_to_be_in_mempool(rpc, aggregator_db, move_txid).await?;
        rpc.mine_blocks_while_synced(1, actors, None).await?;
        mine_once_after_in_mempool(rpc, move_txid, Some("Move tx"), Some(180)).await?;
    }

    Ok((deposit_info, move_txid, deposit_blockhash))
}

/// Signs a replacement deposit transaction using the security council
fn sign_replacement_deposit_tx_with_sec_council(
    replacement_deposit: &TxHandler,
    config: &BridgeConfig,
    old_nofn_xonly_pk: XOnlyPublicKey,
) -> Result<Transaction, BridgeError> {
    let security_council = config.security_council.clone();
    let multisig_script = Multisig::from_security_council(security_council.clone()).to_script_buf();
    let sighash = replacement_deposit.calculate_script_spend_sighash(
        0,
        &multisig_script,
        bitcoin::TapSighashType::SinglePlusAnyoneCanPay,
    )?;

    // sign using first threshold security council members, for rest do not sign
    let signatures = config
        .test_params
        .sec_council_secret_keys
        .iter()
        .enumerate()
        .map(|(idx, sk)| {
            if idx < security_council.threshold as usize {
                let actor = Actor::new(*sk, config.protocol_paramset().network);
                let sig = actor
                    .sign_with_tweak_data(sighash, TapTweakData::ScriptPath, None)
                    .unwrap();
                Some(taproot::Signature {
                    signature: sig,
                    sighash_type: bitcoin::TapSighashType::SinglePlusAnyoneCanPay,
                })
            } else {
                None
            }
        })
        .collect::<Vec<_>>();

    let mut witness =
        Multisig::from_security_council(security_council).generate_script_inputs(&signatures)?;

    // calculate address in movetx vault
    let script_buf = CheckSig::new(old_nofn_xonly_pk).to_script_buf();
    let (_, spend_info) = create_taproot_address(
        &[script_buf.clone(), multisig_script.clone()],
        None,
        config.protocol_paramset().network,
    );
    // add script path to witness
    Actor::add_script_path_to_witness(&mut witness, &multisig_script, &spend_info)?;
    let mut tx = replacement_deposit.get_cached_tx().clone();
    // add witness to tx
    tx.input[0].witness = witness;
    Ok(tx)
}

#[cfg(feature = "automation")]
async fn send_replacement_deposit_tx<C: CitreaClientT>(
    config: &BridgeConfig,
    rpc: &ExtendedBitcoinRpc,
    old_move_txid: Txid,
    actors: &TestActors<C>,
    old_nofn_xonly_pk: XOnlyPublicKey,
) -> Result<Txid, BridgeError> {
    // create a replacement deposit tx, we will sign it using nofn
    let replacement_txhandler = create_replacement_deposit_txhandler(
        old_move_txid,
        OutPoint {
            txid: old_move_txid,
            vout: UtxoVout::DepositInMove.get_vout(),
        },
        old_nofn_xonly_pk,
        actors.get_nofn_aggregated_xonly_pk()?,
        config.protocol_paramset(),
        config.security_council.clone(),
    )?;

    let signed_replacement_deposit_tx = sign_replacement_deposit_tx_with_sec_council(
        &replacement_txhandler,
        config,
        old_nofn_xonly_pk,
    )?;

    let (tx_sender, _, tx_sender_db, _, _) = create_tx_sender(config.clone(), 0).await;
    let mut db_commit = tx_sender_db.begin_transaction().await?;
    tx_sender
        .client()
        .insert_try_to_send(
            &mut db_commit,
            None,
            &signed_replacement_deposit_tx,
            FeePayingType::CPFP,
            None,
            &[],
            &[],
            &[],
            &[],
        )
        .await
        .unwrap();
    db_commit.commit().await?;

    let replacement_deposit_txid = signed_replacement_deposit_tx.compute_txid();

    wait_for_fee_payer_utxos_to_be_in_mempool(rpc, tx_sender_db, replacement_deposit_txid).await?;

    mine_once_after_in_mempool(
        rpc,
        replacement_deposit_txid,
        Some("Replacement deposit"),
        Some(180),
    )
    .await?;
    tracing::info!(
        "Replacement deposit sent, txid: {}",
        replacement_deposit_txid
    );

    Ok(replacement_deposit_txid)
}

/// Ensures that TLS certificates exist for tests.
/// This will run the certificate generation script if certificates don't exist.
pub fn ensure_test_certificates() -> Result<(), std::io::Error> {
    static GENERATE_LOCK: Mutex<()> = Mutex::new(());

    while !Path::new("./certs/ca/ca.pem").exists() {
        if let Ok(_lock) = GENERATE_LOCK.lock() {
            println!("Generating TLS certificates for tests...");

            let output = Command::new("sh")
                .arg("-c")
                .arg("cd .. && ./scripts/generate_certs.sh")
                .output()?;

            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                eprintln!("Failed to generate certificates: {stderr}");
                return Err(std::io::Error::other(format!(
                    "Certificate generation failed: {stderr}"
                )));
            }

            println!("TLS certificates generated successfully");
            break;
        }
    }

    Ok(())
}

mod tests {
    #[cfg(feature = "integration-tests")]
    #[tokio::test]
    async fn test_regtest_create_and_connect() {
        use crate::{
            extended_bitcoin_rpc::ExtendedBitcoinRpc,
            test::common::{create_regtest_rpc, create_test_config_with_thread_name},
        };
        use bitcoincore_rpc::RpcApi;

        let mut config = create_test_config_with_thread_name().await;

        let regtest = create_regtest_rpc(&mut config).await;

        let macro_rpc = regtest.rpc();
        let rpc = ExtendedBitcoinRpc::connect(
            config.bitcoin_rpc_url.clone(),
            config.bitcoin_rpc_user.clone(),
            config.bitcoin_rpc_password.clone(),
            None,
        )
        .await
        .unwrap();

        macro_rpc.mine_blocks(1).await.unwrap();
        let height = macro_rpc.get_block_count().await.unwrap();
        let new_rpc_height = rpc.get_block_count().await.unwrap();
        assert_eq!(height, new_rpc_height);

        rpc.mine_blocks(1).await.unwrap();
        let new_rpc_height = rpc.get_block_count().await.unwrap();
        let height = macro_rpc.get_block_count().await.unwrap();
        assert_eq!(height, new_rpc_height);
    }
}
