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
use crate::errors::BridgeError;
use crate::extended_rpc::ExtendedRpc;
use crate::rpc::clementine::{
    entity_status_with_id, Deposit, Empty, EntityStatuses, GetEntityStatusesRequest,
    SendMoveTxRequest,
};
use crate::utils::FeePayingType;
use crate::EVMAddress;
use bitcoin::secp256k1::rand;
use bitcoin::secp256k1::PublicKey;
use bitcoin::XOnlyPublicKey;
use bitcoin::{taproot, BlockHash, OutPoint, Transaction, Txid};
use bitcoincore_rpc::RpcApi;
use citrea_e2e::bitcoin::DEFAULT_FINALITY_DEPTH;
use eyre::Context;
pub use setup_utils::*;
use std::path::Path;
use std::process::Command;
use std::sync::Mutex;
use std::time::Duration;
use test_actors::TestActors;
use tonic::Request;

pub mod citrea;
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

/// Get the minimum next state manager height from all the state managers
/// If automation is off for any entity, their state manager is assumed to be synced
/// (by setting their next height to u32::MAX).
pub async fn get_next_sync_heights(entity_statuses: EntityStatuses) -> eyre::Result<Vec<u32>> {
    entity_statuses
        .entity_statuses
        .into_iter()
        .map(|entity| {
            if let Some(entity_status_with_id::StatusResult::Status(status)) = entity.status_result
            {
                if status.automation {
                    Ok(status.state_manager_next_height)
                } else {
                    // assume synced if automation is off
                    Ok(u32::MAX)
                }
            } else {
                Err(eyre::eyre!(
                    "Couldn't retrieve sync status from entity {:?}",
                    entity.entity_id
                ))
            }
        })
        .collect::<Result<Vec<_>, _>>()
}

/// Calls get_entity_statuses and returns the minimum next state manager height
pub async fn get_min_next_state_manager_height<C: CitreaClientT>(
    actors: &TestActors<C>,
) -> eyre::Result<u32> {
    let mut aggregator = actors.get_aggregator();
    let l1_sync_status = aggregator
        .get_entity_statuses(Request::new(GetEntityStatusesRequest {
            restart_tasks: false,
        }))
        .await?
        .into_inner();
    let min_next_sync_height = get_next_sync_heights(l1_sync_status)
        .await?
        .into_iter()
        .min()
        .ok_or_else(|| eyre::eyre!("No entities found"))?;
    Ok(min_next_sync_height)
}

/// Checks if all the state managers are synced to the latest finalized block
pub async fn are_all_state_managers_synced<C: CitreaClientT>(
    rpc: &ExtendedRpc,
    actors: &TestActors<C>,
) -> eyre::Result<bool> {
    let min_next_sync_height = get_min_next_state_manager_height(actors).await?;
    let current_chain_height = rpc.get_current_chain_height().await?;
    let finality_depth = actors.aggregator.config.protocol_paramset().finality_depth;
    // get the current finalized chain height
    let current_finalized_chain_height = current_chain_height.saturating_sub(finality_depth);
    // assume synced if state manager is not running
    let state_manager_running = actors
        .aggregator
        .config
        .test_params
        .should_run_state_manager;
    Ok(!state_manager_running || min_next_sync_height > current_finalized_chain_height)
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
    rpc: &ExtendedRpc,
    txid: Txid,
    tx_name: Option<&str>,
    timeout: Option<u64>,
) -> Result<usize, BridgeError> {
    let timeout = timeout.unwrap_or(60);
    let start = std::time::Instant::now();
    let tx_name = tx_name.unwrap_or("Unnamed tx");

    if rpc
        .client
        .get_transaction(&txid, None)
        .await
        .is_ok_and(|tx| tx.info.blockhash.is_some())
    {
        return Err(eyre::eyre!("{} is already mined", tx_name).into());
    }

    loop {
        if start.elapsed() > std::time::Duration::from_secs(timeout) {
            return Err(
                eyre::eyre!("{} didn't hit mempool within {} seconds", tx_name, timeout).into(),
            );
        }

        if rpc.client.get_mempool_entry(&txid).await.is_ok() {
            break;
        };

        // mine if there are some txs in mempool
        if rpc.mempool_size().await? > 0 {
            rpc.mine_blocks(1).await?;
        }

        tracing::info!("Waiting for {} transaction to hit mempool...", tx_name);
        tokio::time::sleep(std::time::Duration::from_millis(1000)).await;
    }

    rpc.mine_blocks(1).await?;

    let tx: bitcoincore_rpc::json::GetRawTransactionResult = rpc
        .client
        .get_raw_transaction_info(&txid, None)
        .await
        .map_err(|e| {
            eyre::eyre!(
            "{} did not land onchain after in mempool and mining 1 block and rpc gave error: {}",
            tx_name,
            e
        )
        })?;

    if tx.blockhash.is_none() {
        tracing::error!(
            "{} did not land onchain after in mempool and mining 1 block",
            tx_name
        );

        return Err(eyre::eyre!(
            "{} did not land onchain after in mempool and mining 1 block",
            tx_name
        )
        .into());
    }

    let tx_block_height = rpc
        .client
        .get_block_info(&tx.blockhash.unwrap())
        .await
        .wrap_err("Failed to get block info")?;

    Ok(tx_block_height.height)
}

pub async fn run_multiple_deposits<C: CitreaClientT>(
    config: &mut BridgeConfig,
    rpc: ExtendedRpc,
    count: usize,
    test_actors: Option<TestActors<C>>,
) -> Result<
    (
        TestActors<C>,
        Vec<DepositInfo>,
        Vec<Txid>,
        Vec<BlockHash>,
        Vec<PublicKey>,
    ),
    BridgeError,
> {
    let actors = match test_actors {
        Some(actors) => actors,
        None => create_actors(config).await,
    };
    let mut aggregator = actors.get_aggregator();

    let evm_address = EVMAddress([1u8; 20]);
    let actor = Actor::new(
        config.secret_key,
        config.winternitz_secret_key,
        config.protocol_paramset().network,
    );

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
        rpc.mine_blocks_while_synced(DEFAULT_FINALITY_DEPTH + 1, &actors)
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
        actors,
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
/// - `rpc` [`ExtendedRpc`]: The RPC client to use.
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
#[cfg(feature = "automation")]
pub async fn run_single_deposit<C: CitreaClientT>(
    config: &mut BridgeConfig,
    rpc: ExtendedRpc,
    evm_address: Option<EVMAddress>,
    actors: Option<TestActors<C>>,
    deposit_outpoint: Option<OutPoint>, // if a deposit outpoint is provided, it will be used instead of creating a new one
) -> Result<(TestActors<C>, DepositInfo, Txid, BlockHash, Vec<PublicKey>), BridgeError> {
    let actors = match actors {
        Some(actors) => actors,
        None => create_actors(config).await,
    };
    let aggregator_db = Database::new(&actors.aggregator.config).await?;

    let evm_address = evm_address.unwrap_or(EVMAddress([1u8; 20]));
    let actor = Actor::new(
        config.secret_key,
        config.winternitz_secret_key,
        config.protocol_paramset().network,
    );

    let setup_start = std::time::Instant::now();
    let mut aggregator = actors.get_aggregator();
    let verifiers_public_keys: Vec<PublicKey> = aggregator
        .setup(Request::new(Empty {}))
        .await
        .wrap_err("Failed to setup aggregator")?
        .into_inner()
        .try_into()?;
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
            mine_once_after_in_mempool(&rpc, outpoint.txid, Some("Deposit outpoint"), None).await?;
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
        // check if deposit outpoint is spent
        let deposit_outpoint_spent = rpc.is_utxo_spent(&deposit_outpoint).await?;
        if deposit_outpoint_spent {
            return Err(eyre::eyre!(
                "Deposit outpoint is spent but move tx is not in chain. In test_bridge_contract_change 
                this means move tx does not match the one in saved state"
            )
            .into());
        }
        wait_for_fee_payer_utxos_to_be_in_mempool(&rpc, aggregator_db, move_txid).await?;
        rpc.mine_blocks_while_synced(1, &actors).await?;
        mine_once_after_in_mempool(&rpc, move_txid, Some("Move tx"), Some(180)).await?;
    }

    // Uncomment below to debug the move tx.
    // let transaction = rpc
    //     .client
    //     .get_raw_transaction(&move_txid, None)
    //     .await
    //     .expect("a");
    // let tx_info: bitcoincore_rpc::json::GetRawTransactionResult = rpc
    //     .client
    //     .get_raw_transaction_info(&move_txid, None)
    //     .await
    //     .expect("a");
    // let block: bitcoincore_rpc::json::GetBlockResult = rpc
    //     .client
    //     .get_block_info(&tx_info.blockhash.unwrap())
    //     .await
    //     .expect("a");
    // let block_height = block.height;
    // let block = rpc
    //     .client
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

    Ok((
        actors,
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
/// - `rpc` [`ExtendedRpc`]: The RPC client to use.
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
    rpc: &ExtendedRpc,
    old_move_txid: Txid,
    current_actors: TestActors<C>,
    old_nofn_xonly_pk: XOnlyPublicKey,
) -> Result<(TestActors<C>, DepositInfo, Txid, BlockHash), BridgeError> {
    let aggregator_db = Database::new(&BridgeConfig {
        db_name: config.db_name.clone() + "0",
        ..config.clone()
    })
    .await?;

    // create a replacement deposit tx, we will sign it using nofn
    let replacement_deposit_txid = send_replacement_deposit_tx(
        config,
        rpc,
        old_move_txid,
        &current_actors,
        old_nofn_xonly_pk,
    )
    .await?;

    let deposit_outpoint = OutPoint {
        txid: replacement_deposit_txid,
        vout: 0,
    };

    let setup_start = std::time::Instant::now();
    let mut aggregator = current_actors.get_aggregator();
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
        rpc.mine_blocks_while_synced(1, &current_actors).await?;
        mine_once_after_in_mempool(rpc, move_txid, Some("Move tx"), Some(180)).await?;
    }

    Ok((current_actors, deposit_info, move_txid, deposit_blockhash))
}

/// Signs a replacement deposit transaction using the security council
fn sign_replacement_deposit_tx_with_sec_council(
    replacement_deposit: &TxHandler,
    config: &BridgeConfig,
    old_nofn_xonly_pk: XOnlyPublicKey,
) -> Transaction {
    let security_council = config.security_council.clone();
    let multisig_script = Multisig::from_security_council(security_council.clone()).to_script_buf();
    let sighash = replacement_deposit
        .calculate_script_spend_sighash(
            0,
            &multisig_script,
            bitcoin::TapSighashType::SinglePlusAnyoneCanPay,
        )
        .unwrap();

    // sign using first threshold security council members, for rest do not sign
    let signatures = config
        .test_params
        .sec_council_secret_keys
        .iter()
        .enumerate()
        .map(|(idx, sk)| {
            if idx < security_council.threshold as usize {
                let actor = Actor::new(*sk, None, config.protocol_paramset().network);
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

    let mut witness = Multisig::from_security_council(security_council)
        .generate_script_inputs(&signatures)
        .unwrap();

    // calculate address in movetx vault
    let script_buf = CheckSig::new(old_nofn_xonly_pk).to_script_buf();
    let (_, spend_info) = create_taproot_address(
        &[script_buf.clone(), multisig_script.clone()],
        None,
        config.protocol_paramset().network,
    );
    // add script path to witness
    Actor::add_script_path_to_witness(&mut witness, &multisig_script, &spend_info).unwrap();
    let mut tx = replacement_deposit.get_cached_tx().clone();
    // add witness to tx
    tx.input[0].witness = witness;
    tx
}

#[cfg(feature = "automation")]
async fn send_replacement_deposit_tx<C: CitreaClientT>(
    config: &BridgeConfig,
    rpc: &ExtendedRpc,
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
    );

    let (tx_sender, tx_sender_db) = create_tx_sender(config, 0).await?;
    let mut db_commit = tx_sender_db.begin_transaction().await?;
    tx_sender
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
                eprintln!("Failed to generate certificates: {}", stderr);
                return Err(std::io::Error::other(format!(
                    "Certificate generation failed: {}",
                    stderr
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
            extended_rpc::ExtendedRpc,
            test::common::{create_regtest_rpc, create_test_config_with_thread_name},
        };
        use bitcoincore_rpc::RpcApi;

        let mut config = create_test_config_with_thread_name().await;

        let regtest = create_regtest_rpc(&mut config).await;

        let macro_rpc = regtest.rpc();
        let rpc = ExtendedRpc::connect(
            config.bitcoin_rpc_url.clone(),
            config.bitcoin_rpc_user.clone(),
            config.bitcoin_rpc_password.clone(),
        )
        .await
        .unwrap();

        macro_rpc.mine_blocks(1).await.unwrap();
        let height = macro_rpc.client.get_block_count().await.unwrap();
        let new_rpc_height = rpc.client.get_block_count().await.unwrap();
        assert_eq!(height, new_rpc_height);

        rpc.mine_blocks(1).await.unwrap();
        let new_rpc_height = rpc.client.get_block_count().await.unwrap();
        let height = macro_rpc.client.get_block_count().await.unwrap();
        assert_eq!(height, new_rpc_height);
    }
}
