//! # Common Utilities for Tests
//!
//! This module provides all the common utilities needed in unit and integration
//! tests, including:
//!
//! - Setting up databases, servers
//! - Creating test configurations
//! - Making common operetions like deposits
//! - Communicating with Citrea

use crate::actor::Actor;
use crate::bitvm_client::SECP;
use crate::builder::address::create_taproot_address;
use crate::builder::script::{CheckSig, Multisig, SpendableScript};
use crate::builder::transaction::input::UtxoVout;
use crate::builder::transaction::{create_replacement_deposit_txhandler, TxHandler};
use crate::citrea::CitreaClientT;
use crate::config::BridgeConfig;
use crate::database::Database;
use crate::deposit::{
    BaseDepositData, DepositInfo, DepositType, ReplacementDepositData, SecurityCouncil,
};
use crate::errors::BridgeError;
use crate::extended_rpc::ExtendedRpc;
use crate::musig2::{
    aggregate_nonces, aggregate_partial_signatures, nonce_pair, partial_sign,
    AggregateFromPublicKeys,
};
use crate::rpc::clementine::clementine_aggregator_client::ClementineAggregatorClient;
use crate::rpc::clementine::clementine_operator_client::ClementineOperatorClient;
use crate::rpc::clementine::clementine_verifier_client::ClementineVerifierClient;
use crate::rpc::clementine::{Deposit, Empty, SendMoveTxRequest};
use crate::rpc::clementine::{NormalSignatureKind, TaggedSignature};
use crate::utils::FeePayingType;
use crate::EVMAddress;
use bitcoin::hashes::Hash;
use bitcoin::key::Keypair;
use bitcoin::secp256k1::rand;
use bitcoin::secp256k1::Message;
use bitcoin::secp256k1::PublicKey;
use bitcoin::XOnlyPublicKey;
use bitcoin::{taproot, BlockHash, OutPoint, Transaction, Txid, Witness};
use bitcoincore_rpc::RpcApi;
use citrea::MockCitreaClient;
use eyre::Context;
pub use setup_utils::*;
use std::path::Path;
use std::process::Command;
use std::sync::Mutex;
use std::time::Duration;
use tonic::transport::Channel;
use tonic::Request;

pub mod citrea;
mod setup_utils;
pub mod tx_utils;

#[cfg(feature = "automation")]
use crate::test::common::tx_utils::wait_for_fee_payer_utxos_to_be_in_mempool;
#[cfg(feature = "automation")]
use tx_utils::{create_tx_sender, get_txid_where_utxo_is_spent};

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
) -> Result<
    (
        Vec<ClementineVerifierClient<Channel>>,
        Vec<ClementineOperatorClient<Channel>>,
        ClementineAggregatorClient<Channel>,
        ActorsCleanup,
        Vec<DepositInfo>,
        Vec<Txid>,
        Vec<BlockHash>,
        Vec<PublicKey>,
    ),
    BridgeError,
> {
    let (verifiers, operators, mut aggregator, cleanup) = create_actors::<C>(config).await;

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
        rpc.mine_blocks(18).await?;

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
        rpc.mine_blocks(1).await?;

        let _tx = poll_get(
            async || {
                rpc.mine_blocks(1).await?;

                let tx_result = rpc.client.get_raw_transaction_info(&move_txid, None).await;

                let _ = tx_result.as_ref().inspect_err(|e| {
                    tracing::info!("Waiting for transaction to be on-chain: {}", e);
                });

                Ok(tx_result.ok())
            },
            None,
            None,
        )
        .await?;

        let deposit_blockhash = rpc.get_blockhash_of_tx(&deposit_outpoint.txid).await?;
        deposit_blockhashes.push(deposit_blockhash);
        move_txids.push(move_txid);
    }

    Ok((
        verifiers,
        operators,
        aggregator,
        cleanup,
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
/// - `user_evm_address` [`EVMAddress`]: Optional EVM address to use for the
///   deposit. If not provided, a default address is used.
///
/// # Returns
///
/// A big tuple, containing:
///
/// - Server clients:
///    - [`ClementineVerifierClient`]: A vector of verifier clients.
///    - [`ClementineOperatorClient`]: A vector of operator clients.
///    - [`ClementineAggregatorClient`]: The aggregator client.
///    - [`ActorsCleanup`]: Cleanup handle for the servers. Must not be dropped.
/// - [`DepositInfo`]: Information about the deposit.
/// - [`Txid`]: TXID of the move transaction.
/// - [`BlockHash`]: Block hash of the block where the user deposit was mined.
/// - [`Vec<PublicKey>`]: Public keys of the verifiers used in the deposit.
#[cfg(feature = "automation")]
pub async fn run_single_deposit<C: CitreaClientT>(
    config: &mut BridgeConfig,
    rpc: ExtendedRpc,
    evm_address: Option<EVMAddress>,
) -> Result<
    (
        Vec<ClementineVerifierClient<Channel>>,
        Vec<ClementineOperatorClient<Channel>>,
        ClementineAggregatorClient<Channel>,
        ActorsCleanup,
        DepositInfo,
        Txid,
        BlockHash,
        Vec<PublicKey>,
    ),
    BridgeError,
> {
    let (verifiers, operators, mut aggregator, cleanup) = create_actors::<C>(config).await;
    let aggregator_db = Database::new(&BridgeConfig {
        db_name: config.db_name.clone() + "0",
        ..config.clone()
    })
    .await?;

    let evm_address = evm_address.unwrap_or(EVMAddress([1u8; 20]));
    let actor = Actor::new(
        config.secret_key,
        config.winternitz_secret_key,
        config.protocol_paramset().network,
    );

    let setup_start = std::time::Instant::now();
    let verifiers_public_keys: Vec<PublicKey> = aggregator
        .setup(Request::new(Empty {}))
        .await
        .wrap_err("Failed to setup aggregator")?
        .into_inner()
        .try_into()?;
    let setup_elapsed = setup_start.elapsed();
    tracing::info!("Setup completed in: {:?}", setup_elapsed);

    let (deposit_address, _) =
        get_deposit_address(config, evm_address, verifiers_public_keys.clone())?;
    let deposit_outpoint = rpc
        .send_to_address(&deposit_address, config.protocol_paramset().bridge_amount)
        .await?;

    mine_once_after_in_mempool(&rpc, deposit_outpoint.txid, Some("Deposit outpoint"), None).await?;
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

    wait_for_fee_payer_utxos_to_be_in_mempool(&rpc, aggregator_db, move_txid).await?;
    rpc.mine_blocks(1).await?;
    mine_once_after_in_mempool(&rpc, move_txid, Some("Move tx"), Some(180)).await?;

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
        verifiers,
        operators,
        aggregator,
        cleanup,
        deposit_info,
        move_txid,
        deposit_blockhash,
        verifiers_public_keys,
    ))
}

fn sign_nofn_deposit_tx(
    deposit_tx: &TxHandler,
    config: &BridgeConfig,
    verifiers_public_keys: Vec<PublicKey>,
    security_council: SecurityCouncil,
) -> Transaction {
    let nofn_xonly_pk =
        bitcoin::XOnlyPublicKey::from_musig2_pks(verifiers_public_keys.clone(), None).unwrap();
    let msg = Message::from_digest(
        deposit_tx
            .calculate_script_spend_sighash(
                0,
                &CheckSig::new(nofn_xonly_pk).to_script_buf(),
                bitcoin::TapSighashType::SinglePlusAnyoneCanPay,
            )
            .unwrap()
            .to_byte_array(),
    );

    let kps = config
        .test_params
        .all_verifiers_secret_keys
        .iter()
        .map(|sk| Keypair::from_secret_key(&SECP, sk))
        .collect::<Vec<_>>();

    let nonce_pairs = kps
        .iter()
        .map(|kp| nonce_pair(kp, &mut secp256k1::rand::thread_rng()).unwrap())
        .collect::<Vec<_>>();

    let agg_nonce = aggregate_nonces(
        nonce_pairs
            .iter()
            .map(|(_, musig_pub_nonces)| musig_pub_nonces)
            .collect::<Vec<_>>()
            .as_slice(),
    );

    let partial_sigs = kps
        .into_iter()
        .zip(nonce_pairs)
        .map(|(kp, nonce_pair)| {
            partial_sign(
                verifiers_public_keys.clone(),
                None,
                nonce_pair.0,
                agg_nonce,
                kp,
                msg,
            )
            .unwrap()
        })
        .collect::<Vec<_>>();

    let final_signature =
        aggregate_partial_signatures(verifiers_public_keys, None, agg_nonce, &partial_sigs, msg)
            .unwrap();

    let final_taproot_sig = taproot::Signature {
        signature: final_signature,
        sighash_type: bitcoin::TapSighashType::SinglePlusAnyoneCanPay,
    };

    let mut witness = Witness::from_slice(&[final_taproot_sig.serialize()]);
    // get script of movetx
    let script_buf = CheckSig::new(nofn_xonly_pk).to_script_buf();
    let multisig_script_buf = Multisig::from_security_council(security_council).to_script_buf();
    let (_, spend_info) = create_taproot_address(
        &[script_buf.clone(), multisig_script_buf.clone()],
        None,
        config.protocol_paramset().network,
    );
    Actor::add_script_path_to_witness(&mut witness, &script_buf, &spend_info).unwrap();
    let mut tx = deposit_tx.get_cached_tx().clone();
    tx.input[0].witness = witness;
    tx
}

#[cfg(feature = "automation")]
pub async fn run_replacement_deposit(
    config: &mut BridgeConfig,
    rpc: ExtendedRpc,
    evm_address: Option<EVMAddress>,
) -> Result<
    (
        Vec<ClementineVerifierClient<Channel>>,
        Vec<ClementineOperatorClient<Channel>>,
        ClementineAggregatorClient<Channel>,
        ActorsCleanup,
        DepositInfo,
        Txid,
        BlockHash,
    ),
    BridgeError,
> {
    let (
        verifiers,
        operators,
        mut aggregator,
        cleanup,
        _dep_params,
        move_txid,
        _,
        verifiers_public_keys,
    ) = run_single_deposit::<MockCitreaClient>(config, rpc.clone(), evm_address).await?;
    tracing::info!("First deposit move txid: {}", move_txid);

    let actor = Actor::new(
        config.secret_key,
        config.winternitz_secret_key,
        config.protocol_paramset().network,
    );
    let nofn_xonly_pk =
        bitcoin::XOnlyPublicKey::from_musig2_pks(verifiers_public_keys.clone(), None)?;

    let (addr, _) = create_taproot_address(
        &[
            CheckSig::new(nofn_xonly_pk).to_script_buf(),
            Multisig::from_security_council(config.security_council.clone()).to_script_buf(),
        ],
        None,
        config.protocol_paramset().network,
    );

    let move_tx = rpc
        .client
        .get_raw_transaction(&move_txid, None)
        .await
        .expect("Failed to get move tx");

    assert_eq!(move_tx.output[0].script_pubkey, addr.script_pubkey());

    // generate replacement deposit tx
    let mut new_deposit_tx = create_replacement_deposit_txhandler(
        move_txid,
        OutPoint {
            txid: move_txid,
            vout: UtxoVout::DepositInMove.get_vout(),
        },
        nofn_xonly_pk,
        config.protocol_paramset(),
        config.security_council.clone(),
    )?;

    actor
        .tx_sign_and_fill_sigs(
            &mut new_deposit_tx,
            &[TaggedSignature {
                // provide temp signature that'll be overridden by nofn signing below
                signature: vec![0; 64],
                signature_id: Some(NormalSignatureKind::NoSignature.into()),
            }],
            None,
        )
        .expect("Failed to sign replacement deposit tx");

    let replacement_deposit_tx = sign_nofn_deposit_tx(
        &new_deposit_tx,
        config,
        verifiers_public_keys.clone(),
        config.security_council.clone(),
    );

    let (tx_sender, tx_sender_db) = create_tx_sender(config, 0).await?;
    let mut db_commit = tx_sender_db.begin_transaction().await?;
    tx_sender
        .insert_try_to_send(
            &mut db_commit,
            None,
            &replacement_deposit_tx,
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

    wait_for_fee_payer_utxos_to_be_in_mempool(
        &rpc,
        tx_sender_db.clone(),
        replacement_deposit_tx.compute_txid(),
    )
    .await?;

    let replacement_deposit_txid = get_txid_where_utxo_is_spent(
        &rpc,
        OutPoint {
            txid: move_txid,
            vout: 0,
        },
    )
    .await?;
    tracing::info!(
        "Replacement deposit sent, txid: {}",
        replacement_deposit_txid
    );

    let deposit_blockhash = rpc.get_blockhash_of_tx(&replacement_deposit_txid).await?;

    let deposit_info = DepositInfo {
        deposit_outpoint: bitcoin::OutPoint {
            txid: replacement_deposit_txid,
            vout: 0,
        },
        deposit_type: DepositType::ReplacementDeposit(ReplacementDepositData {
            old_move_txid: move_txid,
        }),
    };

    let deposit: Deposit = deposit_info.clone().into();

    // First create the raw signed move-to-vault transaction for the replacement deposit
    let raw_signed_tx = aggregator
        .new_deposit(deposit)
        .await
        .wrap_err("Error while making a deposit")?
        .into_inner();
    // Broadcast the move-to-vault transaction and get its Txid
    let move_txid: Txid = aggregator
        .send_move_to_vault_tx(SendMoveTxRequest {
            deposit_outpoint: Some(deposit_info.deposit_outpoint.into()),
            raw_tx: Some(raw_signed_tx),
        })
        .await
        .wrap_err("Error sending replacement deposit move-to-vault tx")?
        .into_inner()
        .try_into()?;

    Ok((
        verifiers,
        operators,
        aggregator,
        cleanup,
        deposit_info,
        move_txid,
        deposit_blockhash,
    ))
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
    use crate::{
        actor::Actor,
        extended_rpc::ExtendedRpc,
        test::common::{
            citrea::MockCitreaClient, create_regtest_rpc, create_test_config_with_thread_name,
        },
    };
    use bitcoin::{absolute::LockTime, transaction::Version, Transaction};
    use bitcoincore_rpc::RpcApi;

    #[cfg(feature = "integration_tests")]
    #[tokio::test]
    async fn test_regtest_create_and_connect() {
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
