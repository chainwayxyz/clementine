//! # Common Utilities for Integration Tests
use std::time::Duration;

use crate::actor::Actor;
use crate::bitvm_client::SECP;
use crate::builder::address::create_taproot_address;
use crate::builder::script::{CheckSig, SpendableScript};
use crate::builder::transaction::{
    create_replacement_deposit_txhandler, BaseDepositData, DepositData, ReplacementDepositData,
    TxHandler,
};
use crate::citrea::mock::MockCitreaClient;
use crate::citrea::CitreaClientT;
use crate::config::BridgeConfig;
use crate::errors::BridgeError;
use crate::extended_rpc::ExtendedRpc;
use crate::musig2::{
    aggregate_nonces, aggregate_partial_signatures, nonce_pair, partial_sign,
    AggregateFromPublicKeys,
};
use crate::rpc::clementine::clementine_aggregator_client::ClementineAggregatorClient;
use crate::rpc::clementine::clementine_operator_client::ClementineOperatorClient;
use crate::rpc::clementine::clementine_verifier_client::ClementineVerifierClient;
use crate::rpc::clementine::{DepositParams, Empty, FeeType, RawSignedTx, SendTxRequest};
use crate::EVMAddress;
use bitcoin::hashes::Hash;
use bitcoin::key::Keypair;
use bitcoin::secp256k1::Message;
use bitcoin::{taproot, BlockHash, OutPoint, Transaction, Txid, Witness};
use bitcoincore_rpc::RpcApi;
use eyre::Context;
pub use setup_utils::*;
use tonic::transport::Channel;
use tonic::Request;
use tx_utils::get_txid_where_utxo_is_spent;

pub mod citrea;
mod setup_utils;
pub mod tx_utils;

pub async fn ensure_async(
    mut func: impl AsyncFnMut() -> Result<bool, eyre::Error>,
    timeout: Option<Duration>,
    poll_interval: Option<Duration>,
) -> Result<(), BridgeError> {
    let timeout = timeout.unwrap_or(Duration::from_secs(60));
    let poll_interval = poll_interval.unwrap_or(Duration::from_millis(500));

    let start = std::time::Instant::now();

    loop {
        if start.elapsed() > timeout {
            return Err(eyre::eyre!("Timeout reached").into());
        }

        if func().await? {
            return Ok(());
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

    loop {
        if start.elapsed() > std::time::Duration::from_secs(timeout) {
            return Err(BridgeError::Error(format!(
                "{} did not land onchain within {} seconds",
                tx_name, timeout
            )));
        }

        if rpc.client.get_mempool_entry(&txid).await.is_ok() {
            break;
        };

        tracing::info!("Waiting for {} transaction to hit mempool...", tx_name);
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }

    rpc.mine_blocks(1).await?;

    let tx: bitcoincore_rpc::json::GetRawTransactionResult = rpc
        .client
        .get_raw_transaction_info(&txid, None)
        .await
        .map_err(|e| {
            BridgeError::Error(format!(
            "{} did not land onchain after in mempool and mining 1 block and rpc gave error: {}",
            tx_name,
            e
        ))
        })?;

    if tx.blockhash.is_none() {
        tracing::error!(
            "{} did not land onchain after in mempool and mining 1 block",
            tx_name
        );

        return Err(BridgeError::Error(format!(
            "{} did not land onchain after in mempool and mining 1 block",
            tx_name
        )));
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
        Vec<OutPoint>,
        Vec<Txid>,
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
    let (deposit_address, _) = get_deposit_address(config, evm_address)?;

    aggregator
        .setup(Request::new(Empty {}))
        .await
        .wrap_err("Failed to setup aggregator")?;

    let mut deposit_outpoints = Vec::new();
    let mut move_txids = Vec::new();

    let nofn_xonly_pk =
        bitcoin::XOnlyPublicKey::from_musig2_pks(config.verifiers_public_keys.clone(), None)
            .unwrap();

    for _ in 0..count {
        let deposit_outpoint: OutPoint = rpc
            .send_to_address(&deposit_address, config.protocol_paramset().bridge_amount)
            .await?;
        rpc.mine_blocks(18).await?;

        let deposit_data = DepositData::BaseDeposit(BaseDepositData {
            deposit_outpoint,
            evm_address,
            recovery_taproot_address: actor.address.as_unchecked().to_owned(),
            nofn_xonly_pk,
            num_verifiers: config.num_verifiers,
        });

        let deposit_params: DepositParams = deposit_data.into();

        let move_txid: Txid = aggregator
            .new_deposit(deposit_params)
            .await?
            .into_inner()
            .try_into()
            .wrap_err("Failed to convert between Txid types")?;
        rpc.mine_blocks(1).await?;

        let start = std::time::Instant::now();
        let timeout = 60;
        let _tx = loop {
            if start.elapsed() > std::time::Duration::from_secs(timeout) {
                panic!("MoveTx did not land onchain within {timeout} seconds");
            }
            rpc.mine_blocks(1).await?;

            let tx_result = rpc.client.get_raw_transaction_info(&move_txid, None).await;

            let tx_result = match tx_result {
                Ok(tx) => tx,
                Err(e) => {
                    tracing::info!("Waiting for transaction to be on-chain: {}", e);
                    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                    continue;
                }
            };

            break tx_result;
        };

        deposit_outpoints.push(deposit_outpoint);
        move_txids.push(move_txid);
    }

    Ok((
        verifiers,
        operators,
        aggregator,
        cleanup,
        deposit_outpoints,
        move_txids,
    ))
}

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
        DepositParams,
        Txid,
        BlockHash,
    ),
    BridgeError,
> {
    let (verifiers, operators, mut aggregator, cleanup) = create_actors::<C>(config).await;

    let evm_address = evm_address.unwrap_or(EVMAddress([1u8; 20]));
    let actor = Actor::new(
        config.secret_key,
        config.winternitz_secret_key,
        config.protocol_paramset().network,
    );
    let (deposit_address, _) = get_deposit_address(config, evm_address)?;

    let setup_start = std::time::Instant::now();
    aggregator
        .setup(Request::new(Empty {}))
        .await
        .wrap_err("Failed to setup aggregator")?;
    let setup_elapsed = setup_start.elapsed();
    tracing::info!("Setup completed in: {:?}", setup_elapsed);

    let deposit_outpoint = rpc
        .send_to_address(&deposit_address, config.protocol_paramset().bridge_amount)
        .await?;

    mine_once_after_in_mempool(&rpc, deposit_outpoint.txid, Some("Deposit outpoint"), None).await?;
    let deposit_blockhash = rpc.get_blockhash_of_tx(&deposit_outpoint.txid).await?;

    let nofn_xonly_pk =
        bitcoin::XOnlyPublicKey::from_musig2_pks(config.verifiers_public_keys.clone(), None)
            .unwrap();

    let deposit_data = DepositData::BaseDeposit(BaseDepositData {
        deposit_outpoint,
        evm_address,
        recovery_taproot_address: actor.address.as_unchecked().to_owned(),
        nofn_xonly_pk,
        num_verifiers: config.num_verifiers,
    });

    let deposit_params: DepositParams = deposit_data.into();

    let move_txid: Txid = aggregator
        .new_deposit(deposit_params.clone())
        .await
        .wrap_err("Failed to execute deposit")?
        .into_inner()
        .try_into()
        .wrap_err("Failed to convert between Txid types")?;

    // sleep 3 seconds so that tx_sender can send the fee_payer_tx to the mempool
    tokio::time::sleep(std::time::Duration::from_secs(3)).await;
    // mine 1 block
    rpc.mine_blocks(1).await?;

    mine_once_after_in_mempool(&rpc, move_txid, Some("Move tx"), None).await?;

    Ok((
        verifiers,
        operators,
        aggregator,
        cleanup,
        deposit_params,
        move_txid,
        deposit_blockhash,
    ))
}

fn sign_nofn_deposit_tx(deposit_tx: &TxHandler, config: &BridgeConfig) -> Transaction {
    let nofn_xonly_pk =
        bitcoin::XOnlyPublicKey::from_musig2_pks(config.verifiers_public_keys.clone(), None)
            .unwrap();
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
        .all_verifiers_secret_keys
        .clone()
        .unwrap()
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
                config.verifiers_public_keys.clone(),
                None,
                nonce_pair.0,
                agg_nonce,
                kp,
                msg,
            )
            .unwrap()
        })
        .collect::<Vec<_>>();

    let final_signature = aggregate_partial_signatures(
        &config.verifiers_public_keys.clone(),
        None,
        agg_nonce,
        &partial_sigs,
        msg,
    )
    .unwrap();

    let final_taproot_sig = taproot::Signature {
        signature: final_signature,
        sighash_type: bitcoin::TapSighashType::SinglePlusAnyoneCanPay,
    };

    let mut witness = Witness::from_slice(&[final_taproot_sig.serialize()]);
    // get script of movetx
    let script_buf = CheckSig::new(nofn_xonly_pk).to_script_buf();
    let (_, spend_info) = create_taproot_address(
        &[script_buf.clone()],
        None,
        config.protocol_paramset().network,
    );
    Actor::add_script_path_to_witness(&mut witness, &script_buf, &spend_info).unwrap();
    let mut tx = deposit_tx.get_cached_tx().clone();
    tx.input[0].witness = witness;
    tx
}

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
        DepositParams,
        Txid,
        BlockHash,
    ),
    BridgeError,
> {
    let (verifiers, operators, mut aggregator, cleanup, dep_params, move_txid, _) =
        run_single_deposit::<MockCitreaClient>(config, rpc.clone(), evm_address).await?;

    tracing::info!(
        "First deposit {} completed, starting replacement deposit",
        DepositData::try_from(dep_params)?
            .get_deposit_outpoint()
            .txid
    );
    tracing::info!("First deposit move txid: {}", move_txid);
    let nofn_xonly_pk =
        bitcoin::XOnlyPublicKey::from_musig2_pks(config.verifiers_public_keys.clone(), None)
            .unwrap();

    // generate replacement deposit tx
    let new_deposit_tx =
        create_replacement_deposit_txhandler(move_txid, nofn_xonly_pk, config.protocol_paramset())?;

    let replacement_deposit_tx = sign_nofn_deposit_tx(&new_deposit_tx, config);

    aggregator
        .internal_send_tx(SendTxRequest {
            raw_tx: Some(RawSignedTx::from(&replacement_deposit_tx)),
            fee_type: FeeType::Rbf as i32,
        })
        .await?;

    // sleep 3 seconds so that tx_sender can send the fee_payer_tx to the mempool
    tokio::time::sleep(std::time::Duration::from_secs(3)).await;

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

    let deposit_data = DepositData::ReplacementDeposit(ReplacementDepositData {
        deposit_outpoint: bitcoin::OutPoint {
            txid: replacement_deposit_txid,
            vout: 0,
        },
        nofn_xonly_pk,
        old_move_txid: move_txid,
        num_verifiers: config.num_verifiers,
    });

    let deposit_params: DepositParams = deposit_data.into();

    let move_txid: Txid = aggregator
        .new_deposit(deposit_params.clone())
        .await?
        .into_inner()
        .try_into()?;

    Ok((
        verifiers,
        operators,
        aggregator,
        cleanup,
        deposit_params,
        move_txid,
        deposit_blockhash,
    ))
}

#[ignore = "Tested everywhere, no need to run again"]
#[tokio::test]
async fn test_deposit() {
    let mut config = create_test_config_with_thread_name().await;
    let regtest = create_regtest_rpc(&mut config).await;
    let rpc = regtest.rpc().clone();
    let _ = run_single_deposit::<MockCitreaClient>(&mut config, rpc, None)
        .await
        .unwrap();
}

#[ignore = "Tested everywhere, no need to run again"]
#[tokio::test]
async fn multiple_deposits_for_operator() {
    let mut config = create_test_config_with_thread_name().await;
    let regtest = create_regtest_rpc(&mut config).await;
    let rpc = regtest.rpc().clone();
    let _ = run_multiple_deposits::<MockCitreaClient>(&mut config, rpc, 2)
        .await
        .unwrap();
}

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
