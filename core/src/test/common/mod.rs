//! # Common Utilities for Integration Tests

use std::sync::Arc;

use crate::actor::Actor;
use crate::bitvm_client::SECP;
use crate::builder::address::create_taproot_address;
use crate::builder::script::{CheckSig, ReplacementDepositScript, SpendableScript};
use crate::builder::transaction::input::SpendableTxIn;
use crate::builder::transaction::output::UnspentTxOut;
use crate::builder::transaction::{
    anchor_output, BaseDepositData, DepositData, ReplacementDepositData, TransactionType,
    TxHandler, TxHandlerBuilder, DEFAULT_SEQUENCE,
};
use crate::config::BridgeConfig;
use crate::constants::ANCHOR_AMOUNT;
use crate::errors::BridgeError;
use crate::extended_rpc::ExtendedRpc;
use crate::musig2::{
    aggregate_nonces, aggregate_partial_signatures, nonce_pair, partial_sign,
    AggregateFromPublicKeys,
};
use crate::rpc::clementine::clementine_aggregator_client::ClementineAggregatorClient;
use crate::rpc::clementine::clementine_operator_client::ClementineOperatorClient;
use crate::rpc::clementine::clementine_verifier_client::ClementineVerifierClient;
use crate::rpc::clementine::clementine_watchtower_client::ClementineWatchtowerClient;
use crate::rpc::clementine::{DepositParams, Empty, NormalSignatureKind, RawSignedTx};
use crate::EVMAddress;
use bitcoin::hashes::Hash;
use bitcoin::key::Keypair;
use bitcoin::secp256k1::Message;
use bitcoin::transaction::Version;
use bitcoin::{BlockHash, OutPoint, Transaction, Txid, Witness};
use bitcoincore_rpc::RpcApi;
pub use test_utils::*;
use tonic::transport::Channel;
use tonic::Request;

pub mod citrea;
mod test_utils;

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
) -> Result<(), BridgeError> {
    let timeout = timeout.unwrap_or(60);
    let start = std::time::Instant::now();
    let tx_name = tx_name.unwrap_or("Unnamed tx");

    loop {
        if start.elapsed() > std::time::Duration::from_secs(timeout) {
            panic!("{} did not land onchain within {timeout} seconds", tx_name);
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

    Ok(())
}

pub async fn run_multiple_deposits(
    config: &mut BridgeConfig,
    rpc: ExtendedRpc,
    count: usize,
) -> Result<
    (
        Vec<ClementineVerifierClient<Channel>>,
        Vec<ClementineOperatorClient<Channel>>,
        ClementineAggregatorClient<Channel>,
        Vec<ClementineWatchtowerClient<Channel>>,
        ActorsCleanup,
        Vec<OutPoint>,
        Vec<Txid>,
    ),
    BridgeError,
> {
    let (verifiers, operators, mut aggregator, watchtowers, cleanup) = create_actors(config).await;

    let evm_address = EVMAddress([1u8; 20]);
    let actor = Actor::new(
        config.secret_key,
        config.winternitz_secret_key,
        config.protocol_paramset().network,
    );
    let (deposit_address, _) = get_deposit_address(config, evm_address)?;

    aggregator.setup(Request::new(Empty {})).await?;

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
        });

        let deposit_params: DepositParams = deposit_data.into();

        let move_txid: Txid = aggregator
            .new_deposit(deposit_params)
            .await?
            .into_inner()
            .try_into()?;
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
        watchtowers,
        cleanup,
        deposit_outpoints,
        move_txids,
    ))
}

pub async fn run_single_deposit(
    config: &mut BridgeConfig,
    rpc: ExtendedRpc,
    evm_address: Option<EVMAddress>,
) -> Result<
    (
        Vec<ClementineVerifierClient<Channel>>,
        Vec<ClementineOperatorClient<Channel>>,
        ClementineAggregatorClient<Channel>,
        Vec<ClementineWatchtowerClient<Channel>>,
        ActorsCleanup,
        DepositParams,
        Txid,
        BlockHash,
    ),
    BridgeError,
> {
    let (verifiers, operators, mut aggregator, watchtowers, cleanup) = create_actors(config).await;

    let evm_address = evm_address.unwrap_or(EVMAddress([1u8; 20]));
    let actor = Actor::new(
        config.secret_key,
        config.winternitz_secret_key,
        config.protocol_paramset().network,
    );
    let (deposit_address, _) = get_deposit_address(config, evm_address)?;

    let setup_start = std::time::Instant::now();
    aggregator.setup(Request::new(Empty {})).await?;
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
    });

    let deposit_params: DepositParams = deposit_data.into();

    let move_txid: Txid = aggregator
        .new_deposit(deposit_params.clone())
        .await?
        .into_inner()
        .try_into()?;

    // sleep 3 seconds so that tx_sender can send the fee_payer_tx to the mempool
    tokio::time::sleep(std::time::Duration::from_secs(3)).await;
    // mine 1 block
    rpc.mine_blocks(1).await?;

    mine_once_after_in_mempool(&rpc, move_txid, Some("Move tx"), None).await?;

    Ok((
        verifiers,
        operators,
        aggregator,
        watchtowers,
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
                bitcoin::TapSighashType::Default,
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

    let mut witness = Witness::from_slice(&[final_signature.serialize()]);
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
        Vec<ClementineWatchtowerClient<Channel>>,
        ActorsCleanup,
        DepositParams,
        Txid,
        BlockHash,
    ),
    BridgeError,
> {
    let (verifiers, operators, mut aggregator, watchtowers, cleanup, dep_params, move_txid, _) =
        run_single_deposit(config, rpc.clone(), evm_address).await?;

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
    let new_deposit_tx = TxHandlerBuilder::new(TransactionType::Dummy)
        .with_version(Version::non_standard(3))
        .add_input(
            NormalSignatureKind::NotStored,
            SpendableTxIn::from_scripts(
                bitcoin::OutPoint {
                    txid: move_txid,
                    vout: 0,
                },
                config.protocol_paramset().bridge_amount - ANCHOR_AMOUNT,
                vec![Arc::new(CheckSig::new(nofn_xonly_pk))],
                None,
                config.protocol_paramset().network,
            ),
            crate::builder::script::SpendPath::ScriptSpend(0),
            DEFAULT_SEQUENCE,
        )
        .add_output(UnspentTxOut::from_scripts(
            config.protocol_paramset().bridge_amount - ANCHOR_AMOUNT * 3,
            vec![Arc::new(ReplacementDepositScript::new(
                nofn_xonly_pk,
                move_txid,
                config.protocol_paramset().bridge_amount,
            ))],
            None,
            config.protocol_paramset().network,
        ))
        .add_output(UnspentTxOut::from_partial(anchor_output()))
        .finalize();

    let replacement_deposit_tx = sign_nofn_deposit_tx(&new_deposit_tx, config);
    let replacement_deposit_txid = replacement_deposit_tx.compute_txid();
    tracing::info!("Replacement deposit txid: {}", replacement_deposit_txid);

    aggregator
        .internal_send_tx(RawSignedTx::from(&replacement_deposit_tx))
        .await?;

    // sleep 3 seconds so that tx_sender can send the fee_payer_tx to the mempool
    tokio::time::sleep(std::time::Duration::from_secs(3)).await;
    // mine 1 block
    rpc.mine_blocks(1).await?;

    mine_once_after_in_mempool(
        &rpc,
        replacement_deposit_txid,
        Some("Replacement deposit tx"),
        None,
    )
    .await?;

    let deposit_blockhash = rpc.get_blockhash_of_tx(&replacement_deposit_txid).await?;

    let deposit_data = DepositData::ReplacementDeposit(ReplacementDepositData {
        deposit_outpoint: bitcoin::OutPoint {
            txid: replacement_deposit_tx.compute_txid(),
            vout: 0,
        },
        nofn_xonly_pk,
        move_txid,
        bridge_amount: config.protocol_paramset().bridge_amount - ANCHOR_AMOUNT * 3,
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
        watchtowers,
        cleanup,
        deposit_params,
        move_txid,
        deposit_blockhash,
    ))
}
