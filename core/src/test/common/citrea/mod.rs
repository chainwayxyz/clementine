//! # Citrea Related Utilities

use crate::bitvm_client::{ClementineBitVMPublicKeys, SECP};
use crate::builder::transaction::input::UtxoVout;
use crate::builder::transaction::TransactionType;
use crate::citrea::{CitreaClient, SATS_TO_WEI_MULTIPLIER};
use crate::database::Database;
use crate::deposit::KickoffData;
use crate::extended_rpc::ExtendedRpc;
use crate::musig2::AggregateFromPublicKeys;
use crate::rpc::clementine::clementine_operator_client::ClementineOperatorClient;
use crate::rpc::clementine::{TransactionRequest, WithdrawParams};
use crate::test::common::tx_utils::get_txid_where_utxo_is_spent_while_waiting_for_state_mngr_sync;
use crate::test::common::{
    generate_withdrawal_transaction_and_signature, mine_once_after_in_mempool,
};
use crate::utils::FeePayingType;
use crate::{config::BridgeConfig, errors::BridgeError};
use alloy::primitives::U256;
use bitcoin::consensus::Encodable;
use bitcoin::secp256k1::{PublicKey, SecretKey};
use bitcoin::{Address, Amount, Block, OutPoint, Transaction, TxOut, Txid, VarInt, XOnlyPublicKey};
use bitcoincore_rpc::RpcApi;
use citrea_e2e::bitcoin::DEFAULT_FINALITY_DEPTH;
use citrea_e2e::{
    bitcoin::BitcoinNode,
    config::{BatchProverConfig, EmptyConfig, LightClientProverConfig, SequencerConfig},
    framework::TestFramework,
    node::{Node, NodeKind},
};
pub use client_mock::*;
use jsonrpsee::http_client::HttpClient;
pub use parameters::*;
pub use requests::*;

use super::test_actors::TestActors;
use super::tx_utils::{
    ensure_outpoint_spent_while_waiting_for_state_mngr_sync,
    mine_once_after_outpoint_spent_in_mempool,
};

mod bitcoin_merkle;
mod client_mock;
mod parameters;
mod requests;

/// Calculates bridge params dynamically with the N-of-N public key which
/// calculated from the verifier secret keys in `BridgeConfig::default`.
pub fn get_bridge_params() -> String {
    let config = BridgeConfig::default();

    let verifiers_secret_keys = config.test_params.all_verifiers_secret_keys;
    let secp = bitcoin::secp256k1::Secp256k1::new();
    let verifiers_public_keys: Vec<PublicKey> = verifiers_secret_keys
        .iter()
        .map(|sk| PublicKey::from_secret_key(&secp, sk))
        .collect();

    let nofn_xonly_pk =
        bitcoin::XOnlyPublicKey::from_musig2_pks(verifiers_public_keys.clone(), None)
            .unwrap()
            .to_string();

    let bridge_params = format!(
        "000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000000c00000000000000000000000000000000000000000000000008ac7230489e80000000000000000000000000000000000000000000000000000000000000000002d4120{}ac006306636974726561140000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000016800000000000000000000000000000000000000000000000000000000000000", nofn_xonly_pk
    );

    tracing::info!("Bridge params: {}", bridge_params);

    bridge_params
}

/// Citrea e2e hardcoded EVM secret keys.
pub const SECRET_KEYS: [&str; 10] = [
    "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
    "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d",
    "0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a",
    "0x7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6",
    "0x47e179ec197488593b187f80a00eb0da91f1b9d0b13f8733639f19c30a34926a",
    "0x8b3a350cf5c34c9194ca85829a2df0ec3153be0318b5e2d3348e872092edffba",
    "0x92db14e403b83dfe3df233f83dfa3a0d7096f21ca9b0d6d6b8d88b2b4ec1564e",
    "0x4bbbf85ce3377467afe5d46f804f221813b2bb87f24d81f60f1fcdbf7cbf4356",
    "0xdbda1821b80551c9d65939329250298aa3472ba22feea921c0cf5d620ea67b97",
    "0x2a871d0798f97d79848a013d4936a73bf4cc922c825d33c1cf7073dff6d409c6",
];

/// Citrea e2e hardcoded EVM addresses.
pub const EVM_ADDRESSES: [&str; 10] = [
    "f39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
    "70997970C51812dc3A010C7d01b50e0d17dc79C8",
    "3C44CdDdB6a900fa2b585dd299e03d12FA4293BC",
    "90F79bf6EB2c4f870365E785982E1f101E93b906",
    "15d34AAf54267DB7D7c367839AAf71A00a2C6A65",
    "9965507D1a55bcC2695C58ba16FB37d819B0A4dc",
    "976EA74026E726554dB657fA54763abd0C3a0aa9",
    "14dC79964da2C08b23698B3D3cc7Ca32193d9955",
    "23618e81E3f5cdF7f54C3d65f7FBc0aBf5B21E8f",
    "a0Ee7A142d267C1f36714E4a8F75612F20a79720",
];

/// Starts typical nodes with typical configs for a test that needs Citrea.
pub async fn start_citrea(
    sequencer_config: SequencerConfig,
    f: &mut TestFramework,
) -> citrea_e2e::Result<(
    &Node<SequencerConfig>,
    &mut Node<EmptyConfig>,
    Option<&Node<LightClientProverConfig>>,
    Option<&Node<BatchProverConfig>>,
    &BitcoinNode,
)> {
    let sequencer = f.sequencer.as_ref().expect("Sequencer is present");
    let full_node = f.full_node.as_mut().expect("Full node is present");
    let batch_prover = f.batch_prover.as_ref();
    let light_client_prover = f.light_client_prover.as_ref();
    let da = f.bitcoin_nodes.get(0).expect("There is a bitcoin node");

    let min_soft_confirmations_per_commitment = sequencer_config.max_l2_blocks_per_commitment;

    if sequencer_config.test_mode {
        for _ in 0..min_soft_confirmations_per_commitment {
            sequencer.client.send_publish_batch_request().await?;
        }
    }
    sequencer
        .wait_for_l2_height(min_soft_confirmations_per_commitment, None)
        .await?;
    println!("Sequencer is ready");

    Ok((sequencer, full_node, light_client_prover, batch_prover, da))
}

/// Updates given config with the values set by the Citrea e2e.
pub fn update_config_with_citrea_e2e_values(
    config: &mut BridgeConfig,
    da: &citrea_e2e::bitcoin::BitcoinNode,
    sequencer: &citrea_e2e::node::Node<SequencerConfig>,
    light_client_prover: Option<(&str, u16)>,
) {
    config.bitcoin_rpc_user = da.config.rpc_user.clone().into();
    config.bitcoin_rpc_password = da.config.rpc_password.clone().into();
    config.bitcoin_rpc_url = format!(
        "http://127.0.0.1:{}/wallet/{}",
        da.config.rpc_port,
        NodeKind::Bitcoin // citrea-e2e internal.
    );

    let citrea_url = format!(
        "http://{}:{}",
        sequencer.config.rollup.rpc.bind_host, sequencer.config.rollup.rpc.bind_port
    );
    config.citrea_rpc_url = citrea_url;

    if let Some(light_client_prover) = light_client_prover {
        let citrea_light_client_prover_url =
            format!("http://{}:{}", light_client_prover.0, light_client_prover.1);
        config.citrea_light_client_prover_url = citrea_light_client_prover_url;
    } else {
        let citrea_light_client_prover_url = format!("http://{}:{}", "127.0.0.1", 8080); // Dummy value
        config.citrea_light_client_prover_url = citrea_light_client_prover_url;
    }
}

pub async fn wait_until_lc_contract_updated(
    client: &HttpClient,
    block_height: u64,
) -> Result<(), BridgeError> {
    let mut attempts = 0;
    let max_attempts = 600;

    while attempts < max_attempts {
        let block_number = block_number(client).await?;
        if block_number >= block_height as u32 {
            break;
        }
        attempts += 1;
        tokio::time::sleep(std::time::Duration::from_millis(1000)).await;
    }
    Ok(())
}

/// Convert scriptbuf into how it would look like as a tapscript in a witness
/// Then search the script bytes, find the location where the next bytes exactly matches cut_bytes
/// cut it from the script and return the resulting prefix and suffix
pub fn extract_suffix_and_prefix_from_witness_script(
    script: bitcoin::ScriptBuf,
    cut_bytes: &[u8],
) -> eyre::Result<(Vec<u8>, Vec<u8>)> {
    // In the witness, the length of the script is appended as VarInt first
    // contract expects this VarInt in the script prefix so we add it manually here
    let mut script_bytes = script.into_bytes();
    let varint = VarInt::from(script_bytes.len());
    let mut varint_vec: Vec<u8> = Vec::with_capacity(varint.size());
    varint.consensus_encode(&mut varint_vec)?;

    // Combine varint and script_bytes back to back
    varint_vec.append(&mut script_bytes);
    let script_bytes = varint_vec;

    // Find the first occurrence of cut_bytes in the script
    if let Some(pos) = script_bytes
        .windows(cut_bytes.len())
        .position(|window| window == cut_bytes)
    {
        let prefix = script_bytes[..pos].to_vec();
        let suffix = script_bytes[pos + cut_bytes.len()..].to_vec();
        Ok((prefix, suffix))
    } else {
        // If cut_bytes is not found, return an error
        Err(eyre::eyre!("The requested bytes not found in script"))
    }
}

/// helper struct to hold e2e nodes and relevant clients/configs
pub struct CitreaE2EData<'a> {
    pub sequencer: &'a Node<SequencerConfig>,
    pub full_node: &'a Node<EmptyConfig>,
    pub lc_prover: &'a Node<LightClientProverConfig>,
    pub batch_prover: &'a Node<BatchProverConfig>,
    pub da: &'a BitcoinNode,
    pub config: BridgeConfig,
    pub citrea_client: &'a CitreaClient,
    pub rpc: &'a ExtendedRpc,
}

/// Creates a new withdrawal utxo and register to citrea using safeWithdraw
///
/// # Parameters
///
/// - `move_txid`: Move txid of the deposit.
/// - `e2e`: Citrea e2e data.
///
/// # Returns
///
/// A tuple of:
///
/// - [`OutPoint`]: UTXO for the given withdrawal.
/// - [`TxOut`]: Output correspoinding to the withdrawal.
/// - [`schnorr::Signature`]: Signature for the withdrawal utxo.
pub async fn get_new_withdrawal_utxo_and_register_to_citrea(
    move_txid: Txid,
    e2e: &CitreaE2EData<'_>,
    actors: &TestActors<CitreaClient>,
) -> (OutPoint, TxOut, bitcoin::secp256k1::schnorr::Signature) {
    e2e.rpc
        .mine_blocks_while_synced(DEFAULT_FINALITY_DEPTH + 2, actors)
        .await
        .unwrap();
    force_sequencer_to_commit(e2e.sequencer).await.unwrap();
    e2e.rpc
        .mine_blocks_while_synced(DEFAULT_FINALITY_DEPTH + 2, actors)
        .await
        .unwrap();
    // Send deposit to Citrea
    let (tx, block, block_height) = get_tx_information_for_citrea(e2e, move_txid).await.unwrap();

    tracing::info!("Depositing to Citrea...");

    deposit(
        e2e.rpc,
        e2e.sequencer.client.http_client().clone(),
        block,
        block_height.try_into().unwrap(),
        tx,
    )
    .await
    .unwrap();

    force_sequencer_to_commit(e2e.sequencer).await.unwrap();

    e2e.rpc.mine_blocks_while_synced(1, actors).await.unwrap();

    // Wait for the deposit to be processed.
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;

    // After the deposit, the balance should be non-zero.
    assert_ne!(
        eth_get_balance(
            e2e.sequencer.client.http_client().clone(),
            crate::EVMAddress([1; 20]),
        )
        .await
        .unwrap(),
        0
    );

    tracing::info!("Deposit operations are successful.");

    // Prepare withdrawal transaction.
    let user_sk = SecretKey::from_slice(&[13u8; 32]).unwrap();
    let withdrawal_address = Address::p2tr(
        &SECP,
        user_sk.x_only_public_key(&SECP).0,
        None,
        e2e.config.protocol_paramset().network,
    );
    let (withdrawal_utxo_with_txout, payout_txout, sig) =
        generate_withdrawal_transaction_and_signature(
            &e2e.config,
            e2e.rpc,
            &withdrawal_address,
            e2e.config.protocol_paramset().bridge_amount
                - e2e
                    .config
                    .operator_withdrawal_fee_sats
                    .unwrap_or(Amount::from_sat(0)),
        )
        .await;

    e2e.rpc
        .mine_blocks_while_synced(DEFAULT_FINALITY_DEPTH + 2, actors)
        .await
        .unwrap();
    force_sequencer_to_commit(e2e.sequencer).await.unwrap();

    let params = get_citrea_safe_withdraw_params(
        e2e.rpc,
        withdrawal_utxo_with_txout.clone(),
        payout_txout.clone(),
        sig,
    )
    .await
    .unwrap();

    tracing::info!("Params: {:?}", params);

    let withdrawal_utxo = withdrawal_utxo_with_txout.outpoint;
    tracing::info!("Created withdrawal UTXO: {:?}", withdrawal_utxo);

    let citrea_withdrawal_tx = e2e
        .citrea_client
        .contract
        .safeWithdraw(params.0, params.1, params.2, params.3, params.4)
        .value(U256::from(
            e2e.config.protocol_paramset().bridge_amount.to_sat() * SATS_TO_WEI_MULTIPLIER,
        ))
        .send()
        .await
        .unwrap();
    tracing::info!("Withdrawal TX sent in Citrea");

    // 1. force sequencer to commit
    force_sequencer_to_commit(e2e.sequencer).await.unwrap();
    tracing::info!("Publish batch request sent");

    let receipt = citrea_withdrawal_tx.get_receipt().await.unwrap();
    tracing::info!("Citrea withdrawal tx receipt: {:?}", receipt);

    e2e.rpc
        .mine_blocks_while_synced(DEFAULT_FINALITY_DEPTH + 2, actors)
        .await
        .unwrap();

    (withdrawal_utxo, payout_txout, sig)
}

pub async fn force_sequencer_to_commit(sequencer: &Node<SequencerConfig>) -> eyre::Result<()> {
    for _ in 0..sequencer.config.node.max_l2_blocks_per_commitment {
        sequencer
            .client
            .send_publish_batch_request()
            .await
            .map_err(|e| eyre::eyre!("Failed to publish block: {:?}", e))?;
    }
    Ok(())
}

pub async fn get_tx_information_for_citrea(
    e2e: &CitreaE2EData<'_>,
    txid: Txid,
) -> eyre::Result<(Transaction, Block, u64)> {
    let tx = e2e.rpc.client.get_raw_transaction(&txid, None).await?;
    let tx_info = e2e.rpc.client.get_raw_transaction_info(&txid, None).await?;
    let block = e2e
        .rpc
        .client
        .get_block(&tx_info.blockhash.unwrap())
        .await?;
    let block_height = e2e
        .rpc
        .client
        .get_block_info(&block.block_hash())
        .await?
        .height as u64;
    Ok((tx, block, block_height))
}

pub async fn register_replacement_deposit_to_citrea(
    e2e: &CitreaE2EData<'_>,
    move_txid: Txid,
    deposit_id: u32,
    actors: &TestActors<CitreaClient>,
) -> eyre::Result<()> {
    e2e.rpc
        .mine_blocks_while_synced(DEFAULT_FINALITY_DEPTH, actors)
        .await
        .unwrap();
    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    force_sequencer_to_commit(e2e.sequencer).await.unwrap();
    tracing::info!("Setting operator to our address");
    // first set our address as operator
    let set_operator_tx = e2e
        .citrea_client
        .contract
        .setOperator(e2e.citrea_client.wallet_address)
        .send()
        .await?;
    force_sequencer_to_commit(e2e.sequencer).await?;
    let receipt = set_operator_tx.get_receipt().await?;
    tracing::info!("Set operator tx receipt: {:?}", receipt);

    e2e.rpc
        .mine_blocks_while_synced(DEFAULT_FINALITY_DEPTH, actors)
        .await
        .unwrap();

    let (replace_tx, block, block_height) = get_tx_information_for_citrea(e2e, move_txid).await?;

    tracing::warn!("Replace transaction: {:?}", replace_tx);
    tracing::warn!("Replace transaction block: {:?}", block);

    // wait for light client to sync until replacement deposit tx
    e2e.lc_prover
        .wait_for_l1_height(block_height, None)
        .await
        .map_err(|e| eyre::eyre!("Failed to wait for light client to sync: {:?}", e))?;

    wait_until_lc_contract_updated(e2e.sequencer.client.http_client(), block_height)
        .await
        .unwrap();

    let (replace_tx, tx_proof, sha_script_pubkeys) =
        get_citrea_deposit_params(e2e.rpc, replace_tx, block, block_height as u32, move_txid)
            .await?;

    tracing::warn!("Replace transaction block height: {:?}", block_height);
    tracing::warn!(
        "Current chain height: {:?}",
        e2e.rpc.get_current_chain_height().await.unwrap()
    );
    tracing::warn!("Replace transaction tx proof : {:?}", tx_proof);

    let replace_deposit_tx = e2e
        .citrea_client
        .contract
        .replaceDeposit(
            replace_tx,
            tx_proof,
            U256::from(deposit_id),
            sha_script_pubkeys,
        )
        .from(e2e.citrea_client.wallet_address)
        .send()
        .await?;

    force_sequencer_to_commit(e2e.sequencer).await?;

    let receipt = replace_deposit_tx.get_receipt().await?;
    tracing::info!("Replace deposit tx receipt: {:?}", receipt);

    e2e.rpc
        .mine_blocks_while_synced(DEFAULT_FINALITY_DEPTH, actors)
        .await
        .unwrap();
    let finalized_height = e2e.da.get_finalized_height(None).await.unwrap();
    e2e.batch_prover
        .wait_for_l1_height(finalized_height, None)
        .await
        .unwrap();
    e2e.rpc
        .mine_blocks_while_synced(DEFAULT_FINALITY_DEPTH + 2, actors)
        .await
        .unwrap();

    Ok(())
}

/// This fn sends a payout tx with given operator, starts a kickoff then returns the reimburse connector of the kickoff.
/// operator_xonly_pk and operator_db should match the operator client ClementineOperatorClient
#[allow(clippy::too_many_arguments)]
pub async fn payout_and_start_kickoff(
    mut operator: ClementineOperatorClient<tonic::transport::Channel>,
    operator_xonly_pk: XOnlyPublicKey,
    operator_db: &Database,
    withdrawal_id: u32,
    withdrawal_utxo: &OutPoint,
    payout_txout: &TxOut,
    sig: &bitcoin::secp256k1::schnorr::Signature,
    e2e: &CitreaE2EData<'_>,
    actors: &TestActors<CitreaClient>,
) -> OutPoint {
    loop {
        let withdrawal_response = operator
            .withdraw(WithdrawParams {
                withdrawal_id,
                input_signature: sig.serialize().to_vec(),
                input_outpoint: Some((*withdrawal_utxo).into()),
                output_script_pubkey: payout_txout.script_pubkey.to_bytes(),
                output_amount: payout_txout.value.to_sat(),
            })
            .await;

        tracing::info!("Withdrawal response: {:?}", withdrawal_response);

        match withdrawal_response {
            Ok(_) => break,
            Err(e) => tracing::info!("Withdrawal error: {:?}", e),
        };
        e2e.rpc.mine_blocks_while_synced(1, actors).await.unwrap();
    }

    let payout_txid = get_txid_where_utxo_is_spent_while_waiting_for_state_mngr_sync(
        e2e.rpc,
        *withdrawal_utxo,
        actors,
    )
    .await
    .unwrap();

    e2e.rpc
        .mine_blocks_while_synced(DEFAULT_FINALITY_DEPTH, actors)
        .await
        .unwrap();

    tracing::info!(
        "Waiting until getting first unhandled payout for operator {:?}",
        operator_xonly_pk
    );

    // wait until payout is handled
    tracing::info!("Waiting until payout is handled");
    while operator_db
        .get_handled_payout_kickoff_txid(None, payout_txid)
        .await
        .unwrap()
        .is_none()
    {
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }

    let kickoff_txid = operator_db
        .get_handled_payout_kickoff_txid(None, payout_txid)
        .await
        .unwrap()
        .expect("Payout must be handled");

    let reimburse_connector = OutPoint {
        txid: kickoff_txid,
        vout: UtxoVout::ReimburseInKickoff.get_vout(),
    };

    let kickoff_block_height =
        mine_once_after_in_mempool(e2e.rpc, kickoff_txid, Some("Kickoff tx"), Some(300))
            .await
            .unwrap();

    tracing::info!(
        "Kickoff height: {:?}, txid: {:?} operator: {:?}",
        kickoff_block_height,
        kickoff_txid,
        operator_xonly_pk
    );

    reimburse_connector
}

#[allow(clippy::too_many_arguments)]
pub async fn reimburse_with_optimistic_payout(
    actors: &TestActors<CitreaClient>,
    withdrawal_id: u32,
    withdrawal_utxo: &OutPoint,
    payout_txout: &TxOut,
    sig: &bitcoin::secp256k1::schnorr::Signature,
    e2e: &CitreaE2EData<'_>,
    move_txid: Txid,
) -> eyre::Result<()> {
    let mut aggregator = actors.get_aggregator();
    aggregator
        .optimistic_payout(WithdrawParams {
            withdrawal_id,
            input_signature: sig.serialize().to_vec(),
            input_outpoint: Some(withdrawal_utxo.to_owned().into()),
            output_script_pubkey: payout_txout.script_pubkey.to_bytes(),
            output_amount: payout_txout.value.to_sat(),
        })
        .await?;

    // ensure the btc in vault is spent
    ensure_outpoint_spent_while_waiting_for_state_mngr_sync(
        e2e.rpc,
        OutPoint {
            txid: move_txid,
            vout: (UtxoVout::DepositInMove).get_vout(),
        },
        actors,
    )
    .await?;

    Ok(())
}

/// Helper fn for common setup for disprove tests
/// Does a single deposit, registers a withdrawal, starts a kickoff from operator 0 and then challenges the kickoff
/// Afterwards it waits until all asserts are sent by operator.
/// Returns the actors, the kickoff txid and the kickoff tx
#[cfg(feature = "automation")]
pub async fn disprove_tests_common_setup(
    e2e: &CitreaE2EData<'_>,
) -> (TestActors<CitreaClient>, Txid, Transaction) {
    use super::run_single_deposit;
    use super::tx_utils::create_tx_sender;
    let mut config = e2e.config.clone();
    let (actors, deposit_info, move_txid, _deposit_blockhash, _) =
        run_single_deposit::<CitreaClient>(&mut config, e2e.rpc.clone(), None, None, None)
            .await
            .unwrap();

    // generate a withdrawal
    let (withdrawal_utxo, payout_txout, sig) =
        get_new_withdrawal_utxo_and_register_to_citrea(move_txid, e2e, &actors).await;

    // withdraw one with a kickoff with operator 0
    let (op0_db, op0_xonly_pk) = actors.get_operator_db_and_xonly_pk_by_index(0).await;
    let mut operator0 = actors.get_operator_client_by_index(0);

    let reimburse_connector = payout_and_start_kickoff(
        operator0.clone(),
        op0_xonly_pk,
        &op0_db,
        0,
        &withdrawal_utxo,
        &payout_txout,
        &sig,
        e2e,
        &actors,
    )
    .await;

    let kickoff_txid = reimburse_connector.txid;

    // send a challenge
    let kickoff_tx = e2e.rpc.get_tx_of_txid(&kickoff_txid).await.unwrap();

    // get kickoff utxo index
    let kickoff_idx = kickoff_tx.input[0].previous_output.vout - 1;
    let base_tx_req = TransactionRequest {
        kickoff_id: Some(
            KickoffData {
                operator_xonly_pk: op0_xonly_pk,
                round_idx: crate::operator::RoundIndex::Round(0),
                kickoff_idx: kickoff_idx as u32,
            }
            .into(),
        ),
        deposit_outpoint: Some(deposit_info.deposit_outpoint.into()),
    };

    let all_txs = operator0
        .internal_create_signed_txs(base_tx_req.clone())
        .await
        .unwrap()
        .into_inner();

    let challenge_tx = bitcoin::consensus::deserialize(
        &all_txs
            .signed_txs
            .iter()
            .find(|tx| tx.transaction_type == Some(TransactionType::Challenge.into()))
            .unwrap()
            .raw_tx,
    )
    .unwrap();

    let (tx_sender, tx_sender_db) = create_tx_sender(&config, 0).await.unwrap();
    let mut db_commit = tx_sender_db.begin_transaction().await.unwrap();
    tx_sender
        .insert_try_to_send(
            &mut db_commit,
            None,
            &challenge_tx,
            FeePayingType::RBF,
            None,
            &[],
            &[],
            &[],
            &[],
        )
        .await
        .unwrap();
    db_commit.commit().await.unwrap();

    e2e.rpc
        .mine_blocks_while_synced(DEFAULT_FINALITY_DEPTH, &actors)
        .await
        .unwrap();

    let challenge_outpoint = OutPoint {
        txid: kickoff_txid,
        vout: UtxoVout::Challenge.get_vout(),
    };
    // wait until challenge tx is in mempool and mine
    mine_once_after_outpoint_spent_in_mempool(e2e.rpc, challenge_outpoint)
        .await
        .unwrap();

    // wait until all asserts are mined
    for i in 0..ClementineBitVMPublicKeys::number_of_assert_txs() {
        ensure_outpoint_spent_while_waiting_for_state_mngr_sync(
            e2e.rpc,
            OutPoint {
                txid: kickoff_txid,
                vout: UtxoVout::Assert(i).get_vout(),
            },
            &actors,
        )
        .await
        .unwrap();
    }

    (actors, kickoff_txid, kickoff_tx)
}
