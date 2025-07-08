//! # Citrea Related Utilities

use crate::bitvm_client::SECP;
use crate::builder::transaction::input::UtxoVout;
use crate::builder::transaction::TransactionType;
use crate::citrea::{CitreaClient, SATS_TO_WEI_MULTIPLIER};
use crate::database::Database;
use crate::deposit::{DepositInfo, KickoffData};
use crate::extended_rpc::ExtendedRpc;
use crate::musig2::AggregateFromPublicKeys;
use crate::operator::RoundIndex;
use crate::rpc::clementine::clementine_aggregator_client::ClementineAggregatorClient;
use crate::rpc::clementine::clementine_operator_client::ClementineOperatorClient;
use crate::rpc::clementine::{TransactionRequest, WithdrawParams};
use crate::test::common::tx_utils::{create_tx_sender, mine_once_after_outpoint_spent_in_mempool};
use crate::test::common::{
    generate_withdrawal_transaction_and_signature, mine_once_after_in_mempool,
};
use crate::utils::{FeePayingType, TxMetadata};
use crate::{config::BridgeConfig, errors::BridgeError};
use alloy::primitives::U256;
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::{PublicKey, SecretKey};
use bitcoin::{Address, Amount, OutPoint, TxOut, Txid, XOnlyPublicKey};
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

use super::tx_utils::ensure_outpoint_spent_while_waiting_for_light_client_sync;

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

pub fn extract_suffix_and_prefix_from_script(
    script: bitcoin::ScriptBuf,
    cut_bytes: &[u8],
) -> eyre::Result<(Vec<u8>, Vec<u8>)> {
    let mut script_bytes = script.into_bytes();
    assert!(script_bytes.len() <= 75); // 75 is the max length that can be pushed to stack with one opcode
    script_bytes.insert(0, script_bytes.len() as u8); // insert length of script to start

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
) -> (OutPoint, TxOut, bitcoin::secp256k1::schnorr::Signature) {
    // Send deposit to Citrea
    let tx = e2e
        .rpc
        .client
        .get_raw_transaction(&move_txid, None)
        .await
        .unwrap();
    let tx_info = e2e
        .rpc
        .client
        .get_raw_transaction_info(&move_txid, None)
        .await
        .unwrap();
    let block = e2e
        .rpc
        .client
        .get_block(&tx_info.blockhash.unwrap())
        .await
        .unwrap();
    let block_height = e2e
        .rpc
        .client
        .get_block_info(&block.block_hash())
        .await
        .unwrap()
        .height as u64;

    wait_until_lc_contract_updated(e2e.sequencer.client.http_client(), block_height)
        .await
        .unwrap();

    tracing::debug!("Depositing to Citrea...");

    deposit(
        e2e.rpc,
        e2e.sequencer.client.http_client().clone(),
        block,
        block_height.try_into().unwrap(),
        tx,
    )
    .await
    .unwrap();

    for _ in 0..e2e.sequencer.config.node.max_l2_blocks_per_commitment {
        e2e.sequencer
            .client
            .send_publish_batch_request()
            .await
            .unwrap();
    }

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

    e2e.rpc.mine_blocks(1).await.unwrap();

    let block_height = e2e.rpc.get_current_chain_height().await.unwrap();

    e2e.rpc.mine_blocks(DEFAULT_FINALITY_DEPTH).await.unwrap();
    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    for _ in 0..e2e.sequencer.config.node.max_l2_blocks_per_commitment {
        e2e.sequencer
            .client
            .send_publish_batch_request()
            .await
            .unwrap();
    }

    wait_until_lc_contract_updated(e2e.sequencer.client.http_client(), block_height.into())
        .await
        .unwrap();

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
    for _ in 0..e2e.sequencer.config.node.max_l2_blocks_per_commitment {
        e2e.sequencer
            .client
            .send_publish_batch_request()
            .await
            .unwrap();
    }
    tracing::info!("Publish batch request sent");

    let receipt = citrea_withdrawal_tx.get_receipt().await.unwrap();
    tracing::info!("Citrea withdrawal tx receipt: {:?}", receipt);

    // 2. wait until 2 commitment txs (commit, reveal) seen from DA to ensure their reveal prefix nonce is found
    e2e.da.wait_mempool_len(2, None).await.unwrap();

    // 3. generate FINALITY_DEPTH da blocks
    e2e.rpc.mine_blocks(DEFAULT_FINALITY_DEPTH).await.unwrap();

    // 4. wait for batch prover to generate proof on the finalized height
    let finalized_height = e2e.da.get_finalized_height(None).await.unwrap();
    e2e.batch_prover
        .wait_for_l1_height(finalized_height, None)
        .await
        .unwrap();
    e2e.lc_prover
        .wait_for_l1_height(finalized_height, None)
        .await
        .unwrap();

    // 5. ensure 2 batch proof txs on DA (commit, reveal)
    e2e.da.wait_mempool_len(2, None).await.unwrap();

    // 6. generate FINALITY_DEPTH da blocks
    e2e.rpc.mine_blocks(DEFAULT_FINALITY_DEPTH).await.unwrap();

    let finalized_height = e2e.da.get_finalized_height(None).await.unwrap();

    tracing::info!("Finalized height: {:?}", finalized_height);
    e2e.lc_prover
        .wait_for_l1_height(finalized_height, None)
        .await
        .unwrap();
    tracing::info!("Waited for L1 height {}", finalized_height);

    e2e.rpc.mine_blocks(DEFAULT_FINALITY_DEPTH).await.unwrap();

    (withdrawal_utxo, payout_txout, sig)
}

/// This fn sends a payout tx with given operator, starts a kickoff then returns the reimburse connector of the kickoff.
#[allow(clippy::too_many_arguments)]
pub async fn payout_and_challenge(
    mut operator: ClementineOperatorClient<tonic::transport::Channel>,
    operator_xonly_pk: XOnlyPublicKey,
    operator_db: &Database,
    withdrawal_id: u32,
    withdrawal_utxo: &OutPoint,
    payout_txout: &TxOut,
    sig: &bitcoin::secp256k1::schnorr::Signature,
    e2e: &CitreaE2EData<'_>,
    deposit_info: &DepositInfo,
) -> OutPoint {
    let payout_txid = loop {
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
            Ok(withdrawal_response) => {
                tracing::info!("Withdrawal response: {:?}", withdrawal_response);
                break Txid::from_byte_array(
                    withdrawal_response
                        .into_inner()
                        .txid
                        .unwrap()
                        .txid
                        .try_into()
                        .unwrap(),
                );
            }
            Err(e) => {
                tracing::info!("Withdrawal error: {:?}", e);
            }
        }

        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    };
    tracing::info!("Payout txid: {:?}", payout_txid);

    mine_once_after_in_mempool(e2e.rpc, payout_txid, Some("Payout tx"), None)
        .await
        .unwrap();

    e2e.rpc.mine_blocks(DEFAULT_FINALITY_DEPTH).await.unwrap();

    // wait until payout part is not null
    while operator_db
        .get_first_unhandled_payout_by_operator_xonly_pk(None, operator_xonly_pk)
        .await
        .unwrap()
        .is_none()
    {
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }

    tracing::info!("Waiting until payout is handled");
    // wait until payout is handled
    while operator_db
        .get_first_unhandled_payout_by_operator_xonly_pk(None, operator_xonly_pk)
        .await
        .unwrap()
        .is_some()
    {
        tracing::info!("Payout is not handled yet");
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

    let kickoff_tx = e2e.rpc.get_tx_of_txid(&kickoff_txid).await.unwrap();

    // wrongfully challenge operator
    let kickoff_idx = kickoff_tx.input[0].previous_output.vout - 1;
    let base_tx_req = TransactionRequest {
        kickoff_id: Some(
            KickoffData {
                operator_xonly_pk,
                round_idx: RoundIndex::Round(0),
                kickoff_idx: kickoff_idx as u32,
            }
            .into(),
        ),
        deposit_outpoint: Some(deposit_info.deposit_outpoint.to_owned().into()),
    };
    let all_txs = operator
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

    let kickoff_tx: bitcoin::Transaction = bitcoin::consensus::deserialize(
        &all_txs
            .signed_txs
            .iter()
            .find(|tx| tx.transaction_type == Some(TransactionType::Kickoff.into()))
            .unwrap()
            .raw_tx,
    )
    .unwrap();

    assert_eq!(kickoff_txid, kickoff_tx.compute_txid());

    // send wrong challenge tx
    let (tx_sender, tx_sender_db) = create_tx_sender(&e2e.config, 0).await.unwrap();
    let mut db_commit = tx_sender_db.begin_transaction().await.unwrap();
    tx_sender
        .insert_try_to_send(
            &mut db_commit,
            Some(TxMetadata {
                deposit_outpoint: None,
                operator_xonly_pk: None,
                round_idx: None,
                kickoff_idx: None,
                tx_type: TransactionType::Challenge,
            }),
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

    e2e.rpc.mine_blocks(DEFAULT_FINALITY_DEPTH).await.unwrap();

    let challenge_outpoint = OutPoint {
        txid: kickoff_txid,
        vout: UtxoVout::Challenge.get_vout(),
    };
    tracing::warn!(
        "Wait until challenge tx is in mempool, kickoff block height: {:?}",
        kickoff_block_height
    );
    // wait until challenge tx is in mempool
    mine_once_after_outpoint_spent_in_mempool(e2e.rpc, challenge_outpoint)
        .await
        .unwrap();
    tracing::warn!("Mined once after challenge tx is in mempool");

    // wait until the light client prover is synced to the same height
    e2e.lc_prover
        .wait_for_l1_height(kickoff_block_height as u64, None)
        .await
        .unwrap();

    reimburse_connector
}

#[allow(clippy::too_many_arguments)]
pub async fn reimburse_with_optimistic_payout(
    mut aggregator: ClementineAggregatorClient<tonic::transport::Channel>,
    withdrawal_id: u32,
    withdrawal_utxo: &OutPoint,
    payout_txout: &TxOut,
    sig: &bitcoin::secp256k1::schnorr::Signature,
    e2e: &CitreaE2EData<'_>,
    move_txid: Txid,
) {
    loop {
        let payout_resp = aggregator
            .optimistic_payout(WithdrawParams {
                withdrawal_id,
                input_signature: sig.serialize().to_vec(),
                input_outpoint: Some(withdrawal_utxo.to_owned().into()),
                output_script_pubkey: payout_txout.script_pubkey.to_bytes(),
                output_amount: payout_txout.value.to_sat(),
            })
            .await;

        match payout_resp {
            Ok(payout_response) => {
                tracing::info!("Optimistic payout response: {:?}", payout_response);
                break;
            }
            Err(e) => {
                tracing::warn!("Optimistic payout error: {:?}", e);
            }
        }

        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }

    // ensure the btc in vault is spent
    ensure_outpoint_spent_while_waiting_for_light_client_sync(
        e2e.rpc,
        e2e.lc_prover,
        OutPoint {
            txid: move_txid,
            vout: (UtxoVout::DepositInMove).get_vout(),
        },
    )
    .await
    .unwrap();
}
