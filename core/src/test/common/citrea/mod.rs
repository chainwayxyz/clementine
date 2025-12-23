//! # Citrea Related Utilities

use crate::bitvm_client::SECP;
use crate::citrea::{CitreaClient, SATS_TO_WEI_MULTIPLIER};
use crate::extended_bitcoin_rpc::ExtendedBitcoinRpc;
use crate::musig2::AggregateFromPublicKeys;
use crate::test::common::generate_withdrawal_transaction_and_signature;
use crate::{config::BridgeConfig, errors::BridgeError};
use alloy::primitives::U256;
use alloy::providers::Provider;
use bitcoin::consensus::Encodable;
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::{PublicKey, SecretKey};
use bitcoin::taproot;
use bitcoin::{Address, Amount, Block, OutPoint, Transaction, TxOut, Txid, VarInt, XOnlyPublicKey};
use bitcoincore_rpc::RpcApi;
use citrea_e2e::bitcoin::{BitcoinNodeCluster, DEFAULT_FINALITY_DEPTH};
use citrea_e2e::{
    config::{BatchProverConfig, EmptyConfig, LightClientProverConfig, SequencerConfig},
    framework::TestFramework,
    node::{Node, NodeKind},
};
pub use client_mock::*;
use eyre::Context;
use jsonrpsee::http_client::HttpClient;
pub use parameters::*;
pub use requests::*;

use super::test_actors::TestActors;

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
        "000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000000c00000000000000000000000000000000000000000000000008ac7230489e80000000000000000000000000000000000000000000000000000000000000000002d4120{nofn_xonly_pk}ac006306636974726561140000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000016800000000000000000000000000000000000000000000000000000000000000"
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
    &BitcoinNodeCluster,
)> {
    let sequencer = f.sequencer.as_ref().expect("Sequencer is present");
    let full_node = f.full_node.as_mut().expect("Full node is present");
    let batch_prover = f.batch_prover.as_ref();
    let light_client_prover = f.light_client_prover.as_ref();

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

    Ok((
        sequencer,
        full_node,
        light_client_prover,
        batch_prover,
        &f.bitcoin_nodes,
    ))
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

/// Wait until the light client contract is updated so that given txid is proven
/// or if no txid is given the current finalized block height is proven.
pub async fn wait_until_lc_contract_updated(
    client: &HttpClient,
    e2e: &CitreaE2EData<'_>,
    actors: &TestActors<CitreaClient>,
    txid: Option<Txid>,
) -> Result<(), BridgeError> {
    let height;
    if let Some(txid) = txid {
        let mut confirmations = u64::from(e2e.rpc.confirmation_blocks(&txid).await?);
        if confirmations <= DEFAULT_FINALITY_DEPTH {
            e2e.rpc
                .mine_blocks_while_synced(
                    DEFAULT_FINALITY_DEPTH - confirmations + 1, // 1 extra, idk why
                    actors,
                    Some(e2e),
                )
                .await
                .unwrap();
            confirmations = DEFAULT_FINALITY_DEPTH;
        }
        let cur_height = e2e
            .rpc
            .get_block_count()
            .await
            .wrap_err("Failed to get block count")?;
        height = cur_height - confirmations + 1;
    } else {
        height = e2e
            .rpc
            .get_block_count()
            .await
            .wrap_err("Failed to get block count")?
            - DEFAULT_FINALITY_DEPTH
            + 1;
    }
    let mut attempts = 0;
    let max_attempts = 600;

    let current_chain_height = e2e.rpc.get_block_count().await.unwrap();

    while attempts < max_attempts {
        let block_number = block_number(client).await?;
        tracing::info!(
            "LC block number: {block_number}, current chain height: {current_chain_height}, requested height: {height}",
        );
        if block_number >= height as u32 {
            break;
        }
        attempts += 1;
        e2e.sequencer
            .client
            .send_publish_batch_request()
            .await
            .map_err(|e| eyre::eyre!("Failed to send publish batch request: {e}"))?;
        tokio::time::sleep(std::time::Duration::from_millis(1000)).await;
    }
    if attempts == max_attempts {
        return Err(eyre::eyre!("LC block number is less than requested height {height}").into());
    }
    Ok(())
}

/// Convert scriptbuf into how it would look like as a tapscript in a witness
/// (basically adds a VarInt to the beginning of the script)
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
    pub bitcoin_nodes: &'a BitcoinNodeCluster,
    pub config: BridgeConfig,
    pub citrea_client: &'a CitreaClient,
    pub rpc: &'a ExtendedBitcoinRpc,
}

/// Creates new withdrawal utxos and registers them to Citrea using safeWithdraw
/// For each move txid, it first registers the deposit to Citrea.
/// After it is registered a new utxo is created and mined, it is registered to citrea
/// using safeWithdraw. Afterwards, this utxo is saved on contract and operators can use this
/// utxo to fulfill withdrawals.
///
/// # Parameters
///
/// - `move_txids`: Move txids of the deposits.
/// - `e2e`: Citrea e2e data.
/// - `actors`: Test actors.
///
/// # Returns
///
/// A vector of tuples of:
///
/// - [`OutPoint`]: UTXO for the given withdrawal.
/// - [`TxOut`]: Output corresponding to the withdrawal.
/// - [`schnorr::Signature`]: Signature for the withdrawal utxo.
pub async fn get_new_withdrawal_utxo_and_register_to_citrea(
    move_txids: &[Txid],
    e2e: &CitreaE2EData<'_>,
    actors: &TestActors<CitreaClient>,
) -> Vec<(OutPoint, TxOut, taproot::Signature)> {
    let mut results = Vec::with_capacity(move_txids.len());
    let mut pending_withdrawals = Vec::with_capacity(move_txids.len());

    // First, wait for all move txids to be reflected in the LC contract before proceeding.
    for move_txid in move_txids {
        wait_until_lc_contract_updated(
            e2e.sequencer.client.http_client(),
            e2e,
            actors,
            Some(*move_txid),
        )
        .await
        .unwrap();
    }

    // Process deposits and construct withdrawal transactions for each move txid.
    for move_txid in move_txids {
        // Send deposit to Citrea
        let (tx, block, block_height) = get_tx_information_for_citrea(e2e, *move_txid)
            .await
            .unwrap();

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

        e2e.sequencer
            .client
            .send_publish_batch_request()
            .await
            .unwrap();

        // Wait for the deposit to be processed.
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;

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

        pending_withdrawals.push((withdrawal_utxo_with_txout, payout_txout, sig));
    }

    // Mine once for all pending withdrawals, then wait for LC updates for all of them together.
    if !pending_withdrawals.is_empty() {
        e2e.rpc
            .mine_blocks_while_synced(1, actors, Some(e2e))
            .await
            .unwrap();

        for (withdrawal_utxo_with_txout, _, _) in &pending_withdrawals {
            wait_until_lc_contract_updated(
                e2e.sequencer.client.http_client(),
                e2e,
                actors,
                Some(withdrawal_utxo_with_txout.outpoint.txid),
            )
            .await
            .unwrap();
        }
    }

    // Register all withdrawals on Citrea.
    let mut current_nonce = e2e
        .citrea_client
        .contract
        .provider()
        .get_transaction_count(e2e.citrea_client.wallet_address)
        .await
        .unwrap_or(0);
    tracing::info!("Current nonce: {current_nonce}");
    let mut pending_citrea_txs = Vec::with_capacity(pending_withdrawals.len());
    for (withdrawal_utxo_with_txout, payout_txout, sig) in pending_withdrawals {
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
            .nonce(current_nonce)
            .value(U256::from(
                e2e.config.protocol_paramset().bridge_amount.to_sat() * SATS_TO_WEI_MULTIPLIER,
            ))
            .send()
            .await
            .unwrap();
        tracing::info!("Withdrawal TX sent in Citrea");

        current_nonce += 1;
        pending_citrea_txs.push(citrea_withdrawal_tx);
        results.push((withdrawal_utxo, payout_txout, sig));
    }

    // Commit once at the end to reduce block usage.
    if !results.is_empty() {
        force_sequencer_to_commit(e2e.sequencer).await.unwrap();
        tracing::info!("Publish batch request sent");

        // Check receipts after commit to ensure all txs are finalized.
        for tx in pending_citrea_txs {
            let receipt = tx.get_receipt().await.unwrap();
            tracing::info!("Citrea withdrawal tx receipt: {:?}", receipt);
        }
    }

    results
}

/// call citrea_testPublishBlock max_l2_blocks_per_commitment times
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

/// For a given txid, get the full tx, block that includes it and height of the block
pub async fn get_tx_information_for_citrea(
    e2e: &CitreaE2EData<'_>,
    txid: Txid,
) -> eyre::Result<(Transaction, Block, u64)> {
    let tx = e2e.rpc.get_raw_transaction(&txid, None).await?;
    let tx_info = e2e.rpc.get_raw_transaction_info(&txid, None).await?;
    let block = e2e.rpc.get_block(&tx_info.blockhash.unwrap()).await?;
    let block_height = e2e.rpc.get_block_info(&block.block_hash()).await?.height as u64;
    Ok((tx, block, block_height))
}

/// After a replacement deposit is done, register this replacement on citrea
/// The move_txid for the corresponding deposit_id will be updated to replacement_move_txid
pub async fn register_replacement_deposit_to_citrea(
    e2e: &CitreaE2EData<'_>,
    replacement_move_txid: Txid,
    deposit_id: u32,
    actors: &TestActors<CitreaClient>,
) -> eyre::Result<()> {
    wait_until_lc_contract_updated(
        e2e.sequencer.client.http_client(),
        e2e,
        actors,
        Some(replacement_move_txid),
    )
    .await?;

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
        .mine_blocks_while_synced(DEFAULT_FINALITY_DEPTH, actors, Some(e2e))
        .await
        .unwrap();

    let (replace_tx, block, block_height) =
        get_tx_information_for_citrea(e2e, replacement_move_txid).await?;

    tracing::info!("Replace transaction: {:?}", replace_tx);
    tracing::info!("Replace transaction block: {:?}", block);

    // wait for light client to sync until replacement deposit tx
    e2e.lc_prover
        .wait_for_l1_height(block_height, None)
        .await
        .map_err(|e| eyre::eyre!("Failed to wait for light client to sync: {:?}", e))?;

    let (replace_tx, tx_proof, sha_script_pubkeys) = get_citrea_deposit_params(
        e2e.rpc,
        replace_tx,
        block,
        block_height as u32,
        replacement_move_txid,
    )
    .await?;

    tracing::info!("Replace transaction block height: {:?}", block_height);
    tracing::info!(
        "Current chain height: {:?}",
        e2e.rpc.get_current_chain_height().await.unwrap()
    );
    tracing::info!("Replace transaction tx proof : {:?}", tx_proof);

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
        .mine_blocks_while_synced(DEFAULT_FINALITY_DEPTH, actors, Some(e2e))
        .await
        .unwrap();
    let finalized_height = e2e
        .bitcoin_nodes
        .get(0)
        .expect("There is a bitcoin node")
        .get_finalized_height(None)
        .await
        .unwrap();
    e2e.batch_prover
        .wait_for_l1_height(finalized_height, None)
        .await
        .unwrap();
    e2e.rpc
        .mine_blocks_while_synced(DEFAULT_FINALITY_DEPTH + 2, actors, Some(e2e))
        .await
        .unwrap();

    Ok(())
}

impl CitreaClient {
    /// Update the nofn aggregated key to the given xonly pk
    /// It updates both deposit and replacement scripts on Citrea side.
    /// To do this it creates a dummy deposit and replacement deposit.
    /// For the deposit script, it cuts the EVM address (only dynamic part) from the script and
    /// sends the prefix and suffix of the remaining script to citrea.
    /// For the replacement script, it cuts the old move txid from the script (again the only dynamic part) instead.
    pub async fn update_nofn_aggregated_key(
        &self,
        nofn_xonly_pk: XOnlyPublicKey,
        paramset: &'static crate::config::protocol::ProtocolParamset,
        sequencer: &citrea_e2e::node::Node<citrea_e2e::config::SequencerConfig>,
    ) -> eyre::Result<()> {
        use std::str::FromStr;

        use crate::deposit::{
            Actors, BaseDepositData, DepositData, DepositInfo, DepositType, ReplacementDepositData,
            SecurityCouncil,
        };
        use crate::test::common::citrea::force_sequencer_to_commit;
        use crate::EVMAddress;

        // create a dummy script with nofn xonly pk
        let dummy_evm_address: EVMAddress = EVMAddress(std::array::from_fn(|i| i as u8));
        let mut dummy_base_deposit_data = DepositData {
            nofn_xonly_pk: Some(nofn_xonly_pk),
            deposit: DepositInfo {
                deposit_outpoint: OutPoint::default(),
                deposit_type: DepositType::BaseDeposit(BaseDepositData {
                    evm_address: dummy_evm_address,
                    recovery_taproot_address: bitcoin::Address::from_str(
                        "bcrt1p65yp9q9fxtf7dyvthyrx26xxm2czanvrnh9rtvphmlsjvhdt4k6qw4pkss", // dummy address
                    )
                    .unwrap(),
                }),
            },
            actors: Actors {
                verifiers: vec![],
                watchtowers: vec![],
                operators: vec![],
            },
            security_council: SecurityCouncil {
                pks: vec![],
                threshold: 0,
            },
        };

        let base_deposit_script =
            dummy_base_deposit_data.get_deposit_scripts(paramset)?[0].to_script_buf();

        let (deposit_prefix, deposit_suffix) =
            crate::test::common::citrea::extract_suffix_and_prefix_from_witness_script(
                base_deposit_script,
                &dummy_evm_address.0,
            )?;

        // Make the transaction more explicit
        let dep_script_tx = self
            .contract
            .setDepositScript(deposit_prefix.into(), deposit_suffix.into())
            .from(self.wallet_address)
            .send()
            .await
            .wrap_err("Failed to update nofn aggregated key")?;

        force_sequencer_to_commit(sequencer).await?;

        dep_script_tx.get_receipt().await?;

        // now update the replacement script
        let dummy_old_move_txid = Txid::from_byte_array(std::array::from_fn(|i| i as u8));
        let mut dummy_replacement_deposit_data = DepositData {
            nofn_xonly_pk: Some(nofn_xonly_pk),
            deposit: DepositInfo {
                deposit_outpoint: OutPoint::default(),
                deposit_type: DepositType::ReplacementDeposit(ReplacementDepositData {
                    old_move_txid: dummy_old_move_txid,
                }),
            },
            actors: Actors {
                verifiers: vec![],
                watchtowers: vec![],
                operators: vec![],
            },
            security_council: SecurityCouncil {
                pks: vec![],
                threshold: 0,
            },
        };

        let replacement_deposit_script =
            dummy_replacement_deposit_data.get_deposit_scripts(paramset)?[0].to_script_buf();

        let (replacement_prefix, replacement_suffix) =
            crate::test::common::citrea::extract_suffix_and_prefix_from_witness_script(
                replacement_deposit_script,
                dummy_old_move_txid.as_byte_array(),
            )?;

        let rep_deposit_tx = self
            .contract
            .setReplaceScript(replacement_prefix.into(), replacement_suffix.into())
            .from(self.wallet_address)
            .send()
            .await
            .wrap_err("Failed to update nofn aggregated key")?;

        force_sequencer_to_commit(sequencer).await?;

        rep_deposit_tx.get_receipt().await?;

        Ok(())
    }
}
