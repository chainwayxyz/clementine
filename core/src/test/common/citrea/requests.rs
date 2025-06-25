use crate::bitvm_client::SECP;
use crate::citrea::{CitreaClient, CitreaClientT, LIGHT_CLIENT_ADDRESS, SATS_TO_WEI_MULTIPLIER};
use crate::config::BridgeConfig;
use crate::errors::BridgeError;
use crate::extended_rpc::ExtendedRpc;
use crate::rpc::clementine::WithdrawParams;
use crate::test::common::citrea::parameters::get_citrea_deposit_params;
use crate::test::common::citrea::{self, get_citrea_safe_withdraw_params, SECRET_KEYS};
use crate::test::common::generate_withdrawal_transaction_and_signature;
use crate::EVMAddress;
use alloy::primitives::U256;
use alloy::sol_types::SolValue;
use bitcoin::secp256k1::ecdsa::Signature;
use bitcoin::secp256k1::{schnorr, SecretKey};
use bitcoin::{Address, Amount, Block, OutPoint, Transaction, TxOut};
use bitcoincore_rpc::RpcApi;
use citrea_e2e::bitcoin::{BitcoinNode, DEFAULT_FINALITY_DEPTH};
use citrea_e2e::config::{BatchProverConfig, LightClientProverConfig, SequencerConfig};
use citrea_e2e::node::Node;
use eyre::Context;
use jsonrpsee::core::client::ClientT;
use jsonrpsee::http_client::HttpClient;
use jsonrpsee::rpc_params;
use serde_json::json;

pub async fn block_number(client: &HttpClient) -> Result<u32, BridgeError> {
    let params = rpc_params![
        json!({
            "to": LIGHT_CLIENT_ADDRESS,
            "data": "0x57e871e7"
        }),
        "latest"
    ];

    let response: String = client
        .request("eth_call", params)
        .await
        .wrap_err("Failed to get block number")?;

    let decoded_hex = hex::decode(&response[2..]).map_err(|e| eyre::eyre!(e.to_string()))?;
    let block_number = decoded_hex
        .iter()
        .rev()
        .take(4)
        .rev()
        .fold(0u32, |acc, &byte| (acc << 8) | byte as u32);

    Ok(block_number)
}

pub async fn eth_get_balance(
    client: HttpClient,
    evm_address: EVMAddress,
) -> Result<u128, BridgeError> {
    let params = rpc_params![evm_address.0, "latest"];

    let response: String = client
        .request("eth_getBalance", params)
        .await
        .wrap_err("Failed to get balance")?;
    let ret = u128::from_str_radix(&response[2..], 16)
        .map_err(|e| eyre::eyre!("Can't convert hex to int: {}", e))?;

    Ok(ret)
}

/// Deposits a transaction to Citrea. This function is different from `contract.deposit` because it
/// won't directly talk with EVM but with Citrea. So that authorization can be done (Citrea will
/// block this call if it isn't an operator).
pub async fn deposit(
    rpc: &ExtendedRpc,
    client: HttpClient,
    block: Block,
    block_height: u32,
    transaction: Transaction,
) -> Result<(), BridgeError> {
    let txid = transaction.compute_txid();

    let params = get_citrea_deposit_params(rpc, transaction, block, block_height, txid).await?;

    let _response: () = client
        .request(
            "citrea_sendRawDepositTransaction",
            rpc_params!(hex::encode(params.abi_encode_params())),
        )
        .await
        .wrap_err("Failed to send deposit transaction")?;

    Ok(())
}

pub async fn make_withdrawal(
    rpc: &ExtendedRpc,
    config: &BridgeConfig,
    sequencer: &Node<SequencerConfig>,
    lc_prover: &Node<LightClientProverConfig>,
    batch_prover: &Node<BatchProverConfig>,
    da: &BitcoinNode,
) -> citrea_e2e::Result<(OutPoint, TxOut, schnorr::Signature)> {
    // This can be made a parameter if needed.
    let user_sk = SecretKey::from_slice(&[13u8; 32]).unwrap();
    let withdrawal_address = Address::p2tr(
        &SECP,
        user_sk.x_only_public_key(&SECP).0,
        None,
        config.protocol_paramset().network,
    );
    let (withdrawal_utxo_with_txout, payout_txout, sig) =
        generate_withdrawal_transaction_and_signature(
            &config,
            &rpc,
            &withdrawal_address,
            config.protocol_paramset().bridge_amount
                - config
                    .operator_withdrawal_fee_sats
                    .unwrap_or(Amount::from_sat(0)),
        )
        .await;

    rpc.mine_blocks(1).await.unwrap();

    let block_height = rpc.client.get_block_count().await.unwrap();

    // Wait for TXs to be on-chain (CPFP etc.).
    rpc.mine_blocks(DEFAULT_FINALITY_DEPTH).await.unwrap();
    tokio::time::sleep(std::time::Duration::from_secs(1)).await;

    for _ in 0..sequencer.config.node.max_l2_blocks_per_commitment {
        sequencer.client.send_publish_batch_request().await.unwrap();
    }

    citrea::wait_until_lc_contract_updated(sequencer.client.http_client(), block_height)
        .await
        .unwrap();

    let params = get_citrea_safe_withdraw_params(
        &rpc,
        withdrawal_utxo_with_txout.clone(),
        payout_txout.clone(),
        sig,
    )
    .await
    .unwrap();

    println!("Params: {:?}", params);

    let withdrawal_utxo = withdrawal_utxo_with_txout.outpoint;
    println!("Created withdrawal UTXO: {:?}", withdrawal_utxo);

    let citrea_client = CitreaClient::new(
        config.citrea_rpc_url.clone(),
        config.citrea_light_client_prover_url.clone(),
        config.citrea_chain_id,
        Some(SECRET_KEYS[0].to_string().parse().unwrap()),
    )
    .await
    .unwrap();

    let citrea_withdrawal_tx = citrea_client
        .contract
        .safeWithdraw(params.0, params.1, params.2, params.3, params.4)
        .value(U256::from(
            config.protocol_paramset().bridge_amount.to_sat() * SATS_TO_WEI_MULTIPLIER,
        ))
        .send()
        .await
        .unwrap();
    println!("Withdrawal TX sent in Citrea");

    // 1. force sequencer to commit
    for _ in 0..sequencer.config.node.max_l2_blocks_per_commitment {
        sequencer.client.send_publish_batch_request().await.unwrap();
    }
    println!("Publish batch request sent");

    let receipt = citrea_withdrawal_tx.get_receipt().await.unwrap();
    println!("Citrea withdrawal tx receipt: {:?}", receipt);

    // 2. wait until 2 commitment txs (commit, reveal) seen from DA to ensure their reveal prefix nonce is found
    da.wait_mempool_len(2, None).await?;

    // 3. generate FINALITY_DEPTH da blocks
    rpc.mine_blocks(DEFAULT_FINALITY_DEPTH).await.unwrap();

    // 4. wait for batch prover to generate proof on the finalized height
    let finalized_height = da.get_finalized_height(None).await.unwrap();
    batch_prover
        .wait_for_l1_height(finalized_height, None)
        .await?;
    lc_prover.wait_for_l1_height(finalized_height, None).await?;

    // 5. ensure 2 batch proof txs on DA (commit, reveal)
    da.wait_mempool_len(2, None).await?;

    // 6. generate FINALITY_DEPTH da blocks
    rpc.mine_blocks(DEFAULT_FINALITY_DEPTH).await.unwrap();

    let finalized_height = da.get_finalized_height(None).await.unwrap();

    println!("Finalized height: {:?}", finalized_height);
    lc_prover.wait_for_l1_height(finalized_height, None).await?;
    println!("Waited for L1 height {}", finalized_height);

    rpc.mine_blocks(DEFAULT_FINALITY_DEPTH).await.unwrap();

    Ok((withdrawal_utxo, payout_txout, sig))
}
