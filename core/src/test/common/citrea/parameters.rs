//! # Parameter Builder For Citrea Requests

use crate::builder;
use crate::builder::script::SpendPath;
use crate::builder::transaction::TransactionType;
use crate::citrea::Bridge::MerkleProof as CitreaMerkleProof;
use crate::citrea::Bridge::Transaction as CitreaTransaction;
use crate::constants::NON_STANDARD_V3;
use crate::errors::BridgeError;
use crate::extended_bitcoin_rpc::ExtendedBitcoinRpc;
use crate::rpc::clementine::NormalSignatureKind;
use crate::test::common::citrea::bitcoin_merkle::BitcoinMerkleTree;
use crate::UTXO;
use alloy::primitives::{Bytes, FixedBytes, Uint};
use bitcoin::consensus::Encodable;
use bitcoin::hashes::sha256;
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::schnorr;
use bitcoin::{Block, Transaction, Txid};
use bitcoincore_rpc::RpcApi;
use eyre::Context;

/// Returns merkle proof for a given transaction (via txid) in a block.
fn get_block_merkle_proof(
    block: &Block,
    target_txid: Txid,
    is_witness_merkle_proof: bool,
) -> Result<(usize, Vec<u8>), BridgeError> {
    let mut txid_index = 0;
    let txids = block
        .txdata
        .iter()
        .enumerate()
        .map(|(i, tx)| {
            let txid = tx.compute_txid();
            if txid == target_txid {
                txid_index = i;
            }

            if is_witness_merkle_proof {
                if i == 0 {
                    [0; 32]
                } else {
                    let wtxid = tx.compute_wtxid();
                    wtxid.as_byte_array().to_owned()
                }
            } else {
                txid.as_byte_array().to_owned()
            }
        })
        .collect::<Vec<_>>();

    let merkle_tree = BitcoinMerkleTree::new(txids.clone());
    let witness_idx_path = merkle_tree.get_idx_path(txid_index.try_into().unwrap());

    let _root = merkle_tree.calculate_root_with_merkle_proof(
        txids[txid_index],
        txid_index.try_into().unwrap(),
        witness_idx_path.clone(),
    );

    Ok((txid_index, witness_idx_path.into_iter().flatten().collect()))
}

fn get_transaction_details_for_citrea(
    transaction: &Transaction,
) -> Result<CitreaTransaction, BridgeError> {
    let version = (transaction.version.0 as u32).to_le_bytes();
    let flag: u16 = 1;

    let vin = [
        vec![transaction.input.len() as u8],
        transaction
            .input
            .iter()
            .map(|x| bitcoin::consensus::serialize(&x))
            .collect::<Vec<_>>()
            .into_iter()
            .flatten()
            .collect::<Vec<u8>>(),
    ]
    .concat();

    let vout = [
        vec![transaction.output.len() as u8],
        transaction
            .output
            .iter()
            .map(|x| bitcoin::consensus::serialize(&x))
            .collect::<Vec<_>>()
            .into_iter()
            .flatten()
            .collect::<Vec<u8>>(),
    ]
    .concat();

    let witness: Vec<u8> = transaction
        .input
        .iter()
        .map(|param| {
            let mut raw = Vec::new();
            param
                .witness
                .consensus_encode(&mut raw)
                .map_err(|e| eyre::eyre!("Can't encode param: {}", e))?;

            Ok::<Vec<u8>, BridgeError>(raw)
        })
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .flatten()
        .collect::<Vec<u8>>();

    let locktime = bitcoin::consensus::serialize(&transaction.lock_time);
    let locktime: [u8; 4] = locktime.try_into().unwrap();
    Ok(CitreaTransaction {
        version: FixedBytes::from(version),
        flag: FixedBytes::from(flag),
        vin: Bytes::copy_from_slice(&vin),
        vout: Bytes::copy_from_slice(&vout),
        witness: Bytes::copy_from_slice(&witness),
        locktime: FixedBytes::from(locktime),
    })
}

fn get_transaction_merkle_proof_for_citrea(
    block_height: u32,
    block: &Block,
    txid: Txid,
    is_witness_merkle_proof: bool,
) -> Result<CitreaMerkleProof, BridgeError> {
    let (index, merkle_proof) = get_block_merkle_proof(block, txid, is_witness_merkle_proof)?;

    Ok(CitreaMerkleProof {
        intermediateNodes: Bytes::copy_from_slice(&merkle_proof),
        blockHeight: Uint::from(block_height),
        index: Uint::from(index),
    })
}

async fn get_transaction_sha_script_pubkeys_for_citrea(
    rpc: &ExtendedBitcoinRpc,
    transaction: Transaction,
) -> Result<FixedBytes<32>, BridgeError> {
    let mut enc_script_pubkeys = sha256::Hash::engine();
    for input in transaction.input {
        let prevout = rpc.get_txout_from_outpoint(&input.previous_output).await?;
        prevout
            .script_pubkey
            .consensus_encode(&mut enc_script_pubkeys)
            .unwrap();
    }
    let sha_script_pubkeys = sha256::Hash::from_engine(enc_script_pubkeys);

    let sha_script_pks: [u8; 32] = sha_script_pubkeys
        .as_byte_array()
        .to_vec()
        .try_into()
        .unwrap();

    let sha_script_pubkeys = FixedBytes::from(sha_script_pks);

    Ok(sha_script_pubkeys)
}

/// Returns [`CitreaTransaction`] for a given transaction, which can be later
/// used for deposit and withdrawal operations.
pub async fn get_citrea_deposit_params(
    rpc: &ExtendedBitcoinRpc,
    transaction: Transaction,
    block: Block,
    block_height: u32,
    txid: Txid,
) -> Result<(CitreaTransaction, CitreaMerkleProof, FixedBytes<32>), BridgeError> {
    let tp = get_transaction_details_for_citrea(&transaction)?;
    let mp = get_transaction_merkle_proof_for_citrea(block_height, &block, txid, true)?;
    let sha_script_pubkeys =
        get_transaction_sha_script_pubkeys_for_citrea(rpc, transaction).await?;
    Ok((tp, mp, sha_script_pubkeys))
}

pub async fn get_citrea_safe_withdraw_params(
    rpc: &ExtendedBitcoinRpc,
    withdrawal_dust_utxo: UTXO,
    payout_output: bitcoin::TxOut,
    sig: schnorr::Signature,
) -> Result<
    (
        CitreaTransaction,
        CitreaMerkleProof,
        CitreaTransaction,
        Bytes,
        Bytes,
    ),
    BridgeError,
> {
    let prepare_tx = rpc
        .get_tx_of_txid(&withdrawal_dust_utxo.outpoint.txid)
        .await?;

    let prepare_tx_struct = get_transaction_details_for_citrea(&prepare_tx)?;

    let prepare_tx_blockhash = rpc
        .get_blockhash_of_tx(&withdrawal_dust_utxo.outpoint.txid)
        .await?;
    let prepare_tx_block_height = rpc
        .client
        .get_block_info(&prepare_tx_blockhash)
        .await
        .wrap_err("Failed to get prepare tx block height")?
        .height;
    let prepare_tx_block_header = rpc
        .client
        .get_block_header(&prepare_tx_blockhash)
        .await
        .wrap_err("Failed to get prepare tx block header")?;
    let prepare_tx_block = rpc
        .client
        .get_block(&prepare_tx_blockhash)
        .await
        .wrap_err("Failed to get prepare tx block")?;

    let prepare_tx_mp = get_transaction_merkle_proof_for_citrea(
        prepare_tx_block_height as u32,
        &prepare_tx_block,
        withdrawal_dust_utxo.outpoint.txid,
        false,
    )?;

    let txin = builder::transaction::input::SpendableTxIn::new(
        withdrawal_dust_utxo.outpoint,
        withdrawal_dust_utxo.txout.clone(),
        vec![],
        None,
    );

    let unspent_txout =
        builder::transaction::output::UnspentTxOut::from_partial(payout_output.clone());

    let mut tx = builder::transaction::TxHandlerBuilder::new(TransactionType::Payout)
        .with_version(NON_STANDARD_V3)
        .add_input(
            NormalSignatureKind::NotStored,
            txin,
            SpendPath::KeySpend,
            builder::transaction::DEFAULT_SEQUENCE,
        )
        .add_output(unspent_txout.clone())
        .finalize();

    let taproot_signature = bitcoin::taproot::Signature {
        signature: sig,
        sighash_type: bitcoin::sighash::TapSighashType::SinglePlusAnyoneCanPay,
    };

    tx.set_p2tr_key_spend_witness(&taproot_signature, 0)?;

    let payout_transaction = tx.get_cached_tx();

    let payout_tx_params = get_transaction_details_for_citrea(payout_transaction)?;

    let block_header_bytes =
        Bytes::copy_from_slice(&bitcoin::consensus::serialize(&prepare_tx_block_header));

    let output_script_pk_bytes = Bytes::copy_from_slice(
        &bitcoin::consensus::serialize(&payout_transaction.output[0].script_pubkey)
            .iter()
            .skip(1)
            .copied()
            .collect::<Vec<u8>>(),
    );

    Ok((
        prepare_tx_struct,
        prepare_tx_mp,
        payout_tx_params,
        block_header_bytes,
        output_script_pk_bytes,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::extended_bitcoin_rpc::ExtendedBitcoinRpc;
    use bitcoincore_rpc::RpcApi;
    use std::str::FromStr;

    #[ignore = "Manual testing utility"]
    #[tokio::test]
    async fn test_get_citrea_deposit_params() {
        let rpc = ExtendedBitcoinRpc::connect(
            "http://127.0.0.1:38332".to_string(),
            "bitcoin".to_string().into(),
            "bitcoin".to_string().into(),
            None,
        )
        .await
        .unwrap();

        let txid_str = "95fe701dd1fab6677d23e550dd7b7af12c9288ec209acb84bcc06708b8181d6a";
        let txid = Txid::from_str(txid_str).unwrap();
        let get_raw_transaction_result = rpc
            .client
            .get_raw_transaction_info(&txid, None)
            .await
            .unwrap();
        let block_hash = get_raw_transaction_result.blockhash.unwrap();
        let block = rpc.client.get_block(&block_hash).await.unwrap();
        let block_info = rpc.client.get_block_info(&block_hash).await.unwrap();
        let tx = rpc.client.get_raw_transaction(&txid, None).await.unwrap();
        println!(
            "Raw tx: {:?}",
            hex::encode(bitcoin::consensus::serialize(&tx))
        );
        let transaction_params =
            get_citrea_deposit_params(&rpc, tx, block, block_info.height as u32, txid)
                .await
                .unwrap();
        println!("{:?}", transaction_params);
    }
}
