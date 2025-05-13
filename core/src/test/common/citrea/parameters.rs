//! # Parameter Builder For Citrea Requests

use crate::citrea::Bridge::MerkleProof as CitreaMerkleProof;
use crate::citrea::Bridge::Transaction as CitreaTransaction;
use crate::errors::BridgeError;
use crate::extended_rpc::ExtendedRpc;
use crate::test::common::citrea::bitcoin_merkle::BitcoinMerkleTree;
use alloy::primitives::{Bytes, FixedBytes, Uint};
use alloy::sol;
use alloy::sol_types;
use bitcoin::consensus::Encodable;
use bitcoin::hashes::sha256;
use bitcoin::hashes::Hash;
use bitcoin::OutPoint;
use bitcoin::{Block, Transaction, Txid};

/// Returns merkle proof for a given transaction (via txid) in a block.
fn get_block_merkle_proof(
    block: Block,
    target_txid: Txid,
) -> Result<(usize, Vec<u8>), BridgeError> {
    let mut txid_index = 0;
    let txids = block
        .txdata
        .iter()
        .enumerate()
        .map(|(i, tx)| {
            if tx.compute_txid() == target_txid {
                txid_index = i;
            }

            if i == 0 {
                [0; 32]
            } else {
                let wtxid = tx.compute_wtxid();
                wtxid.as_byte_array().to_owned()
            }
        })
        .collect::<Vec<_>>();

    let merkle_tree = BitcoinMerkleTree::new(txids.clone());
    let _witness_root = block.witness_root().unwrap();
    let witness_idx_path = merkle_tree.get_idx_path(txid_index.try_into().unwrap());

    let _root = merkle_tree.calculate_root_with_merkle_proof(
        txids[txid_index],
        txid_index.try_into().unwrap(),
        witness_idx_path.clone(),
    );

    Ok((txid_index, witness_idx_path.into_iter().flatten().collect()))
}

/// Returns [`TransactionParams`] for a given transaction, which can be later
/// used for deposit and withdrawal operations.
pub async fn get_transaction_params(
    rpc: &ExtendedRpc,
    transaction: Transaction,
    block: Block,
    block_height: u32,
    txid: Txid,
) -> Result<(CitreaTransaction, CitreaMerkleProof, FixedBytes<32>), BridgeError> {
    // Version is in little endian format in Bitcoin.
    let version = (transaction.version.0 as u32).to_le_bytes();
    // TODO: Flag should be 0 if no witness elements. Do this in the future if
    // needed.
    let flag: u16 = 1;

    let vin: Vec<u8> = transaction
        .input
        .iter()
        .map(|input| {
            let mut encoded_input = Vec::new();
            let mut previous_output = Vec::new();
            input
                .previous_output
                .consensus_encode(&mut previous_output)
                .unwrap();
            let mut script_sig = Vec::new();
            input.script_sig.consensus_encode(&mut script_sig).unwrap();
            let mut sequence = Vec::new();
            input.sequence.consensus_encode(&mut sequence).unwrap();

            encoded_input.extend(previous_output);
            encoded_input.extend(script_sig);
            encoded_input.extend(sequence);

            Ok::<Vec<u8>, BridgeError>(encoded_input)
        })
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .flatten()
        .collect();
    let vin = [vec![transaction.input.len() as u8], vin].concat();

    let vout: Vec<u8> = transaction
        .output
        .iter()
        .map(|param| {
            let mut raw = Vec::new();
            param
                .consensus_encode(&mut raw)
                .map_err(|e| BridgeError::Error(format!("Can't encode param: {}", e)))?;

            Ok::<Vec<u8>, BridgeError>(raw)
        })
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .flatten()
        .collect::<Vec<u8>>();
    let vout = [vec![transaction.output.len() as u8], vout].concat();

    let witness: Vec<u8> = transaction
        .input
        .iter()
        .map(|param| {
            let mut raw = Vec::new();
            param
                .witness
                .consensus_encode(&mut raw)
                .map_err(|e| BridgeError::Error(format!("Can't encode param: {}", e)))?;

            Ok::<Vec<u8>, BridgeError>(raw)
        })
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .flatten()
        .collect::<Vec<u8>>();

    let locktime: u32 = transaction.lock_time.to_consensus_u32();
    let (index, merkle_proof) = get_block_merkle_proof(block, txid)?;

    let tp = CitreaTransaction {
        version: FixedBytes::from(version),
        flag: FixedBytes::from(flag),
        vin: Bytes::copy_from_slice(&vin),
        vout: Bytes::copy_from_slice(&vout),
        witness: Bytes::copy_from_slice(&witness),
        locktime: FixedBytes::from(locktime),
    };
    let mp = CitreaMerkleProof {
        intermediateNodes: Bytes::copy_from_slice(&merkle_proof),
        blockHeight: Uint::from(block_height),
        index: Uint::from(index),
    };

    let mut enc_script_pubkeys = sha256::Hash::engine();
    for input in transaction.input {
        let prevout = rpc.get_txout_from_outpoint(&input.previous_output).await?;
        prevout
            .script_pubkey
            .consensus_encode(&mut enc_script_pubkeys)
            .unwrap();
    }
    let sha_script_pubkeys = sha256::Hash::from_engine(enc_script_pubkeys);

    let mut reversed_sha_script_pubkeys = sha_script_pubkeys.as_byte_array().to_vec();
    // reversed_sha_script_pubkeys.reverse();

    let reversed_sha_script_pks: [u8; 32] = reversed_sha_script_pubkeys.try_into().unwrap();


    let sha_script_pubkeys = FixedBytes::from(reversed_sha_script_pks);

    Ok((tp, mp, sha_script_pubkeys))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::extended_rpc::ExtendedRpc;
    use bitcoincore_rpc::RpcApi;
    use std::str::FromStr;

    #[ignore = "Manual testing utility"]
    #[tokio::test]
    async fn test_get_transaction_params() {
        let rpc = ExtendedRpc::connect(
            "http://127.0.0.1:38332".to_string(),
            "bitcoin".to_string(),
            "bitcoin".to_string(),
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
            get_transaction_params(&rpc, tx, block, block_info.height as u32, txid)
                .await
                .unwrap();
        println!("{:?}", transaction_params);
    }
}
