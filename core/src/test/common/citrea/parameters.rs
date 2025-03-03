//! # Parameter Builder For Citrea Requests

use crate::citrea::Bridge::TransactionParams;
use crate::errors::BridgeError;
use crate::test::common::citrea::bitcoin_merke::BitcoinMerkleTree;
use alloy::primitives::{Bytes, FixedBytes, Uint};
use bitcoin::consensus::Encodable;
use bitcoin::hashes::Hash;
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
pub fn get_transaction_params(
    transaction: Transaction,
    block: Block,
    block_height: u32,
    txid: Txid,
) -> Result<TransactionParams, BridgeError> {
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

    Ok(TransactionParams {
        version: FixedBytes::from(version),
        flag: FixedBytes::from(flag),
        vin: Bytes::copy_from_slice(&vin),
        vout: Bytes::copy_from_slice(&vout),
        witness: Bytes::copy_from_slice(&witness),
        locktime: FixedBytes::from(locktime),
        intermediate_nodes: Bytes::copy_from_slice(&merkle_proof),
        block_height: Uint::from(block_height),
        index: Uint::from(index),
    })
}
