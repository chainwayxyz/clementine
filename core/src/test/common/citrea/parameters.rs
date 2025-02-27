//! # Parameter Builder For Citrea Requests

use crate::errors::BridgeError;
use crate::test::common::citrea::bitcoin_merke::BitcoinMerkleTree;
use alloy::primitives::{Bytes, FixedBytes, Uint};
use alloy::sol;
use alloy::sol_types::SolValue;
use bitcoin::consensus::Encodable;
use bitcoin::hashes::Hash;
use bitcoin::{Block, Transaction, Txid};

sol!(
    #[derive(Debug, PartialEq, Eq)]
    struct TransactionParams {
        bytes4 version;
        bytes2 flag;
        bytes vin;
        bytes vout;
        bytes witness;
        bytes4 locktime;
        bytes intermediate_nodes;
        uint256 block_height;
        uint256 index;
    }
);

// Codegen from ABI file to interact with the contract.
sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    IWETH9,
    "src/test/common/citrea/Bridge.json"
);

macro_rules! encode_btc_params {
    ($params:expr) => {
        $params
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
            .collect::<Vec<u8>>()
    };

    ($params:expr, $inner:tt) => {
        $params
            .iter()
            .map(|param| {
                let mut raw = Vec::new();
                param
                    .$inner
                    .consensus_encode(&mut raw)
                    .map_err(|e| BridgeError::Error(format!("Can't encode param: {}", e)))?;

                Ok::<Vec<u8>, BridgeError>(raw)
            })
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .flatten()
            .collect::<Vec<u8>>()
    };
}

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
                let wtxid = wtxid.as_byte_array();
                wtxid.to_owned()
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

pub fn get_deposit_params(
    transaction: Transaction,
    block: Block,
    block_height: u32,
    txid: Txid,
) -> Result<Vec<u8>, BridgeError> {
    let version: u32 = transaction.version.0 as u32;
    let flag: u16 = 1; // TODO
    let vin: Vec<u8> = transaction
        .input
        .iter()
        .map(|input| {
            let mut encoded_input = Vec::new();
            let mut previous_output = Vec::new();
            input
                .previous_output
                .consensus_encode(&mut previous_output)
                .map_err(|e| BridgeError::Error(format!("Can't encode input: {}", e)))?;
            let mut script_sig = Vec::new();
            input
                .script_sig
                .consensus_encode(&mut script_sig)
                .map_err(|e| BridgeError::Error(format!("Can't encode script_sig: {}", e)))?;
            let mut sequence = Vec::new();
            input
                .sequence
                .consensus_encode(&mut sequence)
                .map_err(|e| BridgeError::Error(format!("Can't encode sequence: {}", e)))?;

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
    let vout: Vec<u8> = encode_btc_params!(transaction.output);
    let vout = [vec![transaction.output.len() as u8], vout].concat();
    let witness: Vec<u8> = encode_btc_params!(transaction.input, witness);
    let locktime: u32 = transaction.lock_time.to_consensus_u32();
    let (index, merkle_proof) = get_block_merkle_proof(block, txid)?;

    let version = version.to_le_bytes();
    let transaction_params = TransactionParams {
        version: FixedBytes::from(version),
        flag: FixedBytes::from(flag),
        vin: Bytes::copy_from_slice(&vin),
        vout: Bytes::copy_from_slice(&vout),
        witness: Bytes::copy_from_slice(&witness),
        locktime: FixedBytes::from(locktime),
        intermediate_nodes: Bytes::copy_from_slice(&merkle_proof),
        block_height: Uint::from(block_height),
        index: Uint::from(index),
    };

    Ok(transaction_params.abi_encode())
}

#[cfg(test)]
mod tests {
    use bitcoin::{
        absolute::Height,
        block::{Header, Version},
        hashes::Hash,
        transaction, Amount, Block, BlockHash, CompactTarget, OutPoint, ScriptBuf, Transaction,
        TxIn, TxMerkleNode, TxOut, Txid, Witness,
    };

    #[test]
    fn get_block_merkle_proof() {
        let default_tx = Transaction {
            version: transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::Blocks(Height::ZERO),
            input: vec![],
            output: vec![],
        };
        let transactions = vec![
            Transaction {
                input: vec![TxIn {
                    previous_output: OutPoint::null(),
                    witness: Witness::from_slice(&[[0x45; 32]]),
                    ..Default::default()
                }],
                output: vec![TxOut {
                    value: Amount::from_int_btc(50),
                    script_pubkey: ScriptBuf::new(),
                }],
                ..default_tx
            },
            Transaction {
                input: vec![],
                output: vec![TxOut {
                    value: Amount::from_sat(0x45),
                    script_pubkey: ScriptBuf::new(),
                }],
                ..default_tx
            },
            Transaction {
                input: vec![TxIn {
                    previous_output: OutPoint {
                        txid: Txid::from_slice(&[0x45; 32]).unwrap(),
                        vout: 0,
                    },
                    ..Default::default()
                }],
                output: vec![TxOut {
                    value: Amount::from_sat(0x45),
                    script_pubkey: ScriptBuf::new(),
                }],
                ..default_tx
            },
        ];
        let txid = transactions[1].compute_txid();

        let block = Block {
            header: Header {
                version: Version::TWO,
                prev_blockhash: BlockHash::all_zeros(),
                merkle_root: TxMerkleNode::all_zeros(),
                time: 0x45,
                bits: CompactTarget::default(),
                nonce: 0x1F,
            },
            txdata: transactions,
        };

        // TODO: Compare with a secondary source
        super::get_block_merkle_proof(block, txid).unwrap();
    }
}
