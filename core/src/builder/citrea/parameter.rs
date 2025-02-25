//! # Parameter Builder For Citrea Requests

use crate::errors::BridgeError;
use alloy::primitives::{Bytes, FixedBytes, Uint};
use alloy::sol;
use alloy::sol_types::SolValue;
use bitcoin::consensus::Encodable;
use bitcoin::{Block, Transaction, Txid};
use merkle::MerkleTree;
use ring::digest::SHA256;

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

            tx.compute_wtxid() // or is this wtxid?
        })
        .collect::<Vec<_>>();

    let merkle_tree = MerkleTree::from_vec(&SHA256, txids);
    let merkle_proof = merkle_tree
        .gen_nth_proof(txid_index)
        .ok_or(BridgeError::Error("TODO".to_string()))?;
    let merkle_proof_leafs =
        merkle_proof.root_hash.as_slice()[0..merkle_proof.root_hash.len() - 1].to_vec();

    // let wtxid_root = merkle_proof_with_root
    //     .root_hash
    //     .last()
    //     .ok_or(BridgeError::Error("TODO".to_string()))?;
    // let witness_reserved_value = block
    //     .txdata
    //     .get(0)
    //     .expect("TODO")
    //     .input
    //     .get(0)
    //     .expect("TODO")
    //     .witness
    //     .iter()
    //     .next()
    //     .expect("TODO");
    // let concat = [&[*wtxid_root], witness_reserved_value].concat();
    // let witness_commit = Hash::const_hash(&concat);
    // if !block.txdata.get(0).expect("TODO").raw_hex().contains(&witness_commit.to_string()){
    //     return Err(BridgeError::Error(format!("Witness Commitment not found in the first transaction of the block: {:?}: {:?}", witness_commit.to_string(), block.txdata.get(0).expect("TODO").raw_hex())));
    // }

    let proof = if txid_index % 2 == 0 {
        merkle_proof_leafs[1..].to_vec()
    } else {
        [
            vec![merkle_proof_leafs[0]],
            merkle_proof_leafs[2..].to_vec(),
        ]
        .concat()
    };

    Ok((txid_index, proof))
}

pub fn get_deposit_params(
    transaction: Transaction,
    block: Block,
    block_height: u32,
    txid: Txid,
) -> Result<Vec<u8>, BridgeError> {
    let version: u32 = transaction.version.0 as u32;
    let flag: u16 = 1; // TODO
    let vin: Vec<u8> = transaction.input.iter().map(|input| {
        let mut encoded_input = Vec::new();
        let mut previous_output = Vec::new();
        input.previous_output.consensus_encode(&mut previous_output)
            .map_err(|e| BridgeError::Error(format!("Can't encode input: {}", e)))?;
        tracing::error!("previous_output: {:?}", previous_output);
        let mut script_sig = Vec::new();
        input.script_sig.consensus_encode(&mut script_sig)
            .map_err(|e| BridgeError::Error(format!("Can't encode script_sig: {}", e)))?;
        let mut sequence = Vec::new();
        input.sequence.consensus_encode(&mut sequence)
            .map_err(|e| BridgeError::Error(format!("Can't encode sequence: {}", e)))?;

        encoded_input.extend(previous_output);
        encoded_input.extend(script_sig);
        encoded_input.extend(sequence);

        Ok::<Vec<u8>, BridgeError>(encoded_input)
    }).collect::<Result<Vec<_>, _>>()?.into_iter().flatten().collect();
    let vin = [vec![transaction.input.len() as u8], vin].concat();
    let vout: Vec<u8> = encode_btc_params!(transaction.output);
    let vout = [vec![transaction.output.len() as u8], vout].concat();
    let witness: Vec<u8> = encode_btc_params!(transaction.input, witness);
    let locktime: u32 = transaction.lock_time.to_consensus_u32();
    let (index, merkle_proof) = get_block_merkle_proof(block, txid)?;

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
