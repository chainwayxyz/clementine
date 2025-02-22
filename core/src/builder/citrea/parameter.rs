//! # Parameter Builder For Citrea Requests

use crate::errors::BridgeError;
use bitcoin::consensus::Encodable;
use bitcoin::{Block, Transaction, Txid};
use merkle::MerkleTree;
use ring::digest::SHA256;

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

pub fn get_deposit_transaction_params(transaction: Transaction) -> Result<Vec<u8>, BridgeError> {
    let version: u32 = transaction.version.0 as u32;
    let flag: u16 = 0; // TODO
    let vin: Vec<u8> = encode_btc_params!(transaction.input);
    let vout: Vec<u8> = encode_btc_params!(transaction.output);
    let witness: Vec<u8> = encode_btc_params!(transaction.input, witness);
    let locktime: u32 = transaction.lock_time.to_consensus_u32();

    let mut message = Vec::new();
    message.extend_from_slice(&version.to_be_bytes());
    message.extend_from_slice(&flag.to_be_bytes());
    message.extend_from_slice(&vin);
    message.extend_from_slice(&vout);
    message.extend_from_slice(&witness);
    message.extend_from_slice(&locktime.to_be_bytes());

    Ok(message)
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

            tx.compute_txid() // or is this wtxid?
        })
        .collect::<Vec<_>>();

    let merkle_tree = MerkleTree::from_vec(&SHA256, txids);
    let merkle_proof = merkle_tree
        .gen_nth_proof(txid_index)
        .ok_or(BridgeError::Error("TODO".to_string()))?;
    let merkle_proof_leafs =
        merkle_proof.root_hash.as_slice()[0..merkle_proof.root_hash.len() - 2].to_vec();

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

pub fn get_deposit_block_params(
    block: Block,
    block_height: u32,
    txid: Txid,
) -> Result<Vec<u8>, BridgeError> {
    let (index, merkle_proof) = get_block_merkle_proof(block, txid)?;

    let mut message = Vec::new();
    message.extend_from_slice(&merkle_proof);
    message.extend_from_slice(&[0u8; 28]); // First 28 bytes of block height
    message.extend_from_slice(&block_height.to_be_bytes());
    message.extend_from_slice(&[0u8; 28]); // First 28 bytes of index
    message.extend_from_slice(&index.to_be_bytes());

    Ok(message)
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
    fn get_deposit_transaction_params() {
        let base_encoded_tx_size = 22;

        let empty_transaction = Transaction {
            version: transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::Blocks(Height::ZERO),
            input: vec![],
            output: vec![],
        };
        let encoded_tx = super::get_deposit_transaction_params(empty_transaction).unwrap();
        assert_eq!(encoded_tx.len(), base_encoded_tx_size);

        let empty_transaction = Transaction {
            version: transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::Blocks(Height::ZERO),
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                witness: Witness::from_slice(&[[0x45; 32]]),
                ..Default::default()
            }],
            output: vec![],
        };
        let encoded_tx = super::get_deposit_transaction_params(empty_transaction).unwrap();
        assert!(encoded_tx.len() > base_encoded_tx_size);
    }

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
