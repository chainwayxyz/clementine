use std::borrow::BorrowMut;

use bitcoin::block::Header;
use bitcoin::hashes::Hash;
use bitcoin::sighash::SighashCache;
use bitcoin::{self, Block, MerkleBlock, OutPoint, TxMerkleNode, Txid, Wtxid, XOnlyPublicKey};

use bitcoin::consensus::Decodable;

use bitcoin::taproot::ControlBlock;
use bitcoin::taproot::LeafVersion;

use bitcoin::taproot::TaprootSpendInfo;

use bitcoin::Amount;

use bitcoin::ScriptBuf;

use clementine_circuits::double_sha256_hash;
use hex;

use sha2::{Digest, Sha256};

use crate::constants::CONFIRMATION_BLOCK_COUNT;
use crate::errors::BridgeError;
use crate::extended_rpc::ExtendedRpc;
use crate::transaction_builder::{CreateTxOutputs, TransactionBuilder};
use crate::{EVMAddress, HashTree};

pub fn parse_hex_to_btc_tx(
    tx_hex: &str,
) -> Result<bitcoin::blockdata::transaction::Transaction, bitcoin::consensus::encode::Error> {
    if let Ok(reader) = hex::decode(tx_hex) {
        bitcoin::blockdata::transaction::Transaction::consensus_decode(&mut &reader[..])
    } else {
        Err(bitcoin::consensus::encode::Error::ParseFailed(
            "Could not decode hex",
        ))
    }
}

pub fn create_control_block(tree_info: TaprootSpendInfo, script: &ScriptBuf) -> ControlBlock {
    tree_info
        .control_block(&(script.clone(), LeafVersion::TapScript))
        .expect("Cannot create control block")
}

pub fn check_deposit_utxo(
    rpc: &ExtendedRpc,
    tx_builder: &TransactionBuilder,
    outpoint: &OutPoint,
    return_address: &XOnlyPublicKey,
    evm_address: &EVMAddress,
    amount_sats: u64,
) -> Result<(), BridgeError> {
    if rpc.confirmation_blocks(&outpoint.txid)? < CONFIRMATION_BLOCK_COUNT {
        return Err(BridgeError::DepositNotFinalized);
    }

    let (deposit_address, _) = tx_builder.generate_deposit_address(return_address, evm_address)?;

    if !rpc.check_utxo_address_and_amount(
        outpoint,
        &deposit_address.script_pubkey(),
        amount_sats,
    )? {
        return Err(BridgeError::InvalidDepositUTXO);
    }

    if rpc.is_utxo_spent(outpoint)? {
        return Err(BridgeError::UTXOSpent);
    }
    Ok(())
}

pub fn calculate_amount(depth: usize, value: Amount, fee: Amount) -> Amount {
    (value + fee) * (2u64.pow(depth as u32))
}

pub fn handle_taproot_witness<T: AsRef<[u8]>>(
    tx: &mut bitcoin::Transaction,
    index: usize,
    witness_elements: &Vec<T>,
    script: &ScriptBuf,
    tree_info: &TaprootSpendInfo,
) -> Result<(), BridgeError> {
    let mut sighash_cache = SighashCache::new(tx.borrow_mut());
    let witness = sighash_cache
        .witness_mut(index)
        .ok_or(BridgeError::TxInputNotFound)?;
    for elem in witness_elements {
        witness.push(elem);
    }
    let spend_control_block = tree_info
        .control_block(&(script.clone(), LeafVersion::TapScript))
        .ok_or(BridgeError::ControlBlockError)?;
    witness.push(script);
    witness.push(&spend_control_block.serialize());
    Ok(())
}

pub fn handle_taproot_witness_new<T: AsRef<[u8]>>(
    tx: &mut CreateTxOutputs,
    witness_elements: &Vec<T>,
    index: usize,
) -> Result<(), BridgeError> {
    let mut sighash_cache = SighashCache::new(tx.tx.borrow_mut());
    let witness = sighash_cache
        .witness_mut(index)
        .ok_or(BridgeError::TxInputNotFound)?;
    for elem in witness_elements {
        witness.push(elem);
    }
    let spend_control_block = tx.taproot_spend_infos[index]
        .control_block(&(tx.scripts[index].clone(), LeafVersion::TapScript))
        .ok_or(BridgeError::ControlBlockError)?;
    witness.push(tx.scripts[index].clone());
    witness.push(&spend_control_block.serialize());
    Ok(())
}

pub fn get_claim_reveal_indices(depth: usize, count: u32) -> Vec<(usize, usize)> {
    assert!(count <= 2u32.pow(depth as u32));

    if count == 0 {
        return vec![(0, 0)];
    }

    let mut indices: Vec<(usize, usize)> = Vec::new();
    if count == 2u32.pow(depth as u32) {
        return indices;
    }

    if count % 2 == 1 {
        indices.push((depth, count as usize));
        indices.extend(get_claim_reveal_indices(depth - 1, (count + 1) / 2));
    } else {
        indices.extend(get_claim_reveal_indices(depth - 1, count / 2));
    }

    indices
}

pub fn get_claim_proof_tree_leaf(
    depth: usize,
    num_claims: usize,
    connector_tree_hashes: &HashTree,
) -> [u8; 32] {
    let indices = get_claim_reveal_indices(depth, num_claims as u32);
    let mut hasher = Sha256::new();
    indices.iter().for_each(|(level, index)| {
        hasher.update(connector_tree_hashes[*level][*index]);
    });
    hasher.finalize().into()
}
pub fn calculate_claim_proof_root(
    depth: usize,
    connector_tree_hashes: &Vec<Vec<[u8; 32]>>,
) -> [u8; 32] {
    let mut hashes: Vec<[u8; 32]> = Vec::new();
    for i in 0..2u32.pow(depth as u32) {
        let hash = get_claim_proof_tree_leaf(depth, i as usize, connector_tree_hashes);
        hashes.push(hash);
    }
    let mut level = 0;
    while level < depth {
        let mut level_hashes: Vec<[u8; 32]> = Vec::new();
        for i in 0..2u32.pow(depth as u32 - level as u32 - 1) {
            let mut hasher = Sha256::new();
            hasher.update(hashes[i as usize * 2]);
            hasher.update(hashes[i as usize * 2 + 1]);
            let hash = hasher.finalize().into();
            level_hashes.push(hash);
        }
        hashes = level_hashes.clone();
        level += 1;
    }
    hashes[0]
}

/// Pretty long and complicated merkle path extraction function to convert rust bitcoins merkleBlock to a flatten single merkle path
/// Need to simplify this
pub fn get_merkle_path_from_merkle_block(
    mb: MerkleBlock,
) -> Result<(Vec<TxMerkleNode>, u32), BridgeError> {
    let mut matches: Vec<Txid> = vec![];
    let mut index: Vec<u32> = vec![];
    mb.extract_matches(&mut matches, &mut index)?;

    if matches.len() != 1 {
        return Err(BridgeError::MerkleProofError);
    }

    if index.len() != 1 {
        return Err(BridgeError::MerkleProofError);
    }

    let txid = matches[0];
    let index = index[0];
    let length = mb.txn.num_transactions();
    let depth = (length - 1).ilog(2) + 1;

    let mut merkle_hashes = mb
        .txn
        .hashes()
        .iter()
        .map(Some)
        .collect::<Vec<Option<&TxMerkleNode>>>();

    // fill the remaining path elements with None s, this indicates that last node should be duplicated
    while merkle_hashes.len() < depth as usize + 1 {
        merkle_hashes.push(None);
    }
    let mut merkle_path = Vec::new();
    for bit in (0..merkle_hashes.len() - 1)
        .rev()
        .map(|n: usize| (index >> n) & 1)
    {
        let i = if bit == 1 { 0 } else { merkle_hashes.len() - 1 };
        merkle_path.push(merkle_hashes[i]);
        merkle_hashes.remove(i);
    }

    // bits of path indicator determines if the next tree node should be read from env or be the copy of last node
    let mut path_indicator = 0_u32;

    // this list may contain less than depth elements, which is normally the size of a merkle path
    let mut merkle_path_to_be_sent = Vec::new();

    for node in merkle_path {
        path_indicator <<= 1;
        match node {
            Some(txmn) => merkle_path_to_be_sent.push(txmn.clone()),
            None => path_indicator += 1,
        }
    }

    merkle_path_to_be_sent.reverse();

    let mut hash = txid.to_byte_array();
    let mut current_index = index;
    let mut reader_pointer = 0;

    for _ in 0..depth {
        let node = if path_indicator & 1 == 1 {
            merkle_path_to_be_sent
                .insert(reader_pointer, TxMerkleNode::from_byte_array(hash.clone()));
            reader_pointer += 1;
            hash
        } else {
            let node = merkle_path_to_be_sent[reader_pointer];
            reader_pointer += 1;
            *node.as_byte_array()
        };
        path_indicator >>= 1;
        hash = if current_index & 1 == 0 {
            double_sha256_hash!(&hash, &node)
        } else {
            double_sha256_hash!(&node, &hash)
        };
        current_index /= 2;
    }

    Ok((merkle_path_to_be_sent, index))
}

pub fn calculate_witness_merkle_path(
    txid: Txid,
    block: &Block,
) -> Result<(u32, Vec<TxMerkleNode>), BridgeError> {
    let mut wtxid = Txid::all_zeros();
    let hashes = block
        .txdata
        .iter()
        .enumerate()
        .map(|(i, t)| {
            if t.txid() == txid {
                wtxid = Txid::from_raw_hash(t.wtxid().to_raw_hash());
            }
            if i == 0 {
                // Replace the first hash with zeroes.
                Txid::from_raw_hash(Wtxid::all_zeros().to_raw_hash())
            } else {
                Txid::from_raw_hash(t.wtxid().to_raw_hash())
            }
        })
        .collect::<Vec<Txid>>();
    let witness_root = block.witness_root().unwrap();
    let dummy_header = Header {
        version: block.header.version,
        prev_blockhash: block.header.prev_blockhash,
        merkle_root: TxMerkleNode::from_raw_hash(witness_root.to_raw_hash()),
        time: block.header.time,
        bits: block.header.bits,
        nonce: block.header.nonce,
    };
    let merkle_block =
        MerkleBlock::from_header_txids_with_predicate(&dummy_header, &hashes, |t| *t == wtxid);

    let (merkle_path_to_be_sent, index) = get_merkle_path_from_merkle_block(merkle_block)?;
    Ok((index, merkle_path_to_be_sent))
}

// tests
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_indices() {
        let test_cases = vec![
            ((0, 0), vec![(0, 0)]),
            ((0, 1), vec![]),
            ((1, 0), vec![(0, 0)]),
            ((1, 1), vec![(1, 1)]),
            ((1, 2), vec![]),
            ((2, 0), vec![(0, 0)]),
            ((2, 1), vec![(2, 1), (1, 1)]),
            ((2, 2), vec![(1, 1)]),
            ((2, 3), vec![(2, 3)]),
            ((2, 4), vec![]),
            ((3, 0), vec![(0, 0)]),
            ((3, 1), vec![(3, 1), (2, 1), (1, 1)]),
            ((3, 2), vec![(2, 1), (1, 1)]),
            ((3, 3), vec![(3, 3), (1, 1)]),
            ((3, 4), vec![(1, 1)]),
            ((3, 5), vec![(3, 5), (2, 3)]),
            ((3, 6), vec![(2, 3)]),
            ((3, 7), vec![(3, 7)]),
            ((3, 8), vec![]),
        ];

        for ((depth, index), expected) in test_cases {
            let indices = get_claim_reveal_indices(depth, index);
            assert_eq!(
                indices, expected,
                "Failed at get_indices({}, {})",
                depth, index
            );
        }
    }
}
