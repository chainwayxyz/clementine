use crate::errors::BridgeError;
use crate::transaction_builder::CreateTxOutputs;
use crate::HashTree;
use bitcoin;
use bitcoin::consensus::Decodable;
use bitcoin::sighash::SighashCache;
use bitcoin::taproot::ControlBlock;
use bitcoin::taproot::LeafVersion;
use bitcoin::taproot::TaprootSpendInfo;
use bitcoin::Amount;
use bitcoin::ScriptBuf;
use hex;
use sha2::{Digest, Sha256};
use std::borrow::BorrowMut;

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

    witness_elements
        .iter()
        .for_each(|element| witness.push(element));

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
    txin_index: usize,
    script_index: usize,
) -> Result<(), BridgeError> {
    let mut sighash_cache = SighashCache::new(tx.tx.borrow_mut());

    let witness = sighash_cache
        .witness_mut(txin_index)
        .ok_or(BridgeError::TxInputNotFound)?;

    witness_elements
        .iter()
        .for_each(|element| witness.push(element));

    let spend_control_block = tx.taproot_spend_infos[txin_index]
        .control_block(&(
            tx.scripts[txin_index][script_index].clone(),
            LeafVersion::TapScript,
        ))
        .ok_or(BridgeError::ControlBlockError)?;

    witness.push(tx.scripts[txin_index][script_index].clone());
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
