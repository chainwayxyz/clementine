//! # Parameter Builder For Citrea Requests

use crate::errors::BridgeError;
use bitcoin::{Block, Txid};
use merkle::{Hashable, MerkleTree, Proof};
use ring::digest::SHA256;

fn create_merkle_proof<T>(data: Vec<T>, index: usize) -> Result<Proof<T>, BridgeError>
where
    T: Hashable + Clone,
{
    let merkle_tree = MerkleTree::from_vec(&SHA256, data.clone());
    let proof = merkle_tree.gen_nth_proof(index);

    proof.ok_or(BridgeError::Error("TODO".to_string()))
}

pub fn prepare_deposit_params(block: Block, target_txid: Txid) -> Result<(), BridgeError> {
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

    let merkle_proof = create_merkle_proof(txids, txid_index)?;

    Ok(())
}
