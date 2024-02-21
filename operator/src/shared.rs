use bitcoin::{taproot::TaprootSpendInfo, Address, Amount, OutPoint, ScriptBuf};
use circuit_helpers::{config::{BRIDGE_AMOUNT_SATS, CONNECTOR_TREE_DEPTH, NUM_ROUNDS}, constant::{CONFIRMATION_BLOCK_COUNT, DUST_VALUE, MIN_RELAY_FEE, PERIOD_BLOCK_COUNT}};
use secp256k1::XOnlyPublicKey;

use crate::{
    custom_merkle::CustomMerkleTree, errors::DepositError, extended_rpc::ExtendedRpc, transaction_builder::TransactionBuilder, utils::calculate_amount
};

pub fn check_deposit_utxo(
    rpc: &ExtendedRpc,
    tx_builder: &TransactionBuilder,
    outpoint: &OutPoint,
    return_address: &XOnlyPublicKey,
    amount_sats: u64,
) -> Result<(Address, TaprootSpendInfo), DepositError> {
    if rpc.confirmation_blocks(&outpoint.txid) < CONFIRMATION_BLOCK_COUNT {
        return Err(DepositError::NotFinalized);
    }

    let (deposit_address, deposit_taproot_spend_info) =
        tx_builder.generate_deposit_address(return_address);

    if !rpc.check_utxo_address_and_amount(&outpoint, &deposit_address.script_pubkey(), amount_sats)
    {
        return Err(DepositError::InvalidAddressOrAmount);
    }

    if rpc.is_utxo_spent(&outpoint) {
        return Err(DepositError::AlreadySpent);
    }
    return Ok((deposit_address, deposit_taproot_spend_info));
}

pub fn create_all_connector_trees(
    secp: &secp256k1::Secp256k1<secp256k1::All>,
    tx_builder: &TransactionBuilder,
    connector_tree_hashes: &Vec<Vec<Vec<[u8; 32]>>>,
    start_blockheight: u64,
    first_source_utxo: &OutPoint,
    operator_pk: &XOnlyPublicKey,
) -> (Vec<[u8; 32]>, Vec<OutPoint>, Vec<Vec<Vec<OutPoint>>>) {
    let single_tree_amount = calculate_amount(
        CONNECTOR_TREE_DEPTH,
        Amount::from_sat(DUST_VALUE),
        Amount::from_sat(MIN_RELAY_FEE),
    );
    let total_amount =
        Amount::from_sat((MIN_RELAY_FEE + single_tree_amount.to_sat()) * NUM_ROUNDS as u64);

    let mut cur_connector_source_utxo = first_source_utxo.clone();
    let mut cur_amount = total_amount;

    let mut claim_proof_merkle_roots: Vec<[u8; 32]> = Vec::new();
    let mut root_utxos: Vec<OutPoint> = Vec::new();
    let mut utxo_trees: Vec<Vec<Vec<OutPoint>>> = Vec::new();

    for i in 0..NUM_ROUNDS {
        claim_proof_merkle_roots.push(CustomMerkleTree::calculate_claim_proof_root(
            CONNECTOR_TREE_DEPTH,
            &connector_tree_hashes[i],
        ));
        let (next_connector_source_address, _) =
            tx_builder.create_connector_tree_root_address(
                operator_pk,
                start_blockheight + ((i + 2) * PERIOD_BLOCK_COUNT as usize) as u64,
            );
        let (connector_bt_root_address, _) = TransactionBuilder::create_connector_tree_node_address(
            secp,
            operator_pk,
            connector_tree_hashes[i][0][0],
        );
        let curr_root_and_next_source_tx_ins =
            TransactionBuilder::create_tx_ins(vec![cur_connector_source_utxo.clone()]);

        let curr_root_and_next_source_tx_outs = TransactionBuilder::create_tx_outs(vec![
            (
                cur_amount - single_tree_amount - Amount::from_sat(MIN_RELAY_FEE),
                next_connector_source_address.script_pubkey(),
            ),
            (
                single_tree_amount,
                connector_bt_root_address.script_pubkey(),
            ),
        ]);

        let curr_root_and_next_source_tx = TransactionBuilder::create_btc_tx(
            curr_root_and_next_source_tx_ins,
            curr_root_and_next_source_tx_outs,
        );

        let txid = curr_root_and_next_source_tx.txid();

        cur_connector_source_utxo = OutPoint {
            txid: txid,
            vout: 0,
        };

        let cur_connector_bt_root_utxo = OutPoint {
            txid: txid,
            vout: 1,
        };

        let utxo_tree = tx_builder.create_connector_binary_tree(
            i,
            operator_pk,
            &cur_connector_bt_root_utxo,
            CONNECTOR_TREE_DEPTH,
            connector_tree_hashes[i].clone(),
        );
        root_utxos.push(cur_connector_bt_root_utxo);
        utxo_trees.push(utxo_tree);
        cur_amount = cur_amount - single_tree_amount - Amount::from_sat(MIN_RELAY_FEE);
    }

    return (claim_proof_merkle_roots, root_utxos, utxo_trees);
}
