use crate::{
    actor::Actor,
    config::{CONNECTOR_TREE_DEPTH, NUM_ROUNDS},
    constant::{
        ConnectorTreeUTXOs, CONFIRMATION_BLOCK_COUNT, DUST_VALUE, MIN_RELAY_FEE, PERIOD_BLOCK_COUNT,
    },
    errors::BridgeError,
    utils::calculate_claim_proof_root,
};
use bitcoin::{Amount, OutPoint};
use secp256k1::{schnorr, XOnlyPublicKey};

use crate::{
    extended_rpc::ExtendedRpc, transaction_builder::TransactionBuilder, utils::calculate_amount,
};

pub fn check_deposit_utxo(
    rpc: &ExtendedRpc,
    tx_builder: &TransactionBuilder,
    outpoint: &OutPoint,
    return_address: &XOnlyPublicKey,
    amount_sats: u64,
) -> Result<(), BridgeError> {
    if rpc.confirmation_blocks(&outpoint.txid)? < CONFIRMATION_BLOCK_COUNT {
        return Err(BridgeError::DepositNotFinalized);
    }

    let (deposit_address, _) = tx_builder.generate_deposit_address(return_address)?;

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

pub fn create_all_connector_trees(
    signer: &Actor,
    rpc: &ExtendedRpc,
    // tx_builder: &TransactionBuilder,
    connector_tree_hashes: &Vec<Vec<Vec<[u8; 32]>>>,
    start_blockheight: u64,
    first_source_utxo: &OutPoint,
    pks: &Vec<XOnlyPublicKey>,
) -> Result<
    (
        Vec<[u8; 32]>,
        Vec<OutPoint>,
        Vec<ConnectorTreeUTXOs>,
        Vec<schnorr::Signature>,
    ),
    BridgeError,
> {
    let tx_builder = TransactionBuilder::new(pks.clone());
    let single_tree_amount = calculate_amount(
        CONNECTOR_TREE_DEPTH,
        Amount::from_sat(DUST_VALUE),
        Amount::from_sat(MIN_RELAY_FEE),
    );
    let total_amount = Amount::from_sat((single_tree_amount.to_sat()) * NUM_ROUNDS as u64);

    let mut cur_connector_source_utxo = *first_source_utxo;
    let mut cur_amount = total_amount;
    let mut curr_prevouts = vec![rpc
        .get_raw_transaction(&first_source_utxo.txid, None)
        .unwrap()
        .output[0]
        .clone()];
    println!("first_source_utxo: {:?}", first_source_utxo);
    println!("cur_prevouts: {:?}", curr_prevouts);

    let script_n_of_n = tx_builder.script_builder.generate_script_n_of_n();

    let mut claim_proof_merkle_roots: Vec<[u8; 32]> = Vec::new();
    let mut root_utxos: Vec<OutPoint> = Vec::new();
    let mut utxo_trees: Vec<ConnectorTreeUTXOs> = Vec::new();
    let mut sigs: Vec<schnorr::Signature> = Vec::new();

    for i in 0..NUM_ROUNDS {
        claim_proof_merkle_roots.push(calculate_claim_proof_root(
            CONNECTOR_TREE_DEPTH,
            &connector_tree_hashes[i],
        ));
        let (next_connector_source_address, _) = tx_builder.create_connector_tree_root_address(
            start_blockheight + ((i + 2) * PERIOD_BLOCK_COUNT as usize) as u64,
        )?;
        let (connector_bt_root_address, _) =
            TransactionBuilder::create_connector_tree_node_address(
                &signer.secp,
                &pks[pks.len() - 1],
                &connector_tree_hashes[i][0][0],
            )?;
        let curr_root_and_next_source_tx_ins =
            TransactionBuilder::create_tx_ins(vec![cur_connector_source_utxo]);

        let curr_root_and_next_source_tx_outs = TransactionBuilder::create_tx_outs(vec![
            (
                cur_amount - single_tree_amount,
                next_connector_source_address.script_pubkey(),
            ),
            (
                single_tree_amount - Amount::from_sat(MIN_RELAY_FEE),
                connector_bt_root_address.script_pubkey(),
            ),
        ]);

        let mut curr_root_and_next_source_tx = TransactionBuilder::create_btc_tx(
            curr_root_and_next_source_tx_ins,
            curr_root_and_next_source_tx_outs,
        );

        let sig = signer
            .sign_taproot_script_spend_tx(
                &mut curr_root_and_next_source_tx,
                &curr_prevouts,
                &script_n_of_n,
                0,
            )
            .unwrap();
        sigs.push(sig);
        curr_prevouts = vec![curr_root_and_next_source_tx.output[0].clone()];

        let txid = curr_root_and_next_source_tx.txid();

        cur_connector_source_utxo = OutPoint { txid, vout: 0 };

        let cur_connector_bt_root_utxo = OutPoint { txid, vout: 1 };

        let utxo_tree = tx_builder.create_connector_binary_tree(
            i,
            &pks[pks.len() - 1],
            &cur_connector_bt_root_utxo,
            CONNECTOR_TREE_DEPTH,
            connector_tree_hashes[i].clone(),
        )?;
        root_utxos.push(cur_connector_bt_root_utxo);
        utxo_trees.push(utxo_tree);
        cur_amount = cur_amount - single_tree_amount;
    }

    Ok((claim_proof_merkle_roots, root_utxos, utxo_trees, sigs))
}
