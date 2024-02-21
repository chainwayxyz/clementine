use std::borrow::BorrowMut;
use std::collections::{HashMap, HashSet};

use crate::constant::{ConnectorTreeUTXOs, PreimageType, HASH_FUNCTION_32, MIN_RELAY_FEE};
use bitcoin::sighash::SighashCache;
use bitcoin::{secp256k1, secp256k1::Secp256k1, OutPoint};
use bitcoin::{Amount, TxOut};
use secp256k1::All;
use secp256k1::{rand::rngs::OsRng, XOnlyPublicKey};

use crate::extended_rpc::ExtendedRpc;
use crate::script_builder::ScriptBuilder;
use crate::shared::{check_deposit_utxo, create_all_connector_trees};
use crate::transaction_builder::TransactionBuilder;
use crate::utils::{create_control_block, handle_taproot_witness};
use crate::{actor::Actor, operator::DepositPresigns};

use crate::config::BRIDGE_AMOUNT_SATS;

#[derive(Debug, Clone)]
pub struct Verifier<'a> {
    pub rpc: &'a ExtendedRpc,
    pub secp: Secp256k1<secp256k1::All>,
    pub signer: Actor,
    pub script_builder: ScriptBuilder,
    pub transaction_builder: TransactionBuilder,
    pub verifiers: Vec<XOnlyPublicKey>,
    pub connector_tree_utxos: Vec<ConnectorTreeUTXOs>,
    pub connector_tree_hashes: Vec<Vec<Vec<[u8; 32]>>>,
    pub operator_pk: XOnlyPublicKey,
}

impl<'a> Verifier<'a> {
    pub fn new(rng: &mut OsRng, rpc: &'a ExtendedRpc, operator_pk: XOnlyPublicKey) -> Self {
        let signer = Actor::new(rng);
        let secp: Secp256k1<secp256k1::All> = Secp256k1::new();
        let verifiers = Vec::new();
        let connector_tree_utxos = Vec::new();
        let connector_tree_hashes = Vec::new();
        let script_builder = ScriptBuilder::new(vec![]);
        let transaction_builder = TransactionBuilder::new(vec![]);
        Verifier {
            rpc,
            secp,
            signer,
            script_builder,
            transaction_builder,
            verifiers,
            connector_tree_utxos,
            connector_tree_hashes,
            operator_pk,
        }
    }

    pub fn set_verifiers(&mut self, verifiers: Vec<XOnlyPublicKey>) {
        self.verifiers = verifiers;
        self.script_builder = ScriptBuilder::new(self.verifiers.clone());
        self.transaction_builder = TransactionBuilder::new(self.verifiers.clone());
    }

    // pub fn set_connector_tree_utxos(&mut self, connector_tree_utxos: Vec<ConnectorTreeUTXOs>) {
    //     self.connector_tree_utxos = connector_tree_utxos;
    // }

    // pub fn set_connector_tree_hashes(&mut self, connector_tree_hashes: &Vec<Vec<Vec<[u8; 32]>>>) {
    //     self.connector_tree_hashes = connector_tree_hashes.clone();
    // }

    /// TODO: Add verification for the connector tree hashes
    pub fn connector_roots_created(
        &mut self,
        _connector_tree_hashes: &Vec<Vec<Vec<[u8; 32]>>>,
        _start_blockheight: u64,
        _first_source_utxo: &OutPoint,
    ) {
        // let tx_res = self.rpc.get_transaction(&_first_source_utxo.txid, None).unwrap();
        // println!("tx_res: {:?}", tx_res);
        // let start_blockheight = tx_res.info.blockheight.unwrap();

        // let single_tree_amount = calculate_amount(
        //     CONNECTOR_TREE_DEPTH,
        //     Amount::from_sat(DUST_VALUE),
        //     Amount::from_sat(MIN_RELAY_FEE),
        // );
        // let total_amount =
        //     Amount::from_sat((MIN_RELAY_FEE + single_tree_amount.to_sat()) * NUM_ROUNDS as u64);

        // let mut cur_connector_source_utxo = _first_source_utxo.clone();
        // let mut cur_amount = total_amount;

        // let mut claim_proof_merkle_roots: Vec<[u8; 32]> = Vec::new();
        // let mut root_utxos: Vec<OutPoint> = Vec::new();
        // let mut utxo_trees: Vec<ConnectorTreeUTXOs> = Vec::new();

        // for i in 0..NUM_ROUNDS {
        //     claim_proof_merkle_roots.push(CustomMerkleTree::calculate_claim_proof_root(CONNECTOR_TREE_DEPTH, &self.connector_tree_hashes[i]));
        //     let (next_connector_source_address, _) =
        //         self.transaction_builder.create_connector_tree_root_address(
        //             &self.operator_pk,
        //             _start_blockheight + ((i + 2) * PERIOD_BLOCK_COUNT as usize) as u64,
        //         );
        //     let (connector_bt_root_address, _) =
        //         TransactionBuilder::create_connector_tree_node_address(
        //             &self.signer.secp,
        //             &self.operator_pk,
        //             self.connector_tree_hashes[i][0][0],
        //         );
        //     let curr_root_and_next_source_tx_ins =
        //         TransactionBuilder::create_tx_ins(vec![cur_connector_source_utxo.clone()]);

        //     let curr_root_and_next_source_tx_outs = TransactionBuilder::create_tx_outs(vec![
        //         (
        //             cur_amount - single_tree_amount - Amount::from_sat(MIN_RELAY_FEE),
        //             next_connector_source_address.script_pubkey(),
        //         ),
        //         (
        //             single_tree_amount,
        //             connector_bt_root_address.script_pubkey(),
        //         ),
        //     ]);

        //     let curr_root_and_next_source_tx = TransactionBuilder::create_btc_tx(
        //         curr_root_and_next_source_tx_ins,
        //         curr_root_and_next_source_tx_outs,
        //     );

        //     let txid = curr_root_and_next_source_tx.txid();

        //     cur_connector_source_utxo = OutPoint {
        //         txid: txid,
        //         vout: 0,
        //     };

        //     let cur_connector_bt_root_utxo = OutPoint {
        //         txid: txid,
        //         vout: 1,
        //     };

        //     let utxo_tree = self.transaction_builder.create_connector_binary_tree(
        //         i,
        //         &self.operator_pk,
        //         &cur_connector_bt_root_utxo,
        //         CONNECTOR_TREE_DEPTH,
        //         self.connector_tree_hashes[i].clone(),
        //     );
        //     root_utxos.push(cur_connector_bt_root_utxo);
        //     utxo_trees.push(utxo_tree);
        //     cur_amount = cur_amount - single_tree_amount - Amount::from_sat(MIN_RELAY_FEE);
        // }

        let (claim_proof_merkle_roots, root_utxos, utxo_trees) = create_all_connector_trees(
            &self.secp,
            &self.transaction_builder,
            &_connector_tree_hashes,
            _start_blockheight,
            &_first_source_utxo,
            &self.operator_pk,
        );

        // self.set_connector_tree_utxos(utxo_trees);
        self.connector_tree_utxos = utxo_trees;
        // self.set_connector_tree_hashes(_connector_tree_hashes);
        self.connector_tree_hashes = _connector_tree_hashes.clone();
        println!(
            "Verifier claim_proof_merkle_roots: {:?}",
            claim_proof_merkle_roots
        );
        println!("Verifier root_utxos: {:?}", root_utxos);
    }

    /// this is a endpoint that only the operator can call
    /// 1. Check if there is any previous pending deposit
    /// 2. Check if the utxo is valid and finalized (6 blocks confirmation)
    /// 3. Check if the utxo is not already spent
    /// 4. Give move signature and operator claim signature
    pub fn new_deposit(
        &self,
        start_utxo: OutPoint,
        return_address: &XOnlyPublicKey,
    ) -> DepositPresigns {
        // 1. Check if there is any previous pending deposit

        let (deposit_address, _) = check_deposit_utxo(
            &self.rpc,
            &self.transaction_builder,
            &start_utxo,
            &return_address,
            BRIDGE_AMOUNT_SATS,
        )
        .unwrap();

        let mut move_tx = self.transaction_builder.create_move_tx(start_utxo);

        let prevouts = TransactionBuilder::create_tx_outs(vec![(
            Amount::from_sat(BRIDGE_AMOUNT_SATS),
            deposit_address.script_pubkey(),
        )]);

        let script_n_of_n = self.script_builder.generate_n_of_n_script_without_hash();

        let sig =
            self.signer
                .sign_taproot_script_spend_tx(&mut move_tx, &prevouts, &script_n_of_n, 0);
        DepositPresigns {
            move_sign: sig,
            operator_claim_sign: vec![],
        }

        // // println!("all_verifiers in new_deposit, in verifier now: {:?}", all_verifiers);
        // let (deposit_address, _) = self
        //     .transaction_builder
        //     .generate_deposit_address(return_address, hash);
        // let deposit_tx_ins = TransactionBuilder::create_tx_ins(vec![start_utxo]);
        // let deposit_tx_outs = TransactionBuilder::create_tx_outs(vec![(
        //     deposit_amount,
        //     deposit_address.script_pubkey(),
        // )]);
        // let deposit_tx = TransactionBuilder::create_btc_tx(deposit_tx_ins, deposit_tx_outs);
        // let deposit_txid = deposit_tx.txid();
        // println!("verifier calculated deposit_txid: {:?}", deposit_txid);
        // let deposit_utxo = TransactionBuilder::create_utxo(deposit_txid, 0);
        // let script_n_of_n = self.script_builder.generate_n_of_n_script(hash);
        // let script_n_of_n_without_hash = self.script_builder.generate_n_of_n_script_without_hash();

        // let (multisig_address, _) = TransactionBuilder::create_taproot_address(
        //     &self.signer.secp,
        //     vec![script_n_of_n_without_hash.clone()],
        // );
        // println!(
        //     "verifier presigning multisig address: {:?}",
        //     multisig_address
        // );

        // let mut move_tx = TransactionBuilder::create_move_tx(
        //     vec![deposit_utxo],
        //     vec![(
        //         deposit_amount - Amount::from_sat(MIN_RELAY_FEE),
        //         multisig_address.script_pubkey().clone(),
        //     )],
        // );

        // let prevouts = TransactionBuilder::create_tx_outs(vec![(
        //     deposit_amount,
        //     deposit_address.script_pubkey(),
        // )]);

        // let move_sign =
        //     self.signer
        //         .sign_taproot_script_spend_tx(&mut move_tx, prevouts, &script_n_of_n, 0);
        // let move_txid = move_tx.txid();

        // let prev_outpoint = TransactionBuilder::create_utxo(move_txid, 0);
        // let prev_amount = deposit_amount - Amount::from_sat(MIN_RELAY_FEE);

        // println!("creating operator claim tx");
        // println!("index: {:?}", index);

        // let mut operator_claim_tx_ins = TransactionBuilder::create_tx_ins(vec![prev_outpoint]);

        // operator_claim_tx_ins.extend(TransactionBuilder::create_tx_ins_with_sequence(vec![
        //     self.connector_tree_utxos[period][self.connector_tree_utxos[period].len() - 1][index as usize],
        // ]));

        // let operator_claim_tx_outs = TransactionBuilder::create_tx_outs(vec![(
        //     prev_amount + Amount::from_sat(DUST_VALUE) - Amount::from_sat(MIN_RELAY_FEE),
        //     operator_address.script_pubkey(),
        // )]);

        // let mut operator_claim_tx =
        //     TransactionBuilder::create_btc_tx(operator_claim_tx_ins, operator_claim_tx_outs);

        // let (address, _) = TransactionBuilder::create_connector_tree_node_address(
        //     &self.secp,
        //     self.operator_pk,
        //     self.connector_tree_hashes[period][self.connector_tree_hashes[period].len() - 1][index as usize],
        // );

        // let prevouts = TransactionBuilder::create_tx_outs(vec![
        //     (prev_amount, multisig_address.script_pubkey().clone()),
        //     (Amount::from_sat(DUST_VALUE), address.script_pubkey()),
        // ]);

        // let operator_claim_sign = self.signer.sign_taproot_script_spend_tx(
        //     &mut operator_claim_tx,
        //     prevouts,
        //     &script_n_of_n_without_hash,
        //     0,
        // );

        // // println!("verifier presigning operator_claim_tx, sign: {:?}", operator_claim_sign);

        // let rollup_sign = self.signer.sign_deposit(move_txid, evm_address, hash);

        // DepositPresigns {
        //     rollup_sign,
        //     move_sign,
        //     operator_claim_sign,
        // }
    }

    // This is a function to reduce gas costs when moving bridge funds
    pub fn do_me_a_favor() {}

    pub fn did_connector_tree_process_start(&self, utxo: OutPoint) -> bool {
        let last_block_hash = self.rpc.get_best_block_hash().unwrap();
        let last_block = self.rpc.get_block(&last_block_hash).unwrap();
        for tx in last_block.txdata {
            // if any of the tx.input.previous_output == utxo return true
            for input in tx.input {
                if input.previous_output == utxo {
                    return true;
                }
            }
        }
        return false;
    }

    pub fn watch_connector_tree(
        &self,
        operator_pk: XOnlyPublicKey,
        preimage_script_pubkey_pairs: &mut HashSet<PreimageType>,
        utxos: &mut HashMap<OutPoint, (u32, u32)>,
    ) -> (HashSet<PreimageType>, HashMap<OutPoint, (u32, u32)>) {
        println!("verifier watching connector tree...");
        let last_block_hash = self.rpc.get_best_block_hash().unwrap();
        let last_block = self.rpc.get_block(&last_block_hash).unwrap();
        for tx in last_block.txdata {
            if utxos.contains_key(&tx.input[0].previous_output) {
                // Check if any of the UTXOs have been spent
                let (depth, index) = utxos.remove(&tx.input[0].previous_output).unwrap();
                utxos.insert(
                    TransactionBuilder::create_utxo(tx.txid(), 0),
                    (depth + 1, index * 2),
                );
                utxos.insert(
                    TransactionBuilder::create_utxo(tx.txid(), 1),
                    (depth + 1, index * 2 + 1),
                );
                //Assert the two new UTXOs have the same value
                assert_eq!(tx.output[0].value, tx.output[1].value);
                let new_amount = tx.output[0].value;
                //Check if any one of the UTXOs can be spent with a preimage
                for (i, tx_out) in tx.output.iter().enumerate() {
                    let mut preimages_to_remove = Vec::new();
                    for preimage in preimage_script_pubkey_pairs.iter() {
                        if is_spendable_with_preimage(
                            &self.secp,
                            operator_pk,
                            tx_out.clone(),
                            *preimage,
                        ) {
                            let utxo_to_spend = OutPoint {
                                txid: tx.txid(),
                                vout: i as u32,
                            };
                            self.spend_connector_tree_utxo(
                                utxo_to_spend,
                                operator_pk,
                                *preimage,
                                new_amount,
                            );
                            utxos.remove(&OutPoint {
                                txid: tx.txid(),
                                vout: i as u32,
                            });
                            preimages_to_remove.push(*preimage);
                        }
                    }
                    for preimage in preimages_to_remove {
                        preimage_script_pubkey_pairs.remove(&preimage);
                    }
                }
            }
        }
        println!("verifier finished watching connector tree...");
        return (preimage_script_pubkey_pairs.clone(), utxos.clone());
    }

    pub fn spend_connector_tree_utxo(
        &self,
        utxo: OutPoint,
        operator_pk: XOnlyPublicKey,
        preimage: PreimageType,
        amount: Amount,
    ) {
        let hash = HASH_FUNCTION_32(preimage);
        let (address, tree_info) =
            TransactionBuilder::create_connector_tree_node_address(&self.secp, &operator_pk, hash);
        let tx_ins = TransactionBuilder::create_tx_ins_with_sequence(vec![utxo]);
        let tx_outs = TransactionBuilder::create_tx_outs(vec![(
            amount - Amount::from_sat(MIN_RELAY_FEE),
            self.signer.address.script_pubkey(),
        )]);
        let mut tx = TransactionBuilder::create_btc_tx(tx_ins, tx_outs);
        let prevouts = TransactionBuilder::create_tx_outs(vec![(amount, address.script_pubkey())]);
        let hash_script = ScriptBuilder::generate_hash_script(hash);
        let _sig = self
            .signer
            .sign_taproot_script_spend_tx(&mut tx, &prevouts, &hash_script, 0);
        // let spend_control_block = create_control_block(tree_info, &hash_script);

        // let mut sighash_cache = SighashCache::new(tx.borrow_mut());
        // let witness = sighash_cache.witness_mut(0).unwrap();
        // witness.push(preimage);
        // witness.push(hash_script);
        // witness.push(&spend_control_block.serialize());

        let mut witness_elements: Vec<&[u8]> = Vec::new();
        witness_elements.push(&preimage);
        handle_taproot_witness(&mut tx, 0, witness_elements, hash_script, tree_info);

        let spending_txid = self.rpc.send_raw_transaction(&tx).unwrap();
        println!("verifier_spending_txid: {:?}", spending_txid);
    }

    // This function is not in use now, will be used if we decide to return the leaf dust back to the operator
    pub fn spend_connector_tree_leaf_utxo(
        &self,
        utxo: OutPoint,
        operator_pk: XOnlyPublicKey,
        preimage: PreimageType,
        amount: Amount,
    ) {
        let hash = HASH_FUNCTION_32(preimage);
        let (address, tree_info) =
            TransactionBuilder::create_connector_tree_node_address(&self.secp, &operator_pk, hash);
        let tx_ins = TransactionBuilder::create_tx_ins_with_sequence(vec![utxo]);
        let tx_outs = TransactionBuilder::create_tx_outs(vec![(
            amount - Amount::from_sat(MIN_RELAY_FEE),
            self.signer.address.script_pubkey(),
        )]);
        let mut tx = TransactionBuilder::create_btc_tx(tx_ins, tx_outs);
        let prevouts = TransactionBuilder::create_tx_outs(vec![(amount, address.script_pubkey())]);
        let hash_script = ScriptBuilder::generate_hash_script(hash);
        let _sig = self
            .signer
            .sign_taproot_script_spend_tx(&mut tx, &prevouts, &hash_script, 0);
        let spend_control_block = create_control_block(tree_info, &hash_script);
        let mut sighash_cache = SighashCache::new(tx.borrow_mut());
        let witness = sighash_cache.witness_mut(0).unwrap();
        witness.push(preimage);
        witness.push(hash_script);
        witness.push(&spend_control_block.serialize());
        let spending_txid = self.rpc.send_raw_transaction(&tx).unwrap();
        println!("verifier_spending_txid: {:?}", spending_txid);
    }
}

pub fn is_spendable_with_preimage(
    secp: &Secp256k1<All>,
    operator_pk: XOnlyPublicKey,
    tx_out: TxOut,
    preimage: PreimageType,
) -> bool {
    let hash = HASH_FUNCTION_32(preimage);
    let (address, _) =
        TransactionBuilder::create_connector_tree_node_address(secp, &operator_pk, hash);

    address.script_pubkey() == tx_out.script_pubkey
}
