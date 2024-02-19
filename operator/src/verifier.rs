use std::borrow::BorrowMut;
use std::collections::{HashMap, HashSet};

use bitcoin::consensus::serialize;
use bitcoin::sighash::SighashCache;
use bitcoin::{secp256k1, secp256k1::Secp256k1, OutPoint};
use bitcoin::{Address, Amount, TxOut};
use circuit_helpers::constant::{EVMAddress, DUST_VALUE, HASH_FUNCTION_32, MIN_RELAY_FEE};
use secp256k1::All;
use secp256k1::{rand::rngs::OsRng, XOnlyPublicKey};

use crate::extended_rpc::ExtendedRpc;
use crate::operator::PreimageType;
use crate::script_builder::ScriptBuilder;
use crate::transaction_builder::TransactionBuilder;
use crate::utils::{create_control_block, handle_taproot_witness};
use crate::{actor::Actor, operator::DepositPresigns};

use circuit_helpers::config::{CONNECTOR_TREE_DEPTH, NUM_ROUNDS};

#[derive(Debug, Clone)]
pub struct Verifier<'a> {
    pub rpc: &'a ExtendedRpc,
    pub secp: Secp256k1<secp256k1::All>,
    pub signer: Actor,
    pub script_builder: ScriptBuilder,
    pub transaction_builder: TransactionBuilder,
    pub verifiers: Vec<XOnlyPublicKey>,
    pub connector_tree_utxos: Vec<Vec<Vec<OutPoint>>>,
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

    pub fn set_connector_tree_utxos(&mut self, connector_tree_utxos: Vec<Vec<Vec<OutPoint>>>) {
        self.connector_tree_utxos = connector_tree_utxos;
    }

    pub fn set_connector_tree_hashes(&mut self, connector_tree_hashes: Vec<Vec<Vec<[u8; 32]>>>) {
        self.connector_tree_hashes = connector_tree_hashes;
    }

    pub fn connector_roots_created(
        &mut self,
        connector_tree_hashes: Vec<Vec<Vec<[u8; 32]>>>,
        connector_tree_root_utxos: Vec<OutPoint>,
    ) {
        self.connector_tree_hashes = connector_tree_hashes;
        let mut utxo_trees = Vec::new();
        for i in 0..NUM_ROUNDS {
            let utxo_tree = self.transaction_builder.create_connector_binary_tree(
                i,
                self.signer.xonly_public_key,
                connector_tree_root_utxos[i].clone(),
                CONNECTOR_TREE_DEPTH,
                self.connector_tree_hashes[i].clone(),
            );
            utxo_trees.push(utxo_tree);
        }

        self.set_connector_tree_utxos(utxo_trees.clone());
    }

    pub fn new_deposit(
        &self,
        period: usize,
        start_utxo: OutPoint,
        deposit_amount: Amount,
        index: u32,
        hash: [u8; 32],
        return_address: XOnlyPublicKey,
        evm_address: EVMAddress,
        _all_verifiers: &Vec<XOnlyPublicKey>,
        operator_address: Address,
    ) -> DepositPresigns {
        // println!("all_verifiers in new_deposit, in verifier now: {:?}", all_verifiers);
        let (deposit_address, _) = self
            .transaction_builder
            .generate_deposit_address(return_address, hash);
        let deposit_tx_ins = TransactionBuilder::create_tx_ins(vec![start_utxo]);
        let deposit_tx_outs = TransactionBuilder::create_tx_outs(vec![(
            deposit_amount,
            deposit_address.script_pubkey(),
        )]);
        let deposit_tx = TransactionBuilder::create_btc_tx(deposit_tx_ins, deposit_tx_outs);
        let deposit_txid = deposit_tx.txid();
        println!("verifier calculated deposit_txid: {:?}", deposit_txid);
        let deposit_utxo = TransactionBuilder::create_utxo(deposit_txid, 0);
        let script_n_of_n = self.script_builder.generate_n_of_n_script(hash);
        let script_n_of_n_without_hash = self.script_builder.generate_n_of_n_script_without_hash();

        let (multisig_address, _) = TransactionBuilder::create_taproot_address(
            &self.signer.secp,
            vec![script_n_of_n_without_hash.clone()],
        );
        println!(
            "verifier presigning multisig address: {:?}",
            multisig_address
        );

        let mut move_tx = TransactionBuilder::create_move_tx(
            vec![deposit_utxo],
            vec![(
                deposit_amount - Amount::from_sat(MIN_RELAY_FEE),
                multisig_address.script_pubkey().clone(),
            )],
        );

        let prevouts = TransactionBuilder::create_tx_outs(vec![(
            deposit_amount,
            deposit_address.script_pubkey(),
        )]);

        let move_sign =
            self.signer
                .sign_taproot_script_spend_tx(&mut move_tx, prevouts, &script_n_of_n, 0);
        let move_txid = move_tx.txid();

        let prev_outpoint = TransactionBuilder::create_utxo(move_txid, 0);
        let prev_amount = deposit_amount - Amount::from_sat(MIN_RELAY_FEE);

        println!("creating operator claim tx");
        println!("index: {:?}", index);

        let mut operator_claim_tx_ins = TransactionBuilder::create_tx_ins(vec![prev_outpoint]);

        operator_claim_tx_ins.extend(TransactionBuilder::create_tx_ins_with_sequence(vec![
            self.connector_tree_utxos[period][self.connector_tree_utxos[period].len() - 1][index as usize],
        ]));

        let operator_claim_tx_outs = TransactionBuilder::create_tx_outs(vec![(
            prev_amount + Amount::from_sat(DUST_VALUE) - Amount::from_sat(MIN_RELAY_FEE),
            operator_address.script_pubkey(),
        )]);

        let mut operator_claim_tx =
            TransactionBuilder::create_btc_tx(operator_claim_tx_ins, operator_claim_tx_outs);

        let (address, _) = TransactionBuilder::create_connector_tree_node_address(
            &self.secp,
            self.operator_pk,
            self.connector_tree_hashes[period][self.connector_tree_hashes[period].len() - 1][index as usize],
        );

        let prevouts = TransactionBuilder::create_tx_outs(vec![
            (prev_amount, multisig_address.script_pubkey().clone()),
            (Amount::from_sat(DUST_VALUE), address.script_pubkey()),
        ]);

        let operator_claim_sign = self.signer.sign_taproot_script_spend_tx(
            &mut operator_claim_tx,
            prevouts,
            &script_n_of_n_without_hash,
            0,
        );

        // println!("verifier presigning operator_claim_tx, sign: {:?}", operator_claim_sign);

        let rollup_sign = self.signer.sign_deposit(move_txid, evm_address, hash);

        DepositPresigns {
            rollup_sign,
            move_sign,
            operator_claim_sign,
        }
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
            TransactionBuilder::create_connector_tree_node_address(&self.secp, operator_pk, hash);
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
            .sign_taproot_script_spend_tx(&mut tx, prevouts, &hash_script, 0);
        // let spend_control_block = create_control_block(tree_info, &hash_script);

        // let mut sighash_cache = SighashCache::new(tx.borrow_mut());
        // let witness = sighash_cache.witness_mut(0).unwrap();
        // witness.push(preimage);
        // witness.push(hash_script);
        // witness.push(&spend_control_block.serialize());

        let mut witness_elements: Vec<&[u8]> = Vec::new();
        witness_elements.push(&preimage);
        handle_taproot_witness(&mut tx, 0, witness_elements, hash_script, tree_info);

        let bytes_tx = serialize(&tx);
        let spending_txid = self.rpc.send_raw_transaction(&bytes_tx).unwrap();
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
            TransactionBuilder::create_connector_tree_node_address(&self.secp, operator_pk, hash);
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
            .sign_taproot_script_spend_tx(&mut tx, prevouts, &hash_script, 0);
        let spend_control_block = create_control_block(tree_info, &hash_script);
        let mut sighash_cache = SighashCache::new(tx.borrow_mut());
        let witness = sighash_cache.witness_mut(0).unwrap();
        witness.push(preimage);
        witness.push(hash_script);
        witness.push(&spend_control_block.serialize());
        let bytes_tx = serialize(&tx);
        let spending_txid = self.rpc.send_raw_transaction(&bytes_tx).unwrap();
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
        TransactionBuilder::create_connector_tree_node_address(secp, operator_pk, hash);

    address.script_pubkey() == tx_out.script_pubkey
}
