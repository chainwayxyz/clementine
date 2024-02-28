use std::borrow::BorrowMut;
use std::collections::{HashMap, HashSet};

use crate::constant::{ConnectorTreeUTXOs, PreimageType, HASH_FUNCTION_32, MIN_RELAY_FEE};
use bitcoin::sighash::SighashCache;
use bitcoin::{secp256k1, secp256k1::Secp256k1, OutPoint};
use bitcoin::{Address, Amount, TxOut};
use circuit_helpers::config::{CONNECTOR_TREE_DEPTH, NUM_ROUNDS};
use circuit_helpers::constant::EVMAddress;
use secp256k1::{rand::rngs::OsRng, XOnlyPublicKey};
use secp256k1::{schnorr, All};

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
    ) -> Vec<schnorr::Signature> {
        println!("Verifier first_source_utxo: {:?}", _first_source_utxo);
        println!("Verifier verifiers_pks len: {:?}", self.verifiers.len());
        let (_, _, utxo_trees, sigs) = create_all_connector_trees(
            &self.signer,
            &self.rpc,
            &_connector_tree_hashes,
            _start_blockheight,
            &_first_source_utxo,
            &self.verifiers,
        );

        // self.set_connector_tree_utxos(utxo_trees);
        self.connector_tree_utxos = utxo_trees;
        // self.set_connector_tree_hashes(_connector_tree_hashes);
        self.connector_tree_hashes = _connector_tree_hashes.clone();
        // println!(
        //     "Verifier claim_proof_merkle_roots: {:?}",
        //     claim_proof_merkle_roots
        // );
        // println!("Verifier root_utxos: {:?}", root_utxos);
        println!("Verifier utxo_trees: {:?}", self.connector_tree_utxos);
        sigs
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
        deposit_index: u32,
        evm_address: &EVMAddress,
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

        let mut move_tx = self
            .transaction_builder
            .create_move_tx(start_utxo, evm_address);
        let move_txid = move_tx.txid();

        let move_utxo = OutPoint {
            txid: move_txid,
            vout: 0,
        };

        let prevouts = TransactionBuilder::create_tx_outs(vec![(
            Amount::from_sat(BRIDGE_AMOUNT_SATS),
            deposit_address.script_pubkey(),
        )]);

        let script_n_of_n_with_user_pk = self
            .script_builder
            .generate_script_n_of_n_with_user_pk(return_address);
        let script_n_of_n = self.script_builder.generate_script_n_of_n();

        let move_sig = self.signer.sign_taproot_script_spend_tx(
            &mut move_tx,
            &prevouts,
            &script_n_of_n_with_user_pk,
            0,
        );

        // let anyone_can_spend_txout: TxOut = ScriptBuilder::anyone_can_spend_txout();

        let mut op_claim_sigs = Vec::new();

        let operator_address = Address::p2tr(
            &self.signer.secp,
            self.operator_pk,
            None,
            bitcoin::Network::Regtest,
        );

        for i in 0..NUM_ROUNDS {
            let connector_utxo =
                self.connector_tree_utxos[i][CONNECTOR_TREE_DEPTH][deposit_index as usize];
            let mut operator_claim_tx = TransactionBuilder::create_operator_claim_tx(
                move_utxo,
                connector_utxo,
                &operator_address,
            );

            let (connector_tree_leaf_address, _) =
                TransactionBuilder::create_connector_tree_node_address(
                    &self.secp,
                    &self.operator_pk,
                    self.connector_tree_hashes[i][CONNECTOR_TREE_DEPTH][deposit_index as usize],
                );

            let op_claim_tx_prevouts = self
                .transaction_builder
                .create_operator_claim_tx_prevouts(&connector_tree_leaf_address);

            let op_claim_sig = self.signer.sign_taproot_script_spend_tx(
                &mut operator_claim_tx,
                &op_claim_tx_prevouts,
                &script_n_of_n,
                0,
            );
            op_claim_sigs.push(op_claim_sig);
            println!("Verifier signing operator_claim_tx...");
            println!("index: {:?}", deposit_index);
            println!("period: {:?}", i);
            println!("operator_claim_tx: {:?}", operator_claim_tx);
            println!("op_claim_sig: {:?}", op_claim_sig);
        }

        DepositPresigns {
            move_sign: move_sig,
            operator_claim_sign: op_claim_sigs,
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
        // witness.push(&spend_control_block.serialize());s

        let mut witness_elements: Vec<&[u8]> = Vec::new();
        witness_elements.push(&preimage);
        handle_taproot_witness(&mut tx, 0, &witness_elements, &hash_script, &tree_info);

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
