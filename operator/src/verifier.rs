use std::borrow::BorrowMut;
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

use bitcoin::sighash::SighashCache;
use bitcoin::transaction::Version;
use bitcoin::{Address, ScriptBuf, TxOut, Amount, Transaction, absolute, TxIn, Witness};
use bitcoin::{
    secp256k1, secp256k1::Secp256k1, OutPoint, TapSighash,
};
use bitcoin::consensus::serialize;
use bitcoincore_rpc::{Client, RpcApi};
use circuit_helpers::constant::{EVMAddress, MIN_RELAY_FEE, HASH_FUNCTION_32, DUST_VALUE};
use secp256k1::All;
use secp256k1::{rand::rngs::OsRng, XOnlyPublicKey};

use crate::operator::{Operator, PreimageType, self};
use crate::utils::{create_btc_tx, create_tx_ins, create_tx_outs, generate_n_of_n_script, create_taproot_address, handle_anyone_can_spend_script, create_kickoff_tx, generate_timelock_script, handle_connector_binary_tree_script, create_tx_ins_with_sequence, generate_hash_script, create_control_block};
use crate::{
    actor::Actor,
    operator::{check_deposit, DepositPresigns},
    user::User,
    utils::generate_n_of_n_script_without_hash,
};

use circuit_helpers::config::{BRIDGE_AMOUNT_SATS, CONNECTOR_TREE_OPERATOR_TAKES_AFTER};

#[derive(Debug, Clone)]
pub struct Verifier<'a> {
    pub rpc: &'a Client,
    pub secp: Secp256k1<secp256k1::All>,
    pub signer: Actor,
    pub verifiers: Vec<XOnlyPublicKey>,
    pub connector_tree_utxos: Vec<Vec<OutPoint>>,
    pub connector_tree_hashes: Vec<Vec<[u8; 32]>>,
    pub operator_pk: XOnlyPublicKey,
}

impl<'a> Verifier<'a> {
    pub fn new(rng: &mut OsRng, rpc: &'a Client, operator_pk: XOnlyPublicKey) -> Self {
        let signer = Actor::new(rng);
        let secp: Secp256k1<secp256k1::All> = Secp256k1::new();
        let verifiers = Vec::new();
        let connector_tree_utxos = Vec::new();
        let connector_tree_hashes = Vec::new();
        Verifier {
            rpc,
            secp,
            signer,
            verifiers,
            connector_tree_utxos,
            connector_tree_hashes,
            operator_pk
        }
    }

    pub fn set_verifiers(&mut self, verifiers: Vec<XOnlyPublicKey>) {
        self.verifiers = verifiers;
    }

    pub fn set_connector_tree_utxos(&mut self, connector_tree_utxos: Vec<Vec<OutPoint>>) {
        self.connector_tree_utxos = connector_tree_utxos;
    }

    pub fn set_connector_tree_hashes(&mut self, connector_tree_hashes: Vec<Vec<[u8; 32]>>) {
        self.connector_tree_hashes = connector_tree_hashes;
    }

    pub fn new_deposit(
        &self,
        utxo: OutPoint,
        index: u32,
        hash: [u8; 32],
        return_address: XOnlyPublicKey,
        evm_address: EVMAddress,
        all_verifiers: &Vec<XOnlyPublicKey>,
        operator_address: Address,
    ) -> DepositPresigns {
        // println!("all_verifiers in new_deposit, in verifier now: {:?}", all_verifiers);
        let timestamp = check_deposit(
            &self.secp,
            self.rpc,
            utxo,
            hash,
            return_address,
            &all_verifiers,
        );
        let script_n_of_n = generate_n_of_n_script(&all_verifiers, hash);

        let script_n_of_n_without_hash = generate_n_of_n_script_without_hash(&all_verifiers);
        let (multisig_address, _) = create_taproot_address(&self.signer.secp, vec![script_n_of_n_without_hash.clone()]);
        println!("verifier presigning multisig address: {:?}", multisig_address);
        println!("verifier presigning multisig script pubkey: {:?}", multisig_address.script_pubkey());

        // let (anyone_can_spend_script_pub_key, dust_value) = handle_anyone_can_spend_script();
        
        let mut kickoff_tx = create_kickoff_tx(vec![utxo], vec![
            (
                BRIDGE_AMOUNT_SATS
                    - MIN_RELAY_FEE,
                multisig_address.script_pubkey().clone(),
            ),
            // (DUST_VALUE, anyone_can_spend_script_pub_key.clone()),
        ]);

        

        let (deposit_address, _) =
            User::generate_deposit_address(&self.signer.secp, &all_verifiers, hash, return_address);

        let prevouts = create_tx_outs(vec![(BRIDGE_AMOUNT_SATS, deposit_address.script_pubkey())]);

        let kickoff_sign = self.signer.sign_taproot_script_spend_tx(&mut kickoff_tx, prevouts, &script_n_of_n, 0);
        let kickoff_txid = kickoff_tx.txid();

        let prev_outpoint = OutPoint {
            txid: kickoff_txid,
            vout: 0,
        };
        let prev_amount = BRIDGE_AMOUNT_SATS
            - MIN_RELAY_FEE;
        println!("creating operator claim tx");
        println!("index: {:?}", index);
        // println!("connector_tree_utxos: {:?}", self.connector_tree_utxos);
        let mut operator_claim_tx = Transaction {
            version: Version(2),
            lock_time: absolute::LockTime::from_consensus(0),
            input: vec![TxIn {
                previous_output: prev_outpoint,
                script_sig: ScriptBuf::new(),
                sequence: bitcoin::transaction::Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            },
            TxIn {
                previous_output: self.connector_tree_utxos.last().unwrap()[index as usize],
                script_sig: ScriptBuf::new(),
                sequence: bitcoin::Sequence::from_height(CONNECTOR_TREE_OPERATOR_TAKES_AFTER),
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: prev_amount + DUST_VALUE - MIN_RELAY_FEE,
                script_pubkey: operator_address.script_pubkey(),
            }],
        };
        println!("verifier presigning operator_claim_tx: {:?}", operator_claim_tx);
        let (_, _, address, _) = handle_connector_binary_tree_script(&self.secp, self.operator_pk, self.connector_tree_hashes[self.connector_tree_hashes.len() - 1][index as usize]);

        let prevouts = create_tx_outs(vec![(prev_amount, multisig_address.script_pubkey().clone()), (DUST_VALUE, address.script_pubkey())]);

        let operator_claim_sign = self.signer.sign_taproot_script_spend_tx(&mut operator_claim_tx, prevouts, &script_n_of_n_without_hash, 0);
        println!("verifier presigning operator_claim_tx, sign: {:?}", operator_claim_sign);
        let rollup_sign = self.signer.sign_deposit(
            kickoff_txid,
            evm_address,
            hash,
            timestamp.to_consensus_u32().to_be_bytes(),
        );

        DepositPresigns {
            rollup_sign,
            kickoff_sign,
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

    pub fn watch_connector_tree(&self, operator_pk: XOnlyPublicKey, preimage_script_pubkey_pairs: &mut HashSet<PreimageType>, utxos: &mut HashMap<OutPoint, (u32, u32)>) -> (HashSet<PreimageType>, HashMap<OutPoint, (u32, u32)>) {
        println!("verifier watching connector tree...");
        let last_block_hash = self.rpc.get_best_block_hash().unwrap();
        let last_block = self.rpc.get_block(&last_block_hash).unwrap();
        for tx in last_block.txdata {
            if utxos.contains_key(&tx.input[0].previous_output) {
                // Check if any of the UTXOs have been spent
                let (depth, index) = utxos.remove(&tx.input[0].previous_output).unwrap();
                utxos.insert(OutPoint {
                    txid: tx.txid(),
                    vout: 0,
                }, (depth + 1, index * 2));
                utxos.insert(OutPoint {
                    txid: tx.txid(),
                    vout: 1,
                }, (depth + 1, index * 2 + 1));
                //Assert the two new UTXOs have the same value
                assert_eq!(tx.output[0].value, tx.output[1].value);
                let new_amount = tx.output[0].value;
                //Check if any one of the UTXOs can be spent with a preimage
                for (i, tx_out) in tx.output.iter().enumerate() {
                    let mut preimages_to_remove = Vec::new();
                    for preimage in preimage_script_pubkey_pairs.iter() {
                        if is_spendable_with_preimage(&self.secp, operator_pk, tx_out.clone(), *preimage) {
                            let utxo_to_spend = OutPoint {
                                txid: tx.txid(),
                                vout: i as u32,
                            };
                            self.spend_connector_tree_utxo(utxo_to_spend, operator_pk, *preimage, depth + 1, new_amount);
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

    pub fn spend_connector_tree_utxo(&self, utxo: OutPoint, operator_pk: XOnlyPublicKey, preimage: PreimageType, level: u32, amount: Amount) {
        let hash = HASH_FUNCTION_32(preimage);
        let (_, _, address, tree_info) = handle_connector_binary_tree_script(
            &self.secp,
            operator_pk,
            hash,
        );
        let tx_ins = create_tx_ins_with_sequence(vec![utxo]);
        let tx_outs = create_tx_outs(vec![(amount - MIN_RELAY_FEE, self.signer.address.script_pubkey())]);
        let mut tx = create_btc_tx(tx_ins, tx_outs);
        let prevouts = create_tx_outs(vec![(amount, address.script_pubkey())]);
        let hash_script = generate_hash_script(hash);
        let sig = self.signer.sign_taproot_script_spend_tx(&mut tx, prevouts, &hash_script, 0);
        let spend_control_block = create_control_block(tree_info, &hash_script);
        let mut sighash_cache = SighashCache::new(tx.borrow_mut());
        let witness = sighash_cache.witness_mut(0).unwrap();
        witness.push(preimage);
        witness.push(hash_script);
        witness.push(&spend_control_block.serialize());
        let bytes_tx = serialize(&tx);
        let spending_txid = self
            .rpc
            .send_raw_transaction(&bytes_tx)
            .unwrap();
        println!("verifier_spending_txid: {:?}", spending_txid);
    }

    pub fn spend_connector_tree_leaf_utxo(&self, utxo: OutPoint, operator_pk: XOnlyPublicKey, preimage: PreimageType, amount: Amount) {
        let hash = HASH_FUNCTION_32(preimage);
        let (_, _, address, tree_info) = handle_connector_binary_tree_script(
            &self.secp,
            operator_pk,
            hash,
        );
        let tx_ins = create_tx_ins_with_sequence(vec![utxo]);
        let tx_outs = create_tx_outs(vec![(amount - MIN_RELAY_FEE, self.signer.address.script_pubkey())]);
        let mut tx = create_btc_tx(tx_ins, tx_outs);
        let prevouts = create_tx_outs(vec![(amount, address.script_pubkey())]);
        let hash_script = generate_hash_script(hash);
        let sig = self.signer.sign_taproot_script_spend_tx(&mut tx, prevouts, &hash_script, 0);
        let spend_control_block = create_control_block(tree_info, &hash_script);
        let mut sighash_cache = SighashCache::new(tx.borrow_mut());
        let witness = sighash_cache.witness_mut(0).unwrap();
        witness.push(preimage);
        witness.push(hash_script);
        witness.push(&spend_control_block.serialize());
        let bytes_tx = serialize(&tx);
        let spending_txid = self
            .rpc
            .send_raw_transaction(&bytes_tx)
            .unwrap();
        println!("verifier_spending_txid: {:?}", spending_txid);
    }

}

pub fn is_spendable_with_preimage(secp: &Secp256k1<All>, operator_pk: XOnlyPublicKey, tx_out: TxOut, preimage: PreimageType) -> bool {
    let hash = HASH_FUNCTION_32(preimage);
    let (_, _, address, _) = handle_connector_binary_tree_script(
        secp,
        operator_pk,
        hash,
    );

    address.script_pubkey() == tx_out.script_pubkey
}
