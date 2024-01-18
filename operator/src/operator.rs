use core::num;
use std::borrow::BorrowMut;
use std::collections::{HashMap, HashSet};
use std::vec;

use crate::actor::{Actor, EVMSignature};
use crate::merkle::MerkleTree;
use crate::user::User;
use crate::utils::{
    create_btc_tx, create_connector_tree_tx, create_control_block, create_kickoff_tx,
    create_taproot_address, create_tx_ins, create_tx_ins_with_sequence, create_tx_outs,
    generate_hash_script, generate_n_of_n_script, generate_n_of_n_script_without_hash,
    generate_timelock_script, get_indices, handle_anyone_can_spend_script,
    handle_connector_binary_tree_script, mine_blocks,
};
use crate::verifier::Verifier;
use bitcoin::address::NetworkChecked;
use bitcoin::consensus::serialize;
use bitcoin::psbt::Output;
use bitcoin::sighash::SighashCache;
use bitcoin::taproot::LeafVersion;
use bitcoin::transaction::Version;
use bitcoin::{absolute, hashes::Hash, secp256k1, secp256k1::schnorr, Address, Txid};
use bitcoin::{Amount, OutPoint, ScriptBuf, Transaction, TxIn, TxOut, Witness};
use bitcoincore_rpc::{Client, RpcApi};
use circuit_helpers::config::{BRIDGE_AMOUNT_SATS, CONNECTOR_TREE_OPERATOR_TAKES_AFTER};
use circuit_helpers::constant::{EVMAddress, DUST_VALUE, HASH_FUNCTION_32, MIN_RELAY_FEE};
use secp256k1::rand::rngs::OsRng;
use secp256k1::rand::Rng;
use secp256k1::schnorr::Signature;
use secp256k1::{All, Secp256k1, XOnlyPublicKey};
pub type PreimageType = [u8; 32];

pub fn check_deposit(
    secp: &Secp256k1<All>,
    rpc: &Client,
    utxo: OutPoint,
    hash: [u8; 32],
    return_address: XOnlyPublicKey,
    verifiers_pks: &Vec<XOnlyPublicKey>,
) -> absolute::Time {
    // 1. Check if txid is mined in bitcoin
    // 2. Check if 0th output of the txid has 1 BTC
    // 3. Check if 0th output of the txid's scriptpubkey is N-of-N multisig and Hash of preimage or return_address after 200 blocks
    // 4. If all checks pass, return true
    // 5. Return the blockheight of the block in which the txid was mined
    let tx_res = rpc
        .get_transaction(&utxo.txid, None)
        .unwrap_or_else(|e| panic!("Failed to get raw transaction: {}, txid: {}", e, utxo.txid));
    let tx = tx_res.transaction().unwrap();
    // println!("tx: {:?}", tx);
    println!("txid: {:?}", tx.txid());
    println!("utxo: {:?}", utxo);
    assert!(tx.output[utxo.vout as usize].value == BRIDGE_AMOUNT_SATS);
    let (address, _) = User::generate_deposit_address(secp, verifiers_pks, hash, return_address);
    // println!("address: {:?}", address);
    // println!("address.script_pubkey(): {:?}", address.script_pubkey());
    assert!(tx.output[utxo.vout as usize].script_pubkey == address.script_pubkey());
    let time = tx_res.info.blocktime.unwrap() as u32;
    println!("time: {:?}", time);
    return absolute::Time::from_consensus(time).unwrap();
}

pub fn create_connector_tree_preimages_and_hashes(
    depth: u32,
    rng: &mut OsRng,
) -> (Vec<Vec<PreimageType>>, Vec<Vec<[u8; 32]>>) {
    let mut connector_tree_preimages: Vec<Vec<PreimageType>> = Vec::new();
    let mut connector_tree_hashes: Vec<Vec<[u8; 32]>> = Vec::new();
    let root_preimage: PreimageType = rng.gen();
    connector_tree_preimages.push(vec![root_preimage]);
    connector_tree_hashes.push(vec![HASH_FUNCTION_32(root_preimage)]);
    for i in 1..(depth + 1) {
        let mut preimages_current_level: Vec<PreimageType> = Vec::new();
        let mut hashes_current_level: Vec<PreimageType> = Vec::new();
        for _ in 0..2u32.pow(i) {
            let temp: PreimageType = rng.gen();
            preimages_current_level.push(temp);
            hashes_current_level.push(HASH_FUNCTION_32(temp));
        }
        connector_tree_preimages.push(preimages_current_level);
        connector_tree_hashes.push(hashes_current_level);
    }
    (connector_tree_preimages, connector_tree_hashes)
}

#[derive(Debug, Clone)]
pub struct DepositPresigns {
    pub rollup_sign: EVMSignature,
    pub kickoff_sign: schnorr::Signature,
    pub operator_claim_sign: schnorr::Signature,
}

#[derive(Debug, Clone)]
pub struct Operator<'a> {
    pub rpc: &'a Client,
    pub signer: Actor,
    pub verifiers_pks: Vec<XOnlyPublicKey>,
    pub verifier_evm_addresses: Vec<EVMAddress>,
    pub deposit_presigns: HashMap<Txid, Vec<DepositPresigns>>,
    pub deposit_merkle_tree: MerkleTree,
    pub withdrawals_merkle_tree: MerkleTree,
    pub withdrawals_payment_txids: Vec<Txid>,
    pub mock_verifier_access: Vec<Verifier<'a>>, // on production this will be removed rather we will call the verifier's API
    pub preimages: Vec<PreimageType>,
    pub connector_tree_utxos: Vec<Vec<OutPoint>>,
    connector_tree_preimages: Vec<Vec<PreimageType>>,
    pub connector_tree_hashes: Vec<Vec<[u8; 32]>>,
    pub deposit_utxos: Vec<OutPoint>,
    pub kickoff_utxos: Vec<OutPoint>,
}

pub fn check_presigns(
    utxo: OutPoint,
    timestamp: absolute::Time,
    deposit_presigns: &DepositPresigns,
) {
}

impl<'a> Operator<'a> {
    pub fn new(rng: &mut OsRng, rpc: &'a Client, num_verifier: u32) -> Self {
        let signer = Actor::new(rng);
        let (connector_tree_preimages, connector_tree_hashes) =
            create_connector_tree_preimages_and_hashes(3, rng);
        let mut verifiers = Vec::new();
        let mut verifiers_pks = Vec::new();
        for _ in 0..num_verifier {
            let verifier = Verifier::new(rng, rpc, signer.xonly_public_key.clone());
            verifiers_pks.push(verifier.signer.xonly_public_key.clone());
            verifiers.push(verifier);
        }
        Self {
            rpc,
            signer,
            verifiers_pks: verifiers_pks,
            verifier_evm_addresses: Vec::new(),
            deposit_presigns: HashMap::new(),
            deposit_merkle_tree: MerkleTree::initial(),
            withdrawals_merkle_tree: MerkleTree::initial(),
            withdrawals_payment_txids: Vec::new(),
            mock_verifier_access: verifiers,
            preimages: Vec::new(),
            connector_tree_utxos: Vec::new(),
            connector_tree_preimages: connector_tree_preimages,
            connector_tree_hashes: connector_tree_hashes,
            deposit_utxos: Vec::new(),
            kickoff_utxos: Vec::new(),
        }
    }

    // pub fn add_verifier(&mut self, verifier: &Verifier<'a>) {
    //     self.mock_verifier_access.push(verifier.clone());
    //     self.verifiers_pks
    //         .push(verifier.signer.xonly_public_key.clone());
    //     self.verifier_evm_addresses
    //         .push(verifier.signer.evm_address.clone());
    // }

    pub fn add_deposit_utxo(&mut self, utxo: OutPoint) {
        self.deposit_utxos.push(utxo);
    }

    pub fn get_all_verifiers(&self) -> Vec<XOnlyPublicKey> {
        let mut all_verifiers = self.verifiers_pks.to_vec();
        all_verifiers.push(self.signer.xonly_public_key.clone());
        all_verifiers
    }

    pub fn set_connector_tree_utxos(&mut self, connector_tree_utxos: Vec<Vec<OutPoint>>) {
        self.connector_tree_utxos = connector_tree_utxos;
    }

    // this is a public endpoint that every depositor can call
    pub fn new_deposit(
        &mut self,
        utxo: OutPoint,
        index: u32,
        hash: [u8; 32],
        return_address: XOnlyPublicKey,
        evm_address: EVMAddress,
    ) -> Vec<EVMSignature> {
        // self.verifiers + signer.public_key
        let all_verifiers = self.get_all_verifiers();
        // println!("all_verifiers checking: {:?}", all_verifiers);
        let timestamp = check_deposit(
            &self.signer.secp,
            self.rpc,
            utxo,
            hash,
            return_address.clone(),
            &all_verifiers,
        );
        // println!("mock verifier access: {:?}", self.mock_verifier_access);
        let presigns_from_all_verifiers = self
            .mock_verifier_access
            .iter()
            .map(|verifier| {
                // println!("verifier in the closure: {:?}", verifier);
                // Note: In this part we will need to call the verifier's API to get the presigns
                let deposit_presigns = verifier.new_deposit(
                    utxo,
                    index,
                    hash,
                    return_address.clone(),
                    evm_address,
                    &all_verifiers,
                );
                println!("checked new deposit");
                check_presigns(utxo, timestamp, &deposit_presigns);
                println!("checked presigns");
                deposit_presigns
            })
            .collect::<Vec<_>>();
        println!("presigns_from_all_verifiers: done");

        let (anyone_can_spend_script_pub_key, dust_value) = handle_anyone_can_spend_script();

        let kickoff_tx = create_kickoff_tx(
            vec![utxo],
            vec![
                (
                    BRIDGE_AMOUNT_SATS - DUST_VALUE - MIN_RELAY_FEE,
                    generate_n_of_n_script_without_hash(&all_verifiers),
                ),
                (DUST_VALUE, anyone_can_spend_script_pub_key),
            ],
        );

        let kickoff_txid = kickoff_tx.txid();

        let rollup_sign = self.signer.sign_deposit(
            kickoff_txid,
            evm_address,
            hash,
            timestamp.to_consensus_u32().to_be_bytes(),
        );
        let mut all_rollup_signs = presigns_from_all_verifiers
            .iter()
            .map(|presigns| presigns.rollup_sign)
            .collect::<Vec<_>>();
        all_rollup_signs.push(rollup_sign);
        self.deposit_presigns
            .insert(utxo.txid, presigns_from_all_verifiers);
        all_rollup_signs
    }

    // this is called when a Withdrawal event emitted on rollup
    pub fn new_withdrawal(&mut self, withdrawal_address: Address<NetworkChecked>) {
        let taproot_script = withdrawal_address.script_pubkey();
        // we are assuming that the withdrawal_address is a taproot address so we get the last 32 bytes
        let hash: [u8; 34] = taproot_script.as_bytes().try_into().unwrap();
        let hash: [u8; 32] = hash[2..].try_into().unwrap();

        // 1. Add the address to WithdrawalsMerkleTree
        self.withdrawals_merkle_tree.add(hash);

        // self.withdrawals_merkle_tree.add(withdrawal_address.to);

        // 2. Pay to the address and save the txid
        let txid = self
            .rpc
            .send_to_address(
                &withdrawal_address,
                bitcoin::Amount::from_sat(1),
                None,
                None,
                None,
                None,
                None,
                None,
            )
            .unwrap();
        self.withdrawals_payment_txids.push(txid);
    }

    // this is called when a Deposit event emitted on rollup
    pub fn preimage_revealed(
        &mut self,
        preimage: PreimageType,
        utxo: OutPoint,
        return_address: XOnlyPublicKey, // TODO: SAVE THIS TO STRUCT
    ) -> OutPoint {
        self.preimages.push(preimage);
        // 1. Add the corresponding txid to DepositsMerkleTree
        self.deposit_merkle_tree.add(utxo.txid.to_byte_array());
        let hash = HASH_FUNCTION_32(preimage);
        let all_verifiers = self.get_all_verifiers();
        let script_n_of_n = generate_n_of_n_script(&all_verifiers, hash);

        let script_n_of_n_without_hash = generate_n_of_n_script_without_hash(&all_verifiers);
        let (address, _) =
            create_taproot_address(&self.signer.secp, vec![script_n_of_n_without_hash.clone()]);

        let (anyone_can_spend_script_pub_key, dust_value) = handle_anyone_can_spend_script();

        let mut kickoff_tx = create_kickoff_tx(
            vec![utxo],
            vec![
                (BRIDGE_AMOUNT_SATS - MIN_RELAY_FEE, address.script_pubkey()),
                // (DUST_VALUE, anyone_can_spend_script_pub_key),
            ],
        );
        self.add_deposit_utxo(utxo);

        let (deposit_address, deposit_taproot_info) =
            User::generate_deposit_address(&self.signer.secp, &all_verifiers, hash, return_address);

        let prevouts = create_tx_outs(vec![(BRIDGE_AMOUNT_SATS, deposit_address.script_pubkey())]);

        let mut kickoff_signatures: Vec<Signature> = Vec::new();
        let deposit_presigns_for_kickoff = self
            .deposit_presigns
            .get(&utxo.txid)
            .expect("Deposit presigns not found");
        for presign in deposit_presigns_for_kickoff.iter() {
            kickoff_signatures.push(presign.kickoff_sign);
        }

        let sig =
            self.signer
                .sign_taproot_script_spend_tx(&mut kickoff_tx, prevouts, &script_n_of_n, 0);
        kickoff_signatures.push(sig);

        let spend_control_block = deposit_taproot_info
            .control_block(&(script_n_of_n.clone(), LeafVersion::TapScript))
            .expect("Cannot create control block");

        let mut sighash_cache = SighashCache::new(kickoff_tx.borrow_mut());
        let witness = sighash_cache.witness_mut(0).unwrap();
        // push signatures to witness
        witness.push(preimage);
        kickoff_signatures.reverse();
        for sig in kickoff_signatures.iter() {
            witness.push(sig.as_ref());
        }

        witness.push(script_n_of_n);
        witness.push(&spend_control_block.serialize());
        // println!("witness size: {:?}", witness.size());
        println!("kickoff_tx: {:?}", kickoff_tx);
        let kickoff_txid = kickoff_tx.txid();
        let deposit_utxo = OutPoint {
            txid: kickoff_txid,
            vout: 0,
        };
        println!("deposit utxo added: {:?}", deposit_utxo);
        // println!("kickoff_txid: {:?}", kickoff_txid);
        // let utxo_for_child = OutPoint {
        //     txid: kickoff_txid,
        //     vout: 1,
        // };

        // let child_tx = self.create_child_pays_for_parent(utxo_for_child);
        let rpc_kickoff_txid = self.rpc.send_raw_transaction(&kickoff_tx).unwrap();
        println!("rpc_kickoff_txid: {:?}", rpc_kickoff_txid);
        // let child_of_kickoff_txid = self.rpc.send_raw_transaction(&child_tx).unwrap();
        // println!("child_of_kickoff_txid: {:?}", child_of_kickoff_txid);
        let kickoff_utxo = OutPoint {
            txid: kickoff_txid,
            vout: 0,
        };
        self.kickoff_utxos.push(kickoff_utxo.clone());
        kickoff_utxo
    }

    pub fn create_child_pays_for_parent(&self, parent_outpoint: OutPoint) -> Transaction {
        let resource_tx_id = self
            .rpc
            .send_to_address(
                &self.signer.address,
                BRIDGE_AMOUNT_SATS,
                None,
                None,
                None,
                None,
                None,
                None,
            )
            .unwrap();
        let resource_tx = self.rpc.get_raw_transaction(&resource_tx_id, None).unwrap();
        println!("resource_tx: {:?}", resource_tx);
        let vout = resource_tx
            .output
            .iter()
            .position(|x| x.value == BRIDGE_AMOUNT_SATS)
            .unwrap();

        let all_verifiers = self.get_all_verifiers();

        let script_n_of_n_without_hash = generate_n_of_n_script_without_hash(&all_verifiers);
        let (address, _) =
            create_taproot_address(&self.signer.secp, vec![script_n_of_n_without_hash.clone()]);

        let (anyone_can_spend_script_pub_key, dust_value) = handle_anyone_can_spend_script();

        let child_tx_ins = create_tx_ins(vec![
            parent_outpoint,
            OutPoint {
                txid: resource_tx_id,
                vout: vout as u32,
            },
        ]);

        let child_tx_outs = create_tx_outs(vec![
            (
                BRIDGE_AMOUNT_SATS - DUST_VALUE - MIN_RELAY_FEE,
                address.script_pubkey(),
            ),
            (DUST_VALUE, anyone_can_spend_script_pub_key.clone()),
        ]);

        let mut child_tx = create_btc_tx(child_tx_ins, child_tx_outs);

        child_tx.input[0].witness.push([0x51]);

        let prevouts = create_tx_outs(vec![
            (DUST_VALUE, anyone_can_spend_script_pub_key),
            (BRIDGE_AMOUNT_SATS, self.signer.address.script_pubkey()),
        ]);
        let sig = self
            .signer
            .sign_taproot_pubkey_spend_tx(&mut child_tx, prevouts, 1);
        let mut sighash_cache = SighashCache::new(child_tx.borrow_mut());
        let witness = sighash_cache.witness_mut(1).unwrap();
        witness.push(sig.as_ref());
        println!("child_tx: {:?}", child_tx);
        println!("child_txid: {:?}", child_tx.txid());
        child_tx
    }

    // this function is interal, where it checks if the current bitcoin height reaced to th end of the period,
    pub fn period1_end(&self) {
        // self.move_bridge_funds();

        // Check if all deposists are satisifed, all remaning bridge funds are moved to a new multisig
    }

    // this function is interal, where it checks if the current bitcoin height reaced to th end of the period,
    pub fn period2_end(&self) {
        // This is the time we generate proof.
    }

    // this function is interal, where it checks if the current bitcoin height reaced to th end of the period,
    pub fn period3_end(&self) {
        // This is the time send generated proof along with k-deep proof
        // and revealing bit-commitments for the next bitVM instance.
    }

    // this function is interal, where it moves remaining bridge funds to a new multisig using DepositPresigns
    // pub fn move_single_bridge_fund(&self, deposit_txid: Txid, prev_outpoint: OutPoint) -> OutPoint {
    //     // 1. Get the deposit tx
    //     let prev_tx = self
    //         .rpc
    //         .get_raw_transaction(&prev_outpoint.txid, None)
    //         .unwrap();
    //     let utxo_amount = prev_tx.output[prev_outpoint.vout as usize].value;
    //     let all_verifiers = self.get_all_verifiers();

    //     let script_n_of_n_without_hash = generate_n_of_n_script_without_hash(&all_verifiers);
    //     let (address, tree_info) =
    //         create_taproot_address(&self.signer.secp, vec![script_n_of_n_without_hash.clone()]);

    //     let (anyone_can_spend_script_pub_key, dust_value) = handle_anyone_can_spend_script();

    //     let move_tx_ins = create_tx_ins(vec![prev_outpoint]);

    //     let move_tx_outs = create_tx_outs(vec![
    //         (
    //             utxo_amount - dust_value - bitcoin::Amount::from_sat(MIN_RELAY_FEE),
    //             address.script_pubkey(),
    //         ),
    //         (dust_value, anyone_can_spend_script_pub_key),
    //     ]);

    //     let mut move_tx = create_btc_tx(move_tx_ins, move_tx_outs);

    //     let mut move_signatures: Vec<Signature> = Vec::new();
    //     let deposit_presigns_from_txid = self
    //         .deposit_presigns
    //         .get(&deposit_txid)
    //         .expect("Deposit presigns not found");
    //     for presign in deposit_presigns_from_txid.iter() {
    //         move_signatures.push(
    //             presign
    //                 .move_bridge_sign_utxo_pairs
    //                 .get(&prev_outpoint)
    //                 .expect("No signatures for such utxo")
    //                 .clone(),
    //         );
    //     }

    //     let prevouts = vec![TxOut {
    //         script_pubkey: address.script_pubkey(),
    //         value: utxo_amount,
    //     }];

    //     let sig = self.signer.sign_taproot_script_spend_tx(
    //         &mut move_tx,
    //         prevouts,
    //         &script_n_of_n_without_hash,
    //         0,
    //     );
    //     move_signatures.push(sig);

    //     let spend_control_block = create_control_block(tree_info, &script_n_of_n_without_hash);

    //     let mut sighash_cache = SighashCache::new(move_tx.borrow_mut());
    //     let witness = sighash_cache.witness_mut(0).unwrap();
    //     // push signatures to witness
    //     move_signatures.reverse();
    //     for sig in move_signatures.iter() {
    //         witness.push(sig.as_ref());
    //     }

    //     witness.push(script_n_of_n_without_hash);
    //     witness.push(&spend_control_block.serialize());
    //     println!("move_tx: {:?}", move_tx);
    //     let move_txid = self.rpc.send_raw_transaction(&move_tx).unwrap();
    //     println!("move_txid: {:?}", move_txid);
    //     let move_tx_from_rpc = self.rpc.get_raw_transaction(&move_txid, None).unwrap();
    //     println!("move_tx_from_rpc: {:?}", move_tx_from_rpc);
    //     OutPoint {
    //         txid: move_txid,
    //         vout: 0,
    //     }
    // }

    // This function is internal, it gives the appropriate response for a bitvm challenge
    pub fn challenge_received() {}

    pub fn spend_connector_tree_utxo(
        &self,
        utxo: OutPoint,
        preimage: PreimageType,
        tree_depth: u32,
    ) {
        let hash = HASH_FUNCTION_32(preimage);
        let (_, _, _, tree_info) = handle_connector_binary_tree_script(
            &self.signer.secp,
            self.signer.xonly_public_key,
            hash,
        );

        let base_tx = match self.rpc.get_raw_transaction(&utxo.txid, None) {
            Ok(txid) => Some(txid),
            Err(e) => {
                eprintln!("Failed to get raw transaction: {}", e);
                None
            }
        };
        println!("base_tx: {:?}", base_tx);

        if base_tx.is_none() {
            return;
        } else {
            let depth = u32::ilog2(
                ((base_tx.unwrap().output[utxo.vout as usize].value + MIN_RELAY_FEE).to_sat()
                    / (DUST_VALUE + MIN_RELAY_FEE).to_sat()) as u32,
            );
            println!("depth: {:?}", depth);
            let level = tree_depth - depth;
            //find the index of preimage in the connector_tree_preimages[level as usize]
            let index = self.connector_tree_preimages[level as usize]
                .iter()
                .position(|x| *x == preimage)
                .unwrap();
            let hashes = (
                self.connector_tree_hashes[(level + 1) as usize][2 * index],
                self.connector_tree_hashes[(level + 1) as usize][2 * index + 1],
            );

            let utxo_tx = self.rpc.get_raw_transaction(&utxo.txid, None).unwrap();
            // println!("utxo_tx: {:?}", utxo_tx);
            // println!("utxo_txid: {:?}", utxo_tx.txid());
            let timelock_script = generate_timelock_script(self.signer.xonly_public_key, 1);

            let (_, _, first_address, _) = handle_connector_binary_tree_script(
                &self.signer.secp,
                self.signer.xonly_public_key,
                hashes.0,
            );

            let (_, _, second_address, _) = handle_connector_binary_tree_script(
                &self.signer.secp,
                self.signer.xonly_public_key,
                hashes.1,
            );

            let mut tx = create_connector_tree_tx(&utxo, depth - 1, first_address, second_address);
            println!("created spend tx: {:?}", tx);

            let sig = self.signer.sign_taproot_script_spend_tx(
                &mut tx,
                vec![utxo_tx.output[utxo.vout as usize].clone()],
                &timelock_script,
                0,
            );
            let spend_control_block = tree_info
                .control_block(&(timelock_script.clone(), LeafVersion::TapScript))
                .expect("Cannot create control block");
            let mut sighash_cache = SighashCache::new(tx.borrow_mut());
            let witness = sighash_cache.witness_mut(0).unwrap();
            witness.push(sig.as_ref());
            witness.push(timelock_script);
            witness.push(&spend_control_block.serialize());
            let bytes_tx = serialize(&tx);
            // println!("bytes_connector_tree_tx length: {:?}", bytes_connector_tree_tx.len());
            // let hex_utxo_tx = hex::encode(bytes_utxo_tx.clone());
            let spending_txid = match self.rpc.send_raw_transaction(&bytes_tx) {
                Ok(txid) => Some(txid),
                Err(e) => {
                    eprintln!("Failed to send raw transaction: {}", e);
                    None
                }
            };
            println!("spending_txid: {:?}", spending_txid);
        }
    }

    fn reveal_connector_tree_preimages(&self, number_of_funds_claim: u32) -> HashSet<PreimageType> {
        let indices = get_indices(
            (self.connector_tree_hashes.len() - 1) as u32,
            number_of_funds_claim,
        );
        println!("indices: {:?}", indices);
        let mut preimages: HashSet<PreimageType> = HashSet::new();
        for (depth, index) in indices {
            preimages.insert(self.connector_tree_preimages[depth as usize][index as usize]);
        }
        preimages
    }

    pub fn claim_deposit(&self, index: u32) {
        let preimage = self.connector_tree_preimages.last().unwrap()[index as usize];
        let hash = HASH_FUNCTION_32(preimage);
        let (_, _, address, tree_info1) = handle_connector_binary_tree_script(
            &self.signer.secp,
            self.signer.xonly_public_key,
            hash,
        );
        println!("deposit_utxos: {:?}", self.deposit_utxos);
        let deposit_utxo = self.deposit_utxos[index as usize];
        let fund_utxo = self.kickoff_utxos[index as usize];
        let connector_utxo = self.connector_tree_utxos.last().unwrap()[index as usize];

        let first_input = create_tx_ins(vec![fund_utxo]);
        let second_input = create_tx_ins_with_sequence(vec![connector_utxo]);

        let mut tx_ins = first_input.clone();
        tx_ins.extend(second_input.clone());

        let tx_outs = create_tx_outs(vec![(
            BRIDGE_AMOUNT_SATS + DUST_VALUE - MIN_RELAY_FEE * 2,
            self.signer.address.script_pubkey(),
        )]);

        let mut claim_tx = Transaction {
            version: Version(2),
            lock_time: absolute::LockTime::from_consensus(0),
            input: tx_ins,
            output: tx_outs,
        };
        println!("claim_tx: {:?}", claim_tx);

        let timelock_script = generate_timelock_script(
            self.signer.xonly_public_key,
            CONNECTOR_TREE_OPERATOR_TAKES_AFTER as u32,
        );
        let script_n_of_n_without_hash = generate_n_of_n_script_without_hash(&self.verifiers_pks);
        let (multisig_address, tree_info0) =
            create_taproot_address(&self.signer.secp, vec![script_n_of_n_without_hash.clone()]);

        let prevouts = create_tx_outs(vec![
            (
                BRIDGE_AMOUNT_SATS - MIN_RELAY_FEE,
                multisig_address.script_pubkey(),
            ),
            (DUST_VALUE, address.script_pubkey()),
        ]);

        let spend_control_block1 = tree_info1
            .control_block(&(timelock_script.clone(), LeafVersion::TapScript))
            .expect("Cannot create control block");

        let spend_control_block0 = tree_info0
            .control_block(&(script_n_of_n_without_hash.clone(), LeafVersion::TapScript))
            .expect("Cannot create control block");

        let sig0 =
            self.signer
                .sign_taproot_script_spend_tx(&mut claim_tx, prevouts.clone(), &script_n_of_n_without_hash, 0);
        let sig1 =
            self.signer
                .sign_taproot_script_spend_tx(&mut claim_tx, prevouts, &timelock_script, 1);
        // println!("deposit presigns: {:?}", self.deposit_presigns);
        println!("deposit_utxo.txid: {:?}", deposit_utxo.txid);
        let sig_vec = self.deposit_presigns.get(&deposit_utxo.txid).unwrap();

        let mut sighash_cache = SighashCache::new(claim_tx.borrow_mut());
        let witness1 = sighash_cache.witness_mut(1).unwrap();
        // witness1.push(sig0.as_ref());
        witness1.push(timelock_script);
        witness1.push(&spend_control_block1.serialize());

        let witness0 = sighash_cache.witness_mut(0).unwrap();
        witness0.push(sig0.as_ref());
        for index in 0..sig_vec.len() {
            witness0.push(sig_vec[index as usize].operator_claim_sign.as_ref());
        }
        witness0.push(script_n_of_n_without_hash.clone());
        witness0.push(&spend_control_block0.serialize());

        println!("claim_tx: {:?}", claim_tx);
        let tx_bytes = serialize(&claim_tx);
        let txid = self.rpc.send_raw_transaction(&tx_bytes).unwrap();
        println!("claim successful, txid: {:?}", txid);
    }
}

#[cfg(test)]
mod tests {

    use std::collections::{HashMap, HashSet};

    use bitcoin::{OutPoint, ScriptBuf};
    use bitcoincore_rpc::{Auth, Client, RpcApi};
    use circuit_helpers::{
        config::{BRIDGE_AMOUNT_SATS, NUM_USERS, NUM_VERIFIERS},
        constant::{DUST_VALUE, MIN_RELAY_FEE},
    };
    use secp256k1::rand::rngs::OsRng;

    use crate::{
        operator::{Operator, PreimageType},
        user::User,
        utils::{create_connector_binary_tree, handle_connector_binary_tree_script, mine_blocks},
        verifier::Verifier,
    };

    #[test]
    fn test_connector_tree_tx() {
        let mut bridge_funds: Vec<bitcoin::Txid> = Vec::new();
        let rpc = Client::new(
            "http://localhost:18443/wallet/admin",
            Auth::UserPass("admin".to_string(), "admin".to_string()),
        )
        .unwrap_or_else(|e| panic!("Failed to connect to Bitcoin RPC: {}", e));

        let depth: u32 = 3;
        let total_amount = MIN_RELAY_FEE * (2u64.pow(depth) - 1) + DUST_VALUE * 2u64.pow(depth);
        let mut operator = Operator::new(&mut OsRng, &rpc, NUM_VERIFIERS as u32);
        let mut users = Vec::new();
        for _ in 0..NUM_USERS {
            users.push(User::new(&mut OsRng, &rpc));
        }
        let verifiers_pks = operator.get_all_verifiers();
        for verifier in &mut operator.mock_verifier_access {
            verifier.set_verifiers(verifiers_pks.clone());
        }
        let mut verifiers_evm_addresses = operator.verifier_evm_addresses.clone();
        verifiers_evm_addresses.push(operator.signer.evm_address);
        let mut utxo_vec = Vec::new();
        let mut return_addresses = Vec::new();

        let (_, _, root_address, _) = handle_connector_binary_tree_script(
            &operator.signer.secp,
            operator.signer.xonly_public_key,
            operator.connector_tree_hashes[0][0],
        );
        let root_txid = operator
            .rpc
            .send_to_address(
                &root_address,
                total_amount,
                None,
                None,
                None,
                None,
                None,
                None,
            )
            .unwrap();
        let root_tx = operator.rpc.get_raw_transaction(&root_txid, None).unwrap();
        println!("resource_tx: {:?}", root_tx);

        let vout = root_tx
            .output
            .iter()
            .position(|x| x.value == total_amount)
            .unwrap();

        let root_utxo = OutPoint {
            txid: root_txid,
            vout: vout as u32,
        };
        let mut preimage_script_pubkey_pairs: HashSet<PreimageType> = HashSet::new();
        let mut utxos: HashMap<OutPoint, (u32, u32)> = HashMap::new();

        let mut flag =
            operator.mock_verifier_access[0].did_connector_tree_process_start(root_utxo.clone());
        println!("flag: {:?}", flag);
        if flag {
            operator.mock_verifier_access[0].watch_connector_tree(
                operator.signer.xonly_public_key,
                &mut preimage_script_pubkey_pairs,
                &mut utxos,
            );
        }

        println!("resource_utxo: {:?}", root_utxo);

        let utxo_tree = create_connector_binary_tree(
            &rpc,
            &operator.signer.secp,
            operator.signer.xonly_public_key,
            root_utxo,
            3,
            operator.connector_tree_hashes.clone(),
        );

        operator.set_connector_tree_utxos(utxo_tree.clone());
        // println!(
        //     "operator.connector_tree_utxos: {:?}",
        //     operator.connector_tree_utxos
        // );
        for verifier in &mut operator.mock_verifier_access {
            verifier.set_connector_tree_utxos(utxo_tree.clone());
            verifier.set_connector_tree_hashes(operator.connector_tree_hashes.clone());
            // println!(
            //     "verifier.connector_tree_utxos: {:?}",
            //     verifier.connector_tree_utxos
            // );
        }

        for i in 0..8 {
            let user = &users[i];
            // println!("verifiers_pks in for: {:?}", verifiers_pks);
            let (mut utxo, mut hash, mut return_address) = user.deposit_tx(
                &user.rpc,
                BRIDGE_AMOUNT_SATS,
                &user.secp,
                verifiers_pks.clone(),
            );
            bridge_funds.push(utxo.txid);
            return_addresses.push(return_address);
            utxo_vec.push(utxo);
            rpc.generate_to_address(1, &operator.signer.address)
                .unwrap();
            let signatures = operator.new_deposit(
                utxo,
                i as u32,
                hash,
                return_address,
                user.signer.evm_address,
            );
        }

        let mut fund_utxos = Vec::new();

        for i in 0..8 {
            let fund = operator.preimage_revealed(
                users[i].reveal_preimage(),
                utxo_vec[i],
                return_addresses[i],
            );
            fund_utxos.push(fund);
        }

        flag = operator.mock_verifier_access[0].did_connector_tree_process_start(root_utxo.clone());
        println!("flag: {:?}", flag);
        if flag {
            operator.mock_verifier_access[0].watch_connector_tree(
                operator.signer.xonly_public_key,
                &mut preimage_script_pubkey_pairs,
                &mut utxos,
            );
        }

        mine_blocks(&rpc, 3);

        let preimages = operator.reveal_connector_tree_preimages(3);
        println!("preimages revealed: {:?}", preimages);

        for (i, utxo_level) in utxo_tree[0..utxo_tree.len() - 1].iter().enumerate() {
            flag = operator.mock_verifier_access[0]
                .did_connector_tree_process_start(root_utxo.clone());
            println!("flag: {:?}", flag);
            if flag {
                operator.mock_verifier_access[0].watch_connector_tree(
                    operator.signer.xonly_public_key,
                    &mut preimage_script_pubkey_pairs,
                    &mut utxos,
                );
            }
            for (j, utxo) in utxo_level.iter().enumerate() {
                let preimage = operator.connector_tree_preimages[i][j];
                println!("preimage: {:?}", preimage);
                operator.spend_connector_tree_utxo(*utxo, preimage, 3);
            }
            mine_blocks(&rpc, 1);
        }

        mine_blocks(&rpc, 2);

        for i in 0..3 {
            operator.claim_deposit(i);
        }
    }
}
