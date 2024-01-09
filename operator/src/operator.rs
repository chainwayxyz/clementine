use std::borrow::BorrowMut;
use std::collections::HashMap;

use crate::actor::{Actor, EVMSignature};
use crate::merkle::MerkleTree;
use crate::transactions::INTERNAL_KEY;
use crate::user::User;
use crate::utils::{generate_n_of_n_script, generate_n_of_n_script_without_hash};
use crate::verifier::Verifier;
use bitcoin::address::NetworkChecked;
use bitcoin::opcodes::OP_TRUE;
use bitcoin::script::Builder;
use bitcoin::sighash::SighashCache;
use bitcoin::taproot::{LeafVersion, TaprootBuilder};
use bitcoin::transaction::Version;
use bitcoin::{absolute, hashes::Hash, secp256k1, secp256k1::schnorr, Address, Txid};
use bitcoin::{
    Amount, OutPoint, ScriptBuf, TapLeafHash, Transaction, TxIn, TxOut, Witness,
};
use bitcoincore_rpc::{Client, RpcApi};
use circuit_helpers::config::{
    EVMAddress, BRIDGE_AMOUNT_SATS, FEE, MIN_RELAY_FEE, NUM_VERIFIERS, REGTEST,
};
use circuit_helpers::hashes::sha256_32bytes;
use secp256k1::rand::rngs::OsRng;
use secp256k1::schnorr::Signature;
use secp256k1::{All, Secp256k1, XOnlyPublicKey};
pub const NUM_ROUNDS: usize = 10;
type PreimageType = [u8; 32];

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

    assert!(tx.output[utxo.vout as usize].value == bitcoin::Amount::from_sat(BRIDGE_AMOUNT_SATS));
    let (address, _) = User::generate_deposit_address(secp, verifiers_pks, hash, return_address);
    assert!(tx.output[utxo.vout as usize].script_pubkey == address.script_pubkey());
    let time = tx_res.info.blocktime.unwrap() as u32;
    return absolute::Time::from_consensus(time).unwrap();
}

pub struct DepositPresigns {
    pub rollup_sign: EVMSignature,
    pub kickoff_sign: schnorr::Signature,
    pub move_bridge_sign: Vec<schnorr::Signature>,
    pub operator_take_sign: Vec<schnorr::Signature>,
}

pub struct Operator<'a> {
    pub rpc: &'a Client,
    pub signer: Actor,
    pub verifiers: Vec<XOnlyPublicKey>,
    pub verifier_evm_addresses: Vec<EVMAddress>,
    pub deposit_presigns: HashMap<Txid, Vec<DepositPresigns>>,
    pub deposit_merkle_tree: MerkleTree,
    pub withdrawals_merkle_tree: MerkleTree,
    pub withdrawals_payment_txids: Vec<Txid>,
    pub mock_verifier_access: Vec<Verifier<'a>>, // on production this will be removed rather we will call the verifier's API
    pub preimages: Vec<PreimageType>,
}

pub fn check_presigns(
    utxo: OutPoint,
    timestamp: absolute::Time,
    deposit_presigns: &DepositPresigns,
) {
}

impl<'a> Operator<'a> {
    pub fn new(rng: &mut OsRng, rpc: &'a Client) -> Self {
        let signer = Actor::new(rng);
        let mut verifiers = Vec::new();
        for _ in 0..NUM_VERIFIERS {
            verifiers.push(Verifier::new(rng, rpc, signer.xonly_public_key));
        }
        let verifiers_pks = verifiers
            .iter()
            .map(|verifier| verifier.signer.xonly_public_key)
            .collect::<Vec<_>>();

        verifiers.iter_mut().for_each(|verifier| {
            verifier.set_verifiers(verifiers_pks.clone());
        });

        let verifier_evm_addresses = verifiers
            .iter()
            .map(|verifier| verifier.signer.evm_address)
            .collect::<Vec<_>>();
        let deposit_presigns = HashMap::new();

        Self {
            rpc,
            signer,
            verifiers: verifiers_pks,
            verifier_evm_addresses,
            deposit_presigns,
            deposit_merkle_tree: MerkleTree::initial(),
            withdrawals_merkle_tree: MerkleTree::initial(),
            withdrawals_payment_txids: Vec::new(),
            mock_verifier_access: verifiers,
            preimages: Vec::new(),
        }
    }
    // this is a public endpoint that every depositor can call
    pub fn new_deposit(
        &mut self,
        utxo: OutPoint,
        hash: [u8; 32],
        return_address: XOnlyPublicKey,
        evm_address: EVMAddress,
    ) -> Vec<EVMSignature> {
        // self.verifiers + signer.public_key
        let mut all_verifiers = self.verifiers.to_vec();
        all_verifiers.push(self.signer.xonly_public_key.clone());
        let timestamp = check_deposit(
            &self.signer.secp,
            self.rpc,
            utxo,
            hash,
            return_address.clone(),
            &all_verifiers,
        );

        let presigns_from_all_verifiers = self
            .mock_verifier_access
            .iter()
            .map(|verifier| {
                // Note: In this part we will need to call the verifier's API to get the presigns
                let deposit_presigns =
                    verifier.new_deposit(utxo, hash, return_address.clone(), evm_address);
                check_presigns(utxo, timestamp, &deposit_presigns);
                deposit_presigns
            })
            .collect::<Vec<_>>();

        let script_anyone_can_spend = Builder::new().push_opcode(OP_TRUE).into_script();
        let anyone_can_spend_script_pub_key = script_anyone_can_spend.to_p2wsh();
        let dust_value = script_anyone_can_spend.dust_value();
        // println!("dust_value: {:?}", dust_value);
        let kickoff_tx = Transaction {
            version: Version(2),
            lock_time: absolute::LockTime::from_consensus(0),
            input: vec![TxIn {
                previous_output: utxo,
                sequence: bitcoin::transaction::Sequence::ENABLE_RBF_NO_LOCKTIME,
                script_sig: ScriptBuf::default(),
                witness: Witness::new(),
            }],
            output: vec![
                TxOut {
                    value: bitcoin::Amount::from_sat(BRIDGE_AMOUNT_SATS) - dust_value - bitcoin::Amount::from_sat(MIN_RELAY_FEE),
                    script_pubkey: generate_n_of_n_script_without_hash(&all_verifiers),
                },
                TxOut {
                    value: dust_value,
                    script_pubkey: anyone_can_spend_script_pub_key,
                },
            ],
        };
        // println!("kickoff_tx: {:?}", kickoff_tx);

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
            .insert(kickoff_txid, presigns_from_all_verifiers);
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
    ) {
        self.preimages.push(preimage);
        // 1. Add the corresponding txid to DepositsMerkleTree
        self.deposit_merkle_tree.add(utxo.txid.to_byte_array());
        let hash = sha256_32bytes(preimage);
        let mut all_verifiers = self.verifiers.to_vec();
        all_verifiers.push(self.signer.xonly_public_key.clone());
        let script_n_of_n = generate_n_of_n_script(&all_verifiers, hash);

        let script_n_of_n_without_hash = generate_n_of_n_script_without_hash(&all_verifiers);
        let taproot = TaprootBuilder::new()
            .add_leaf(0, script_n_of_n_without_hash.clone())
            .unwrap();
        let internal_key = *INTERNAL_KEY;
        let tree_info = taproot.finalize(&self.signer.secp, internal_key).unwrap();
        let address = Address::p2tr(
            &self.signer.secp,
            internal_key,
            tree_info.merkle_root(),
            REGTEST,
        );

        let script_anyone_can_spend = Builder::new().push_opcode(OP_TRUE).into_script();
        let anyone_can_spend_script_pub_key = script_anyone_can_spend.to_p2wsh();
        let dust_value = script_anyone_can_spend.dust_value();

        let mut kickoff_tx = Transaction {
            version: Version(2),
            lock_time: absolute::LockTime::from_consensus(0),
            input: vec![TxIn {
                previous_output: utxo,
                sequence: bitcoin::transaction::Sequence::ENABLE_RBF_NO_LOCKTIME,
                script_sig: ScriptBuf::default(),
                witness: Witness::new(),
            }],
            output: vec![
                TxOut {
                    value: bitcoin::Amount::from_sat(BRIDGE_AMOUNT_SATS) - dust_value - bitcoin::Amount::from_sat(MIN_RELAY_FEE),
                    script_pubkey: address.script_pubkey(),
                },
                TxOut {
                    value: dust_value,
                    script_pubkey: anyone_can_spend_script_pub_key,
                },
            ],
        };
        // println!("kickoff_tx: {:?}", kickoff_tx);
        let mut sighash_cache = SighashCache::new(kickoff_tx.borrow_mut());

        let (deposit_address, deposit_taproot_info) =
            User::generate_deposit_address(&self.signer.secp, &all_verifiers, hash, return_address); // TODO: Add operator into verifiers

        let prevouts = vec![TxOut {
            script_pubkey: deposit_address.script_pubkey(),
            value: bitcoin::Amount::from_sat(BRIDGE_AMOUNT_SATS),
        }];

        let mut signatures: Vec<Signature> = Vec::new();
        for verifier in self.mock_verifier_access.iter() {
            let sig_hash = sighash_cache
                .taproot_script_spend_signature_hash(
                    0_usize,
                    &bitcoin::sighash::Prevouts::All(&prevouts),
                    TapLeafHash::from_script(&script_n_of_n, LeafVersion::TapScript),
                    bitcoin::sighash::TapSighashType::Default,
                )
                .unwrap();
            let sig = verifier.signer.sign(sig_hash);
            // witness.push(sig.as_ref());
            signatures.push(sig);
        }

        let sig_hash = sighash_cache
            .taproot_script_spend_signature_hash(
                0_usize,
                &bitcoin::sighash::Prevouts::All(&prevouts),
                TapLeafHash::from_script(&script_n_of_n, LeafVersion::TapScript),
                bitcoin::sighash::TapSighashType::Default,
            )
            .unwrap();
        let sig = self.signer.sign(sig_hash);
        // witness.push(sig.as_ref());
        signatures.push(sig);

        let spend_control_block = deposit_taproot_info
            .control_block(&(script_n_of_n.clone(), LeafVersion::TapScript))
            .expect("Cannot create control block");

        let witness = sighash_cache.witness_mut(0).unwrap();
        // push signatures to witness
        witness.push(preimage);
        signatures.reverse();
        for sig in signatures.iter() {
            witness.push(sig.as_ref());
        }

        witness.push(script_n_of_n);
        witness.push(&spend_control_block.serialize());

        let kickoff_txid = kickoff_tx.txid();
        // println!("kickoff_txid: {:?}", kickoff_txid);
        let utxo_for_child = OutPoint {
            txid: kickoff_txid,
            vout: 1,
        };

        let child_tx = self.create_child_pays_for_parent(utxo_for_child);
        let rpc_kickoff_txid = self.rpc.send_raw_transaction(&kickoff_tx).unwrap();
        // println!("child_tx: {:?}", child_tx);
        let child_kickoff_txid = self.rpc.send_raw_transaction(&child_tx).unwrap();
    }

    pub fn create_child_pays_for_parent(&self, parent_outpoint: OutPoint) -> Transaction {
        let resource_tx_id = self
            .rpc
            .send_to_address(
                &self.signer.address,
                bitcoin::Amount::from_sat(BRIDGE_AMOUNT_SATS),
                None,
                None,
                None,
                None,
                None,
                None,
            )
            .unwrap();
        // let resource_tx_res = self.rpc.get_transaction(&resource_tx_id, None).unwrap();
        // println!("resource_tx result: {:?}", resource_tx_res);
        // let resource_tx = self.rpc.get_raw_transaction(&resource_tx_id, None).unwrap();
        // println!("resource_tx: {:?}", resource_tx);
        let mut all_verifiers = self.verifiers.to_vec();
        all_verifiers.push(self.signer.xonly_public_key.clone());

        let script_anyone_can_spend = Builder::new().push_opcode(OP_TRUE).into_script();
        let anyone_can_spend_script_pub_key = script_anyone_can_spend.to_p2wsh();
        let dust_value = script_anyone_can_spend.dust_value();
        // println!("dust_value: {:?}", dust_value);

        let mut child_tx = Transaction {
            version: Version(2),
            lock_time: absolute::LockTime::from_consensus(0),
            input: vec![
                TxIn {
                    previous_output: parent_outpoint,
                    sequence: bitcoin::transaction::Sequence::ENABLE_RBF_NO_LOCKTIME,
                    script_sig: ScriptBuf::default(),
                    witness: Witness::from(vec![vec![0x51]]),
                },
                TxIn {
                    previous_output: OutPoint {
                        txid: resource_tx_id,
                        vout: 0,
                    },
                    sequence: bitcoin::transaction::Sequence::ENABLE_RBF_NO_LOCKTIME,
                    script_sig: ScriptBuf::default(),
                    witness: Witness::new(),
                },
            ],
            output: vec![
                TxOut {
                    value: Amount::from_sat(BRIDGE_AMOUNT_SATS) + dust_value - Amount::from_sat(FEE),
                    script_pubkey: self.signer.address.script_pubkey(),
                },
            ],
        };

        let mut sighash_cache = SighashCache::new(child_tx.borrow_mut());

        let prevouts = vec![
            TxOut {
                script_pubkey: anyone_can_spend_script_pub_key,
                value: dust_value,
            },
            TxOut {
                script_pubkey: self.signer.address.script_pubkey(),
                value: Amount::from_sat(BRIDGE_AMOUNT_SATS),
            },
        ];

        let sig_hash = sighash_cache
            .taproot_key_spend_signature_hash(
                1,
                &bitcoin::sighash::Prevouts::All(&prevouts),
                bitcoin::sighash::TapSighashType::Default,
            )
            .unwrap();
        let sig = self.signer.sign_with_tweak(sig_hash, None);
        let witness = sighash_cache.witness_mut(1).unwrap();
        witness.push(sig.as_ref());

        child_tx
    }

    // this function is interal, where it checks if the current bitcoin height reaced to th end of the period,
    pub fn period1_end(&self) {
        self.move_bridge_funds();

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
    fn move_bridge_funds(&self) {}

    // This function is internal, it gives the appropriate response for a bitvm challenge
    pub fn challenge_received() {}
}
