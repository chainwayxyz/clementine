use std::borrow::BorrowMut;

use bitcoin::taproot::LeafVersion;
use bitcoin::TapLeafHash;
use bitcoin::{
    absolute, hashes::Hash, opcodes::OP_TRUE, script::Builder, secp256k1, secp256k1::Secp256k1,
    sighash::SighashCache, taproot::TaprootBuilder, transaction::Version, Address, OutPoint,
    ScriptBuf, TapSighash, Transaction, TxIn, TxOut, Txid, Witness,
};
use bitcoincore_rpc::{Client, RpcApi};
use secp256k1::schnorr::Signature;
use secp256k1::{rand::rngs::OsRng, XOnlyPublicKey};

use crate::utils::generate_n_of_n_script;
use crate::{
    actor::Actor,
    operator::{check_deposit, DepositPresigns},
    transactions::INTERNAL_KEY,
    user::User,
    utils::generate_n_of_n_script_without_hash,
};

use circuit_helpers::config::{EVMAddress, BRIDGE_AMOUNT_SATS, MIN_RELAY_FEE, REGTEST, NUM_ROUNDS};

pub struct Verifier<'a> {
    pub rpc: &'a Client,
    pub secp: Secp256k1<secp256k1::All>,
    pub signer: Actor,
    pub operator: XOnlyPublicKey,
    pub verifiers: Vec<XOnlyPublicKey>,
}

impl<'a> Verifier<'a> {
    pub fn new(rng: &mut OsRng, rpc: &'a Client, operator_pk: XOnlyPublicKey) -> Self {
        let signer = Actor::new(rng);
        let secp: Secp256k1<secp256k1::All> = Secp256k1::new();
        let verifiers = Vec::new();
        Verifier {
            rpc,
            secp,
            signer,
            operator: operator_pk,
            verifiers,
        }
    }

    pub fn set_verifiers(&mut self, verifiers: Vec<XOnlyPublicKey>) {
        self.verifiers = verifiers;
    }

    // this is a public endpoint that only depositor can call
    pub fn new_deposit(
        &self,
        utxo: OutPoint,
        hash: [u8; 32],
        return_address: XOnlyPublicKey,
        evm_address: EVMAddress,
    ) -> DepositPresigns {
        let mut all_verifiers = self.verifiers.to_vec();
        all_verifiers.push(self.operator);
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
                    value: bitcoin::Amount::from_sat(BRIDGE_AMOUNT_SATS)
                        - dust_value
                        - bitcoin::Amount::from_sat(MIN_RELAY_FEE),
                    script_pubkey: address.script_pubkey(),
                },
                TxOut {
                    value: dust_value,
                    script_pubkey: anyone_can_spend_script_pub_key.clone(),
                },
            ],
        };

        let mut sighash_cache = SighashCache::new(kickoff_tx.borrow_mut());

        let (deposit_address, _) =
            User::generate_deposit_address(&self.signer.secp, &all_verifiers, hash, return_address);

        let prevouts = vec![TxOut {
            script_pubkey: deposit_address.script_pubkey(),
            value: bitcoin::Amount::from_sat(BRIDGE_AMOUNT_SATS),
        }];

        let sig_hash = sighash_cache
            .taproot_script_spend_signature_hash(
                0_usize,
                &bitcoin::sighash::Prevouts::All(&prevouts),
                TapLeafHash::from_script(&script_n_of_n, LeafVersion::TapScript),
                bitcoin::sighash::TapSighashType::Default,
            )
            .unwrap();
        let kickoff_sign = self.signer.sign(sig_hash);
        let kickoff_txid = kickoff_tx.txid();

        let mut prev_outpoint = OutPoint {
            txid: kickoff_txid,
            vout: 0,
        };
        let mut prev_amount = bitcoin::Amount::from_sat(BRIDGE_AMOUNT_SATS)
        - dust_value
        - bitcoin::Amount::from_sat(MIN_RELAY_FEE);

        let mut move_bridge_signs = Vec::new();
        let mut operator_take_signs = Vec::new();

        for _ in 0..NUM_ROUNDS {
            let mut move_tx = Transaction {
                version: Version(2),
                lock_time: absolute::LockTime::from_consensus(0),
                input: vec![TxIn {
                    previous_output: prev_outpoint,
                    sequence: bitcoin::transaction::Sequence::ENABLE_RBF_NO_LOCKTIME,
                    script_sig: ScriptBuf::default(),
                    witness: Witness::new(),
                }],
                output: vec![
                    TxOut {
                        value: prev_amount - dust_value - bitcoin::Amount::from_sat(MIN_RELAY_FEE),
                        script_pubkey: address.script_pubkey(),
                    },
                    TxOut {
                        value: dust_value,
                        script_pubkey: anyone_can_spend_script_pub_key.clone(),
                    },
                ],
            };

            let prevouts = vec![TxOut {
                script_pubkey: address.script_pubkey(),
                value: prev_amount,
            }];

            let mut sighash_cache = SighashCache::new(move_tx.borrow_mut());

            let sig_hash = sighash_cache
                .taproot_script_spend_signature_hash(
                    0_usize,
                    &bitcoin::sighash::Prevouts::All(&prevouts),
                    TapLeafHash::from_script(&script_n_of_n_without_hash, LeafVersion::TapScript),
                    bitcoin::sighash::TapSighashType::Default,
                )
                .unwrap();
            let move_fund_sign = self.signer.sign(sig_hash);

            move_bridge_signs.push(move_fund_sign);
            operator_take_signs.push(self.signer.sign(TapSighash::all_zeros()));

            prev_outpoint = OutPoint {
                txid: move_tx.txid(),
                vout: 0,
            };
            prev_amount = prev_amount - dust_value - bitcoin::Amount::from_sat(MIN_RELAY_FEE);
        }
        
        let rollup_sign = self.signer.sign_deposit(
            kickoff_txid,
            evm_address,
            hash,
            timestamp.to_consensus_u32().to_be_bytes(),
        );
        DepositPresigns {
            rollup_sign,
            kickoff_sign,
            move_bridge_signs,
            operator_take_signs,
        }
    }

    // This is a function to reduce gas costs when moving bridge funds
    pub fn do_me_a_favor() {}
}
