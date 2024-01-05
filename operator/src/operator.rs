use std::collections::HashMap;

use crate::actor::{Actor, EVMAddress, EVMSignature};
use crate::merkle::MerkleTree;
use crate::user::User;
use crate::utils::{generate_n_of_n_script, UTXO};
use crate::verifier::Verifier;
use bitcoin::address::{self, NetworkChecked};
use bitcoin::script;
use bitcoin::taproot::TaprootBuilder;
use bitcoin::{absolute, hashes::Hash, secp256k1, secp256k1::schnorr, Address, Txid};
use bitcoincore_rpc::{Client, RpcApi};
use circuit_helpers::config::{NUM_VERIFIERS, REGTEST, USER_TAKES_AFTER};
use secp256k1::rand::rngs::OsRng;
use secp256k1::{All, Secp256k1, XOnlyPublicKey};
use sha2::{Digest, Sha256};

pub const NUM_ROUNDS: usize = 10;
type PreimageType = [u8; 32];
type HashType = [u8; 32];

pub fn check_deposit(
    secp: &Secp256k1<All>,
    rpc: &Client,
    utxo: UTXO,
    hash: [u8; 32],
    return_address: XOnlyPublicKey,
    verifiers_pks: Vec<XOnlyPublicKey>,
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

    assert!(tx.output[utxo.vout as usize].value == bitcoin::Amount::from_sat(100_000_000));
    let (address, _) = User::generate_deposit_address(secp, verifiers_pks, hash, return_address);
    assert!(tx.output[utxo.vout as usize].script_pubkey == address.script_pubkey());
    let time = tx_res.info.blocktime.unwrap() as u32;
    return absolute::Time::from_consensus(time).unwrap();
}

pub struct DepositPresigns {
    pub rollup_sign: EVMSignature,
    pub kickoff_sign: schnorr::Signature,
    pub kickoff_txid: Txid,
    pub move_bridge_sign: Vec<schnorr::Signature>,
    pub operator_take_sign: Vec<schnorr::Signature>,
}

pub struct Operator<'a> {
    pub rpc: &'a Client,
    pub signer: Actor,
    pub verifiers: Vec<XOnlyPublicKey>,
    pub verifier_evm_addresses: Vec<EVMAddress>,
    pub deposit_presigns: Vec<[DepositPresigns; NUM_VERIFIERS]>,
    pub deposit_merkle_tree: MerkleTree,
    pub withdrawals_merkle_tree: MerkleTree,
    pub withdrawals_payment_txids: Vec<Txid>,
    pub mock_verifier_access: Vec<Verifier<'a>>, // on production this will be removed rather we will call the verifier's API
    pub preimages: Vec<PreimageType>,
}

pub fn check_presigns(utxo: UTXO, timestamp: absolute::Time, deposit_presigns: &DepositPresigns) {}

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
        let deposit_presigns = vec![];

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
        &self,
        utxo: UTXO,
        hash: [u8; 32],
        return_address: XOnlyPublicKey,
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
            all_verifiers,
        );

        let presigns_from_all_verifiers = self
            .mock_verifier_access
            .iter()
            .map(|verifier| {
                // Note: In this part we will need to call the verifier's API to get the presigns
                let deposit_presigns =
                    verifier.new_deposit(utxo, hash, return_address.clone());
                check_presigns(utxo, timestamp, &deposit_presigns);
                deposit_presigns
            })
            .collect::<Vec<_>>();

        let kickoff_txid = Txid::all_zeros();

        let rollup_sign = self.signer.sign_deposit(
            kickoff_txid,
            timestamp.to_consensus_u32().to_be_bytes(),
            hash,
        );
        let mut all_rollup_signs = presigns_from_all_verifiers
            .iter()
            .map(|presigns| presigns.rollup_sign)
            .collect::<Vec<_>>();
        all_rollup_signs.push(rollup_sign);

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
    pub fn preimage_revealed(&mut self, preimage: PreimageType, txid: Txid) {
        self.preimages.push(preimage);
        // 1. Add the corresponding txid to DepositsMerkleTree
        self.deposit_merkle_tree.add(txid.to_byte_array());
        // this function is interal, where it checks if the preimage is revealed, then if it is revealed
        // it starts the kickoff tx.
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
