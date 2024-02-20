use std::borrow::BorrowMut;
use std::collections::{HashMap, HashSet};
use std::vec;

use crate::actor::Actor;
use crate::custom_merkle::CustomMerkleTree;
use crate::errors::BridgeError;
use crate::extended_rpc::ExtendedRpc;
use crate::giga_merkle::GigaMerkleTree;
use crate::merkle::MerkleTree;
use crate::script_builder::ScriptBuilder;
use crate::transaction_builder::TransactionBuilder;
use crate::utils::{calculate_amount, handle_anyone_can_spend_script, handle_taproot_witness};
use crate::verifier::Verifier;
use bitcoin::address::NetworkChecked;
use bitcoin::sighash::SighashCache;
use bitcoin::{secp256k1, secp256k1::schnorr, Address, Txid};
use bitcoin::{Amount, OutPoint, Transaction, TxOut};
use bitcoincore_rpc::{Client, RpcApi};
use circuit_helpers::config::{
    BRIDGE_AMOUNT_SATS, CONNECTOR_TREE_DEPTH, NUM_ROUNDS,
};
use circuit_helpers::constant::{
    CONFIRMATION_BLOCK_COUNT, DUST_VALUE, HASH_FUNCTION_32, MIN_RELAY_FEE, PERIOD_BLOCK_COUNT,
};
use secp256k1::rand::rngs::OsRng;
use secp256k1::rand::Rng;
use secp256k1::{All, Secp256k1, XOnlyPublicKey};
pub type PreimageType = [u8; 32];
pub type InscriptionTxs = (OutPoint, Txid);

pub fn check_deposit(
    _secp: &Secp256k1<All>,
    rpc: &Client,
    start_utxo: OutPoint,
    deposit_utxo: OutPoint,
    _hash: [u8; 32],
    _return_address: XOnlyPublicKey,
    _verifiers_pks: &Vec<XOnlyPublicKey>,
) {
    // 1. Check if tx is mined in bitcoin
    // 2. Check if the start_utxo matches input[0].previous_output
    // 2. Check if 0th output of the txid has 1 BTC
    // 3. Check if 0th output of the txid's scriptpubkey is N-of-N multisig and Hash of preimage or return_address after 200 blocks
    // 4. If all checks pass, return true
    // 5. Return the blockheight of the block in which the txid was mined
    let tx = rpc
        .get_raw_transaction(&deposit_utxo.txid, None)
        .unwrap_or_else(|e| {
            panic!(
                "Failed to get raw transaction: {}, txid: {}",
                e, deposit_utxo.txid
            )
        });
    println!("user deposit utxo: {:?}", deposit_utxo);
    assert!(tx.input[0].previous_output == start_utxo);
    println!("from user start utxo: {:?}", start_utxo);
    assert!(tx.output[deposit_utxo.vout as usize].value == Amount::from_sat(BRIDGE_AMOUNT_SATS));
    println!("amount: {:?}", tx.output[deposit_utxo.vout as usize].value);
    // let (address, _) = generate_deposit_address(secp, verifiers_pks, return_address, hash); // TODO: Update this function
    // assert!(tx.output[deposit_utxo.vout as usize].script_pubkey == address.script_pubkey());
}

pub fn create_connector_tree_preimages_and_hashes(
    depth: usize,
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
        for _ in 0..2u32.pow(i as u32) {
            let temp: PreimageType = rng.gen();
            preimages_current_level.push(temp);
            hashes_current_level.push(HASH_FUNCTION_32(temp));
        }
        connector_tree_preimages.push(preimages_current_level);
        connector_tree_hashes.push(hashes_current_level);
    }
    (connector_tree_preimages, connector_tree_hashes)
}

pub fn create_all_rounds_connector_preimages(
    depth: usize,
    num_rounds: usize,
    rng: &mut OsRng,
) -> (Vec<Vec<Vec<PreimageType>>>, Vec<Vec<Vec<[u8; 32]>>>) {
    let mut preimages = Vec::new();
    let mut hashes = Vec::new();
    for _ in 0..num_rounds {
        let (tree_preimages, tree_hashes) = create_connector_tree_preimages_and_hashes(depth, rng);
        preimages.push(tree_preimages);
        hashes.push(tree_hashes);
    }
    // let mut leaves = Vec::new();
    // for i in 0..num_rounds {
    //     for j in 1..u32::pow(2, depth as u32) + 1 {
    //         let indices = GigaMerkleTree::get_indices(depth, j);
    //         let mut hash_info = Vec::new();
    //         for (depth, index) in indices {
    //             hash_info.push(hashes[i][depth][index]);
    //         }
    //         leaves.push(hash_info);
    //     }
    // }
    // let giga_merkle_tree = GigaMerkleTree::new(num_rounds, depth, leaves);
    (preimages, hashes)
}

#[derive(Debug, Clone)]
pub struct DepositPresigns {
    pub move_sign: schnorr::Signature,
    pub operator_claim_sign: Vec<schnorr::Signature>,
}

#[derive(Debug, Clone)]
pub struct OperatorClaimSigs {
    pub operator_claim_sigs: Vec<Vec<schnorr::Signature>>,
}

#[derive(Debug, Clone)]
pub struct Operator<'a> {
    pub rpc: &'a ExtendedRpc,
    pub signer: Actor,
    pub script_builder: ScriptBuilder,
    pub transaction_builder: TransactionBuilder,
    pub pending_deposit: Option<OutPoint>,
    pub deposit_take_sigs: Vec<OperatorClaimSigs>,

    pub connector_tree_preimages: Vec<Vec<Vec<PreimageType>>>,
    pub connector_tree_hashes: Vec<Vec<Vec<[u8; 32]>>>,
    pub inscription_txs: Vec<InscriptionTxs>,
    pub start_blockheight: u64,

    pub verifiers_pks: Vec<XOnlyPublicKey>,
    pub deposit_presigns: HashMap<Txid, Vec<DepositPresigns>>,
    pub deposit_merkle_tree: MerkleTree,
    pub withdrawals_merkle_tree: MerkleTree,
    pub withdrawals_payment_txids: Vec<Txid>,
    pub mock_verifier_access: Vec<Verifier<'a>>, // on production this will be removed rather we will call the verifier's API
    pub preimages: Vec<PreimageType>,
    pub connector_tree_utxos: Vec<Vec<Vec<OutPoint>>>,
    // pub giga_merkle_tree: GigaMerkleTree,
    pub deposit_utxos: Vec<OutPoint>,
    pub move_utxos: Vec<OutPoint>,
    pub current_preimage_for_deposit_requests: PreimageType,
    pub deposit_index: u32,
}

impl<'a> Operator<'a> {
    pub fn new(rng: &mut OsRng, rpc: &'a ExtendedRpc, num_verifier: u32) -> Self {
        let signer = Actor::new(rng);
        let (connector_tree_preimages, connector_tree_hashes) =
            create_all_rounds_connector_preimages(CONNECTOR_TREE_DEPTH, NUM_ROUNDS, rng);
        let mut verifiers = Vec::new();
        let mut verifiers_pks = Vec::new();
        for _ in 0..num_verifier {
            let verifier = Verifier::new(rng, &rpc, signer.xonly_public_key.clone());
            verifiers_pks.push(verifier.signer.xonly_public_key.clone());
            verifiers.push(verifier);
        }
        let mut all_verifiers = verifiers_pks.to_vec();
        all_verifiers.push(signer.xonly_public_key.clone());
        let script_builder = ScriptBuilder::new(all_verifiers.clone());
        let transaction_builder = TransactionBuilder::new(all_verifiers.clone());

        Self {
            rpc,
            signer,
            script_builder,
            transaction_builder,
            pending_deposit: None,
            deposit_take_sigs: Vec::new(),
            connector_tree_preimages: connector_tree_preimages,
            connector_tree_hashes: connector_tree_hashes,
            inscription_txs: Vec::new(),
            start_blockheight: 0,

            verifiers_pks: verifiers_pks,
            deposit_presigns: HashMap::new(),
            deposit_merkle_tree: MerkleTree::initial(),
            withdrawals_merkle_tree: MerkleTree::initial(),
            withdrawals_payment_txids: Vec::new(),
            mock_verifier_access: verifiers,
            preimages: Vec::new(),
            connector_tree_utxos: Vec::new(),
            deposit_utxos: Vec::new(),
            move_utxos: Vec::new(),
            current_preimage_for_deposit_requests: rng.gen(),
            deposit_index: 0,
        }
    }

    pub fn change_preimage_for_deposit_requests(&mut self, rng: &mut OsRng) {
        self.current_preimage_for_deposit_requests = rng.gen();
    }

    pub fn add_deposit_utxo(&mut self, utxo: OutPoint) {
        self.deposit_utxos.push(utxo);
    }

    pub fn get_all_verifiers(&self) -> Vec<XOnlyPublicKey> {
        let mut all_verifiers = self.verifiers_pks.to_vec();
        all_verifiers.push(self.signer.xonly_public_key.clone());
        all_verifiers
    }

    pub fn set_connector_tree_utxos(&mut self, connector_tree_utxos: Vec<Vec<Vec<OutPoint>>>) {
        self.connector_tree_utxos = connector_tree_utxos;
    }

    /// this is a public endpoint that every depositor can call
    /// it will get signatures from every verifiers.
    /// 1. Check if there is any previous pending deposit
    /// 2. Check if the utxo is valid and finalized (6 blocks confirmation)
    /// 3. Check if the utxo is not already spent
    /// 4. Get signatures from all verifiers 1 move signature, ~150 operator takes signatures
    /// 5. Create a move transaction and return the output utxo, save the utxo as a pending deposit
    pub fn new_deposit(
        &mut self,
        start_utxo: OutPoint,
        return_address: XOnlyPublicKey,
    ) -> Result<OutPoint, BridgeError> {
        // 1. Check if there is any previous pending deposit
        println!("Checking pending deposit: {:?}", self.pending_deposit);
        if self.pending_deposit.is_some()
            && self
                .rpc
                .confirmation_blocks(&self.pending_deposit.unwrap().txid)
                < CONFIRMATION_BLOCK_COUNT
        {
            return Err(BridgeError::OperatorPendingDeposit);
        }
        println!("Checking current deposit");

        // 2. Check if the utxo is valid and finalized (6 blocks confirmation)
        if self.rpc.confirmation_blocks(&start_utxo.txid) < CONFIRMATION_BLOCK_COUNT {
            panic!("Deposit utxo is not finalized yet");
        }
        let (deposit_address, deposit_taproot_spend_info) = self
            .transaction_builder
            .generate_deposit_address(return_address);

        if !self.rpc.check_utxo_address_and_amount(
            &start_utxo,
            &deposit_address.script_pubkey(),
            BRIDGE_AMOUNT_SATS,
        ) {
            panic!("Deposit utxo address or amount is not valid");
        }

        // 3. Check if the utxo is not already spent
        if self.rpc.is_utxo_spent(&start_utxo) {
            panic!("Deposit utxo is already spent");
        }

        // 4. Get signatures from all verifiers 1 move signature, ~150 operator takes signatures
        let presigns_from_all_verifiers = self
            .mock_verifier_access
            .iter()
            .map(|verifier| {
                // Note: In this part we will need to call the verifier's API to get the presigns
                let deposit_presigns = verifier.new_deposit(start_utxo, return_address);
                println!("checked new deposit");
                // check_presigns(deposit_utxo, &deposit_presigns);
                println!("checked presigns");
                deposit_presigns
            })
            .collect::<Vec<_>>();
        println!("presigns_from_all_verifiers: done");

        // 5. Create a move transaction and return the output utxo, save the utxo as a pending deposit
        let mut move_tx = self.transaction_builder.create_move_tx(start_utxo);

        let prevouts = vec![TxOut {
            script_pubkey: deposit_address.script_pubkey(),
            value: Amount::from_sat(BRIDGE_AMOUNT_SATS),
        }];

        let script_n_of_n = self.script_builder.generate_n_of_n_script_without_hash();

        // let mut move_signatures: Vec<Signature> = presigns_from_all_verifiers
        //     .iter()
        //     .map(|presign| presign.move_sign)
        //     .collect();

        let mut move_signatures = self
            .mock_verifier_access
            .iter()
            .map(|verifier| {
                verifier.signer.sign_taproot_script_spend_tx(
                    &mut move_tx,
                    &prevouts,
                    &script_n_of_n,
                    0,
                )
            })
            .collect::<Vec<_>>();

        let sig =
            self.signer
                .sign_taproot_script_spend_tx(&mut move_tx, &prevouts, &script_n_of_n, 0);
        move_signatures.push(sig);
        move_signatures.reverse();

        let mut witness_elements: Vec<&[u8]> = Vec::new();
        for sig in move_signatures.iter() {
            witness_elements.push(sig.as_ref());
        }

        handle_taproot_witness(
            &mut move_tx,
            0,
            witness_elements,
            script_n_of_n,
            deposit_taproot_spend_info,
        );
        let rpc_move_txid = self.rpc.inner.send_raw_transaction(&move_tx).unwrap();
        let move_utxo = OutPoint {
            txid: rpc_move_txid,
            vout: 0,
        };
        self.pending_deposit = Some(move_utxo);
        let operator_claim_sigs = OperatorClaimSigs {
            operator_claim_sigs: presigns_from_all_verifiers
                .iter()
                .map(|presign| presign.operator_claim_sign.clone())
                .collect::<Vec<_>>(),
        };
        self.deposit_take_sigs.push(operator_claim_sigs);

        Ok(move_utxo)
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
            .send_to_address(&withdrawal_address, 100_000_000)
            .txid;
        println!(
            "operator paid to withdrawal address: {:?}, txid: {:?}",
            withdrawal_address, txid
        );
        self.withdrawals_payment_txids.push(txid);
    }

    // // this is called start utxo is spent and deposit utxo is created
    // pub fn deposit_happened(
    //     &mut self,
    //     start_utxo: OutPoint,
    //     hash: [u8; 32],
    //     deposit_utxo: OutPoint,
    //     return_address: XOnlyPublicKey, // TODO: SAVE THIS TO STRUCT
    // ) -> OutPoint {
    //     check_deposit(
    //         &self.signer.secp,
    //         &self.rpc.inner,
    //         start_utxo,
    //         deposit_utxo,
    //         hash,
    //         return_address.clone(),
    //         &self.get_all_verifiers(),
    //     );
    //     // 1. Add the corresponding txid to DepositsMerkleTree
    //     self.deposit_merkle_tree
    //         .add(deposit_utxo.txid.to_byte_array());
    //     let preimage = self.current_preimage_for_deposit_requests.clone();
    //     let hash = HASH_FUNCTION_32(preimage);
    //     let _all_verifiers = self.get_all_verifiers();
    //     let script_n_of_n = self.script_builder.generate_n_of_n_script(hash);

    //     let script_n_of_n_without_hash = self.script_builder.generate_n_of_n_script_without_hash();
    //     let (address, _) = TransactionBuilder::create_taproot_address(
    //         &self.signer.secp,
    //         vec![script_n_of_n_without_hash.clone()],
    //     );
    //     println!("address while taking deposit: {:?}", address);
    //     println!(
    //         "address.script_pubkey() while taking deposit: {:?}",
    //         address.script_pubkey()
    //     );

    //     let mut move_tx = TransactionBuilder::create_move_tx(
    //         vec![deposit_utxo],
    //         vec![(
    //             Amount::from_sat(BRIDGE_AMOUNT_SATS) - Amount::from_sat(MIN_RELAY_FEE),
    //             address.script_pubkey(),
    //         )],
    //     );
    //     println!("move_tx is from: {:?}", deposit_utxo);
    //     self.add_deposit_utxo(deposit_utxo);

    //     let (deposit_address, deposit_taproot_info) = self
    //         .transaction_builder
    //         .generate_deposit_address(return_address, hash);

    //     let prevouts = TransactionBuilder::create_tx_outs(vec![(
    //         Amount::from_sat(BRIDGE_AMOUNT_SATS),
    //         deposit_address.script_pubkey(),
    //     )]);

    // let mut move_signatures: Vec<Signature> = Vec::new();
    // let deposit_presigns_for_move = self
    //     .deposit_presigns
    //     .get(&deposit_utxo.txid)
    //     .expect("Deposit presigns not found");
    // for presign in deposit_presigns_for_move.iter() {
    //     move_signatures.push(presign.move_sign);
    // }

    // let sig =
    //     self.signer
    //         .sign_taproot_script_spend_tx(&mut move_tx, prevouts, &script_n_of_n, 0);
    // move_signatures.push(sig);
    // move_signatures.reverse();

    // let mut witness_elements: Vec<&[u8]> = Vec::new();
    // witness_elements.push(&preimage);
    // for sig in move_signatures.iter() {
    //     witness_elements.push(sig.as_ref());
    // }

    // handle_taproot_witness(
    //     &mut move_tx,
    //     0,
    //     witness_elements,
    //     script_n_of_n,
    //     deposit_taproot_info,
    // );

    //     // println!("witness size: {:?}", witness.size());
    //     // println!("kickoff_tx: {:?}", kickoff_tx);

    //     let rpc_move_txid = self.rpc.inner.send_raw_transaction(&move_tx).unwrap();
    //     println!("rpc_move_txid: {:?}", rpc_move_txid);
    //     let move_utxo = TransactionBuilder::create_utxo(rpc_move_txid, 0);
    //     self.move_utxos.push(move_utxo.clone());
    //     self.deposit_index += 1;
    //     move_utxo
    // }

    pub fn create_child_pays_for_parent(&self, parent_outpoint: OutPoint) -> Transaction {
        // TODO: Move to Transaction Builder
        let resource_utxo = self
            .rpc
            .send_to_address(&self.signer.address, BRIDGE_AMOUNT_SATS);
        let _resource_tx = self
            .rpc
            .get_raw_transaction(&resource_utxo.txid, None)
            .unwrap();

        let _all_verifiers = self.get_all_verifiers();

        let script_n_of_n_without_hash = self.script_builder.generate_n_of_n_script_without_hash();
        let (address, _) = TransactionBuilder::create_taproot_address(
            &self.signer.secp,
            vec![script_n_of_n_without_hash.clone()],
        )
        .unwrap();

        let (anyone_can_spend_script_pub_key, _) = handle_anyone_can_spend_script();

        let child_tx_ins = TransactionBuilder::create_tx_ins(vec![parent_outpoint, resource_utxo]);

        let child_tx_outs = TransactionBuilder::create_tx_outs(vec![
            (
                Amount::from_sat(BRIDGE_AMOUNT_SATS)
                    - Amount::from_sat(DUST_VALUE)
                    - Amount::from_sat(MIN_RELAY_FEE),
                address.script_pubkey(),
            ),
            (
                Amount::from_sat(DUST_VALUE),
                anyone_can_spend_script_pub_key.clone(),
            ),
        ]);

        let mut child_tx = TransactionBuilder::create_btc_tx(child_tx_ins, child_tx_outs);

        child_tx.input[0].witness.push([0x51]);

        let prevouts = TransactionBuilder::create_tx_outs(vec![
            (
                Amount::from_sat(DUST_VALUE),
                anyone_can_spend_script_pub_key,
            ),
            (
                Amount::from_sat(BRIDGE_AMOUNT_SATS),
                self.signer.address.script_pubkey(),
            ),
        ]);
        let sig = self
            .signer
            .sign_taproot_pubkey_spend_tx(&mut child_tx, prevouts, 1);
        let mut sighash_cache = SighashCache::new(child_tx.borrow_mut());
        let witness = sighash_cache.witness_mut(1).unwrap();
        witness.push(sig.as_ref());
        // println!("child_tx: {:?}", child_tx);
        // println!("child_txid: {:?}", child_tx.txid());
        child_tx
    }

    // this function is internal, where it checks if the current bitcoin height reaced to th end of the period,
    pub fn period1_end(&self) {
        // self.move_bridge_funds();

        // Check if all deposists are satisifed, all remaning bridge funds are moved to a new multisig
    }

    // this function is internal, where it checks if the current bitcoin height reaced to th end of the period,
    pub fn period2_end(&self) {
        // This is the time we generate proof.
    }

    // this function is internal, where it checks if the current bitcoin height reaced to th end of the period,
    pub fn period3_end(&self) {
        // This is the time send generated proof along with k-deep proof
        // and revealing bit-commitments for the next bitVM instance.
    }

    // This function is internal, it gives the appropriate response for a bitvm challenge
    pub fn challenge_received() {}

    pub fn spend_connector_tree_utxo(
        // TODO: To big, move some parts to Transaction Builder
        &self,
        period: usize,
        utxo: OutPoint,
        preimage: PreimageType,
        tree_depth: usize,
    ) {
        let hash = HASH_FUNCTION_32(preimage);
        let (_, tree_info) = TransactionBuilder::create_connector_tree_node_address(
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
        }
        let depth = u32::ilog2(
            ((base_tx.unwrap().output[utxo.vout as usize].value.to_sat() + MIN_RELAY_FEE)
                / (DUST_VALUE + MIN_RELAY_FEE)) as u32,
        );
        println!("depth: {:?}", depth);
        let level = tree_depth - depth as usize;
        //find the index of preimage in the connector_tree_preimages[level as usize]
        let index = self.connector_tree_preimages[period][level as usize]
            .iter()
            .position(|x| *x == preimage)
            .unwrap();
        let hashes = (
            self.connector_tree_hashes[period][(level + 1) as usize][2 * index],
            self.connector_tree_hashes[period][(level + 1) as usize][2 * index + 1],
        );

        let utxo_tx = self.rpc.get_raw_transaction(&utxo.txid, None).unwrap();
        // println!("utxo_tx: {:?}", utxo_tx);
        // println!("utxo_txid: {:?}", utxo_tx.txid());
        let timelock_script =
            ScriptBuilder::generate_timelock_script(self.signer.xonly_public_key, 1);

        let (first_address, _) = TransactionBuilder::create_connector_tree_node_address(
            &self.signer.secp,
            self.signer.xonly_public_key,
            hashes.0,
        );

        let (second_address, _) = TransactionBuilder::create_connector_tree_node_address(
            &self.signer.secp,
            self.signer.xonly_public_key,
            hashes.1,
        );

        let mut tx = TransactionBuilder::create_connector_tree_tx(
            &utxo,
            depth as usize - 1,
            first_address,
            second_address,
        );
        // println!("created spend tx: {:?}", tx);

        let sig = self.signer.sign_taproot_script_spend_tx(
            &mut tx,
            &vec![utxo_tx.output[utxo.vout as usize].clone()],
            &timelock_script,
            0,
        );
        // let spend_control_block = tree_info
        //     .control_block(&(timelock_script.clone(), LeafVersion::TapScript))
        //     .expect("Cannot create control block");
        // let mut sighash_cache = SighashCache::new(tx.borrow_mut());
        // let witness = sighash_cache.witness_mut(0).unwrap();
        // witness.push(sig.as_ref());
        // witness.push(timelock_script);
        // witness.push(&spend_control_block.serialize());

        let mut witness_elements: Vec<&[u8]> = Vec::new();
        witness_elements.push(sig.as_ref());

        handle_taproot_witness(&mut tx, 0, witness_elements, timelock_script, tree_info);

        // println!("bytes_connector_tree_tx length: {:?}", bytes_connector_tree_tx.len());
        // let hex_utxo_tx = hex::encode(bytes_utxo_tx.clone());
        let spending_txid = match self.rpc.send_raw_transaction(&tx) {
            Ok(txid) => Some(txid),
            Err(e) => {
                eprintln!("Failed to send raw transaction: {}", e);
                None
            }
        };
        println!("operator_spending_txid: {:?}", spending_txid);
    }

    pub fn reveal_connector_tree_preimages(
        &self,
        period: usize,
        number_of_funds_claim: u32,
    ) -> HashSet<PreimageType> {
        let indices = GigaMerkleTree::get_indices(CONNECTOR_TREE_DEPTH, number_of_funds_claim);
        println!("indices: {:?}", indices);
        let mut preimages: HashSet<PreimageType> = HashSet::new();
        for (depth, index) in indices {
            preimages.insert(self.connector_tree_preimages[period][depth as usize][index as usize]);
        }
        preimages
    }

    fn get_current_period(&self) -> usize {
        return 0;
    }

    fn get_num_withdrawals_for_period(&self, _period: usize) -> u32 {
        self.withdrawals_merkle_tree.index // TODO: This is not corret, we should have a cutoff
    }

    /// This is called internally when every withdrawal for the current period is satisfied
    /// Double checks if all withdrawals are satisfied
    /// Checks that we are in the correct period, and withdrawal period has end for the given period
    /// inscribe the connector tree preimages to the blockchain
    pub fn inscribe_connector_tree_preimages(&mut self) -> Result<(), BridgeError> {
        let period = self.get_current_period();
        if self.inscription_txs.len() != period {
            return Err(BridgeError::InvalidPeriod);
        }

        let number_of_funds_claim = self.get_num_withdrawals_for_period(period);

        let indices = CustomMerkleTree::get_indices(CONNECTOR_TREE_DEPTH, number_of_funds_claim);
        println!("indices: {:?}", indices);

        let preimages_to_be_revealed = indices
            .iter()
            .map(|(depth, index)| {
                self.connector_tree_preimages[period][*depth as usize][*index as usize]
            })
            .collect::<Vec<_>>();

        let (commit_address, commit_tree_info, inscribe_preimage_script) =
            self.transaction_builder.create_inscription_commit_address(
                &self.signer.xonly_public_key,
                &preimages_to_be_revealed,
            );

        let commit_utxo = self.rpc.send_to_address(&commit_address, DUST_VALUE * 2);
        let mut reveal_tx = self.transaction_builder.create_inscription_reveal_tx(
            commit_utxo,
            &commit_tree_info,
            &preimages_to_be_revealed,
        );

        let prevouts = vec![TxOut {
            script_pubkey: commit_address.script_pubkey(),
            value: Amount::from_sat(DUST_VALUE * 2),
        }];

        let sig = self.signer.sign_taproot_script_spend_tx(
            &mut reveal_tx,
            &prevouts,
            &inscribe_preimage_script,
            0,
        );

        handle_taproot_witness(
            &mut reveal_tx,
            0,
            vec![sig.as_ref()],
            inscribe_preimage_script,
            commit_tree_info,
        );

        let reveal_txid = self.rpc.send_raw_transaction(&reveal_tx).unwrap();

        self.inscription_txs.push((commit_utxo, reveal_txid));

        // let inscription_source_utxo = self
        //     .rpc
        //     .send_to_address(&self.signer.address, DUST_VALUE * 3);
        // let (commit_tx, reveal_tx) = TransactionBuilder::create_inscription_transactions(
        //     &self.signer,
        //     inscription_source_utxo,
        //     preimages,
        // );
        // let commit_txid = self
        //     .rpc
        //     .send_raw_transaction(&serialize(&commit_tx))
        //     .unwrap();
        // println!("commit_txid: {:?}", commit_txid);
        // let reveal_txid = self
        //     .rpc
        //     .send_raw_transaction(&serialize(&reveal_tx))
        //     .unwrap();
        // println!("reveal_txid: {:?}", reveal_txid);
        return Ok(());
    }

    // pub fn claim_deposit(&self, period: usize, index: usize) {
    //     let preimage = self.connector_tree_preimages[period]
    //         [self.connector_tree_preimages[period].len() - 1][index];
    //     let hash = HASH_FUNCTION_32(preimage);
    //     let (address, tree_info_1) = TransactionBuilder::create_connector_tree_node_address(
    //         &self.signer.secp,
    //         self.signer.xonly_public_key,
    //         hash,
    //     );
    //     // println!("deposit_utxos: {:?}", self.deposit_utxos);
    //     let deposit_utxo = self.deposit_utxos[index as usize];
    //     let fund_utxo = self.move_utxos[index as usize];
    //     let connector_utxo = self.connector_tree_utxos[period]
    //         [self.connector_tree_utxos[period].len() - 1][index as usize];

    //     let mut tx_ins = TransactionBuilder::create_tx_ins(vec![fund_utxo]);
    //     tx_ins.extend(TransactionBuilder::create_tx_ins_with_sequence(vec![
    //         connector_utxo,
    //     ]));

    //     let tx_outs = TransactionBuilder::create_tx_outs(vec![(
    //         Amount::from_sat(BRIDGE_AMOUNT_SATS) + Amount::from_sat(DUST_VALUE)
    //             - Amount::from_sat(MIN_RELAY_FEE) * 2,
    //         self.signer.address.script_pubkey(),
    //     )]);

    //     let mut claim_tx = TransactionBuilder::create_btc_tx(tx_ins, tx_outs);

    //     println!("operator ready to send claim_tx: {:?}", claim_tx);

    //     let _all_verifiers = self.get_all_verifiers();

    //     let script_n_of_n_without_hash = self.script_builder.generate_n_of_n_script_without_hash();
    //     let (multisig_address, tree_info_0) = TransactionBuilder::create_taproot_address(
    //         &self.signer.secp,
    //         vec![script_n_of_n_without_hash.clone()],
    //     );

    //     let timelock_script = ScriptBuilder::generate_timelock_script(
    //         self.signer.xonly_public_key,
    //         CONNECTOR_TREE_OPERATOR_TAKES_AFTER as u32,
    //     );

    //     let prevouts = TransactionBuilder::create_tx_outs(vec![
    //         (
    //             Amount::from_sat(BRIDGE_AMOUNT_SATS) - Amount::from_sat(MIN_RELAY_FEE),
    //             multisig_address.script_pubkey(),
    //         ),
    //         (Amount::from_sat(DUST_VALUE), address.script_pubkey()),
    //     ]);
    //     // println!("multisig address: {:?}", multisig_address);
    //     // println!(
    //     //     "multisig script pubkey: {:?}",
    //     //     multisig_address.script_pubkey()
    //     // );

    //     // let spend_control_block0 = tree_info_0
    //     //     .control_block(&(script_n_of_n_without_hash.clone(), LeafVersion::TapScript))
    //     //     .expect("Cannot create control block");

    //     // let spend_control_block1 = tree_info_1
    //     //     .control_block(&(timelock_script.clone(), LeafVersion::TapScript))
    //     //     .expect("Cannot create control block");

    //     let sig0 = self.signer.sign_taproot_script_spend_tx(
    //         &mut claim_tx,
    //         prevouts.clone(),
    //         &script_n_of_n_without_hash,
    //         0,
    //     );
    //     // let mut claim_sigs = self.mock_verifier_access.iter().map(|verifier|
    //     //     verifier.signer.sign_taproot_script_spend_tx(&mut claim_tx, prevouts.clone(), &script_n_of_n_without_hash, 0)
    //     // ).collect::<Vec<_>>();

    //     // println!("claim_sigs: {:?}", claim_sigs);

    //     let sig_1 =
    //         self.signer
    //             .sign_taproot_script_spend_tx(&mut claim_tx, prevouts, &timelock_script, 1);

    //     // let mut sighash_cache = SighashCache::new(claim_tx.borrow_mut());
    //     let sig_vec = self.deposit_presigns.get(&deposit_utxo.txid).unwrap();

    //     // let witness0 = sighash_cache.witness_mut(0).unwrap();
    //     let mut claim_sigs = sig_vec
    //         .iter()
    //         .map(|presig| presig.operator_claim_sign)
    //         .collect::<Vec<_>>();
    //     // println!("claim_sigs: {:?}", claim_sigs);
    //     claim_sigs.push(sig0);
    //     claim_sigs.reverse();
    //     // for sig in claim_sigs.iter() {
    //     //     witness0.push(sig.as_ref());
    //     // }
    //     // witness0.push(script_n_of_n_without_hash.clone());
    //     // witness0.push(&spend_control_block0.serialize());

    //     let mut witness_elements_0: Vec<&[u8]> = Vec::new();
    //     for sig in claim_sigs.iter() {
    //         witness_elements_0.push(sig.as_ref());
    //     }
    //     handle_taproot_witness(
    //         &mut claim_tx,
    //         0,
    //         witness_elements_0,
    //         script_n_of_n_without_hash,
    //         tree_info_0,
    //     );

    //     let mut witness_elements_1: Vec<&[u8]> = Vec::new();
    //     witness_elements_1.push(sig_1.as_ref());
    //     handle_taproot_witness(
    //         &mut claim_tx,
    //         1,
    //         witness_elements_1,
    //         timelock_script,
    //         tree_info_1,
    //     );

    //     // println!("deposit_utxo.txid: {:?}", deposit_utxo.txid);
    //     // let witness1 = sighash_cache.witness_mut(1).unwrap();
    //     // witness1.push(sig_1.as_ref());
    //     // witness1.push(timelock_script);
    //     // witness1.push(&spend_control_block1.serialize());

    //     // println!("claim_tx: {:?}", claim_tx);
    //     let tx_bytes = serialize(&claim_tx);
    //     let txid = match self.rpc.send_raw_transaction(&tx_bytes) {
    //         Ok(txid) => Some(txid),
    //         Err(e) => {
    //             eprintln!("Failed to send raw transaction: {}", e);
    //             None
    //         }
    //     };
    //     if txid.is_none() {
    //         println!("claim failed");
    //         return;
    //     } else {
    //         println!("claim successful, txid: {:?}", txid);
    //     }
    // }

    /// This starts the whole setup
    /// 1. get the current blockheight
    pub fn initial_setup(&mut self) -> Result<OutPoint, BridgeError> {
        let cur_blockheight = self.rpc.get_block_height();
        if self.start_blockheight == 0 {
            self.start_blockheight = cur_blockheight;
        }

        let single_tree_amount = calculate_amount(
            CONNECTOR_TREE_DEPTH,
            Amount::from_sat(DUST_VALUE),
            Amount::from_sat(MIN_RELAY_FEE),
        );
        let total_amount =
            Amount::from_sat((MIN_RELAY_FEE + single_tree_amount.to_sat()) * NUM_ROUNDS as u64);
        let (connector_tree_source_address, _) =
            self.transaction_builder.create_connector_tree_root_address(
                self.signer.xonly_public_key,
                self.start_blockheight + PERIOD_BLOCK_COUNT as u64,
            );

        let first_source_utxo = self
            .rpc
            .send_to_address(&connector_tree_source_address, total_amount.to_sat());

        let mut cur_connector_source_utxo = first_source_utxo.clone();
        let mut cur_amount = total_amount;

        let mut claim_proof_merkle_roots: Vec<[u8; 32]> = Vec::new();
        let mut root_utxos: Vec<OutPoint> = Vec::new();
        let mut utxo_trees: Vec<Vec<Vec<OutPoint>>> = Vec::new();

        for i in 0..NUM_ROUNDS {
            claim_proof_merkle_roots.push(CustomMerkleTree::calculate_claim_proof_root(CONNECTOR_TREE_DEPTH, &self.connector_tree_hashes[i]));
            let (next_connector_source_address, _) =
                self.transaction_builder.create_connector_tree_root_address(
                    self.signer.xonly_public_key,
                    self.start_blockheight + ((i + 2) * PERIOD_BLOCK_COUNT as usize) as u64,
                );
            let (connector_bt_root_address, _) =
                TransactionBuilder::create_connector_tree_node_address(
                    &self.signer.secp,
                    self.signer.xonly_public_key,
                    self.connector_tree_hashes[i][0][0],
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

            let utxo_tree = self.transaction_builder.create_connector_binary_tree(
                i,
                self.signer.xonly_public_key,
                cur_connector_bt_root_utxo.clone(),
                CONNECTOR_TREE_DEPTH,
                self.connector_tree_hashes[i].clone(),
            );
            root_utxos.push(cur_connector_bt_root_utxo);
            utxo_trees.push(utxo_tree);
            cur_amount = cur_amount - single_tree_amount - Amount::from_sat(MIN_RELAY_FEE);
        }
        self.set_connector_tree_utxos(utxo_trees.clone());
        println!("asd : {:?}", claim_proof_merkle_roots);
        Ok(first_source_utxo)
    }
}

#[cfg(test)]
mod tests {
    use crate::user::User;

    use super::*;
    use circuit_helpers::config::{NUM_USERS, NUM_VERIFIERS};
    use secp256k1::rand::rngs::OsRng;

    // #[test]
    // fn test_giga_merkle_tree_works() {
    //     let mut rng = OsRng;
    //     let giga_merkle_tree = create_giga_merkle_tree(2, 4, &mut rng);
    //     println!("giga_merkle_tree: {:?}", giga_merkle_tree);
    // }

    #[test]
    fn test_concurrent_deposit() {
        let rpc = ExtendedRpc::new();

        let mut operator = Operator::new(&mut OsRng, &rpc, NUM_VERIFIERS as u32);
        let mut users = Vec::new();

        let verifiers_pks = operator.get_all_verifiers();
        for verifier in &mut operator.mock_verifier_access {
            verifier.set_verifiers(verifiers_pks.clone());
        }
        println!("verifiers_pks.len: {:?}", verifiers_pks.len());

        for _ in 0..NUM_USERS {
            users.push(User::new(&rpc, verifiers_pks.clone()));
        }

        let user1 = User::new(&rpc, verifiers_pks.clone());
        let user2 = User::new(&rpc, verifiers_pks.clone());

        let (deposit1_utxo, deposit1_pk) = user1.deposit_tx();
        rpc.mine_blocks(1);
        let (deposit2_utxo, deposit2_pk) = user2.deposit_tx();
        rpc.mine_blocks(5);

        operator.new_deposit(deposit1_utxo, deposit1_pk).unwrap();
        rpc.mine_blocks(1);
        assert!(matches!(
            operator.new_deposit(deposit2_utxo, deposit2_pk),
            Err(BridgeError::OperatorPendingDeposit)
        ));
    }
}
