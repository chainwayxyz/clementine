use std::borrow::BorrowMut;
use std::collections::HashSet;
use std::vec;

use crate::actor::Actor;
use crate::config::{BRIDGE_AMOUNT_SATS, CONNECTOR_TREE_DEPTH, NUM_ROUNDS};
use crate::constant::{HashType, PreimageType, DUST_VALUE, MIN_RELAY_FEE, PERIOD_BLOCK_COUNT};
use crate::errors::BridgeError;
use crate::extended_rpc::ExtendedRpc;

use crate::mock_db::OperatorMockDB;
use crate::script_builder::ScriptBuilder;
use crate::shared::{check_deposit_utxo, create_all_connector_trees};
use crate::transaction_builder::TransactionBuilder;
use crate::utils::{calculate_amount, get_claim_reveal_indices, handle_taproot_witness};
use crate::verifier::Verifier;
use bitcoin::address::NetworkChecked;
use bitcoin::hashes::Hash;
use bitcoin::sighash::SighashCache;

use bitcoin::taproot::LeafVersion;
use bitcoin::{secp256k1, secp256k1::schnorr, Address};
use bitcoin::{Amount, OutPoint, TapLeafHash, Transaction, TxOut};
use circuit_helpers::constant::EVMAddress;
use circuit_helpers::sha256_hash;
use secp256k1::rand::rngs::OsRng;
use secp256k1::rand::Rng;
use secp256k1::{Message, XOnlyPublicKey};

pub fn create_connector_tree_preimages_and_hashes(
    depth: usize,
    rng: &mut OsRng,
) -> (Vec<Vec<PreimageType>>, Vec<Vec<HashType>>) {
    let mut connector_tree_preimages: Vec<Vec<PreimageType>> = Vec::new();
    let mut connector_tree_hashes: Vec<Vec<HashType>> = Vec::new();
    let root_preimage: PreimageType = rng.gen();
    connector_tree_preimages.push(vec![root_preimage]);
    connector_tree_hashes.push(vec![sha256_hash!(root_preimage)]);
    for i in 1..(depth + 1) {
        let mut preimages_current_level: Vec<PreimageType> = Vec::new();
        let mut hashes_current_level: Vec<PreimageType> = Vec::new();
        for _ in 0..2u32.pow(i as u32) {
            let temp: PreimageType = rng.gen();
            preimages_current_level.push(temp);
            hashes_current_level.push(sha256_hash!(temp));
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
) -> (Vec<Vec<Vec<PreimageType>>>, Vec<Vec<Vec<HashType>>>) {
    let mut preimages = Vec::new();
    let mut hashes = Vec::new();
    for _ in 0..num_rounds {
        let (tree_preimages, tree_hashes) = create_connector_tree_preimages_and_hashes(depth, rng);
        preimages.push(tree_preimages);
        hashes.push(tree_hashes);
    }
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

#[derive(Debug)]
pub struct Operator<'a> {
    pub rpc: &'a ExtendedRpc,
    pub signer: Actor,
    pub script_builder: ScriptBuilder,
    pub transaction_builder: TransactionBuilder,
    pub start_blockheight: u64,
    pub verifiers_pks: Vec<XOnlyPublicKey>,
    pub mock_verifier_access: Vec<Verifier<'a>>, // on production this will be removed rather we will call the verifier's API

    pub operator_mock_db: OperatorMockDB,
}

impl<'a> Operator<'a> {
    pub fn new(rng: &mut OsRng, rpc: &'a ExtendedRpc, num_verifier: u32) -> Self {
        let signer = Actor::new(rng);
        let (connector_tree_preimages, connector_tree_hashes) =
            create_all_rounds_connector_preimages(CONNECTOR_TREE_DEPTH, NUM_ROUNDS, rng);
        let mut verifiers = Vec::new();
        let mut verifiers_pks = Vec::new();
        for _ in 0..num_verifier {
            let verifier = Verifier::new(rng, rpc, signer.xonly_public_key);
            verifiers_pks.push(verifier.signer.xonly_public_key);
            verifiers.push(verifier);
        }
        let mut all_verifiers = verifiers_pks.to_vec();
        all_verifiers.push(signer.xonly_public_key);
        let script_builder = ScriptBuilder::new(all_verifiers.clone());
        let transaction_builder = TransactionBuilder::new(all_verifiers.clone());
        let mut operator_mock_db = OperatorMockDB::new();
        operator_mock_db.connector_tree_preimages = connector_tree_preimages.clone();
        operator_mock_db.connector_tree_hashes = connector_tree_hashes.clone();

        Self {
            rpc,
            signer,
            script_builder,
            transaction_builder,
            start_blockheight: 0,
            mock_verifier_access: verifiers,
            verifiers_pks,

            operator_mock_db,
        }
    }

    pub fn get_all_verifiers(&self) -> Vec<XOnlyPublicKey> {
        let mut all_verifiers = self.verifiers_pks.to_vec();
        all_verifiers.push(self.signer.xonly_public_key);
        all_verifiers
    }

    // pub fn set_connector_tree_utxos(&mut self, connector_tree_utxos: Vec<ConnectorTreeUTXOs>) {
    //     self.connector_tree_utxos = connector_tree_utxos;
    // }

    /// this is a public endpoint that every depositor can call
    /// it will get signatures from all verifiers.
    /// 1. Check if there is any previous pending deposit
    /// 2. Check if the utxo is valid and finalized (6 blocks confirmation)
    /// 3. Check if the utxo is not already spent
    /// 4. Get signatures from all verifiers 1 move signature, ~150 operator takes signatures
    /// 5. Create a move transaction and return the output utxo, save the utxo as a pending deposit
    pub fn new_deposit(
        &mut self,
        start_utxo: OutPoint,
        return_address: &XOnlyPublicKey,
        evm_address: &EVMAddress,
        user_sig: schnorr::Signature,
    ) -> Result<OutPoint, BridgeError> {
        // 1. Check if there is any previous pending deposit

        println!("Checking current deposit");

        // 2. Check if the utxo is valid and finalized (6 blocks confirmation)
        // 3. Check if the utxo is not already spent
        // 4. Get signatures from all verifiers 1 move signature, ~150 operator takes signatures

        let (deposit_address, deposit_taproot_spend_info) = check_deposit_utxo(
            self.rpc,
            &self.transaction_builder,
            &start_utxo,
            return_address,
            BRIDGE_AMOUNT_SATS,
        )?;

        let deposit_index = self.operator_mock_db.deposit_take_sigs.len() as u32;
        println!("deposit_index: {:?}", deposit_index);

        let presigns_from_all_verifiers: Result<Vec<_>, BridgeError> = self
            .mock_verifier_access
            .iter()
            .enumerate()
            .map(|(i, verifier)| {
                println!("Verifier number {:?} is checking new deposit:", i);
                // Attempt to get the deposit presigns. If an error occurs, it will be propagated out
                // of the map, causing the collect call to return a Result::Err, effectively stopping
                // the iteration and returning the error from your_function_name.
                let deposit_presigns = verifier
                    .new_deposit(start_utxo, return_address, deposit_index, evm_address)
                    .map_err(|e| {
                        // Log the error or convert it to BridgeError if necessary
                        eprintln!("Error getting deposit presigns: {:?}", e);
                        e
                    })?;
                println!("deposit presigns: {:?}", deposit_presigns);
                println!("Verifier checked new deposit");
                Ok(deposit_presigns)
            })
            .collect(); // This tries to collect into a Result<Vec<DepositPresigns>, BridgeError>

        // Handle the result of the collect operation
        let presigns_from_all_verifiers = presigns_from_all_verifiers?;
        println!("presigns_from_all_verifiers: done");

        // 5. Create a move transaction and return the output utxo, save the utxo as a pending deposit
        let mut move_tx = self
            .transaction_builder
            .create_move_tx(start_utxo, evm_address)?;

        let move_tx_prevouts = TransactionBuilder::create_move_tx_prevouts(&deposit_address);

        let script_n_of_n_with_user_pk = self
            .script_builder
            .generate_script_n_of_n_with_user_pk(return_address);

        let script_n_of_n = self.script_builder.generate_script_n_of_n();

        let mut move_signatures = presigns_from_all_verifiers
            .iter()
            .map(|presign| presign.move_sign)
            .collect::<Vec<_>>();

        let sig = self.signer.sign_taproot_script_spend_tx(
            &mut move_tx,
            &move_tx_prevouts,
            &script_n_of_n_with_user_pk,
            0,
        )?;
        move_signatures.push(sig);
        move_signatures.push(user_sig);
        move_signatures.reverse();

        let mut witness_elements: Vec<&[u8]> = Vec::new();
        for sig in move_signatures.iter() {
            witness_elements.push(sig.as_ref());
        }

        handle_taproot_witness(
            &mut move_tx,
            0,
            &witness_elements,
            &script_n_of_n_with_user_pk,
            &deposit_taproot_spend_info,
        )?;
        // println!("move_tx: {:?}", move_tx);
        let rpc_move_txid = self.rpc.send_raw_transaction(&move_tx)?;
        let move_utxo = OutPoint {
            txid: rpc_move_txid,
            vout: 0,
        };
        let operator_claim_sigs = OperatorClaimSigs {
            operator_claim_sigs: presigns_from_all_verifiers
                .iter()
                .map(|presign| presign.operator_claim_sign.clone())
                .collect::<Vec<_>>(),
        };
        self.operator_mock_db
            .deposit_take_sigs
            .push(operator_claim_sigs);

        // let anyone_can_spend_txout: TxOut = ScriptBuilder::anyone_can_spend_txout();
        // let timelock_script = ScriptBuilder::generate_timelock_script(
        //     &self.signer.xonly_public_key,
        //     CONNECTOR_TREE_OPERATOR_TAKES_AFTER as u32,
        // );

        for i in 0..NUM_ROUNDS {
            let connector_utxo = self.operator_mock_db.connector_tree_utxos[i]
                [CONNECTOR_TREE_DEPTH][deposit_index as usize];
            let operator_claim_tx = TransactionBuilder::create_operator_claim_tx(
                move_utxo,
                connector_utxo,
                &self.signer.address,
            );

            let (connector_tree_leaf_address, _) =
                TransactionBuilder::create_connector_tree_node_address(
                    &self.signer.secp,
                    &self.signer.xonly_public_key,
                    self.operator_mock_db.connector_tree_hashes[i][CONNECTOR_TREE_DEPTH]
                        [deposit_index as usize],
                )?;

            let op_claim_tx_prevouts = self
                .transaction_builder
                .create_operator_claim_tx_prevouts(&connector_tree_leaf_address)?;

            let op_claim_sigs_for_period_i = presigns_from_all_verifiers
                .iter()
                .map(|presign| {
                    println!(
                        "presign.operator_claim_sign[{:?}]: {:?}",
                        i, presign.operator_claim_sign[i]
                    );
                    presign.operator_claim_sign[i]
                })
                .collect::<Vec<_>>();

            println!("Operator checking presigns for period {:?}: ", i);
            println!("operator_claim_tx: {:?}", operator_claim_tx);
            let mut sighash_cache = SighashCache::new(operator_claim_tx.clone());

            let sig_hash = sighash_cache.taproot_script_spend_signature_hash(
                0,
                &bitcoin::sighash::Prevouts::All(&op_claim_tx_prevouts),
                TapLeafHash::from_script(&script_n_of_n, LeafVersion::TapScript),
                bitcoin::sighash::TapSighashType::Default,
            )?;
            for (idx, sig) in op_claim_sigs_for_period_i.iter().enumerate() {
                println!("verifying presigns for index {:?}: ", idx);
                println!("sig: {:?}", sig);
                self.signer.secp.verify_schnorr(
                    sig,
                    &Message::from_digest_slice(sig_hash.as_byte_array()).expect("should be hash"),
                    &self.verifiers_pks[idx],
                )?;
            }

            // let claim_sig_for_bridge = self.signer.sign_taproot_script_spend_tx(
            //     &mut operator_claim_tx,
            //     &prevouts,
            //     &script_n_of_n,
            //     0,
            // );
            // let claim_sig_for_connector = self.signer.sign_taproot_script_spend_tx(
            //     &mut operator_claim_tx,
            //     &prevouts,
            //     &timelock_script,
            //     1,
            // );

            // let mut witness_elements_0: Vec<&[u8]> = Vec::new();

            // for sig in op_claim_sigs_for_period_i.iter() {
            //     witness_elements_0.push(sig.as_ref());
            // }

            // witness_elements_0.push(claim_sig_for_bridge.as_ref());

            // let mut witness_elements_1: Vec<&[u8]> = Vec::new();
            // witness_elements_1.push(claim_sig_for_connector.as_ref());

            // handle_taproot_witness(
            //     &mut operator_claim_tx,
            //     0,
            //     &witness_elements_0,
            //     &script_n_of_n,
            //     &bridge_spend_info,
            // );

            // handle_taproot_witness(
            //     &mut operator_claim_tx,
            //     1,
            //     &witness_elements_1,
            //     &timelock_script,
            //     &connector_tree_leaf_spend_info,
            // );

            // print!("{:?}", verify_presigns(&operator_claim_tx, &prevouts));
        }

        Ok(move_utxo)
    }

    // this is called when a Withdrawal event emitted on rollup
    pub fn new_withdrawal(
        &mut self,
        withdrawal_address: Address<NetworkChecked>,
    ) -> Result<(), BridgeError> {
        let taproot_script = withdrawal_address.script_pubkey();
        // we are assuming that the withdrawal_address is a taproot address so we get the last 32 bytes
        let hash: [u8; 34] = taproot_script.as_bytes().try_into()?;
        let hash: [u8; 32] = hash[2..].try_into()?;

        // 1. Add the address to WithdrawalsMerkleTree
        self.operator_mock_db.withdrawals_merkle_tree.add(hash);

        // self.withdrawals_merkle_tree.add(withdrawal_address.to);

        // 2. Pay to the address and save the txid
        let txid = self
            .rpc
            .send_to_address(&withdrawal_address, 100_000_000)?
            .txid;
        println!(
            "operator paid to withdrawal address: {:?}, txid: {:?}",
            withdrawal_address, txid
        );
        self.operator_mock_db.withdrawals_payment_txids.push(txid);
        Ok(())
    }

    pub fn create_child_pays_for_parent(
        &self,
        parent_outpoint: OutPoint,
    ) -> Result<Transaction, BridgeError> {
        // TODO: Move to Transaction Builder
        let resource_utxo = self
            .rpc
            .send_to_address(&self.signer.address, BRIDGE_AMOUNT_SATS)?;
        let _resource_tx = self.rpc.get_raw_transaction(&resource_utxo.txid, None)?;

        let _all_verifiers = self.get_all_verifiers();

        let script_n_of_n_without_hash = self.script_builder.generate_script_n_of_n();
        let (address, _) = TransactionBuilder::create_taproot_address(
            &self.signer.secp,
            vec![script_n_of_n_without_hash.clone()],
        )?;

        let anyone_can_spend_txout = ScriptBuilder::anyone_can_spend_txout();

        let child_tx_ins = TransactionBuilder::create_tx_ins(vec![parent_outpoint, resource_utxo]);

        let child_tx_outs = TransactionBuilder::create_tx_outs(vec![
            (
                Amount::from_sat(BRIDGE_AMOUNT_SATS)
                    - Amount::from_sat(DUST_VALUE)
                    - Amount::from_sat(MIN_RELAY_FEE),
                address.script_pubkey(),
            ),
            (
                anyone_can_spend_txout.value,
                anyone_can_spend_txout.script_pubkey,
            ),
        ]);

        let mut child_tx = TransactionBuilder::create_btc_tx(child_tx_ins, child_tx_outs);

        child_tx.input[0].witness.push([0x51]);

        let anyone_can_spend_txout = ScriptBuilder::anyone_can_spend_txout();
        let prevouts = TransactionBuilder::create_tx_outs(vec![
            (
                anyone_can_spend_txout.value,
                anyone_can_spend_txout.script_pubkey,
            ),
            (
                Amount::from_sat(BRIDGE_AMOUNT_SATS),
                self.signer.address.script_pubkey(),
            ),
        ]);
        let sig = self
            .signer
            .sign_taproot_pubkey_spend_tx(&mut child_tx, &prevouts, 1)?;
        let mut sighash_cache = SighashCache::new(child_tx.borrow_mut());
        let witness = sighash_cache
            .witness_mut(1)
            .ok_or(BridgeError::TxInputNotFound)?;
        witness.push(sig.as_ref());
        // println!("child_tx: {:?}", child_tx);
        // println!("child_txid: {:?}", child_tx.txid());
        Ok(child_tx)
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
    ) -> Result<(), BridgeError> {
        let hash = sha256_hash!(preimage);
        let (_, tree_info) = TransactionBuilder::create_connector_tree_node_address(
            &self.signer.secp,
            &self.signer.xonly_public_key,
            hash,
        )?;

        let base_tx = match self.rpc.get_raw_transaction(&utxo.txid, None) {
            Ok(txid) => Some(txid),
            Err(e) => {
                eprintln!("Failed to get raw transaction: {}", e);
                None
            }
        };
        println!("base_tx: {:?}", base_tx);

        if base_tx.is_none() {
            return Ok(());
        }
        let depth = u32::ilog2(
            ((base_tx.unwrap().output[utxo.vout as usize].value.to_sat() + MIN_RELAY_FEE)
                / (DUST_VALUE + MIN_RELAY_FEE)) as u32,
        );
        println!("depth: {:?}", depth);
        let level = tree_depth - depth as usize;
        //find the index of preimage in the connector_tree_preimages[level as usize]
        let index = self.operator_mock_db.connector_tree_preimages[period][level as usize]
            .iter()
            .position(|x| *x == preimage)
            .ok_or(BridgeError::PreimageNotFound)?;
        let hashes = (
            self.operator_mock_db.connector_tree_hashes[period][(level + 1) as usize][2 * index],
            self.operator_mock_db.connector_tree_hashes[period][(level + 1) as usize]
                [2 * index + 1],
        );

        let utxo_tx = self.rpc.get_raw_transaction(&utxo.txid, None)?;
        // println!("utxo_tx: {:?}", utxo_tx);
        // println!("utxo_txid: {:?}", utxo_tx.txid());
        let timelock_script =
            ScriptBuilder::generate_timelock_script(&self.signer.xonly_public_key, 1);

        let (first_address, _) = TransactionBuilder::create_connector_tree_node_address(
            &self.signer.secp,
            &self.signer.xonly_public_key,
            hashes.0,
        )?;

        let (second_address, _) = TransactionBuilder::create_connector_tree_node_address(
            &self.signer.secp,
            &self.signer.xonly_public_key,
            hashes.1,
        )?;

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
        )?;
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

        handle_taproot_witness(&mut tx, 0, &witness_elements, &timelock_script, &tree_info)?;

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
        Ok(())
    }

    pub fn reveal_connector_tree_preimages(
        &self,
        period: usize,
        number_of_funds_claim: u32,
    ) -> HashSet<PreimageType> {
        let indices = get_claim_reveal_indices(CONNECTOR_TREE_DEPTH, number_of_funds_claim);
        println!("indices: {:?}", indices);
        let mut preimages: HashSet<PreimageType> = HashSet::new();
        for (depth, index) in indices {
            preimages.insert(self.operator_mock_db.connector_tree_preimages[period][depth][index]);
        }
        preimages
    }

    fn get_current_period(&self) -> usize {
        0
    }

    fn get_num_withdrawals_for_period(&self, _period: usize) -> u32 {
        self.operator_mock_db.withdrawals_merkle_tree.index // TODO: This is not corret, we should have a cutoff
    }

    /// This is called internally when every withdrawal for the current period is satisfied
    /// Double checks if all withdrawals are satisfied
    /// Checks that we are in the correct period, and withdrawal period has end for the given period
    /// inscribe the connector tree preimages to the blockchain
    pub fn inscribe_connector_tree_preimages(&mut self) -> Result<(), BridgeError> {
        let period = self.get_current_period();
        if self.operator_mock_db.inscription_txs.len() != period {
            return Err(BridgeError::InvalidPeriod);
        }

        let number_of_funds_claim = self.get_num_withdrawals_for_period(period);

        let indices = get_claim_reveal_indices(CONNECTOR_TREE_DEPTH, number_of_funds_claim);
        println!("indices: {:?}", indices);

        let preimages_to_be_revealed = indices
            .iter()
            .map(|(depth, index)| {
                self.operator_mock_db.connector_tree_preimages[period][*depth][*index]
            })
            .collect::<Vec<_>>();

        let (commit_address, commit_tree_info, inscribe_preimage_script) =
            self.transaction_builder.create_inscription_commit_address(
                &self.signer.xonly_public_key,
                &preimages_to_be_revealed,
            )?;

        let commit_utxo = self.rpc.send_to_address(&commit_address, DUST_VALUE * 2)?;
        println!(
            "is_commit_utxo_spent? {:?}",
            self.rpc.is_utxo_spent(&commit_utxo)
        );

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
        )?;

        handle_taproot_witness(
            &mut reveal_tx,
            0,
            &vec![sig.as_ref()],
            &inscribe_preimage_script,
            &commit_tree_info,
        )?;

        let reveal_txid = self.rpc.send_raw_transaction(&reveal_tx)?;

        println!(
            "is_commit_utxo_spent? {:?}",
            self.rpc.is_utxo_spent(&commit_utxo)
        );

        self.operator_mock_db
            .inscription_txs
            .push((commit_utxo, reveal_txid));

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
        Ok(())
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
    pub fn initial_setup(&mut self) -> Result<(OutPoint, u64), BridgeError> {
        let cur_blockheight = self.rpc.get_block_height()?;
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
        println!("total_amount: {:?}", total_amount);
        let (connector_tree_source_address, _) = self
            .transaction_builder
            .create_connector_tree_root_address(
                &self.signer.xonly_public_key,
                self.start_blockheight + PERIOD_BLOCK_COUNT as u64,
            )?;

        let first_source_utxo = self
            .rpc
            .send_to_address(&connector_tree_source_address, total_amount.to_sat())?;
        println!("first_source_utxo: {:?}", first_source_utxo);
        let first_source_utxo_create_tx = self
            .rpc
            .get_raw_transaction(&first_source_utxo.txid, None)?;
        println!(
            "first_source_utxo_create_tx: {:?}",
            first_source_utxo_create_tx
        );

        let (claim_proof_merkle_roots, root_utxos, utxo_trees) = create_all_connector_trees(
            &self.signer.secp,
            &self.transaction_builder,
            &self.operator_mock_db.connector_tree_hashes,
            self.start_blockheight,
            &first_source_utxo,
            &self.signer.xonly_public_key,
        )?;

        // self.set_connector_tree_utxos(utxo_trees.clone());
        self.operator_mock_db.connector_tree_utxos = utxo_trees;
        println!(
            "Operator claim_proof_merkle_roots: {:?}",
            claim_proof_merkle_roots
        );
        println!("Operator root_utxos: {:?}", root_utxos);
        println!(
            "Operator utxo_trees: {:?}",
            self.operator_mock_db.connector_tree_utxos
        );
        Ok((first_source_utxo, self.start_blockheight))
    }
}

#[cfg(test)]
mod tests {

    // use super::*;

    // #[test]
    // fn test_giga_merkle_tree_works() {
    //     let mut rng = OsRng;
    //     let giga_merkle_tree = create_giga_merkle_tree(2, 4, &mut rng);
    //     println!("giga_merkle_tree: {:?}", giga_merkle_tree);
    // }

    // #[test]
    // fn test_concurrent_deposit() {
    //     let rpc = ExtendedRpc::new();

    //     let mut operator = Operator::new(&mut OsRng, &rpc, NUM_VERIFIERS as u32);
    //     let mut users = Vec::new();

    //     let verifiers_pks = operator.get_all_verifiers();
    //     for verifier in &mut operator.mock_verifier_access {
    //         verifier.set_verifiers(verifiers_pks.clone());
    //     }
    //     println!("verifiers_pks.len: {:?}", verifiers_pks.len());

    //     for _ in 0..NUM_USERS {
    //         users.push(User::new(&rpc, verifiers_pks.clone()));
    //     }

    //     let user1 = User::new(&rpc, verifiers_pks.clone());
    //     let user2 = User::new(&rpc, verifiers_pks.clone());

    //     let (deposit1_utxo, deposit1_pk) = user1.deposit_tx();
    //     rpc.mine_blocks(1);
    //     let (deposit2_utxo, deposit2_pk) = user2.deposit_tx();
    //     rpc.mine_blocks(5);

    //     operator.new_deposit(deposit1_utxo, &deposit1_pk).unwrap();
    //     rpc.mine_blocks(1);
    //     assert!(matches!(
    //         operator.new_deposit(deposit2_utxo, &deposit2_pk),
    //         Err(BridgeError::OperatorPendingDeposit)
    //     ));
    // }

    // use bitcoin::{Amount, ScriptBuf, TxOut};

    // use crate::operator::verify_presigns;

    // #[test]
    // fn test_verify_signatures() {
    //     let tx_hex = "020000000001022b86e82b3335af40d206e416155c66542f96d8bc98b6c07c6f3e0175e9708ba10000000000fdffffff1c6e567c2f0c370652af95d03385e26c9f4cb9ea88ed52dd7c5c052ae53a17910000000000010000000100e1f50500000000225120d3c0878411a63e670cbcaa03604cadc2f61d3a0297819e26dab4986aa83738bd07403835ac4cc7a7fcf68dfa56ba70018dbd977673cb05cbe8287e65c6c4fc08f2515b3e0f224718f840ae69b3679196d02193eea1f603012847b5aa1909a125a216408636dce230218013f350685815bb0d2fd9e64a0162ed09186cf057841ca9dfa80c6a72fa36350fa3f5bb12a90484e8b612054edd07a3a5d5d447eb2fba5f064040ff621f4aec25217d23410bfc6ec7bc2f56a37f0a6b0947a0932cc0747e450e4df283e52b38ebc4edfe1b2bb00753e75be9565c1f2575e736e2c79154b366b63e4073fb9833dac0af5738e4485a1300956810573c6de7eda0340c91426e4db8e5d43c9b8e9880fe33bd7c7f9a94f8dbe29ae542d09e7cde4c4a10883e973d17312640d4c4f33c09517d1a0a2fadb9369f0eedf52016e520159b688685e9cb475320b3be1fa44ef2944b3dfdc0b07a95179696f30733c3e63e80cc35451957fcab6000ab2063f147b96c98681468d9ab166e7b6818ce0b58df3c05d4935047b106a6fb06bfad20f0c323602416c30856c27f59b7ea4513222836a92250e9d55e3b70d9cf9bee2dad2081cf3e3e9200fac45faddbb2a19a171331878176b028bc366a15868f78b1f97fad20c4a870a421bfac0a6462631efd84f4cd27344dfe6392b36704f34c3b37f03790ad20b0974516bb328e5f610ce84e9b918116c5c13aa40fc0d3b96ef8a60900cd7569ad5121c093c7378d96518a75448821c4f7c8f4bae7ce60f804d03d1f0628dd5dd0f5de510340d1c2e2eb093850719104032b082c7f2b87078722089730254921fd321782742355c8405effc1aeae65d59d3328c84eaf2bebb4fd40fe4520554297e6ee5913542551b27520b0974516bb328e5f610ce84e9b918116c5c13aa40fc0d3b96ef8a60900cd7569ac41c193c7378d96518a75448821c4f7c8f4bae7ce60f804d03d1f0628dd5dd0f5de51d8c17994a69136b8eb137f1fb2f09a7ca866e720d30bdb605f92718d83e4f9cd00000000";
    //     let tx: bitcoin::Transaction =
    //         bitcoin::consensus::deserialize(&hex::decode(tx_hex).unwrap()).unwrap();
    //     // println!("tx: {:?}", tx);
    //     let prevouts: Vec<bitcoin::TxOut> = vec![
    //         TxOut {
    //             value: Amount::from_sat(99_999_500),
    //             script_pubkey: ScriptBuf::from_hex(
    //                 "512054d9859140cde3d23e44d94592466aa6cd4c837c284aa835f0a92a1b7203f496",
    //             )
    //             .unwrap(),
    //         },
    //         TxOut {
    //             value: Amount::from_sat(1000),
    //             script_pubkey: ScriptBuf::from_hex(
    //                 "5120706d91fa2893c9f8e39f378dbabbbca56cbcfefd4da530d07d7485cce0e4988a",
    //             )
    //             .unwrap(),
    //         },
    //     ];
    //     verify_presigns(&tx, &prevouts);
    // }
}
