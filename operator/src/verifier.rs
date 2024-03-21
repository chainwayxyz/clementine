use crate::constants::{VerifierChallenge, CONNECTOR_TREE_DEPTH};
use crate::errors::BridgeError;

use crate::merkle::MerkleTree;
use crate::traits::verifier::VerifierConnector;
use crate::utils::check_deposit_utxo;
use crate::{ConnectorUTXOTree, EVMAddress, HashTree};
use bitcoin::Address;
use bitcoin::{secp256k1, secp256k1::Secp256k1, OutPoint};

use circuit_helpers::constants::{BRIDGE_AMOUNT_SATS, CLAIM_MERKLE_TREE_DEPTH, NUM_ROUNDS};
use secp256k1::SecretKey;
use secp256k1::XOnlyPublicKey;

use crate::extended_rpc::ExtendedRpc;
use crate::transaction_builder::TransactionBuilder;

use crate::{actor::Actor, operator::DepositPresigns};

#[derive(Debug)]
pub struct Verifier {
    pub rpc: ExtendedRpc,
    pub secp: Secp256k1<secp256k1::All>,
    pub signer: Actor,
    pub transaction_builder: TransactionBuilder,
    pub verifiers: Vec<XOnlyPublicKey>,
    pub connector_tree_utxos: Vec<ConnectorUTXOTree>,
    pub connector_tree_hashes: Vec<Vec<Vec<[u8; 32]>>>,
    pub claim_proof_merkle_trees: Vec<MerkleTree<CLAIM_MERKLE_TREE_DEPTH>>,
    pub operator_pk: XOnlyPublicKey,
    pub start_block_height: u64,
    pub period_relative_block_heights: Vec<u32>,
}

// impl VerifierConnector
impl VerifierConnector for Verifier {
    /// this is a endpoint that only the operator can call
    /// 1. Check if there is any previous pending deposit
    /// 2. Check if the utxo is valid and finalized (6 blocks confirmation)
    /// 3. Check if the utxo is not already spent
    /// 4. Give move signature and operator claim signature
    fn new_deposit(
        &self,
        start_utxo: OutPoint,
        return_address: &XOnlyPublicKey,
        deposit_index: u32,
        evm_address: &EVMAddress,
        operator_address: &Address,
    ) -> Result<DepositPresigns, BridgeError> {
        // 1. Check if there is any previous pending deposit

        check_deposit_utxo(
            &self.rpc,
            &self.transaction_builder,
            &start_utxo,
            return_address,
            BRIDGE_AMOUNT_SATS,
        )?;

        let mut move_tx =
            self.transaction_builder
                .create_move_tx(start_utxo, evm_address, &return_address)?;
        let move_txid = move_tx.tx.txid();

        let move_utxo = OutPoint {
            txid: move_txid,
            vout: 0,
        };

        let move_sig = self
            .signer
            .sign_taproot_script_spend_tx_new(&mut move_tx, 0)?;

        let mut op_claim_sigs = Vec::new();

        for i in 0..NUM_ROUNDS {
            let connector_utxo =
                self.connector_tree_utxos[i][CONNECTOR_TREE_DEPTH][deposit_index as usize];
            let connector_hash =
                self.connector_tree_hashes[i][CONNECTOR_TREE_DEPTH][deposit_index as usize];

            let mut operator_claim_tx = self.transaction_builder.create_operator_claim_tx(
                move_utxo,
                connector_utxo,
                &operator_address,
                &self.operator_pk,
                &connector_hash,
            )?;

            let op_claim_sig = self
                .signer
                .sign_taproot_script_spend_tx_new(&mut operator_claim_tx, 0)?;
            op_claim_sigs.push(op_claim_sig);
        }

        Ok(DepositPresigns {
            move_sign: move_sig,
            operator_claim_sign: op_claim_sigs,
        })
    }

    /// TODO: Add verification for the connector tree hashes
    fn connector_roots_created(
        &mut self,
        connector_tree_hashes: &Vec<HashTree>,
        first_source_utxo: &OutPoint,
        start_blockheight: u64,
        period_relative_block_heights: Vec<u32>,
    ) -> Result<(), BridgeError> {
        // tracing::debug!("Verifier first_source_utxo: {:?}", first_source_utxo);
        // tracing::debug!("Verifier verifiers_pks len: {:?}", self.verifiers.len());
        let (_claim_proof_merkle_roots, _, utxo_trees, claim_proof_merkle_trees) =
            self.transaction_builder.create_all_connector_trees(
                &connector_tree_hashes,
                &first_source_utxo,
                start_blockheight,
                &period_relative_block_heights,
            )?;
        // tracing::debug!("Verifier claim_proof_merkle_roots: {:?}", _claim_proof_merkle_roots);

        // self.set_connector_tree_utxos(utxo_trees);
        self.connector_tree_utxos = utxo_trees;
        // self.set_connector_tree_hashes(_connector_tree_hashes);
        self.connector_tree_hashes = connector_tree_hashes.clone();

        self.claim_proof_merkle_trees = claim_proof_merkle_trees;

        self.start_block_height = start_blockheight;
        self.period_relative_block_heights = period_relative_block_heights;

        // tracing::debug!(
        //     "Verifier claim_proof_merkle_roots: {:?}",
        //     claim_proof_merkle_roots
        // );
        // tracing::debug!("Verifier root_utxos: {:?}", root_utxos);
        // tracing::debug!("Verifier utxo_trees: {:?}", self.connector_tree_utxos);
        Ok(())
    }

    /// Challenges the operator for current period for now
    /// Will return the blockhash, total work, and period
    fn challenge_operator(&self, period: u8) -> Result<VerifierChallenge, BridgeError> {
        tracing::debug!("Verifier starts challenging");
        let last_blockheight = self.rpc.get_block_count()?;
        let last_blockhash = self.rpc.get_block_hash(
            self.start_block_height + self.period_relative_block_heights[period as usize] as u64
                - 1,
        )?;
        tracing::debug!("Verifier last_blockhash: {:?}", last_blockhash);
        //    let challenged_period_start = if period == 0 {
        //         self.start_block_height
        //     } else {
        //         self.start_block_height + self.period_relative_block_heights[period as usize - 1] as u64
        //     };
        //     let challenged_period_end =
        //         self.start_block_height + self.period_relative_block_heights[period as usize] as u64;
        // let period_end_blockhash = self.rpc.get_block_hash(challenged_period_end)?;
        let total_work = self
            .rpc
            .calculate_total_work_between_blocks(self.start_block_height, last_blockheight)?;
        Ok((last_blockhash, total_work, period))
    }
}

impl Verifier {
    pub fn new(
        rpc: ExtendedRpc,
        all_xonly_pks: Vec<XOnlyPublicKey>,
        sk: SecretKey,
    ) -> Result<Self, BridgeError> {
        let signer = Actor::new(sk);
        let secp: Secp256k1<secp256k1::All> = Secp256k1::new();

        let pk: secp256k1::PublicKey = sk.public_key(&secp);
        let xonly_pk = XOnlyPublicKey::from(pk);
        // if pk is not in all_pks, we should raise an error
        if !all_xonly_pks.contains(&xonly_pk) {
            return Err(BridgeError::PublicKeyNotFound);
        }

        let connector_tree_utxos = Vec::new();
        let connector_tree_hashes = Vec::new();
        let claim_proof_merkle_trees = Vec::new();

        let transaction_builder = TransactionBuilder::new(all_xonly_pks.clone());
        let operator_pk = all_xonly_pks[all_xonly_pks.len() - 1];
        Ok(Verifier {
            rpc,
            secp,
            signer,
            transaction_builder,
            verifiers: all_xonly_pks,
            connector_tree_utxos,
            connector_tree_hashes,
            operator_pk,
            claim_proof_merkle_trees,
            start_block_height: 0,
            period_relative_block_heights: Vec::new(),
        })
    }

    // pub fn set_verifiers(&mut self, verifiers: Vec<XOnlyPublicKey>) {
    //     self.verifiers = verifiers;
    //     self.script_builder = ScriptBuilder::new(self.verifiers.clone());
    //     self.transaction_builder = TransactionBuilder::new(self.verifiers.clone());
    // }

    // pub fn did_connector_tree_process_start(&self, utxo: OutPoint) -> bool {
    //     let last_block_hash = self.rpc.get_best_block_hash().unwrap();
    //     let last_block = self.rpc.get_block(&last_block_hash).unwrap();
    //     for tx in last_block.txdata {
    //         // if any of the tx.input.previous_output == utxo return true
    //         for input in tx.input {
    //             if input.previous_output == utxo {
    //                 return true;
    //             }
    //         }
    //     }
    //     false
    // }

    // pub fn watch_connector_tree(
    //     &self,
    //     operator_pk: XOnlyPublicKey,
    //     preimage_script_pubkey_pairs: &mut HashSet<PreimageType>,
    //     utxos: &mut HashMap<OutPoint, (u32, u32)>,
    // ) -> Result<(HashSet<PreimageType>, HashMap<OutPoint, (u32, u32)>), BridgeError> {
    //     tracing::debug!("verifier watching connector tree...");
    //     let last_block_hash = self.rpc.get_best_block_hash().unwrap();
    //     let last_block = self.rpc.get_block(&last_block_hash).unwrap();
    //     for tx in last_block.txdata {
    //         if utxos.contains_key(&tx.input[0].previous_output) {
    //             // Check if any of the UTXOs have been spent
    //             let (depth, index) = utxos.remove(&tx.input[0].previous_output).unwrap();
    //             utxos.insert(
    //                 TransactionBuilder::create_utxo(tx.txid(), 0),
    //                 (depth + 1, index * 2),
    //             );
    //             utxos.insert(
    //                 TransactionBuilder::create_utxo(tx.txid(), 1),
    //                 (depth + 1, index * 2 + 1),
    //             );
    //             //Assert the two new UTXOs have the same value
    //             assert_eq!(tx.output[0].value, tx.output[1].value);
    //             let new_amount = tx.output[0].value;
    //             //Check if any one of the UTXOs can be spent with a preimage
    //             for (i, tx_out) in tx.output.iter().enumerate() {
    //                 let mut preimages_to_remove = Vec::new();
    //                 for preimage in preimage_script_pubkey_pairs.iter() {
    //                     if is_spendable_with_preimage(
    //                         &self.secp,
    //                         operator_pk,
    //                         tx_out.clone(),
    //                         *preimage,
    //                     )? {
    //                         let utxo_to_spend = OutPoint {
    //                             txid: tx.txid(),
    //                             vout: i as u32,
    //                         };
    //                         self.spend_connector_tree_utxo(
    //                             utxo_to_spend,
    //                             operator_pk,
    //                             *preimage,
    //                             new_amount,
    //                         )?;
    //                         utxos.remove(&OutPoint {
    //                             txid: tx.txid(),
    //                             vout: i as u32,
    //                         });
    //                         preimages_to_remove.push(*preimage);
    //                     }
    //                 }
    //                 for preimage in preimages_to_remove {
    //                     preimage_script_pubkey_pairs.remove(&preimage);
    //                 }
    //             }
    //         }
    //     }
    //     tracing::debug!("verifier finished watching connector tree...");
    //     Ok((preimage_script_pubkey_pairs.clone(), utxos.clone()))
    // }

    // pub fn spend_connector_tree_utxo(
    //     &self,
    //     utxo: OutPoint,
    //     operator_pk: XOnlyPublicKey,
    //     preimage: PreimageType,
    //     amount: Amount,
    // ) -> Result<(), BridgeError> {
    //     let hash = sha256_hash!(preimage);
    //     let (address, tree_info) =
    //         TransactionBuilder::create_connector_tree_node_address(&self.secp, &operator_pk, hash)?;
    //     let tx_ins = TransactionBuilder::create_tx_ins_with_sequence(vec![utxo]);
    //     let tx_outs = TransactionBuilder::create_tx_outs(vec![(
    //         amount - Amount::from_sat(MIN_RELAY_FEE),
    //         self.signer.address.script_pubkey(),
    //     )]);
    //     let mut tx = TransactionBuilder::create_btc_tx(tx_ins, tx_outs);
    //     let prevouts = TransactionBuilder::create_tx_outs(vec![(amount, address.script_pubkey())]);
    //     let hash_script = ScriptBuilder::generate_hash_script(hash);
    //     let _sig = self
    //         .signer
    //         .sign_taproot_script_spend_tx(&mut tx, &prevouts, &hash_script, 0);
    //     // let spend_control_block = create_control_block(tree_info, &hash_script);

    //     // let mut sighash_cache = SighashCache::new(tx.borrow_mut());
    //     // let witness = sighash_cache.witness_mut(0).unwrap();
    //     // witness.push(preimage);
    //     // witness.push(hash_script);
    //     // witness.push(&spend_control_block.serialize());s

    //     let mut witness_elements: Vec<&[u8]> = Vec::new();
    //     witness_elements.push(&preimage);
    //     handle_taproot_witness(&mut tx, 0, &witness_elements, &hash_script, &tree_info)?;

    //     let spending_txid = self.rpc.send_raw_transaction(&tx).unwrap();
    //     tracing::debug!("verifier_spending_txid: {:?}", spending_txid);
    //     Ok(())
    // }

    // // This function is not in use now, will be used if we decide to return the leaf dust back to the operator
    // pub fn spend_connector_tree_leaf_utxo(
    //     &self,
    //     utxo: OutPoint,
    //     operator_pk: XOnlyPublicKey,
    //     preimage: PreimageType,
    //     amount: Amount,
    // ) -> Result<(), BridgeError> {
    //     let hash = sha256_hash!(preimage);
    //     let (address, tree_info) =
    //         TransactionBuilder::create_connector_tree_node_address(&self.secp, &operator_pk, hash)?;
    //     let tx_ins = TransactionBuilder::create_tx_ins_with_sequence(vec![utxo]);
    //     let tx_outs = TransactionBuilder::create_tx_outs(vec![(
    //         amount - Amount::from_sat(MIN_RELAY_FEE),
    //         self.signer.address.script_pubkey(),
    //     )]);
    //     let mut tx = TransactionBuilder::create_btc_tx(tx_ins, tx_outs);
    //     let prevouts = TransactionBuilder::create_tx_outs(vec![(amount, address.script_pubkey())]);
    //     let hash_script = ScriptBuilder::generate_hash_script(hash);
    //     let _sig = self
    //         .signer
    //         .sign_taproot_script_spend_tx(&mut tx, &prevouts, &hash_script, 0);
    //     let spend_control_block = create_control_block(tree_info, &hash_script);
    //     let mut sighash_cache = SighashCache::new(tx.borrow_mut());
    //     let witness = sighash_cache.witness_mut(0).unwrap();
    //     witness.push(preimage);
    //     witness.push(hash_script);
    //     witness.push(&spend_control_block.serialize());
    //     let spending_txid = self.rpc.send_raw_transaction(&tx).unwrap();
    //     tracing::debug!("verifier_spending_txid: {:?}", spending_txid);
    //     Ok(())
    // }
}

// pub fn is_spendable_with_preimage(
//     secp: &Secp256k1<All>,
//     operator_pk: XOnlyPublicKey,
//     tx_out: TxOut,
//     preimage: PreimageType,
// ) -> Result<bool, BridgeError> {
//     let hash = sha256_hash!(preimage);
//     let (address, _) =
//         TransactionBuilder::create_connector_tree_node_address(secp, &operator_pk, hash)?;

//     Ok(address.script_pubkey() == tx_out.script_pubkey)
// }
