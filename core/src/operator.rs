use std::sync::Arc;
use std::vec;

use crate::actor::Actor;
use crate::constants::{
    VerifierChallenge, CONNECTOR_TREE_DEPTH, DUST_VALUE, K_DEEP,
    MAX_BITVM_CHALLENGE_RESPONSE_BLOCKS, MIN_RELAY_FEE, PERIOD_BLOCK_COUNT,
};
use crate::db::operator::OperatorMockDB;
use crate::env_writer::ENVWriter;
use crate::errors::{BridgeError, InvalidPeriodError};
use crate::extended_rpc::ExtendedRpc;

use crate::merkle::MerkleTree;
use crate::script_builder::ScriptBuilder;
use crate::traits::verifier::VerifierConnector;
use crate::transaction_builder::TransactionBuilder;
use crate::utils::{
    calculate_amount, check_deposit_utxo, get_claim_reveal_indices, handle_taproot_witness,
    handle_taproot_witness_new,
};
use crate::{EVMAddress, WithdrawalPayment};

use bitcoin::address::NetworkChecked;
use bitcoin::block::Header;
use bitcoin::hashes::Hash;

use bitcoin::{secp256k1, secp256k1::schnorr, Address};
use bitcoin::{Amount, BlockHash, OutPoint};
use clementine_circuits::constants::{
    BLOCKHASH_MERKLE_TREE_DEPTH, BRIDGE_AMOUNT_SATS, CLAIM_MERKLE_TREE_DEPTH, MAX_BLOCK_HANDLE_OPS,
    NUM_ROUNDS, WITHDRAWAL_MERKLE_TREE_DEPTH,
};
use clementine_circuits::env::Environment;
use clementine_circuits::{sha256_hash, HashType, PreimageType};
use crypto_bigint::{Encoding, U256};
use futures::stream::FuturesOrdered;
use futures::TryStreamExt;
use secp256k1::rand::{Rng, RngCore};
use secp256k1::{Message, SecretKey, XOnlyPublicKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub fn create_connector_tree_preimages_and_hashes(
    depth: usize,
    rng: &mut impl RngCore,
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
    rng: &mut impl RngCore,
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DepositPresigns {
    pub move_sign: schnorr::Signature,
    pub operator_claim_sign: Vec<schnorr::Signature>,
}

#[derive(Debug, Clone)]
pub struct OperatorClaimSigs {
    pub operator_claim_sigs: Vec<Vec<schnorr::Signature>>,
}

#[derive(Debug, Clone)]
pub struct Operator {
    pub rpc: ExtendedRpc,
    pub signer: Actor,
    pub transaction_builder: TransactionBuilder,
    pub verifiers_pks: Vec<XOnlyPublicKey>,
    pub verifier_connector: Vec<Arc<dyn VerifierConnector>>,
    operator_db_connector: OperatorMockDB,
}

impl Operator {
    pub fn new(
        rpc: ExtendedRpc,
        all_xonly_pks: Vec<XOnlyPublicKey>,
        operator_sk: SecretKey,
        verifiers: Vec<Arc<dyn VerifierConnector>>,
    ) -> Result<Self, BridgeError> {
        let num_verifiers = all_xonly_pks.len() - 1;
        let signer = Actor::new(operator_sk); // Operator is the last one

        if signer.xonly_public_key != all_xonly_pks[num_verifiers] {
            return Err(BridgeError::InvalidOperatorKey);
        }

        let transaction_builder = TransactionBuilder::new(all_xonly_pks.clone());
        let operator_db_connector = OperatorMockDB::new();

        Ok(Self {
            rpc,
            signer,
            transaction_builder,
            verifier_connector: verifiers,
            verifiers_pks: all_xonly_pks.clone(),
            operator_db_connector,
        })
    }

    /// this is a public endpoint that every depositor can call
    /// it will get signatures from all verifiers.
    /// 1. Check if the deposit utxo is valid and finalized (6 blocks confirmation)
    /// 2. Check if the utxo is not already spent
    /// 3. Get signatures from all verifiers 1 move signature, ~150 operator takes signatures
    /// 4. Create a move transaction and return the output utxo
    pub async fn new_deposit(
        &mut self,
        start_utxo: OutPoint,
        return_address: &XOnlyPublicKey,
        evm_address: &EVMAddress,
    ) -> Result<OutPoint, BridgeError> {
        check_deposit_utxo(
            &self.rpc,
            &self.transaction_builder,
            &start_utxo,
            return_address,
            evm_address,
            BRIDGE_AMOUNT_SATS,
        )?;

        let deposit_index = self.operator_db_connector.get_deposit_index();
        // tracing::debug!("deposit_index: {:?}", deposit_index);

        let presigns_from_all_verifiers: Result<Vec<_>, BridgeError> = self
            .verifier_connector
            .iter()
            .map(|verifier| async {
                // tracing::debug!("Verifier number {:?} is checking new deposit:", i);
                // Attempt to get the deposit presigns. If an error occurs, it will be propagated out
                // of the map, causing the collect call to return a Result::Err, effectively stopping
                // the iteration and returning the error from your_function_name.
                let deposit_presigns = verifier
                    .new_deposit(
                        start_utxo,
                        return_address,
                        deposit_index as u32,
                        evm_address,
                        &self.signer.address,
                    )
                    .await
                    .map_err(|e| {
                        // Log the error or convert it to BridgeError if necessary
                        tracing::error!("Error getting deposit presigns: {:?}", e);
                        BridgeError::FailedToGetPresigns
                    })?;
                // tracing::debug!("deposit presigns: {:?}", deposit_presigns);
                // tracing::info!("Verifier checked new deposit");
                Ok(deposit_presigns)
            })
            // Because we're using async blocks, we need to use `then` and `try_collect` to properly await and collect results
            .collect::<FuturesOrdered<_>>()
            .try_collect()
            .await;
        // Handle the result of the collect operation
        let presigns_from_all_verifiers = presigns_from_all_verifiers?;
        tracing::info!("presigns_from_all_verifiers: done");

        // 5. Create a move transaction and return the output utxo, save the utxo as a pending deposit
        let mut move_tx =
            self.transaction_builder
                .create_move_tx(start_utxo, evm_address, &return_address)?;

        // TODO: Simplify this move_signatures thing, maybe with a macro
        let mut move_signatures = presigns_from_all_verifiers
            .iter()
            .map(|presign| presign.move_sign)
            .collect::<Vec<_>>();

        let sig = self
            .signer
            .sign_taproot_script_spend_tx_new(&mut move_tx, 0)?;
        move_signatures.push(sig);
        move_signatures.reverse();

        let mut witness_elements: Vec<&[u8]> = Vec::new();
        for sig in move_signatures.iter() {
            witness_elements.push(sig.as_ref());
        }

        handle_taproot_witness_new(&mut move_tx, &witness_elements, 0)?;
        // tracing::debug!("move_tx: {:?}", move_tx);
        let rpc_move_txid = self.rpc.send_raw_transaction(&move_tx.tx)?;
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
        self.operator_db_connector
            .add_deposit_take_sigs(operator_claim_sigs);

        for i in 0..NUM_ROUNDS {
            let connector_utxo = self.operator_db_connector.get_connector_tree_utxo(i)
                [CONNECTOR_TREE_DEPTH][deposit_index as usize];
            let connector_hash = self.operator_db_connector.get_connector_tree_hash(
                i,
                CONNECTOR_TREE_DEPTH,
                deposit_index as usize,
            );
            let mut operator_claim_tx = self.transaction_builder.create_operator_claim_tx(
                move_utxo,
                connector_utxo,
                &self.signer.address,
                &self.signer.xonly_public_key,
                &connector_hash,
            )?;

            let sig_hash = self
                .signer
                .sighash_taproot_script_spend(&mut operator_claim_tx, 0)?;

            let op_claim_sigs_for_period_i = presigns_from_all_verifiers
                .iter()
                .map(|presign| {
                    // tracing::debug!(
                    //     "presign.operator_claim_sign[{:?}]: {:?}",
                    //     i, presign.operator_claim_sign[i]
                    // );
                    presign.operator_claim_sign[i]
                })
                .collect::<Vec<_>>();
            // tracing::debug!(
            //     "len of op_claim_sigs_for_period_i: {:?}",
            //     op_claim_sigs_for_period_i.len()
            // );
            for (idx, sig) in op_claim_sigs_for_period_i.iter().enumerate() {
                // tracing::debug!("verifying presigns for index {:?}: ", idx);
                // tracing::debug!("sig: {:?}", sig);
                self.signer.secp.verify_schnorr(
                    sig,
                    &Message::from_digest_slice(sig_hash.as_byte_array()).expect("should be hash"),
                    &self.verifiers_pks[idx],
                )?;
            }
        }

        Ok(move_utxo)
    }

    /// Returns the current withdrawal
    fn get_current_withdrawal_period(&self) -> Result<usize, BridgeError> {
        let cur_block_height = self.rpc.get_block_count().unwrap();
        let start_block_height = self.operator_db_connector.get_start_block_height();
        let period_relative_block_heights = self
            .operator_db_connector
            .get_period_relative_block_heights();
        for (i, block_height) in period_relative_block_heights.iter().enumerate() {
            if cur_block_height
                < start_block_height + *block_height as u64 - MAX_BLOCK_HANDLE_OPS as u64
            {
                tracing::debug!("Checking current withdrawal period: {:?}", i);
                return Ok(i);
            }
        }
        Err(BridgeError::InvalidPeriod(
            InvalidPeriodError::WithdrawalPeriodMismatch,
        ))
    }

    fn get_current_preimage_reveal_period(&self) -> Result<usize, BridgeError> {
        let cur_block_height = self.rpc.get_block_count().unwrap();
        tracing::debug!("Cur block height: {:?}", cur_block_height);
        let start_block_height = self.operator_db_connector.get_start_block_height();
        tracing::debug!("Start block height: {:?}", start_block_height);
        let period_relative_block_heights = self
            .operator_db_connector
            .get_period_relative_block_heights();

        for (i, block_height) in period_relative_block_heights.iter().enumerate() {
            tracing::debug!(
                "{:?} <= {:?} < {:?}",
                start_block_height + *block_height as u64 - MAX_BLOCK_HANDLE_OPS as u64,
                cur_block_height,
                start_block_height + *block_height as u64
            );
            if cur_block_height
                >= start_block_height + *block_height as u64 - MAX_BLOCK_HANDLE_OPS as u64
                && cur_block_height < start_block_height + *block_height as u64
            {
                return Ok(i);
            }
        }
        Err(BridgeError::InvalidPeriod(
            InvalidPeriodError::PreimageRevealPeriodMismatch,
        ))
    }

    // this is called when a Withdrawal event emitted on rollup and its corresponding batch proof is finalized
    pub fn new_withdrawal(
        &mut self,
        withdrawal_address: Address<NetworkChecked>,
    ) -> Result<(), BridgeError> {
        let taproot_script = withdrawal_address.script_pubkey();
        // we are assuming that the withdrawal_address is a taproot address so we get the last 32 bytes
        let hash: [u8; 34] = taproot_script.as_bytes().try_into()?;
        let hash: [u8; 32] = hash[2..].try_into()?;

        // 1. Add the address to WithdrawalsMerkleTree
        self.operator_db_connector
            .add_to_withdrawals_merkle_tree(hash);

        // self.withdrawals_merkle_tree.add(withdrawal_address.to);

        // 2. Pay to the address and save the txid
        let txid = self
            .rpc
            .send_to_address(&withdrawal_address, 100_000_000)?
            .txid;
        // tracing::debug!(
        //     "operator paid to withdrawal address: {:?}, txid: {:?}",
        //     withdrawal_address, txid
        // );
        let current_withdrawal_period = self.get_current_withdrawal_period()?;
        self.operator_db_connector.add_to_withdrawals_payment_txids(
            current_withdrawal_period,
            (txid, hash) as WithdrawalPayment,
        );
        Ok(())
    }

    pub fn spend_connector_tree_utxo(
        // TODO: Too big, move some parts to Transaction Builder
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
            &hash,
        )?;

        let base_tx = match self.rpc.get_raw_transaction(&utxo.txid, None) {
            Ok(txid) => Some(txid),
            Err(e) => {
                tracing::error!("Failed to get raw transaction: {}", e);
                None
            }
        };
        // tracing::debug!("base_tx: {:?}", base_tx);

        if base_tx.is_none() {
            return Ok(());
        }
        let depth = u32::ilog2(
            ((base_tx.unwrap().output[utxo.vout as usize].value.to_sat() + MIN_RELAY_FEE)
                / (DUST_VALUE + MIN_RELAY_FEE)) as u32,
        );
        // tracing::debug!("depth: {:?}", depth);
        let level = tree_depth - depth as usize;
        //find the index of preimage in the connector_tree_preimages[level as usize]
        let index = self
            .operator_db_connector
            .get_connector_tree_preimages_level(period, level)
            .iter()
            .position(|x| *x == preimage)
            .ok_or(BridgeError::PreimageNotFound)?;
        let hashes = (
            self.operator_db_connector
                .get_connector_tree_hash(period, level + 1, 2 * index),
            self.operator_db_connector
                .get_connector_tree_hash(period, level + 1, 2 * index + 1),
        );

        let utxo_tx = self.rpc.get_raw_transaction(&utxo.txid, None)?;
        // tracing::debug!("utxo_tx: {:?}", utxo_tx);
        // tracing::debug!("utxo_txid: {:?}", utxo_tx.txid());
        let timelock_script =
            ScriptBuilder::generate_timelock_script(&self.signer.xonly_public_key, 1);

        let (first_address, _) = TransactionBuilder::create_connector_tree_node_address(
            &self.signer.secp,
            &self.signer.xonly_public_key,
            &hashes.0,
        )?;

        let (second_address, _) = TransactionBuilder::create_connector_tree_node_address(
            &self.signer.secp,
            &self.signer.xonly_public_key,
            &hashes.1,
        )?;

        let mut tx = TransactionBuilder::create_connector_tree_tx(
            &utxo,
            depth as usize - 1,
            first_address,
            second_address,
        );
        // tracing::debug!("created spend tx: {:?}", tx);

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

        // tracing::debug!("bytes_connector_tree_tx length: {:?}", bytes_connector_tree_tx.len());
        // let hex_utxo_tx = hex::encode(bytes_utxo_tx.clone());
        let _spending_txid = match self.rpc.send_raw_transaction(&tx) {
            Ok(txid) => Some(txid),
            Err(e) => {
                tracing::error!("Failed to send raw transaction: {}", e);
                None
            }
        };
        // tracing::debug!("operator_spending_txid: {:?}", spending_txid);
        Ok(())
    }

    fn get_num_withdrawals_for_period(&self, _period: usize) -> u32 {
        self.operator_db_connector
            .get_withdrawals_merkle_tree_index() // TODO: This is not correct, we should have a cutoff
    }

    /// This is called internally when every withdrawal for the current period is satisfied
    /// Double checks if all withdrawals are satisfied
    /// Checks that we are in the correct period, and withdrawal period has end for the given period
    /// inscribe the connector tree preimages to the blockchain
    pub fn inscribe_connector_tree_preimages(
        &mut self,
    ) -> Result<(Vec<[u8; 32]>, Address), BridgeError> {
        tracing::info!("inscribe_connector_tree_preimages");
        let period = self.get_current_preimage_reveal_period()?;
        tracing::debug!("period: {:?}", period);
        if self.operator_db_connector.get_inscription_txs_len() != period {
            tracing::debug!(
                "self.operator_db_connector.get_inscription_txs_len(): {:?}",
                self.operator_db_connector.get_inscription_txs_len()
            );
            return Err(BridgeError::InvalidPeriod(
                InvalidPeriodError::InscriptionPeriodMismatch,
            ));
        }
        let number_of_funds_claim = self.get_num_withdrawals_for_period(period);
        tracing::debug!("number_of_funds_claim: {:?}", number_of_funds_claim);

        let indices = get_claim_reveal_indices(CONNECTOR_TREE_DEPTH, number_of_funds_claim);
        tracing::debug!("indices for preimages: {:?}", indices);

        let preimages_to_be_revealed = indices
            .iter()
            .map(|(depth, index)| {
                self.operator_db_connector
                    .get_connector_tree_preimages(period, *depth, *index)
            })
            .collect::<Vec<_>>();

        // tracing::debug!("preimages_to_be_revealed: {:?}", preimages_to_be_revealed);

        let (commit_address, _commit_tree_info, _inscribe_preimage_script) =
            self.transaction_builder.create_inscription_commit_address(
                &self.signer.xonly_public_key,
                &preimages_to_be_revealed,
            )?;

        // tracing::debug!("script_pubkey: {:?}", commit_address.script_pubkey());

        let commit_utxo = self.rpc.send_to_address(&commit_address, DUST_VALUE * 2)?;

        let mut reveal_tx = self.transaction_builder.create_inscription_reveal_tx(
            commit_utxo,
            &self.signer.xonly_public_key,
            &preimages_to_be_revealed,
        )?;

        let sig = self
            .signer
            .sign_taproot_script_spend_tx_new(&mut reveal_tx, 0)?;

        handle_taproot_witness_new(&mut reveal_tx, &vec![sig.as_ref()], 0)?;

        let reveal_txid = self.rpc.send_raw_transaction(&reveal_tx.tx)?;

        self.operator_db_connector
            .add_to_inscription_txs((commit_utxo, reveal_txid));

        self.operator_db_connector
            .add_inscribed_preimages(period, preimages_to_be_revealed.clone());

        Ok((preimages_to_be_revealed, commit_address))
    }

    /// Helper function for operator to write blocks to env
    fn write_blocks_and_add_to_merkle_tree<E: Environment>(
        &self,
        start_block_height: u64,
        end_block_height: u64,
        blockhashes_mt: &mut MerkleTree<BLOCKHASH_MERKLE_TREE_DEPTH>,
    ) -> Result<BlockHash, BridgeError> {
        let block_headers_vec_result = (start_block_height..end_block_height)
            .map(|i| {
                let blockhash = self.rpc.get_block_hash(i).map_err(|e| {
                    tracing::error!("Failed to get block hash: {}", e);
                    BridgeError::BitcoinRpcError(e)
                })?;
                let block_header = self.rpc.get_block_header(&blockhash).map_err(|e| {
                    tracing::error!("Failed to get block header: {}", e);
                    BridgeError::BitcoinRpcError(e)
                })?;
                Ok(block_header)
            })
            .collect::<Result<Vec<_>, BridgeError>>();

        let block_headers_vec = block_headers_vec_result?;

        let lc_cutoff_blockhash = block_headers_vec
            [block_headers_vec.len() - 1 - MAX_BLOCK_HANDLE_OPS as usize]
            .block_hash();
        ENVWriter::<E>::write_blocks_and_add_to_merkle_tree(block_headers_vec, blockhashes_mt);
        Ok(lc_cutoff_blockhash)
    }

    fn write_withdrawals_and_add_to_merkle_tree<E: Environment>(
        &self,
        withdrawal_payments: Vec<WithdrawalPayment>,
        withdrawal_mt: &mut MerkleTree<WITHDRAWAL_MERKLE_TREE_DEPTH>,
        blockhash_mt: &MerkleTree<BLOCKHASH_MERKLE_TREE_DEPTH>,
    ) -> Result<(), BridgeError> {
        E::write_u32(withdrawal_payments.len() as u32);
        tracing::debug!(
            "WROTE withdrawal_payments.len(): {:?}",
            withdrawal_payments.len() as u32
        );

        for (txid, hash) in withdrawal_payments {
            E::write_32bytes(hash);
            tracing::debug!("WROTE output_address: {:?}", hash);
            // get transaction from txid
            let tx = self.rpc.get_raw_transaction(&txid, None)?;
            // tracing::debug!("GOT tx: {:?}", tx);
            ENVWriter::<E>::write_tx_to_env(&tx);
            tracing::debug!("WROTE tx and calculated txid: {:?}", txid);
            let get_transaction_result = self.rpc.get_transaction(&txid, None)?;
            let blockhash = get_transaction_result.info.blockhash.ok_or_else(|| {
                tracing::error!("Failed to get blockhash for transaction: {:?}", txid);
                BridgeError::BlockhashNotFound
            })?;

            let block = self.rpc.get_block(&blockhash).map_err(|e| {
                tracing::error!("Failed to get block: {}", e);
                BridgeError::BlockNotFound
            })?;

            ENVWriter::<E>::write_bitcoin_merkle_path(txid, &block)?;
            tracing::debug!("WROTE bitcoin merkle path for txid: {:?}", txid);

            // We get the merkle root of the block, so we need to write the remaining part
            // of the block header so we can calculate the blockhash
            ENVWriter::<E>::write_block_header_without_mt_root(&block.header);

            ENVWriter::<E>::write_merkle_tree_proof(blockhash.to_byte_array(), None, blockhash_mt);
            tracing::debug!(
                "WROTE merkle_tree_proof for blockhash: {:?}",
                blockhash.to_byte_array()
            );

            withdrawal_mt.add(hash);
        }
        // tracing::debug!("WROTE WITHDRAWALS AND ADDED TO MERKLE TREE");
        // tracing::debug!("withdrawal_mt.root(): {:?}", withdrawal_mt.root());

        Ok(())
    }

    /// TODO: change this
    fn write_lc_proof<E: Environment>(
        &self,
        lc_blockhash: BlockHash,
        withdrawal_mt_root: [u8; 32],
    ) {
        E::write_32bytes(lc_blockhash.to_byte_array());
        E::write_32bytes(withdrawal_mt_root);
    }

    fn write_verifiers_challenge_proof<E: Environment>(
        proof: [[u8; 32]; 4],
        challenge: VerifierChallenge,
    ) -> Result<(), BridgeError> {
        for i in 0..4 {
            E::write_32bytes(proof[i]);
        }
        E::write_32bytes(challenge.0.to_byte_array());
        tracing::debug!(
            "WROTE challenge blockhash: {:?}",
            challenge.0.to_byte_array()
        );
        E::write_32bytes(challenge.1.to_le_bytes());
        E::write_u32(challenge.2 as u32);
        Ok(())
    }

    /// Currently PoC for a bridge proof
    /// Light Client proofs are not yet implemented
    /// Verifier's Challenge proof is not yet implemented, instead we assume
    /// that the verifier gave correct blockhash
    /// In the future this will be probably a seperate Prover struct to be able to save old proofs
    /// and continue from old proof state when necessary
    pub fn prove<E: Environment>(
        &self,
        challenge: (BlockHash, U256, u8),
    ) -> Result<(), BridgeError> {
        tracing::info!("Operator starts proving");

        let mut blockhashes_mt = MerkleTree::<BLOCKHASH_MERKLE_TREE_DEPTH>::new();
        let mut withdrawal_mt = MerkleTree::<WITHDRAWAL_MERKLE_TREE_DEPTH>::new();

        let start_block_height = self.operator_db_connector.get_start_block_height();
        // tracing::debug!("start_block_height: {:?}", start_block_height);

        let period_relative_block_heights = self
            .operator_db_connector
            .get_period_relative_block_heights();
        // tracing::debug!(
        //     "period_relative_block_heights: {:?}",
        //     period_relative_block_heights
        // );

        let inscription_txs = self.operator_db_connector.get_inscription_txs();
        // tracing::debug!("inscription_txs: {:?}", inscription_txs);

        let mut lc_blockhash: BlockHash = BlockHash::all_zeros();

        let start_blockhash = self
            .rpc
            .get_block_hash(start_block_height - 1)
            .map_err(|e| {
                tracing::error!("Failed to get block hash: {}", e);
                BridgeError::BitcoinRpcError(e)
            })?;
        tracing::debug!("start_blockhash: {:?}", start_blockhash);

        E::write_32bytes(start_blockhash.to_byte_array());
        tracing::debug!(
            "WROTE START BLOCKHASH: {:?}",
            start_blockhash.to_byte_array()
        );

        let mut end_height: u64 = 0;
        let mut start_height: u64;
        let mut total_num_withdrawals = 0;

        let last_period = inscription_txs.len() - 1;

        for i in 0..last_period + 1 {
            tracing::debug!("[OPERATOR] Period: {:?}", i);
            // Writing blocks until current period
            // First write specific blockhashes to the circuit
            start_height = if i == 0 {
                start_block_height
            } else {
                start_block_height + period_relative_block_heights[i - 1] as u64
            };
            end_height = start_block_height + period_relative_block_heights[i] as u64;
            lc_blockhash = self.write_blocks_and_add_to_merkle_tree::<E>(
                start_height,
                end_height,
                &mut blockhashes_mt,
            )?;
            tracing::debug!("lc_blockhash: {:?}", lc_blockhash);

            let withdrawal_payments = self
                .operator_db_connector
                .get_withdrawals_payment_for_period(i);
            tracing::debug!("withdrawal_payments: {:?}", withdrawal_payments);
            total_num_withdrawals += withdrawal_payments.len();

            // Then write withdrawal proofs:
            self.write_withdrawals_and_add_to_merkle_tree::<E>(
                withdrawal_payments,
                &mut withdrawal_mt,
                &blockhashes_mt,
            )?;
            if i != last_period {
                E::write_u32(0); // do_you_want_to_end_proving
            }
        }
        E::write_u32(1); // do_you_want_to_end_proving

        Self::write_verifiers_challenge_proof::<E>([[0u8; 32]; 4], challenge)?;

        // write all the remaining blocks so that we will have more pow than the given challenge
        // adding more block hashes to the tree is not a problem.
        let cur_block_height = self.rpc.get_block_count().unwrap();

        let mut k_deep_blocks: Vec<Header> = Vec::new();

        for i in end_height..cur_block_height {
            let blockhash = self.rpc.get_block_hash(i).unwrap();
            let block_header = self.rpc.get_block_header(&blockhash).unwrap();
            k_deep_blocks.push(block_header);
        }

        ENVWriter::<E>::write_blocks(k_deep_blocks.clone());
        tracing::debug!("WROTE k_deep_blocks: {:?}", k_deep_blocks);

        self.write_lc_proof::<E>(lc_blockhash, withdrawal_mt.root());
        tracing::info!("WROTE LC PROOF");

        let preimages: Vec<PreimageType> = self
            .operator_db_connector
            .get_inscribed_preimages(last_period as usize);

        // tracing::debug!("PREIMAGES: {:?}", preimages);

        ENVWriter::<E>::write_preimages(self.signer.xonly_public_key, &preimages);
        tracing::debug!("WROTE preimages: {:?}", preimages);
        let mut preimage_hasher = Sha256::new();
        for preimage in preimages.iter() {
            preimage_hasher.update(sha256_hash!(preimage));
        }
        let preimage_hash: [u8; 32] = preimage_hasher.finalize().into();
        tracing::debug!("preimage_hash: {:?}", preimage_hash);

        // tracing::info!("WROTE PREIMAGES");

        let (commit_utxo, reveal_txid) =
            self.operator_db_connector.get_inscription_txs()[last_period as usize];

        // tracing::debug!("commit_utxo: {:?}", commit_utxo);
        let commit_tx = self.rpc.get_raw_transaction(&commit_utxo.txid, None)?;
        // tracing::debug!("commit_tx: {:?}", commit_tx);

        let reveal_tx = self.rpc.get_raw_transaction(&reveal_txid, None)?;

        // tracing::debug!("reveal_tx: {:?}", reveal_tx);

        ENVWriter::<E>::write_tx_to_env(&commit_tx);

        E::write_u32(reveal_tx.input[0].previous_output.vout);
        ENVWriter::<E>::write_tx_to_env(&reveal_tx);
        // tracing::debug!("WROTE reveal_tx: {:?}", reveal_tx);

        let reveal_tx_result = self
            .rpc
            .get_raw_transaction_info(&reveal_txid, None)
            .unwrap_or_else(|e| {
                tracing::error!("Failed to get transaction: {}, {}", reveal_txid, e);
                panic!("");
            });

        // tracing::debug!("REVEAL TX IS: {:?}", reveal_tx_result);

        let blockhash = reveal_tx_result.blockhash.ok_or_else(|| {
            tracing::error!("Failed to get blockhash for transaction: {:?}", reveal_txid);
            BridgeError::BlockhashNotFound
        })?;

        let block = self.rpc.get_block(&blockhash).map_err(|e| {
            tracing::error!("Failed to get block: {}", e);
            BridgeError::BlockNotFound
        })?;

        ENVWriter::<E>::write_bitcoin_merkle_path(reveal_txid, &block)?;
        tracing::debug!(
            "WROTE bitcoin merkle path for reveal_txid: {:?}",
            reveal_txid
        );

        ENVWriter::<E>::write_block_header_without_mt_root(&block.header);

        ENVWriter::<E>::write_merkle_tree_proof(blockhash.to_byte_array(), None, &blockhashes_mt);
        tracing::debug!(
            "WROTE merkle_tree_proof for blockhash: {:?}",
            blockhash.to_byte_array()
        );

        // For period i, we need to prove that the hash of the preimages is in the PERIOD_CLAIM_MT_ROOTS[i] merkle tree.
        ENVWriter::<E>::write_merkle_tree_proof(
            preimage_hash,
            Some(total_num_withdrawals as u32),
            &self
                .operator_db_connector
                .get_claim_proof_merkle_tree(last_period as usize),
        );
        tracing::debug!(
            "WROTE merkle_tree_proof for preimage_hash: {:?}",
            preimage_hash
        );

        // write_blocks_and_add_to_merkle_tree(
        //     start_block_height + period_relative_block_heights[last_period].into(),
        //     cur_block_height,
        //     blockhashes_mt,
        // );

        // let env = MockEnvironment::output_env();
        // let prover = default_prover();
        // let receipt = prover.prove(env, GUEST_ELF).unwrap();
        // MockEnvironment::prove();
        Ok(())
    }

    pub fn prove_test<E: Environment>(&self) -> Result<(), BridgeError> {
        let inscription_txs = self.operator_db_connector.get_inscription_txs();
        let last_period = inscription_txs.len() - 1;
        let preimages: Vec<PreimageType> = self
            .operator_db_connector
            .get_inscribed_preimages(last_period as usize);
        tracing::debug!("PREIMAGES: {:?}", preimages);
        tracing::debug!("operator pk: {:?}", self.signer.xonly_public_key);
        ENVWriter::<E>::write_preimages(self.signer.xonly_public_key, &preimages);
        Ok(())
    }

    /// This starts the whole setup
    /// 1. get the current blockheight
    /// 2. Create perod blockheights
    /// 3. Create connector tree preimages and hashes
    /// 4. Create and fund the first source utxo
    pub fn initial_setup(
        &mut self,
        rng: &mut impl RngCore,
    ) -> Result<
        (
            OutPoint,
            u64,
            Vec<Vec<Vec<HashType>>>,
            Vec<u32>,
            Vec<MerkleTree<CLAIM_MERKLE_TREE_DEPTH>>,
        ),
        BridgeError,
    > {
        // tracing::info!("Operator starts initial setup");
        let blockheight = self.operator_db_connector.get_start_block_height();
        if blockheight != 0 {
            return Err(BridgeError::AlreadyInitialized);
        }
        // initial setup starts with getting the current blockheight to set the start blockheight
        let start_block_height = self.rpc.get_block_height()?;
        self.operator_db_connector
            .set_start_block_height(start_block_height);
        // this is a vector [PERIOD_BLOCK_COUNT, 2*PERIOD_BLOCK_COUNT, ...] with NUM_ROUNDS elements.
        // this can be changed to specific blockheights that we want in the initial setup.
        // Note that PERIOD_BLOCK_COUNT should be bigger than K_DEEP + MAX_BITVM_CHALLENGE_RESPONSE_BLOCKS
        let period_relative_block_heights = (0..NUM_ROUNDS as u32 + 1)
            .map(|i| PERIOD_BLOCK_COUNT * (i + 1))
            .collect::<Vec<u32>>();
        self.operator_db_connector
            .set_period_relative_block_heights(period_relative_block_heights.clone());

        let (connector_tree_preimages, connector_tree_hashes) =
            create_all_rounds_connector_preimages(CONNECTOR_TREE_DEPTH, NUM_ROUNDS, rng);
        self.operator_db_connector
            .set_connector_tree_preimages(connector_tree_preimages);
        self.operator_db_connector
            .set_connector_tree_hashes(connector_tree_hashes.clone());
        let single_tree_amount = calculate_amount(
            CONNECTOR_TREE_DEPTH,
            Amount::from_sat(DUST_VALUE),
            Amount::from_sat(MIN_RELAY_FEE),
        );
        let total_amount =
            Amount::from_sat((MIN_RELAY_FEE + single_tree_amount.to_sat()) * NUM_ROUNDS as u64);
        // tracing::debug!("total_amount: {:?}", total_amount);
        let (connector_tree_source_address, _) = self
            .transaction_builder
            .create_connector_tree_source_address(
                start_block_height
                    + (period_relative_block_heights[0]
                        + MAX_BITVM_CHALLENGE_RESPONSE_BLOCKS
                        + K_DEEP) as u64,
            )
            .unwrap();
        let first_source_utxo = self
            .rpc
            .send_to_address(&connector_tree_source_address, total_amount.to_sat())
            .unwrap();
        // tracing::debug!("first_source_utxo: {:?}", first_source_utxo);
        let _first_source_utxo_create_tx = self
            .rpc
            .get_raw_transaction(&first_source_utxo.txid, None)?;

        let (claim_proof_merkle_roots, _root_utxos, utxo_trees, claim_proof_merkle_trees) = self
            .transaction_builder
            .create_all_connector_trees(
                &connector_tree_hashes,
                &first_source_utxo,
                start_block_height,
                &period_relative_block_heights,
            )
            .unwrap();
        tracing::debug!(
            "Operator claim_proof_merkle_roots: {:?}",
            claim_proof_merkle_roots
        );
        tracing::debug!("Operator start_block_height: {:?}", start_block_height);
        tracing::debug!(
            "Operator period_relative_block_heights for start_block_heigth: {:?}",
            period_relative_block_heights
        );
        self.operator_db_connector
            .set_claim_proof_merkle_trees(claim_proof_merkle_trees.clone());

        self.operator_db_connector
            .set_connector_tree_utxos(utxo_trees);
        Ok((
            first_source_utxo,
            start_block_height,
            connector_tree_hashes.clone(),
            period_relative_block_heights,
            claim_proof_merkle_trees,
        ))
    }
}
