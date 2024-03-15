use std::vec;

use crate::actor::Actor;
use crate::constants::{
    VerifierChallenge, CONNECTOR_TREE_DEPTH, DUST_VALUE, K_DEEP,
    MAX_BITVM_CHALLENGE_RESPONSE_BLOCKS, MIN_RELAY_FEE, PERIOD_BLOCK_COUNT,
};
use crate::env_writer::ENVWriter;
use crate::errors::BridgeError;
use crate::extended_rpc::ExtendedRpc;

use crate::merkle::MerkleTree;
use crate::mock_db::OperatorMockDB;
use crate::mock_env::MockEnvironment;
use crate::script_builder::ScriptBuilder;
use crate::traits::operator_db::OperatorDBConnector;
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
use circuit_helpers::constants::{
    BLOCKHASH_MERKLE_TREE_DEPTH, BRIDGE_AMOUNT_SATS, CLAIM_MERKLE_TREE_DEPTH, MAX_BLOCK_HANDLE_OPS,
    NUM_ROUNDS, WITHDRAWAL_MERKLE_TREE_DEPTH,
};
use circuit_helpers::env::Environment;
use circuit_helpers::{sha256_hash, HashType, PreimageType};
use crypto_bigint::{Encoding, U256};
use secp256k1::rand::{Rng, RngCore};
use secp256k1::{Message, SecretKey, XOnlyPublicKey};
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
pub struct Operator {
    pub rpc: ExtendedRpc,
    pub signer: Actor,
    pub transaction_builder: TransactionBuilder,
    pub verifiers_pks: Vec<XOnlyPublicKey>,
    pub verifier_connector: Vec<Box<dyn VerifierConnector>>,
    operator_db_connector: Box<dyn OperatorDBConnector>,
}

impl Operator {
    pub fn new(
        rpc: ExtendedRpc,
        all_xonly_pks: Vec<XOnlyPublicKey>,
        operator_sk: SecretKey,
        verifiers: Vec<Box<dyn VerifierConnector>>,
    ) -> Result<Self, BridgeError> {
        let num_verifiers = all_xonly_pks.len() - 1;
        let signer = Actor::new(operator_sk); // Operator is the last one

        if signer.xonly_public_key != all_xonly_pks[num_verifiers] {
            return Err(BridgeError::InvalidOperatorKey);
        }

        // let mut verifiers: Vec<Box<dyn VerifierConnector>> = Vec::new();
        // for i in 0..num_verifiers {
        //     let verifier = Verifier::new(rpc, all_xonly_pks.clone(), all_sks[i])?;
        //     // Convert the Verifier instance into a boxed trait object
        //     verifiers.push(Box::new(verifier) as Box<dyn VerifierConnector>);
        // }

        let transaction_builder = TransactionBuilder::new(all_xonly_pks.clone());
        let operator_db_connector = Box::new(OperatorMockDB::new());

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

        // println!("Checking current deposit");

        // 2. Check if the utxo is valid and finalized (6 blocks confirmation)
        // 3. Check if the utxo is not already spent
        // 4. Get signatures from all verifiers 1 move signature, ~150 operator takes signatures

        check_deposit_utxo(
            &self.rpc,
            &self.transaction_builder,
            &start_utxo,
            return_address,
            BRIDGE_AMOUNT_SATS,
        )?;

        let deposit_index = self.operator_db_connector.get_deposit_index();
        // println!("deposit_index: {:?}", deposit_index);

        let presigns_from_all_verifiers: Result<Vec<_>, BridgeError> = self
            .verifier_connector
            .iter()
            .map(|verifier| {
                // println!("Verifier number {:?} is checking new deposit:", i);
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
                    .map_err(|e| {
                        // Log the error or convert it to BridgeError if necessary
                        eprintln!("Error getting deposit presigns: {:?}", e);
                        e
                    })?;
                // println!("deposit presigns: {:?}", deposit_presigns);
                // println!("Verifier checked new deposit");
                Ok(deposit_presigns)
            })
            .collect(); // This tries to collect into a Result<Vec<DepositPresigns>, BridgeError>

        // Handle the result of the collect operation
        let presigns_from_all_verifiers = presigns_from_all_verifiers?;
        // println!("presigns_from_all_verifiers: done");

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
        move_signatures.push(user_sig);
        move_signatures.reverse();

        let mut witness_elements: Vec<&[u8]> = Vec::new();
        for sig in move_signatures.iter() {
            witness_elements.push(sig.as_ref());
        }

        handle_taproot_witness_new(&mut move_tx, &witness_elements, 0)?;
        // println!("move_tx: {:?}", move_tx);
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

        // let anyone_can_spend_txout: TxOut = ScriptBuilder::anyone_can_spend_txout();
        // let timelock_script = ScriptBuilder::generate_timelock_script(
        //     &self.signer.xonly_public_key,
        //     CONNECTOR_TREE_OPERATOR_TAKES_AFTER as u32,
        // );

        for i in 0..NUM_ROUNDS {
            let connector_utxo = self.operator_db_connector.get_connector_tree_utxo(i)
                [CONNECTOR_TREE_DEPTH][deposit_index as usize];
            let connector_hash = self.operator_db_connector.get_connector_tree_hash(
                i,
                CONNECTOR_TREE_DEPTH,
                deposit_index as usize,
            );
            // println!("______________ OPERATOR _____________");
            // println!("connector_utxo: {:?}", connector_utxo);
            // println!("connector_hash: {:?}", connector_hash);
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
                    // println!(
                    //     "presign.operator_claim_sign[{:?}]: {:?}",
                    //     i, presign.operator_claim_sign[i]
                    // );
                    presign.operator_claim_sign[i]
                })
                .collect::<Vec<_>>();
            // println!(
            //     "len of op_claim_sigs_for_period_i: {:?}",
            //     op_claim_sigs_for_period_i.len()
            // );
            for (idx, sig) in op_claim_sigs_for_period_i.iter().enumerate() {
                // println!("verifying presigns for index {:?}: ", idx);
                // println!("sig: {:?}", sig);
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
                println!("Checking current withdrawal period: {:?}", i);
                return Ok(i);
            }
        }
        Err(BridgeError::InvalidPeriod)
    }

    fn get_current_preimage_reveal_period(&self) -> Result<usize, BridgeError> {
        let cur_block_height = self.rpc.get_block_count().unwrap();
        println!("Cur block height: {:?}", cur_block_height);
        let start_block_height = self.operator_db_connector.get_start_block_height();
        println!("Start block height: {:?}", start_block_height);
        let period_relative_block_heights = self
            .operator_db_connector
            .get_period_relative_block_heights();

        for (i, block_height) in period_relative_block_heights.iter().enumerate() {
            println!(
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
        Err(BridgeError::InvalidPeriod)
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
        // println!(
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
                eprintln!("Failed to get raw transaction: {}", e);
                None
            }
        };
        // println!("base_tx: {:?}", base_tx);

        if base_tx.is_none() {
            return Ok(());
        }
        let depth = u32::ilog2(
            ((base_tx.unwrap().output[utxo.vout as usize].value.to_sat() + MIN_RELAY_FEE)
                / (DUST_VALUE + MIN_RELAY_FEE)) as u32,
        );
        // println!("depth: {:?}", depth);
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
        // println!("utxo_tx: {:?}", utxo_tx);
        // println!("utxo_txid: {:?}", utxo_tx.txid());
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
        let _spending_txid = match self.rpc.send_raw_transaction(&tx) {
            Ok(txid) => Some(txid),
            Err(e) => {
                eprintln!("Failed to send raw transaction: {}", e);
                None
            }
        };
        // println!("operator_spending_txid: {:?}", spending_txid);
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
        println!("inscribe_connector_tree_preimages");
        let period = self.get_current_preimage_reveal_period()?;
        println!("period: {:?}", period);
        if self.operator_db_connector.get_inscription_txs_len() != period {
            println!(
                "self.operator_db_connector.get_inscription_txs_len(): {:?}",
                self.operator_db_connector.get_inscription_txs_len()
            );
            return Err(BridgeError::InvalidPeriod);
        }
        let number_of_funds_claim = self.get_num_withdrawals_for_period(period);
        println!("number_of_funds_claim: {:?}", number_of_funds_claim);

        let indices = get_claim_reveal_indices(CONNECTOR_TREE_DEPTH, number_of_funds_claim);
        println!("indices for preimages: {:?}", indices);

        let preimages_to_be_revealed = indices
            .iter()
            .map(|(depth, index)| {
                self.operator_db_connector
                    .get_connector_tree_preimages(period, *depth, *index)
            })
            .collect::<Vec<_>>();

        // println!("preimages_to_be_revealed: {:?}", preimages_to_be_revealed);

        let (commit_address, _commit_tree_info, _inscribe_preimage_script) =
            self.transaction_builder.create_inscription_commit_address(
                &self.signer.xonly_public_key,
                &preimages_to_be_revealed,
            )?;

        // println!("script_pubkey: {:?}", commit_address.script_pubkey());

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
                    eprintln!("Failed to get block hash: {}", e);
                    BridgeError::RpcError
                })?;
                let block_header = self.rpc.get_block_header(&blockhash).map_err(|e| {
                    eprintln!("Failed to get block header: {}", e);
                    BridgeError::RpcError
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
        println!(
            "WROTE withdrawal_payments.len(): {:?}",
            withdrawal_payments.len() as u32
        );

        for (txid, hash) in withdrawal_payments {
            E::write_32bytes(hash);
            println!("WROTE output_address: {:?}", hash);
            // get transaction from txid
            let tx = self.rpc.get_raw_transaction(&txid, None)?;
            // println!("GOT tx: {:?}", tx);
            ENVWriter::<E>::write_tx_to_env(&tx);
            println!("WROTE tx and calculated txid: {:?}", txid);
            let get_transaction_result = self.rpc.get_transaction(&txid, None)?;
            let blockhash = get_transaction_result.info.blockhash.ok_or_else(|| {
                eprintln!("Failed to get blockhash for transaction: {:?}", txid);
                BridgeError::RpcError
            })?;

            let block = self.rpc.get_block(&blockhash).map_err(|e| {
                eprintln!("Failed to get block: {}", e);
                BridgeError::RpcError
            })?;

            // println!("blockhashhhhhh: {:?}", blockhash);

            ENVWriter::<E>::write_bitcoin_merkle_path(txid, &block)?;
            println!("WROTE bitcoin merkle path for txid: {:?}", txid);

            // We get the merkle root of the block, so we need to write the remaining part
            // of the block header so we can calculate the blockhash
            ENVWriter::<E>::write_block_header_without_mt_root(&block.header);

            ENVWriter::<E>::write_merkle_tree_proof(blockhash.to_byte_array(), None, blockhash_mt);
            println!(
                "WROTE merkle_tree_proof for blockhash: {:?}",
                blockhash.to_byte_array()
            );

            withdrawal_mt.add(hash);
        }
        // println!("WROTE WITHDRAWALS AND ADDED TO MERKLE TREE");
        // println!("withdrawal_mt.root(): {:?}", withdrawal_mt.root());

        // TODO: Add proof of work calculation for K-deep assumption

        Ok(())
    }

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
        println!(
            "WROTE challenge blockhash: {:?}",
            challenge.0.to_byte_array()
        );
        E::write_32bytes(challenge.1.to_le_bytes());
        E::write_u32(challenge.2 as u32);
        Ok(())
    }

    /// Currently boilerplate code for generating a bridge proof
    /// Light Client proofs are not yet implemented
    /// Verifier's Challenge proof is not yet implemented, instead we assume
    /// that the verifier gave correct blockhash
    /// In the future this will be probably a seperate Prover struct to be able to save old proofs
    /// and continue from old proof state when necessary
    pub fn prove<E: Environment>(
        &self,
        challenge: (BlockHash, U256, u8),
    ) -> Result<(), BridgeError> {
        println!("Operator starts proving");

        let mut blockhashes_mt = MerkleTree::<BLOCKHASH_MERKLE_TREE_DEPTH>::new();
        let mut withdrawal_mt = MerkleTree::<WITHDRAWAL_MERKLE_TREE_DEPTH>::new();

        let start_block_height = self.operator_db_connector.get_start_block_height();
        // println!("start_block_height: {:?}", start_block_height);

        let period_relative_block_heights = self
            .operator_db_connector
            .get_period_relative_block_heights();
        // println!(
        //     "period_relative_block_heights: {:?}",
        //     period_relative_block_heights
        // );

        let inscription_txs = self.operator_db_connector.get_inscription_txs();
        // println!("inscription_txs: {:?}", inscription_txs);

        let mut lc_blockhash: BlockHash = BlockHash::all_zeros();

        let start_blockhash = self
            .rpc
            .get_block_hash(start_block_height - 1)
            .map_err(|e| {
                eprintln!("Failed to get block hash: {}", e);
                BridgeError::RpcError
            })?;
        println!("start_blockhash: {:?}", start_blockhash);

        E::write_32bytes(start_blockhash.to_byte_array());
        println!(
            "WROTE START BLOCKHASH: {:?}",
            start_blockhash.to_byte_array()
        );

        let mut end_height: u64 = 0;

        for i in 0..inscription_txs.len() {
            // First write specific blockhashes to the circuit
            let start_height = if i == 0 {
                start_block_height
            } else {
                start_block_height + period_relative_block_heights[i - 1] as u64
            };
            end_height = start_block_height + period_relative_block_heights[i] as u64;
            // println!("Writing BLOCKS AND ADDED TO MERKLE TREE");
            lc_blockhash = self.write_blocks_and_add_to_merkle_tree::<E>(
                start_height,
                end_height,
                &mut blockhashes_mt,
            )?;
            println!("lc_blockhash: {:?}", lc_blockhash);
            println!("WROTE BLOCKS AND ADDED TO MERKLE TREE:");

            // println!("From {:?} to {:?} ", start_height, end_height);

            // println!("WROTE BLOCKS AND ADDED TO MERKLE TREE");
            let withdrawal_payments = self
                .operator_db_connector
                .get_withdrawals_payment_for_period(i);
            println!("withdrawal_payments: {:?}", withdrawal_payments);

            // println!("WITHDRAWAL PAYMENTS: {:?}", withdrawal_payments);

            // Then write withdrawal proofs:
            self.write_withdrawals_and_add_to_merkle_tree::<E>(
                withdrawal_payments,
                &mut withdrawal_mt,
                &blockhashes_mt,
            )?;
            // println!("withdrawal_mt: {:?}", withdrawal_mt);
            // println!("blockhashes_mt: {:?}", blockhashes_mt);
            // println!("WROTE WITHDRAWALS AND ADDED TO MERKLE TREE");

            // Now we finish the proving, since we provided blockhashes and withdrawal proofs
            if i == challenge.2 as usize {
                MockEnvironment::write_u32(1);
                println!("WROTE 1, finishing proving");
            } else {
                MockEnvironment::write_u32(0);
                println!("WROTE 0, continue proving");
            }
        }
        let last_period = inscription_txs.len() - 1;

        self.write_lc_proof::<E>(lc_blockhash, withdrawal_mt.root());
        println!("WROTE LC PROOF");

        let preimages: Vec<PreimageType> = self
            .operator_db_connector
            .get_inscribed_preimages(last_period);

        // println!("PREIMAGES: {:?}", preimages);

        ENVWriter::<E>::write_preimages(self.signer.xonly_public_key, &preimages);
        println!("WROTE preimages: {:?}", preimages);
        let mut preimage_hasher = Sha256::new();
        for preimage in preimages.iter() {
            preimage_hasher.update(sha256_hash!(preimage));
        }
        let preimage_hash: [u8; 32] = preimage_hasher.finalize().into();
        println!("preimage_hash: {:?}", preimage_hash);

        // println!("WROTE PREIMAGES");

        let (commit_utxo, reveal_txid) =
            self.operator_db_connector.get_inscription_txs()[last_period];

        // println!("commit_utxo: {:?}", commit_utxo);
        let commit_tx = self.rpc.get_raw_transaction(&commit_utxo.txid, None)?;
        // println!("commit_tx: {:?}", commit_tx);

        let reveal_tx = self.rpc.get_raw_transaction(&reveal_txid, None)?;

        // println!("reveal_tx: {:?}", reveal_tx);

        ENVWriter::<E>::write_tx_to_env(&commit_tx);
        // println!("WROTE commit_tx: {:?}", commit_tx);
        ENVWriter::<E>::write_tx_to_env(&reveal_tx);
        // println!("WROTE reveal_tx: {:?}", reveal_tx);

        let reveal_tx_result = self
            .rpc
            .get_raw_transaction_info(&reveal_txid, None)
            .unwrap_or_else(|e| {
                eprintln!("Failed to get transaction: {}, {}", reveal_txid, e);
                panic!("");
            });

        // println!("REVEAL TX IS: {:?}", reveal_tx_result);

        let blockhash = reveal_tx_result.blockhash.ok_or_else(|| {
            eprintln!("Failed to get blockhash for transaction: {:?}", reveal_txid);
            BridgeError::RpcError
        })?;

        let block = self.rpc.get_block(&blockhash).map_err(|e| {
            eprintln!("Failed to get block: {}", e);
            BridgeError::RpcError
        })?;

        ENVWriter::<E>::write_bitcoin_merkle_path(reveal_txid, &block)?;
        println!(
            "WROTE bitcoin merkle path for reveal_txid: {:?}",
            reveal_txid
        );

        ENVWriter::<E>::write_block_header_without_mt_root(&block.header);

        // println!("Reading height: {:?}", block.bip34_block_height());

        ENVWriter::<E>::write_merkle_tree_proof(blockhash.to_byte_array(), None, &blockhashes_mt);
        println!(
            "WROTE merkle_tree_proof for blockhash: {:?}",
            blockhash.to_byte_array()
        );

        // TODO: do the claim merkle proof here.
        // For period i, we need to prove that the hash of the preimages is in the PERIOD_CLAIM_MT_ROOTS[i] merkle tree.
        // TODO: Add period for the claim proof
        // println!("claim_proof_merkle_tree: {:?}", self.operator_db_connector.get_claim_proof_merkle_tree(0));
        ENVWriter::<E>::write_merkle_tree_proof(
            preimage_hash,
            Some(12), //TODO: CHANGE THIS WITH THE NUMBER OF WITHDRAWALS UNTIL THE END OF THE CHALLENGE PERIOD
            &self
                .operator_db_connector
                .get_claim_proof_merkle_tree(challenge.2 as usize),
        );

        // write_preimages(preimages);
        // write_inscription_commit_tx(inscription_txs[last_period].0);
        // write_inscription_reveal_tx(inscription_txs[last_period].1);
        // let block = self.rpc.get_block(inscription_txs[last_period].1)?;
        // write_bitcoin_merkle_path(inscription_txs[last_period].1, block);
        // write_merkle_tree_proof(blockhashes_mt, block);
        // write_claim_proof_merkle_path(i, &preimages);
        // // write all the remaining blocks so that we will have more pow than the given challenge
        // // adding more block hashes to the tree is not a problem.
        let _cur_block_height = self.rpc.get_block_count().unwrap();

        let mut k_deep_blocks: Vec<Header> = Vec::new();

        for i in end_height.._cur_block_height {
            let blockhash = self.rpc.get_block_hash(i).unwrap();
            let block_header = self.rpc.get_block_header(&blockhash).unwrap();
            k_deep_blocks.push(block_header);
        }

        ENVWriter::<E>::write_blocks(k_deep_blocks.clone());
        println!("WROTE k_deep_blocks: {:?}", k_deep_blocks);
        // write_blocks_and_add_to_merkle_tree(
        //     start_block_height + period_relative_block_heights[last_period].into(),
        //     cur_block_height,
        //     blockhashes_mt,
        // );
        Self::write_verifiers_challenge_proof::<E>([[0u8; 32]; 4], challenge)?;

        // MockEnvironment::prove();
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
    //     // let mut claim_sigs = self.verifier_connector.iter().map(|verifier|
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
        // println!("total_amount: {:?}", total_amount);
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
        // println!("first_source_utxo: {:?}", first_source_utxo);
        let _first_source_utxo_create_tx = self
            .rpc
            .get_raw_transaction(&first_source_utxo.txid, None)?;
        // println!(
        //     "first_source_utxo_create_tx: {:?}",
        //     first_source_utxo_create_tx
        // );

        let (claim_proof_merkle_roots, _root_utxos, utxo_trees, claim_proof_merkle_trees) = self
            .transaction_builder
            .create_all_connector_trees(
                &connector_tree_hashes,
                &first_source_utxo,
                start_block_height,
                &period_relative_block_heights,
            )
            .unwrap();
        println!(
            "Operator claim_proof_merkle_roots: {:?}",
            claim_proof_merkle_roots
        );
        println!("Operator start_block_height: {:?}", start_block_height);
        println!(
            "Operator period_relative_block_heights: {:?}",
            period_relative_block_heights
        );
        self.operator_db_connector
            .set_claim_proof_merkle_trees(claim_proof_merkle_trees.clone());

        // self.set_connector_tree_utxos(utxo_trees.clone());
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
    //     for verifier in &mut operator.verifier_connector {
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
