use crate::constants::{VerifierChallenge, CONNECTOR_TREE_DEPTH};
use crate::db::verifier::VerifierMockDB;
use crate::errors::BridgeError;

use crate::traits::verifier::VerifierConnector;
use crate::utils::check_deposit_utxo;
use crate::{EVMAddress, HashTree};
use bitcoin::Address;
use bitcoin::{secp256k1, secp256k1::Secp256k1, OutPoint};

use clementine_circuits::constants::{BRIDGE_AMOUNT_SATS, NUM_ROUNDS};
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
    pub operator_pk: XOnlyPublicKey,
    verifier_db_connector: VerifierMockDB,
}

// impl VerifierConnector
impl VerifierConnector for Verifier {
    /// this is a endpoint that only the operator can call
    /// 1. Check if the deposit utxo is valid and finalized (6 blocks confirmation)
    /// 2. Check if the utxo is not already spent
    /// 3. Give move signature and operator claim signatures
    fn new_deposit(
        &self,
        start_utxo: OutPoint,
        return_address: &XOnlyPublicKey,
        deposit_index: u32,
        evm_address: &EVMAddress,
        operator_address: &Address,
    ) -> Result<DepositPresigns, BridgeError> {
        check_deposit_utxo(
            &self.rpc,
            &self.transaction_builder,
            &start_utxo,
            return_address,
            evm_address,
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
            let connector_utxo = self.verifier_db_connector.get_connector_tree_utxo(i)
                [CONNECTOR_TREE_DEPTH][deposit_index as usize];
            let connector_hash = self.verifier_db_connector.get_connector_tree_hash(
                i,
                CONNECTOR_TREE_DEPTH,
                deposit_index as usize,
            );

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
        let (_claim_proof_merkle_roots, _, utxo_trees, claim_proof_merkle_trees) =
            self.transaction_builder.create_all_connector_trees(
                &connector_tree_hashes,
                &first_source_utxo,
                start_blockheight,
                &period_relative_block_heights,
            )?;

        self.verifier_db_connector
            .set_connector_tree_utxos(utxo_trees);
        self.verifier_db_connector
            .set_connector_tree_hashes(connector_tree_hashes.clone());
        self.verifier_db_connector
            .set_claim_proof_merkle_trees(claim_proof_merkle_trees);
        self.verifier_db_connector
            .set_start_block_height(start_blockheight);
        self.verifier_db_connector
            .set_period_relative_block_heights(period_relative_block_heights);

        Ok(())
    }

    /// Challenges the operator for current period for now
    /// Will return the blockhash, total work, and period
    fn challenge_operator(&self, period: u8) -> Result<VerifierChallenge, BridgeError> {
        tracing::info!("Verifier starts challenges");
        let last_blockheight = self.rpc.get_block_count()?;
        let last_blockhash = self.rpc.get_block_hash(
            self.verifier_db_connector.get_start_block_height()
                + self
                    .verifier_db_connector
                    .get_period_relative_block_heights()[period as usize] as u64
                - 1,
        )?;
        tracing::debug!("Verifier last_blockhash: {:?}", last_blockhash);
        let total_work = self.rpc.calculate_total_work_between_blocks(
            self.verifier_db_connector.get_start_block_height(),
            last_blockheight,
        )?;
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

        let verifier_db_connector = VerifierMockDB::new();

        let transaction_builder = TransactionBuilder::new(all_xonly_pks.clone());
        let operator_pk = all_xonly_pks[all_xonly_pks.len() - 1];
        Ok(Verifier {
            rpc,
            secp,
            signer,
            transaction_builder,
            verifiers: all_xonly_pks,
            operator_pk,
            verifier_db_connector,
        })
    }
}
