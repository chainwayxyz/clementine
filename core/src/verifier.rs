use crate::config::BridgeConfig;
use crate::database::verifier::VerifierDB;
use crate::errors::BridgeError;
use crate::script_builder::ScriptBuilder;
use crate::traits::bitcoin_rpc::BitcoinRPC;
use crate::traits::rpc::VerifierRpcServer;
use crate::transaction_builder::TransactionBuilder;
use crate::EVMAddress;
use crate::{actor::Actor, operator::DepositPresigns};
use bitcoin::address::{NetworkChecked, NetworkUnchecked};
use bitcoin::{secp256k1, secp256k1::Secp256k1, OutPoint};
use bitcoin::{Address, Amount, Network, TxOut, Txid};
use clementine_circuits::constants::BRIDGE_AMOUNT_SATS;
use jsonrpsee::core::async_trait;
use secp256k1::schnorr;
use secp256k1::XOnlyPublicKey;

#[derive(Debug, Clone)]
pub struct Verifier<T> {
    rpc: T,
    signer: Actor,
    transaction_builder: TransactionBuilder,
    db: VerifierDB,
    network: Network,
    confirmation_treshold: u32,
    min_relay_fee: u64,
}

impl<T> Verifier<T>
where
    T: BitcoinRPC,
{
    pub async fn new(rpc: T, config: BridgeConfig) -> Result<Self, BridgeError> {
        let signer = Actor::new(config.secret_key, config.network);

        let secp: Secp256k1<secp256k1::All> = Secp256k1::new();

        let pk: secp256k1::PublicKey = config.secret_key.public_key(&secp);
        let xonly_pk = XOnlyPublicKey::from(pk);

        // Generated public key must be in given public key list.
        if !config.verifiers_public_keys.contains(&xonly_pk) {
            return Err(BridgeError::PublicKeyNotFound);
        }

        let db = VerifierDB::new(config.clone()).await;

        let transaction_builder = TransactionBuilder::new(
            config.verifiers_public_keys.clone(),
            config.network,
            config.user_takes_after,
            config.min_relay_fee,
        );

        Ok(Verifier {
            rpc,
            signer,
            transaction_builder,
            db,
            network: config.network,
            confirmation_treshold: config.confirmation_treshold,
            min_relay_fee: config.min_relay_fee,
        })
    }

    /// Operator only endpoint for verifier.
    ///
    /// 1. Check if the deposit UTXO is valid and finalized (6 blocks confirmation)
    /// 2. Check if the UTXO is not already spent
    /// 3. Give move signature and operator claim signatures
    async fn new_deposit(
        &self,
        start_utxo: OutPoint,
        recovery_taproot_address: &Address<NetworkUnchecked>,
        _deposit_index: u32,
        evm_address: &EVMAddress,
        _operator_address: &Address,
    ) -> Result<DepositPresigns, BridgeError> {
        self.rpc.check_deposit_utxo(
            &self.transaction_builder,
            &start_utxo,
            recovery_taproot_address,
            evm_address,
            BRIDGE_AMOUNT_SATS,
            self.confirmation_treshold,
        )?;

        let mut move_tx = self.transaction_builder.create_move_tx(
            start_utxo,
            evm_address,
            recovery_taproot_address,
        )?;
        let move_txid = move_tx.tx.compute_txid();

        tracing::info!(
            "Verifier with public key {:?} is signing {:?}.",
            self.signer.xonly_public_key.to_string(),
            move_txid
        );

        let move_sig = self
            .signer
            .sign_taproot_script_spend_tx_new(&mut move_tx, 0, 0)?;

        Ok(DepositPresigns {
            move_sign: move_sig,
            operator_claim_sign: vec![],
        })
    }

    async fn new_withdrawal_direct(
        &self,
        withdrawal_idx: usize,
        bridge_fund_txid: Txid,
        withdrawal_address: &Address<NetworkChecked>,
    ) -> Result<schnorr::Signature, BridgeError> {
        // TODO: Check Citrea RPC if the withdrawal is already been made or not.

        if let Ok((db_bridge_fund_txid, sig)) =
            self.db.get_withdrawal_sig_by_idx(withdrawal_idx).await
        {
            if db_bridge_fund_txid == bridge_fund_txid {
                return Ok(sig);
            } else {
                return Err(BridgeError::AlreadySpentWithdrawal);
            }
        };

        tracing::info!(
            "Verifier is signing withdrawal transaction with TXID: {:?}",
            bridge_fund_txid
        );

        let bridge_utxo = OutPoint {
            txid: bridge_fund_txid,
            vout: 0,
        };

        let (bridge_address, _) = self.transaction_builder.generate_bridge_address()?;

        let dust_value = ScriptBuilder::anyone_can_spend_txout().value;
        let bridge_txout = TxOut {
            value: Amount::from_sat(BRIDGE_AMOUNT_SATS - self.min_relay_fee) - dust_value,
            script_pubkey: bridge_address.script_pubkey(),
        };

        let mut withdrawal_tx = self.transaction_builder.create_withdraw_tx(
            bridge_utxo,
            bridge_txout,
            withdrawal_address,
        )?;

        let sig = self
            .signer
            .sign_taproot_script_spend_tx_new(&mut withdrawal_tx, 0, 0)?;

        self.db
            .save_withdrawal_sig(withdrawal_idx, bridge_fund_txid, sig)
            .await?;

        Ok(sig)
    }
}

#[async_trait]
impl<T> VerifierRpcServer for Verifier<T>
where
    T: BitcoinRPC,
{
    async fn new_deposit_rpc(
        &self,
        start_utxo: OutPoint,
        recovery_taproot_address: Address<NetworkUnchecked>,
        deposit_index: u32,
        evm_address: EVMAddress,
        operator_address: Address<NetworkUnchecked>,
    ) -> Result<DepositPresigns, BridgeError> {
        let operator_address = operator_address.require_network(self.network)?;

        self.new_deposit(
            start_utxo,
            &recovery_taproot_address,
            deposit_index,
            &evm_address,
            &operator_address,
        )
        .await
    }

    async fn new_withdrawal_direct_rpc(
        &self,
        withdrawal_idx: usize,
        bridge_fund_txid: Txid,
        withdrawal_address: Address<NetworkUnchecked>,
    ) -> Result<schnorr::Signature, BridgeError> {
        let withdrawal_address = withdrawal_address.require_network(self.network)?;

        self.new_withdrawal_direct(withdrawal_idx, bridge_fund_txid, &withdrawal_address)
            .await
    }
}

#[cfg(feature = "poc")]
impl Verifier {
    /// TODO: Add verification for the connector tree hashes
    fn connector_roots_created(
        &self,
        connector_tree_hashes: &Vec<HashTree>,
        first_source_utxo: &OutPoint,
        start_blockheight: u64,
        period_relative_block_heights: Vec<u32>,
    ) -> Result<(), BridgeError> {
        let (_claim_proof_merkle_roots, _, _utxo_trees, _claim_proof_merkle_trees) =
            self.transaction_builder.create_all_connector_trees(
                &connector_tree_hashes,
                &first_source_utxo,
                start_blockheight,
                &period_relative_block_heights,
            )?;

        self.db.set_connector_tree_utxos(utxo_trees);
        self.db
            .set_connector_tree_hashes(connector_tree_hashes.clone());
        self.db
            .set_claim_proof_merkle_trees(claim_proof_merkle_trees);
        self.db.set_start_block_height(start_blockheight);
        self.db
            .set_period_relative_block_heights(period_relative_block_heights);

        Ok(())
    }

    /// Challenges the operator for current period for now
    /// Will return the blockhash, total work, and period
    fn challenge_operator(&self, period: u8) -> Result<VerifierChallenge, BridgeError> {
        tracing::info!("Verifier starts challenges");
        let last_blockheight = self.rpc.get_block_count()?;
        let last_blockhash = self.rpc.get_block_hash(
            self.db.get_start_block_height()
                + self.db.get_period_relative_block_heights()[period as usize] as u64
                - 1,
        )?;
        tracing::debug!("Verifier last_blockhash: {:?}", last_blockhash);
        let total_work = self.rpc.calculate_total_work_between_blocks(
            self.db.get_start_block_height(),
            last_blockheight,
        )?;
        Ok((last_blockhash, total_work, period))
    }
}
