use crate::actor::Actor;
use crate::config::BridgeConfig;
use crate::database::operator::OperatorDB;
use crate::errors::BridgeError;
use crate::extended_rpc::ExtendedRpc;
use crate::traits::rpc::OperatorRpcServer;
use crate::transaction_builder::TransactionBuilder;
use crate::{utils, EVMAddress, PsbtOutPoint};
use bitcoin::address::NetworkUnchecked;
use bitcoin::{Address, OutPoint};
use bitcoin_mock_rpc::RpcApiWrapper;
use clementine_circuits::constants::BRIDGE_AMOUNT_SATS;
use jsonrpsee::core::async_trait;

#[derive(Debug, Clone)]
pub struct Operator<R>
where
    R: RpcApiWrapper,
{
    rpc: ExtendedRpc<R>,
    db: OperatorDB,
    signer: Actor,
    config: BridgeConfig,
}

impl<R> Operator<R>
where
    R: RpcApiWrapper,
{
    /// Creates a new `Operator`.
    pub async fn new(config: BridgeConfig, rpc: ExtendedRpc<R>) -> Result<Self, BridgeError> {
        let num_verifiers = config.verifiers_public_keys.len();

        let signer = Actor::new(config.secret_key, config.network);
        if signer.public_key != config.verifiers_public_keys[num_verifiers - 1] {
            return Err(BridgeError::InvalidOperatorKey);
        }

        let db = OperatorDB::new(config.clone()).await;

        Ok(Self {
            rpc,
            db,
            signer,
            config,
        })
    }

    /// Public endpoint for every depositor to call.
    ///
    /// It will get signatures from all verifiers:
    ///
    /// 1. Check if the deposit UTXO is valid, finalized (6 blocks confirmation) and not spent
    /// 2. Check if we alredy created a kickoff UTXO for this deposit UTXO
    /// 3. Create a kickoff transaction but do not broadcast it
    /// TODO: Create multiple kickoffs in single transaction
    pub async fn new_deposit(
        &self,
        deposit_utxo: &OutPoint,
        recovery_taproot_address: &Address<NetworkUnchecked>,
        evm_address: &EVMAddress,
    ) -> Result<PsbtOutPoint, BridgeError> {
        tracing::info!(
            "New deposit request for UTXO: {:?}, EVM address: {:?} and recovery taproot address of: {:?}",
            deposit_utxo,
            evm_address,
            recovery_taproot_address
        );

        // 1. Check if the deposit UTXO is valid, finalized (6 blocks confirmation) and not spent
        self.rpc.check_deposit_utxo(
            &vec![utils::UNSPENDABLE_XONLY_PUBKEY.clone()], // TODO: Fix this to use N-of-N
            &deposit_utxo,
            recovery_taproot_address,
            evm_address,
            BRIDGE_AMOUNT_SATS,
            self.user_takes_after,
            self.confirmation_treshold,
        )?;

        // 2. Check if we alredy created a kickoff UTXO for this deposit UTXO
        let deposit_tx_info = self.db.get_kickoff_utxo(deposit_utxo).await?;

        // if we already have a kickoff UTXO for this deposit UTXO, return it
        if let Some(deposit_tx_info) = deposit_tx_info {
            return Ok(deposit_tx_info);
        }

        // 3. Create a kickoff transaction but do not broadcast it

        // To create a kickoff tx, we first need a funding utxo
        let funding_utxo_and_amount = self.db.get_funding_utxo_and_amount().await?;

        // if we don't have a funding utxo, return an error
        let (funding_utxo, funding_utxo_amount) = funding_utxo_and_amount.ok_or(
            BridgeError::OperatorFundingUtxoNotFound(self.signer.address.clone()),
        )?;

        // if the amount is not enough, return an error
        if funding_utxo_amount.to_sat() < 150_000 {
            // TODO: Change this amount
            return Err(BridgeError::OperatorFundingUtxoAmountNotEnough(
                self.signer.address.clone(),
            ));
        }

        let (kickoff_tx, funding_change, change_amount) = TransactionBuilder::create_kickoff_tx(
            funding_utxo,
            funding_utxo_amount,
            &self.signer.address,
        );

        let kickoff_utxo = PsbtOutPoint {
            tx: kickoff_tx,
            vout: 0,
        };

        let kickoff_txid = kickoff_utxo.tx.compute_txid();

        // In a db tx, save the kickoff_utxo for this deposit_utxo
        // and update the db with the new funding_utxo as the change

        let transaction = self.db.begin_transaction().await?;

        // We save the funding txid and the kickoff txid to be able to track them later
        self.db
            .save_kickoff_utxo(
                &deposit_utxo,
                &kickoff_utxo,
                &kickoff_txid,
                &funding_utxo.txid,
            )
            .await?;
        self.db
            .set_funding_utxo_and_amount(&funding_change, change_amount)
            .await?;

        transaction.commit().await?;

        Ok(kickoff_utxo)
    }

    /// Checks if utxo is valid, spendable by operator and not spent
    /// Saves the utxo to the db
    async fn set_operator_funding_utxo_rpc(
        &self,
        _funding_utxo: &OutPoint,
    ) -> Result<(), BridgeError> {
        unimplemented!();
    }
}

#[async_trait]
impl<R> OperatorRpcServer for Operator<R>
where
    R: RpcApiWrapper,
{
    async fn new_deposit_rpc(
        &self,
        deposit_utxo: OutPoint,
        recovery_taproot_address: Address<NetworkUnchecked>,
        evm_address: EVMAddress,
    ) -> Result<PsbtOutPoint, BridgeError> {
        self.new_deposit(&deposit_utxo, &recovery_taproot_address, &evm_address)
            .await
    }

    async fn set_operator_funding_utxo_rpc(
        &self,
        _funding_utxo: OutPoint,
    ) -> Result<(), BridgeError> {
        unimplemented!();
    }
}
