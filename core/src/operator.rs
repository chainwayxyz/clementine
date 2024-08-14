use crate::actor::Actor;
use crate::config::BridgeConfig;
use crate::database::operator::OperatorDB;
use crate::errors::BridgeError;
use crate::extended_rpc::ExtendedRpc;
use crate::musig2::{self, MuSigAggNonce, MuSigPartialSignature, MuSigPubNonce};
use crate::traits::rpc::OperatorRpcServer;
use crate::transaction_builder::TransactionBuilder;
use crate::{utils, EVMAddress, PsbtOutPoint, UTXO};
use ::musig2::secp::Point;
use bitcoin::address::NetworkUnchecked;
use bitcoin::hashes::Hash;
use bitcoin::{Address, OutPoint, TapSighash};
use bitcoin_mock_rpc::RpcApiWrapper;
use clementine_circuits::constants::BRIDGE_AMOUNT_SATS;
use clementine_circuits::sha256_hash;
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
    nofn_xonly_pk: secp256k1::XOnlyPublicKey,
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

        let key_agg_context =
            musig2::create_key_agg_ctx(config.verifiers_public_keys.clone(), None)?;
        let agg_point: Point = key_agg_context.aggregated_pubkey_untweaked();
        let nofn_xonly_pk = secp256k1::XOnlyPublicKey::from_slice(&agg_point.serialize_xonly())?;

        Ok(Self {
            rpc,
            db,
            signer,
            config,
            nofn_xonly_pk,
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
        deposit_outpoint: &OutPoint,
        recovery_taproot_address: &Address<NetworkUnchecked>,
        evm_address: &EVMAddress,
    ) -> Result<(UTXO, secp256k1::schnorr::Signature), BridgeError> {
        tracing::info!(
            "New deposit request for UTXO: {:?}, EVM address: {:?} and recovery taproot address of: {:?}",
            deposit_outpoint,
            evm_address,
            recovery_taproot_address
        );

        // 1. Check if the deposit UTXO is valid, finalized (6 blocks confirmation) and not spent
        self.rpc.check_deposit_utxo(
            &self.nofn_xonly_pk,
            &deposit_outpoint,
            recovery_taproot_address,
            evm_address,
            BRIDGE_AMOUNT_SATS,
            self.config.user_takes_after,
            self.config.confirmation_treshold,
            self.config.network,
        )?;

        // 2. Check if we alredy created a kickoff UTXO for this deposit UTXO
        let kickoff_utxo = self.db.get_kickoff_utxo(deposit_outpoint).await?;

        // if we already have a kickoff UTXO for this deposit UTXO, return it
        if let Some(kickoff_utxo) = kickoff_utxo {
            let kickoff_sig_hash = sha256_hash!(
                deposit_outpoint.txid,
                deposit_outpoint.vout.to_be_bytes(),
                kickoff_utxo.outpoint.txid,
                kickoff_utxo.outpoint.vout.to_be_bytes()
            );

            let sig = self
                .signer
                .sign(TapSighash::from_byte_array(kickoff_sig_hash));

            return Ok((kickoff_utxo, sig));
        }

        // 3. Create a kickoff transaction but do not broadcast it

        // To create a kickoff tx, we first need a funding utxo
        let funding_utxo =
            self.db
                .get_funding_utxo()
                .await?
                .ok_or(BridgeError::OperatorFundingUtxoNotFound(
                    self.signer.address.clone(),
                ))?;

        // if the amount is not enough, return an error
        if funding_utxo.txout.value.to_sat() < 150_000 {
            // TODO: Change this amount
            return Err(BridgeError::OperatorFundingUtxoAmountNotEnough(
                self.signer.address.clone(),
            ));
        }

        let kickoff_tx = TransactionBuilder::create_kickoff_tx(&funding_utxo, &self.signer.address);

        let change_utxo = UTXO {
            outpoint: OutPoint {
                txid: kickoff_tx.compute_txid(),
                vout: 1,
            },
            txout: kickoff_tx.output[1].clone(),
        };

        let kickoff_utxo = UTXO {
            outpoint: OutPoint {
                txid: kickoff_tx.compute_txid(),
                vout: 0,
            },
            txout: kickoff_tx.output[0].clone(),
        };

        let kickoff_sig_hash = sha256_hash!(
            deposit_outpoint.txid,
            deposit_outpoint.vout.to_be_bytes(),
            kickoff_utxo.outpoint.txid,
            kickoff_utxo.outpoint.vout.to_be_bytes()
        );

        let sig = self
            .signer
            .sign(TapSighash::from_byte_array(kickoff_sig_hash));

        // In a db tx, save the kickoff_utxo for this deposit_utxo
        // and update the db with the new funding_utxo as the change

        let transaction = self.db.begin_transaction().await?;

        // We save the funding txid and the kickoff txid to be able to track them later
        self.db
            .save_kickoff_utxo(
                &deposit_outpoint,
                &kickoff_utxo,
                &funding_utxo.outpoint.txid,
            )
            .await?;

        self.db.set_funding_utxo(&change_utxo).await?;

        transaction.commit().await?;

        Ok((kickoff_utxo, sig))
    }

    /// Checks if utxo is valid, spendable by operator and not spent
    /// Saves the utxo to the db
    async fn set_operator_funding_utxo_rpc(&self, _funding_utxo: &UTXO) -> Result<(), BridgeError> {
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
    ) -> Result<(UTXO, secp256k1::schnorr::Signature), BridgeError> {
        self.new_deposit(&deposit_utxo, &recovery_taproot_address, &evm_address)
            .await
    }

    async fn set_operator_funding_utxo_rpc(&self, funding_utxo: UTXO) -> Result<(), BridgeError> {
        self.set_operator_funding_utxo_rpc(&funding_utxo).await
    }
}
