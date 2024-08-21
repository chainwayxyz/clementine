use crate::actor::Actor;
use crate::config::BridgeConfig;
use crate::errors::BridgeError;
use crate::extended_rpc::ExtendedRpc;
use crate::musig2::{self};
use crate::transaction_builder::TransactionBuilder;
use crate::{EVMAddress, UTXO};
use ::musig2::secp::Point;
use bitcoin::{Address, TxOut};
use bitcoin::{Amount, OutPoint};
use bitcoin::{TapSighashType, XOnlyPublicKey};
use bitcoin_mock_rpc::RpcApiWrapper;
use clementine_circuits::constants::BRIDGE_AMOUNT_SATS;
use secp256k1::SecretKey;
use secp256k1::{schnorr, PublicKey};

#[derive(Debug)]
pub struct User<R> {
    rpc: ExtendedRpc<R>,
    signer: Actor,
    config: BridgeConfig,
    nofn_xonly_pk: XOnlyPublicKey,
}

impl<R> User<R>
where
    R: RpcApiWrapper,
{
    /// Creates a new `User`.
    pub fn new(rpc: ExtendedRpc<R>, sk: SecretKey, config: BridgeConfig) -> Self {
        let signer = Actor::new(sk, config.network);

        let key_agg_context =
            musig2::create_key_agg_ctx(config.verifiers_public_keys.clone(), None).unwrap();
        let agg_point: Point = key_agg_context.aggregated_pubkey_untweaked();
        let nofn_xonly_pk =
            secp256k1::XOnlyPublicKey::from_slice(&agg_point.serialize_xonly()).unwrap();

        User {
            rpc,
            signer,
            config,
            nofn_xonly_pk,
        }
    }

    pub fn deposit_tx(
        &self,
        evm_address: EVMAddress,
    ) -> Result<(OutPoint, XOnlyPublicKey, EVMAddress), BridgeError> {
        let (deposit_address, _) = TransactionBuilder::generate_deposit_address(
            &self.nofn_xonly_pk,
            self.signer.address.as_unchecked(),
            &evm_address,
            BRIDGE_AMOUNT_SATS,
            self.config.user_takes_after,
            self.config.network,
        );

        let deposit_utxo = self
            .rpc
            .send_to_address(&deposit_address, BRIDGE_AMOUNT_SATS)?;

        Ok((deposit_utxo, self.signer.xonly_public_key, evm_address))
    }

    pub fn get_deposit_address(&self, evm_address: EVMAddress) -> Result<Address, BridgeError> {
        let (deposit_address, _) = TransactionBuilder::generate_deposit_address(
            &self.nofn_xonly_pk,
            self.signer.address.as_unchecked(),
            &evm_address,
            BRIDGE_AMOUNT_SATS,
            self.config.user_takes_after,
            self.config.network,
        );

        Ok(deposit_address)
    }

    pub fn generate_withdrawal_sig(
        &self,
        withdrawal_address: Address,
    ) -> Result<(UTXO, TxOut, schnorr::Signature), BridgeError> {
        let dust_outpoint = self.rpc.send_to_address(&self.signer.address, 550)?; // TODO: make this a constants
        let dust_utxo = UTXO {
            outpoint: dust_outpoint,
            txout: TxOut {
                value: Amount::from_sat(550),
                script_pubkey: self.signer.address.script_pubkey(),
            },
        };
        let txins = TransactionBuilder::create_tx_ins(vec![dust_utxo.outpoint]);
        let txout = TxOut {
            value: Amount::from_sat(BRIDGE_AMOUNT_SATS),
            script_pubkey: withdrawal_address.script_pubkey(),
        };
        let txouts = vec![txout.clone()];
        let mut tx = TransactionBuilder::create_btc_tx(txins, txouts.clone());
        let prevouts = vec![dust_utxo.txout.clone()];
        let sig = self.signer.sign_taproot_pubkey_spend_tx_with_sighash(
            &mut tx,
            &prevouts,
            0,
            Some(TapSighashType::SinglePlusAnyoneCanPay),
        )?;
        Ok((dust_utxo, txout, sig))
    }
}
