use crate::actor::Actor;
use crate::config::BridgeConfig;
use crate::errors::BridgeError;
use crate::extended_rpc::ExtendedRpc;
use crate::musig2::AggregateFromPublicKeys;
use crate::transaction_builder::TransactionBuilder;
use crate::{EVMAddress, UTXO};
use bitcoin::{Address, TxOut};
use bitcoin::{Amount, OutPoint};
use bitcoin::{TapSighashType, XOnlyPublicKey};
use bitcoin_mock_rpc::RpcApiWrapper;
use secp256k1::schnorr;
use secp256k1::SecretKey;

pub const WITHDRAWAL_EMPTY_UTXO_SATS: u64 = 550;

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

        let nofn_xonly_pk = secp256k1::XOnlyPublicKey::from_musig2_pks(
            config.verifiers_public_keys.clone(),
            None,
            false,
        );

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
            self.config.bridge_amount_sats,
            self.config.network,
            self.config.user_takes_after,
        );

        let deposit_outpoint = self
            .rpc
            .send_to_address(&deposit_address, self.config.bridge_amount_sats)?;

        Ok((deposit_outpoint, self.signer.xonly_public_key, evm_address))
    }

    pub fn get_deposit_address(&self, evm_address: EVMAddress) -> Result<Address, BridgeError> {
        let (deposit_address, _) = TransactionBuilder::generate_deposit_address(
            &self.nofn_xonly_pk,
            self.signer.address.as_unchecked(),
            &evm_address,
            self.config.bridge_amount_sats,
            self.config.network,
            self.config.user_takes_after,
        );

        Ok(deposit_address)
    }

    pub fn generate_withdrawal_sig(
        &self,
        withdrawal_address: Address,
        withdrawal_amount: u64,
    ) -> Result<(UTXO, TxOut, schnorr::Signature), BridgeError> {
        let dust_outpoint = self
            .rpc
            .send_to_address(&self.signer.address, WITHDRAWAL_EMPTY_UTXO_SATS)?;
        let dust_utxo = UTXO {
            outpoint: dust_outpoint,
            txout: TxOut {
                value: Amount::from_sat(WITHDRAWAL_EMPTY_UTXO_SATS),
                script_pubkey: self.signer.address.script_pubkey(),
            },
        };
        let txins = TransactionBuilder::create_tx_ins(vec![dust_utxo.outpoint]);
        let txout = TxOut {
            value: Amount::from_sat(withdrawal_amount), // TODO: Change this in the future since Operators should profit from the bridge
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
