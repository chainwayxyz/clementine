//! # Extended Remote Procedure Call
//!
//! This module provides helpful functions for Bitcoin RPC.

use crate::builder;
use crate::builder::transaction::create_btc_tx;
use crate::errors::BridgeError;
use crate::EVMAddress;
use bitcoin::address::NetworkUnchecked;
use bitcoin::Address;
use bitcoin::Amount;
use bitcoin::BlockHash;
use bitcoin::OutPoint;
use bitcoin::ScriptBuf;
use bitcoin::Transaction;
use bitcoin::TxIn;
use bitcoin::TxOut;
use bitcoin::Witness;
use bitcoin::XOnlyPublicKey;
use bitcoincore_rpc::Auth;
use bitcoincore_rpc::Client;
use bitcoincore_rpc::RpcApi;

#[derive(Debug)]
pub struct ExtendedRpc {
    url: String,
    auth: Auth,
    pub client: Client,
}

impl ExtendedRpc {
    /// Connects to Bitcoin RPC and returns a new `ExtendedRpc`.
    ///
    /// # Panics
    ///
    /// Panics if it cannot connect to Bitcoin RPC.
    pub async fn new(url: String, user: String, password: String) -> Self {
        let auth = Auth::UserPass(user, password);

        let rpc = Client::new(&url, auth.clone())
            .await
            .unwrap_or_else(|e| panic!("Failed to connect to Bitcoin RPC: {}", e));

        Self {
            url,
            auth,
            client: rpc,
        }
    }

    #[tracing::instrument(skip(self), err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
    pub async fn confirmation_blocks(&self, txid: &bitcoin::Txid) -> Result<u32, BridgeError> {
        let raw_transaction_results = self.client.get_raw_transaction_info(txid, None).await?;

        raw_transaction_results
            .confirmations
            .ok_or(BridgeError::NoConfirmationData)
    }

    #[tracing::instrument(skip(self), err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
    pub async fn check_utxo_address_and_amount(
        &self,
        outpoint: &OutPoint,
        address: &ScriptBuf,
        amount_sats: Amount,
    ) -> Result<bool, BridgeError> {
        let tx = self
            .client
            .get_raw_transaction(&outpoint.txid, None)
            .await?;

        let current_output = tx.output[outpoint.vout as usize].clone();

        let expected_output = TxOut {
            script_pubkey: address.clone(),
            value: amount_sats,
        };

        Ok(expected_output == current_output)
    }

    #[tracing::instrument(skip(self), err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
    pub async fn is_utxo_spent(&self, outpoint: &OutPoint) -> Result<bool, BridgeError> {
        let res = self
            .client
            .get_tx_out(&outpoint.txid, outpoint.vout, Some(true))
            .await?;

        Ok(res.is_none())
    }

    /// Mines blocks to a new address.
    #[tracing::instrument(skip(self), err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
    pub async fn mine_blocks(&self, block_num: u64) -> Result<Vec<BlockHash>, BridgeError> {
        let new_address = self
            .client
            .get_new_address(None, None)
            .await?
            .assume_checked();

        Ok(self
            .client
            .generate_to_address(block_num, &new_address)
            .await?)
    }

    #[tracing::instrument(skip(self), err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
    pub async fn send_to_address(
        &self,
        address: &Address,
        amount_sats: Amount,
    ) -> Result<OutPoint, BridgeError> {
        let txid = self
            .client
            .send_to_address(address, amount_sats, None, None, None, None, None, None)
            .await?;

        let tx_result = self.client.get_transaction(&txid, None).await?;
        let vout = tx_result.details[0].vout;

        Ok(OutPoint { txid, vout })
    }

    #[tracing::instrument(skip(self), err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
    pub async fn get_txout_from_outpoint(&self, outpoint: &OutPoint) -> Result<TxOut, BridgeError> {
        let tx = self
            .client
            .get_raw_transaction(&outpoint.txid, None)
            .await?;
        let txout = tx.output[outpoint.vout as usize].clone();

        Ok(txout)
    }

    #[tracing::instrument(skip(self), err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
    pub async fn check_deposit_utxo(
        &self,
        nofn_xonly_pk: XOnlyPublicKey,
        deposit_outpoint: &OutPoint,
        recovery_taproot_address: &Address<NetworkUnchecked>,
        evm_address: EVMAddress,
        amount_sats: Amount,
        confirmation_block_count: u32,
        network: bitcoin::Network,
        user_takes_after: u32,
    ) -> Result<(), BridgeError> {
        if self.confirmation_blocks(&deposit_outpoint.txid).await? < confirmation_block_count {
            return Err(BridgeError::DepositNotFinalized);
        }

        let (deposit_address, _) = builder::address::generate_deposit_address(
            nofn_xonly_pk,
            recovery_taproot_address,
            evm_address,
            amount_sats,
            network,
            user_takes_after,
        );

        if !self
            .check_utxo_address_and_amount(
                deposit_outpoint,
                &deposit_address.script_pubkey(),
                amount_sats,
            )
            .await?
        {
            return Err(BridgeError::InvalidDepositUTXO);
        }

        if self.is_utxo_spent(deposit_outpoint).await? {
            return Err(BridgeError::UTXOSpent);
        }

        Ok(())
    }
}

impl Clone for ExtendedRpc {
    fn clone(&self) -> Self {
        let new_client = futures::executor::block_on(Client::new(&self.url, self.auth.clone()))
            .unwrap_or_else(|e| panic!("Failed to clone Bitcoin RPC client: {}", e));

        Self {
            url: self.url.clone(),
            auth: self.auth.clone(),
            client: new_client,
        }
    }
}

/// For now, we will implement the fee bumping feature to have an effective fee rate = 1 (TODO).
/// Parent transaction needs to be signed (ready to be broadcasted) and have a P2A output.
#[allow(async_fn_in_trait)]
pub trait FeeBumper {
    async fn fund_parent(&self, parent_tx: Transaction) -> Result<Vec<Transaction>, BridgeError>;
}

impl FeeBumper for ExtendedRpc {
    #[tracing::instrument(skip(self), err(level = tracing::Level::ERROR), ret(level = tracing::Level::TRACE))]
    async fn fund_parent(&self, parent_tx: Transaction) -> Result<Vec<Transaction>, BridgeError> {
        // First, check if the transaction has an P2A output as its last output.
        let last_output = parent_tx.output.last().unwrap();
        let last_script = last_output.script_pubkey.to_hex_string();
        if last_script != "51024e73" {
            return Err(BridgeError::NoP2AOutputFound);
        }
        // Second, using the wallet, create a transaction that spends the P2A output with enough fee rate.
        let anchor_outpoint: OutPoint = OutPoint {
            txid: parent_tx.compute_txid(),
            vout: parent_tx.output.len() as u32 - 1,
        };
        let anchor_txin = TxIn {
            previous_output: anchor_outpoint,
            sequence: bitcoin::transaction::Sequence::ENABLE_RBF_NO_LOCKTIME,
            script_sig: ScriptBuf::default(),
            witness: Witness::new(),
        };
        let txout = TxOut {
            value: Amount::from_sat(0),
            script_pubkey: ScriptBuf::from_hex("6a").unwrap(),
        };
        let tx = create_btc_tx(vec![anchor_txin], vec![txout]);
        let funded_tx = self
            .client
            .fund_raw_transaction(
                &tx,
                Some(&bitcoincore_rpc::json::FundRawTransactionOptions {
                    add_inputs: Some(true),
                    change_address: None,
                    change_position: Some(0),
                    change_type: None,
                    include_watching: None,
                    lock_unspents: None,
                    fee_rate: Some(Amount::from_sat(2)),
                    subtract_fee_from_outputs: None,
                    replaceable: None,
                    conf_target: None,
                    estimate_mode: None,
                }),
                None,
            )
            .await?
            .hex;

        let signed_tx: Transaction = bitcoin::consensus::deserialize(
            &self
                .client
                .sign_raw_transaction_with_wallet(&funded_tx, None, None)
                .await?
                .hex,
        )?;

        Ok(vec![parent_tx, signed_tx])
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use bitcoin::hashes::Hash;
    use bitcoin::{
        params::Params, sighash::SighashCache, Address, Amount, Network, Script, ScriptBuf,
        TapTweakHash, TxOut, Witness,
    };
    use bitcoincore_rpc::{Auth, RpcApi};
    use secp256k1::Message;

    use crate::{
        builder::transaction::{create_btc_tx, create_tx_ins, create_tx_outs},
        extended_rpc::FeeBumper,
    };

    #[tokio::test]
    async fn test_funding_parent() {
        // let rpc = bitcoincore_rpc::Client::new("http://127.0.0.1:18443", Auth::UserPass("admin".to_string(), "admin".to_string())).await.unwrap();
        let extended_rpc = super::ExtendedRpc::new(
            "http://127.0.0.1:18443".to_string(),
            "admin".to_string(),
            "admin".to_string(),
        )
        .await;
        let secp = bitcoin::secp256k1::Secp256k1::new();
        let secret_key_str: &str =
            "1111111111111111111111111111111111111111111111111111111111111111";
        let secret_key = bitcoin::secp256k1::SecretKey::from_str(secret_key_str).unwrap();
        let keypair = bitcoin::secp256k1::Keypair::from_secret_key(&secp, &secret_key);
        let (xonly_public_key, _parity) =
            bitcoin::secp256k1::XOnlyPublicKey::from_keypair(&keypair);
        println!("XOnly Public Key: {}", xonly_public_key);
        let taproot_address = Address::p2tr(&secp, xonly_public_key, None, Network::Regtest);
        println!("Taproot address: {}", taproot_address);
        println!(
            "Taproot address script: {}",
            taproot_address.script_pubkey()
        );
        let taproot_xonly_pubkey_bytes: [u8; 32] = taproot_address.script_pubkey().to_bytes()
            [2..34]
            .try_into()
            .unwrap();
        println!(
            "Taproot XOnly Public Key Bytes: {:?}",
            taproot_xonly_pubkey_bytes
        );
        let taproot_xonly_pubkey =
            bitcoin::secp256k1::XOnlyPublicKey::from_slice(&taproot_xonly_pubkey_bytes).unwrap();
        println!("Taproot XOnly Public Key: {}", taproot_xonly_pubkey);
        // let outpoint = extended_rpc.send_to_address(&Address::from_script(&Script::from_bytes(&[0x51, 0x02, 0x4e, 0x73]), Params::REGTEST).unwrap(), Amount::from_sat(240)).await.unwrap();
        let outpoint = extended_rpc
            .send_to_address(&taproot_address, Amount::from_sat(100000))
            .await
            .unwrap();
        let zero_fee_txins = create_tx_ins(vec![outpoint]);
        let zero_fee_txouts = create_tx_outs(vec![
            (Amount::from_sat(99760), taproot_address.script_pubkey()),
            (
                Amount::from_sat(240),
                Address::from_script(
                    &Script::from_bytes(&[0x51, 0x02, 0x4e, 0x73]),
                    Params::REGTEST,
                )
                .unwrap()
                .script_pubkey(),
            ),
        ]);
        let mut zero_fee_tx = create_btc_tx(zero_fee_txins, zero_fee_txouts);
        let prevout = TxOut {
            value: Amount::from_sat(100000),
            script_pubkey: taproot_address.script_pubkey(),
        };
        let prevouts = vec![prevout];
        let mut sighash_cache = SighashCache::new(zero_fee_tx.clone());

        let sig_hash = sighash_cache
            .taproot_key_spend_signature_hash(
                0,
                &bitcoin::sighash::Prevouts::All(&prevouts),
                bitcoin::sighash::TapSighashType::Default,
            )
            .unwrap();

        let child_sig = secp.sign_schnorr(
            &Message::from_digest_slice(sig_hash.as_byte_array()).expect("should be hash"),
            &keypair
                .add_xonly_tweak(
                    &secp,
                    &TapTweakHash::from_key_and_tweak(xonly_public_key, None).to_scalar(),
                )
                .unwrap(),
        );
        zero_fee_tx.input[0].witness = Witness::from_slice(&[child_sig.as_ref()]);
        let tx_vec = extended_rpc.fund_parent(zero_fee_tx).await.unwrap();
        println!("Parent tx: {:#?}", tx_vec[0]);
        println!("Child tx: {:#?}", tx_vec[1]);
    }
}
