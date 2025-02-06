use std::collections::HashMap;

use bitcoin::{hashes::Hash, Address, Amount, OutPoint, Transaction, TxOut, Txid};
use bitcoincore_rpc::{
    json::{EstimateMode, FundRawTransactionOptions},
    RpcApi,
};

use crate::{
    actor::Actor,
    builder::{
        self,
        transaction::{
            input::SpendableTxIn, output::UnspentTxOut, TxHandlerBuilder, DEFAULT_SEQUENCE,
        },
    },
    database::Database,
    errors::BridgeError,
    extended_rpc::ExtendedRpc,
};

/// Operator needs to bump fees of txs:
/// These txs should be sent fast:
/// Kickoff Tx (this depends on the number of kickoff connectors per sequential collateral tx.)
/// Start Happy Reimburse Tx
/// Assert Txs
/// Disprove Timeout
/// Reimburse Tx
/// Happy Reimburse Tx
///
/// Operator also can send these txs with RBF:
/// Payout Tx
/// Operator Challenge ACK Tx
///
struct TxSender {
    pub(crate) signer: Actor,
    pub(crate) rpc: ExtendedRpc,
    pub(crate) db: Database,
    pub(crate) network: bitcoin::Network,
}

impl TxSender {
    pub fn new(signer: Actor, rpc: ExtendedRpc, db: Database, network: bitcoin::Network) -> Self {
        Self {
            signer,
            rpc,
            db,
            network,
        }
    }

    pub async fn get_fee_rate(&self) -> Result<Amount, BridgeError> {
        let fee_rate = self
            .rpc
            .client
            .estimate_smart_fee(1, Some(EstimateMode::Conservative))
            .await;

        if fee_rate.is_err() {
            return Ok(Amount::from_sat(1));
        }

        let fee_rate = fee_rate?;
        if fee_rate.errors.is_some() {
            tracing::error!("Fee estimation errors: {:?}", fee_rate.errors);
            return Ok(Amount::from_sat(1));
            // Err(BridgeError::FeeEstimationError(
            //     fee_rate
            //         .errors
            //         .expect("Fee estimation errors should be present"),
            // ))
        } else {
            Ok(fee_rate
                .fee_rate
                .expect("Fee rate should be present when no errors"))
        }
    }

    /// We want to allocate more than the required amount to be able to bump fees.
    pub fn calculate_required_amount_for_fee_payer(
        &self,
        bumped_tx_size: u64,
        fee_rate: Amount,
    ) -> Result<Amount, BridgeError> {
        let required_amount = fee_rate * 3 * bumped_tx_size;
        Ok(required_amount)
    }

    /// Uses trick in https://bitcoin.stackexchange.com/a/106204
    async fn custom_send_to_address(
        &self,
        address: &Address,
        amount_sats: Amount,
    ) -> Result<OutPoint, BridgeError> {
        self.rpc.send_to_address(address, amount_sats).await
        // let mut outputs = HashMap::new();
        // outputs.insert(address.to_string(), amount_sats);

        // let raw_tx = self
        //     .rpc
        //     .client
        //     .create_raw_transaction(&[], &outputs, None, None)
        //     .await?;

        // let fee_rate = self.get_fee_rate().await?;

        // let options = FundRawTransactionOptions {
        //     change_position: Some(1),
        //     lock_unspents: Some(true),
        //     fee_rate: Some(fee_rate),
        //     replaceable: Some(true),
        //     ..Default::default()
        // };

        // let funded_tx = self
        //     .rpc
        //     .client
        //     .fund_raw_transaction(&raw_tx, Some(&options), Some(true))
        //     .await?;

        // // Sign the funded tx
        // let signed_tx = self
        //     .rpc
        //     .client
        //     .sign_raw_transaction_with_wallet(funded_tx.hex.as_ref() as &[u8], None, None)
        //     .await?;

        // if signed_tx.complete {
        //     let txid = self
        //         .rpc
        //         .client
        //         .send_raw_transaction(signed_tx.hex.as_ref() as &[u8])
        //         .await?;

        //     Ok(OutPoint { txid, vout: 0 })
        // } else {
        //     Err(BridgeError::BitcoinRPCSigningError(
        //         signed_tx
        //             .errors
        //             .expect("Signing errors should be present when incomplete")
        //             .iter()
        //             .map(|e| e.error.clone())
        //             .collect(),
        //     ))
        // }
    }

    pub async fn create_fee_payer_tx(
        &self,
        bumped_txid: Txid,
        bumped_tx_size: u64,
    ) -> Result<OutPoint, BridgeError> {
        let fee_rate = self.get_fee_rate().await?;
        tracing::info!("Fee rate: {}", fee_rate);
        let required_amount =
            self.calculate_required_amount_for_fee_payer(bumped_tx_size, fee_rate)?;

        tracing::info!("Required amount: {}", required_amount);

        let outpoint = self
            .custom_send_to_address(&self.signer.address, required_amount)
            .await?;

        // save the db
        // self.db.save_fee_payer_tx(bumped_txid, outpoint.txid, outpoint.vout, self.signer.address.script_pubkey(), required_amount)?;

        Ok(outpoint)
    }

    /// Creates a child tx that spends the p2a anchor using the fee payer tx.
    /// It assumes the parent tx pays 0 fees.
    /// It also assumes the fee payer tx is signable by the self.signer.
    fn create_child_tx(
        &self,
        p2a_anchor: OutPoint,
        fee_payer_outpoint: OutPoint,
        fee_payer_amount: Amount,
        parent_tx_size: Amount,
        fee_rate: Amount,
    ) -> Result<Transaction, BridgeError> {
        let (address, spend_info) = builder::address::create_taproot_address(
            &[],
            Some(self.signer.xonly_public_key),
            self.network,
        );

        let child_tx_size = Amount::from_sat(300); // TODO: Fix this.
        let required_fee = fee_rate * (child_tx_size + parent_tx_size).to_sat();

        let mut builder = TxHandlerBuilder::new()
            .add_input(
                SpendableTxIn::new_partial(p2a_anchor, builder::transaction::anchor_output()),
                DEFAULT_SEQUENCE,
            )
            .add_input(
                SpendableTxIn::new(
                    fee_payer_outpoint,
                    TxOut {
                        value: fee_payer_amount,
                        script_pubkey: address.script_pubkey(),
                    },
                    vec![],
                    Some(spend_info),
                ),
                DEFAULT_SEQUENCE,
            )
            .add_output(UnspentTxOut::from_partial(TxOut {
                value: fee_payer_amount - required_fee,
                script_pubkey: address.script_pubkey(), // TODO: This should be the wallet address, not the signer address
            }))
            .finalize();

        let sighash = builder.calculate_pubkey_spend_sighash(1, None)?;
        let signature = self.signer.sign_with_tweak(sighash, None)?;
        builder.set_p2tr_key_spend_witness(
            &bitcoin::taproot::Signature {
                signature,
                sighash_type: bitcoin::TapSighashType::All,
            },
            1,
        )?;
        let child_tx = builder.get_cached_tx().clone();
        let child_tx_size = child_tx.weight().to_wu();
        tracing::info!("Child tx size: {}", child_tx_size);
        Ok(builder.get_cached_tx().clone())
    }

    /// This will just persist the raw tx to the db
    pub async fn send_tx_with_cpfp(&self, tx: Transaction) -> Result<(), BridgeError> {
        let bumped_txid = tx.compute_txid();
        // let (
        //     fee_payer_txid,
        //     fee_payer_vout,
        //     fee_payer_scriptpubkey,
        //     fee_payer_amount,
        //     is_confirmed,
        // ) = self
        //     .db
        //     .get_fee_payer_tx(bumped_txid, self.signer.address.script_pubkey())?;

        // Now create the raw tx.

        // let txid = self.rpc.client.submit_package(tx).await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {

    // Imports required for create_test_config_with_thread_name macro.
    use crate::config::BridgeConfig;
    use crate::utils::initialize_logger;
    use crate::{create_test_config_with_thread_name, database::Database, initialize_database};
    use std::env;
    use std::thread;

    use bitcoin::consensus::encode::deserialize_hex;
    use bitcoin::secp256k1::SecretKey;
    use secp256k1::rand;

    use super::*;

    async fn create_test_tx_sender() -> (TxSender, ExtendedRpc, Database) {
        let sk = SecretKey::new(&mut rand::thread_rng());
        let network = bitcoin::Network::Regtest;
        let actor = Actor::new(sk, None, network);

        let config = create_test_config_with_thread_name!(None);
        let rpc = ExtendedRpc::connect(
            config.bitcoin_rpc_url.clone(),
            config.bitcoin_rpc_user.clone(),
            config.bitcoin_rpc_password.clone(),
        )
        .await
        .unwrap();

        let db = Database::new(&config).await.unwrap();

        let tx_sender = TxSender::new(actor, rpc.clone(), db.clone(), network);

        (tx_sender, rpc, db)
    }

    #[tokio::test]
    async fn test_create_fee_payer_tx() {
        let (tx_sender, rpc, _db) = create_test_tx_sender().await;

        let outpoint = tx_sender
            .create_fee_payer_tx(Txid::all_zeros(), 300000)
            .await
            .unwrap();

        let tx = rpc
            .client
            .get_raw_transaction(&outpoint.txid, None)
            .await
            .unwrap();

        println!("tx: {:#?}", tx);
    }
}
