use bitcoin::{
    transaction::Version, Address, Amount, FeeRate, OutPoint, Transaction, TxOut, Txid, Weight,
};
use bitcoincore_rpc::{json::EstimateMode, RpcApi};
use tokio::sync::broadcast::Receiver;

use crate::{
    actor::Actor,
    bitcoin_syncer::BitcoinSyncerEvent,
    builder::{
        self,
        script::SpendPath,
        transaction::{
            input::SpendableTxIn, output::UnspentTxOut, TxHandlerBuilder, DEFAULT_SEQUENCE,
        },
    },
    database::Database,
    errors::BridgeError,
    extended_rpc::ExtendedRpc,
    rpc::clementine::NormalSignatureKind,
};

#[derive(Clone, Debug)]
pub struct TxSender {
    pub signer: Actor,
    pub rpc: ExtendedRpc,
    pub db: Database,
    pub network: bitcoin::Network,
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

    pub async fn get_fee_rate(&self) -> Result<FeeRate, BridgeError> {
        let fee_rate = self
            .rpc
            .client
            .estimate_smart_fee(1, Some(EstimateMode::Conservative))
            .await;

        if fee_rate.is_err() {
            return Ok(FeeRate::from_sat_per_vb_unchecked(1));
        }

        let fee_rate = fee_rate?;
        if fee_rate.errors.is_some() {
            if self.network == bitcoin::Network::Regtest {
                tracing::error!("Fee estimation errors: {:?}", fee_rate.errors);
                Ok(FeeRate::from_sat_per_vb_unchecked(1))
            } else {
                Err(BridgeError::FeeEstimationError(
                    fee_rate
                        .errors
                        .expect("Fee estimation errors should be present"),
                ))
            }
        } else {
            Ok(FeeRate::from_sat_per_kwu(
                fee_rate
                    .fee_rate
                    .expect("Fee rate should be present when no errors")
                    .to_sat(),
            ))
        }
    }

    /// We want to allocate more than the required amount to be able to bump fees.
    pub fn calculate_required_amount_for_fee_payer(
        &self,
        bumped_tx_size: Weight,
        fee_rate: FeeRate,
    ) -> Result<Amount, BridgeError> {
        let required_fee = fee_rate
            .checked_mul_by_weight(bumped_tx_size)
            .ok_or(BridgeError::Overflow)?;
        Ok(required_fee * 3)
    }

    /// Uses trick in https://bitcoin.stackexchange.com/a/106204
    async fn custom_send_to_address(
        &self,
        address: &Address,
        amount_sats: Amount,
    ) -> Result<OutPoint, BridgeError> {
        // TODO: Fix the issue with create_raw_transaction and use the code below.
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
        bumped_tx_size: Weight,
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
        self.db
            .save_fee_payer_tx(
                None,
                bumped_txid,
                outpoint.txid,
                outpoint.vout,
                self.signer.address.script_pubkey(),
                required_amount,
                None,
            )
            .await?;

        tracing::info!(
            "Fee payer tx saved to db with bumped txid: {} and script pubkey: {}",
            bumped_txid,
            self.signer.address.script_pubkey()
        );

        Ok(outpoint)
    }

    /// Creates a child tx that spends the p2a anchor using the fee payer tx.
    /// It assumes the parent tx pays 0 fees.
    /// It also assumes the fee payer tx is signable by the self.signer.
    fn create_child_tx(
        &self,
        p2a_anchor: OutPoint,
        fee_payer_utxos: Vec<SpendableTxIn>,
        parent_tx_size: Weight,
        fee_rate: FeeRate,
        change_address: Address,
    ) -> Result<Transaction, BridgeError> {
        let child_tx_size = Weight::from_wu_usize(230 * fee_payer_utxos.len() + 200); // TODO: Fix this 200 constant, it should be p2a anchor size + change output size.
        let total_weight = child_tx_size + parent_tx_size;
        let required_fee = fee_rate
            .checked_mul_by_weight(total_weight)
            .ok_or(BridgeError::Overflow)?;

        let total_fee_payer_amount = fee_payer_utxos
            .iter()
            .map(|utxo| utxo.get_prevout().value)
            .sum::<Amount>()
            + builder::transaction::anchor_output().value; // We add the anchor output value to the total amount.

        if change_address.script_pubkey().minimal_non_dust() + required_fee > total_fee_payer_amount
        {
            return Err(BridgeError::InsufficientFeePayerAmount);
        }

        let mut builder = TxHandlerBuilder::new()
            .with_version(Version::non_standard(3))
            .add_input(
                NormalSignatureKind::NotStored,
                SpendableTxIn::new_partial(p2a_anchor, builder::transaction::anchor_output()),
                SpendPath::Unknown,
                DEFAULT_SEQUENCE,
            );

        for fee_payer_utxo in fee_payer_utxos {
            builder = builder.add_input(
                NormalSignatureKind::NotStored,
                fee_payer_utxo,
                SpendPath::KeySpend,
                DEFAULT_SEQUENCE,
            );
        }

        builder = builder.add_output(UnspentTxOut::from_partial(TxOut {
            value: total_fee_payer_amount - required_fee,
            script_pubkey: change_address.script_pubkey(),
        }));

        let mut tx_handler = builder.finalize();

        let sighash = tx_handler.calculate_pubkey_spend_sighash(1, None)?;
        let signature = self.signer.sign_with_tweak(sighash, None)?;
        tx_handler.set_p2tr_key_spend_witness(
            &bitcoin::taproot::Signature {
                signature,
                sighash_type: bitcoin::TapSighashType::Default,
            },
            1,
        )?;
        let child_tx = tx_handler.get_cached_tx().clone();
        Ok(child_tx)
    }

    fn is_p2a_anchor(&self, output: &TxOut) -> bool {
        output.value == builder::transaction::anchor_output().value
            && output.script_pubkey == builder::transaction::anchor_output().script_pubkey
    }

    fn find_p2a_vout(&self, tx: &Transaction) -> Result<usize, BridgeError> {
        let p2a_anchor = tx
            .output
            .iter()
            .enumerate()
            .find(|(_, output)| self.is_p2a_anchor(output));
        if let Some((vout, _)) = p2a_anchor {
            Ok(vout)
        } else {
            Err(BridgeError::P2AAnchorNotFound)
        }
    }

    pub async fn send_tx_with_cpfp(&self, _txid: Txid) -> Result<f64, BridgeError> {
        Ok(0.0)
    }

    /// This will just persist the raw tx to the db
    pub async fn save_tx(&self, tx: Transaction) -> Result<f64, BridgeError> {
        let bumped_txid = tx.compute_txid();
        let p2a_vout = self.find_p2a_vout(&tx)?;
        tracing::info!(
            "Bumped txid: {} and script pubkey: {}",
            bumped_txid,
            self.signer.address.script_pubkey()
        );
        let fee_payer_txs: Vec<(Txid, u32, Amount, bool)> = self
            .db
            .get_fee_payer_tx(None, bumped_txid, self.signer.address.script_pubkey())
            .await?;

        if fee_payer_txs.is_empty() {
            return Err(BridgeError::FeePayerTxNotFound);
        }

        // Persist the tx to the db
        // self.db.save_tx(None, bumped_txid, tx).await?;

        // get confirmed fee payer tx
        let (fee_payer_txid, fee_payer_vout, fee_payer_amount, _) = fee_payer_txs
            .iter()
            .find(|(_, _, _, is_confirmed)| *is_confirmed)
            .ok_or(BridgeError::ConfirmedFeePayerTxNotFound)?;

        let fee_rate = self.get_fee_rate().await?;

        // Now create the raw tx.
        let child_tx = self.create_child_tx(
            OutPoint {
                txid: bumped_txid,
                vout: p2a_vout as u32,
            },
            vec![SpendableTxIn::new(
                OutPoint {
                    txid: *fee_payer_txid,
                    vout: *fee_payer_vout,
                },
                TxOut {
                    value: *fee_payer_amount,
                    script_pubkey: self.signer.address.script_pubkey(),
                },
                vec![],
                Some(
                    builder::address::create_taproot_address(
                        &[],
                        Some(self.signer.xonly_public_key),
                        self.network,
                    )
                    .1,
                ),
            )],
            tx.weight(),
            fee_rate,
            self.signer.address.clone(),
        )?;

        tracing::info!(
            "bqr submitpackage '[\"{}\", \"{}\"]'",
            hex::encode(bitcoin::consensus::serialize(&tx)),
            hex::encode(bitcoin::consensus::serialize(&child_tx))
        );
        let submit_package_result = self.rpc.client.submit_package(vec![&tx, &child_tx]).await?;
        tracing::info!("Submit package result: {:?}", submit_package_result);
        // effective fee_rates
        let effective_fee_rates: Vec<_> = submit_package_result
            .tx_results
            .iter()
            .map(|(txid, result)| (txid.clone(), result.fees.effective_feerate))
            .collect();

        let effective_fee_rate = effective_fee_rates[0]
            .1
            .expect("Effective fee rate should be present");

        tracing::info!("Effective fee rates: {:?}", effective_fee_rates);
        Ok(effective_fee_rate)
    }

    pub async fn bump_fees_of_fee_payer_txs(
        &self,
        bumped_txid: Txid,
        fee_rate: FeeRate,
    ) -> Result<(), BridgeError> {
        let bumpable_fee_payer_txs = self
            .db
            .get_bumpable_fee_payer_txs(None, bumped_txid)
            .await?;

        for (id, fee_payer_txid, vout, amount, script_pubkey) in bumpable_fee_payer_txs {
            let bump_fee_result = self
                .rpc
                .client
                .bump_fee(
                    &fee_payer_txid,
                    Some(&bitcoincore_rpc::json::BumpFeeOptions {
                        fee_rate: Some(bitcoincore_rpc::json::FeeRate::per_vbyte(
                            Amount::from_sat(fee_rate.to_sat_per_vb_ceil()),
                        )),
                        replaceable: Some(true),
                        ..Default::default()
                    }),
                )
                .await?;

            if let Some(new_txid) = bump_fee_result.txid {
                self.db
                    .save_fee_payer_tx(
                        None,
                        bumped_txid,
                        new_txid,
                        vout,
                        script_pubkey,
                        amount,
                        Some(id),
                    )
                    .await?;
            }
        }

        Ok(())
    }

    /// Tries to send unconfirmed txs that have a new effective fee rate.
    pub async fn try_to_send_unconfirmed_txs(
        &self,
        new_effective_fee_rate: FeeRate,
    ) -> Result<(), BridgeError> {
        let txs = self
            .db
            .get_unconfirmed_txs(None, new_effective_fee_rate)
            .await?;
        for (txid, _tx) in txs {
            self.send_tx_with_cpfp(txid).await?;
        }
        Ok(())
    }

    pub async fn apply_block(&self, blockhash: &bitcoin::BlockHash) -> Result<(), BridgeError> {
        let block = self.rpc.client.get_block(blockhash).await?;

        for tx in block.txdata {
            let txid = tx.compute_txid();
            self.db.confirm_fee_payer_tx(None, txid, *blockhash).await?;
        }

        Ok(())
    }

    pub async fn apply_reorg(&self, _reorg_block: &bitcoin::BlockHash) -> Result<(), BridgeError> {
        // self.apply_block(&reorg_block).await?;
        Ok(())
    }

    pub async fn bitcoin_syncer_event_handler(
        &self,
        bitcoin_syncer_receiver: &mut Receiver<BitcoinSyncerEvent>,
    ) -> Result<(), BridgeError> {
        loop {
            let event = bitcoin_syncer_receiver.recv().await?;
            match event {
                BitcoinSyncerEvent::NewBlocks(block_hashes) => {
                    for block in block_hashes {
                        self.apply_block(&block.block_hash).await?;
                    }
                }
                BitcoinSyncerEvent::NewBlocksWithTxs(_) => {
                    // panic
                    return Err(BridgeError::Error(
                        "New blocks with txs not implemented".to_string(),
                    ));
                }
                BitcoinSyncerEvent::ReorgedBlocks(block_hashes) => {
                    for block in block_hashes {
                        self.apply_reorg(&block).await?;
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    // Imports required for create_test_config_with_thread_name macro.
    use crate::config::BridgeConfig;
    use crate::utils::initialize_logger;
    use crate::{create_test_config_with_thread_name, database::Database, initialize_database};

    use bitcoin::secp256k1::SecretKey;
    use bitcoin::transaction::Version;
    use secp256k1::rand;

    use super::*;

    async fn create_test_tx_sender() -> (TxSender, ExtendedRpc, Database, Actor, bitcoin::Network) {
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

        let tx_sender = TxSender::new(actor.clone(), rpc.clone(), db.clone(), network);

        (tx_sender, rpc, db, actor, network)
    }

    async fn create_bumpable_tx(
        rpc: &ExtendedRpc,
        signer: Actor,
        network: bitcoin::Network,
    ) -> Result<Transaction, BridgeError> {
        let (address, spend_info) =
            builder::address::create_taproot_address(&[], Some(signer.xonly_public_key), network);

        let amount = Amount::from_sat(100000);
        let outpoint = rpc.send_to_address(&address, amount).await?;
        rpc.mine_blocks(1).await?;

        let mut builder = TxHandlerBuilder::new()
            .with_version(Version::non_standard(3))
            .add_input(
                NormalSignatureKind::NotStored,
                SpendableTxIn::new(
                    outpoint,
                    TxOut {
                        value: amount,
                        script_pubkey: address.script_pubkey(),
                    },
                    vec![],
                    Some(spend_info),
                ),
                SpendPath::KeySpend,
                DEFAULT_SEQUENCE,
            )
            .add_output(UnspentTxOut::from_partial(TxOut {
                value: amount - builder::transaction::anchor_output().value,
                script_pubkey: address.script_pubkey(), // TODO: This should be the wallet address, not the signer address
            }))
            .add_output(UnspentTxOut::from_partial(
                builder::transaction::anchor_output(),
            ))
            .finalize();

        let signature = signer.sign_taproot_pubkey_spend(&mut builder, 0, None)?;
        builder.set_p2tr_key_spend_witness(
            &bitcoin::taproot::Signature {
                signature,
                sighash_type: bitcoin::TapSighashType::Default,
            },
            0,
        )?;

        let tx = builder.get_cached_tx().clone();
        Ok(tx)
    }
    #[tokio::test]
    #[serial_test::serial]
    async fn test_create_fee_payer_tx() {
        let (tx_sender, rpc, _db, signer, network) = create_test_tx_sender().await;

        let tx = create_bumpable_tx(&rpc, signer, network).await.unwrap();

        let outpoint = tx_sender
            .create_fee_payer_tx(tx.compute_txid(), tx.weight())
            .await
            .unwrap();

        // tokio::time::sleep(Duration::from_millis(100)).await;

        let fee_payer_tx = rpc
            .client
            .get_raw_transaction(&outpoint.txid, None)
            .await
            .unwrap();

        tx_sender
            .bump_fees_of_fee_payer_txs(tx.compute_txid(), FeeRate::from_sat_per_vb_unchecked(2))
            .await
            .unwrap();

        assert!(fee_payer_tx.output[outpoint.vout as usize].value.to_sat() > tx.weight().to_wu());

        // Mine a block and wait for confirmation
        rpc.mine_blocks(1).await.unwrap();

        // Give enough time for the block to be processed and event to be handled
        // tokio::time::sleep(Duration::from_secs(20)).await;
        let latest_block_hash = rpc.client.get_best_block_hash().await.unwrap();
        tx_sender.apply_block(&latest_block_hash).await.unwrap();

        // Send the CPFP transaction
        tx_sender.save_tx(tx).await.unwrap();

        // Clean shutdown of background tasks
        // drop(sender); // This will cause the receiver loop to exit
    }
}
