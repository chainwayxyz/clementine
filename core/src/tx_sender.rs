use bitcoin::{transaction::Version, Address, Amount, OutPoint, Transaction, TxOut, Txid, Weight};
use bitcoincore_rpc::{json::EstimateMode, RpcApi};
use tokio::sync::broadcast::Receiver;

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

use self::chain_head::ChainHeadEvent;

#[derive(Clone)]
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
            Ok(Amount::from_sat(1))
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
        bumped_tx_size: Weight,
        fee_rate: Amount,
    ) -> Result<Amount, BridgeError> {
        let required_amount = fee_rate * 3 * bumped_tx_size.to_wu();
        Ok(required_amount)
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
        fee_payer_outpoint: OutPoint,
        fee_payer_amount: Amount,
        parent_tx_size: Weight,
        fee_rate: Amount,
    ) -> Result<Transaction, BridgeError> {
        let (address, spend_info) = builder::address::create_taproot_address(
            &[],
            Some(self.signer.xonly_public_key),
            self.network,
        );

        let child_tx_size = Amount::from_sat(300); // TODO: Fix this.
        let required_fee = fee_rate * (child_tx_size.to_sat() + parent_tx_size.to_wu());

        let mut builder = TxHandlerBuilder::new()
            .with_version(Version::non_standard(3))
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
                sighash_type: bitcoin::TapSighashType::Default,
            },
            1,
        )?;
        let child_tx = builder.get_cached_tx().clone();
        let child_tx_size = child_tx.weight().to_wu();
        tracing::info!("Child tx size: {}", child_tx_size);
        Ok(builder.get_cached_tx().clone())
    }

    fn find_p2a_anchor(&self, tx: &Transaction) -> Result<OutPoint, BridgeError> {
        let p2a_anchor = tx
            .output
            .iter()
            .enumerate()
            .find(|(_, output)| output.value == builder::transaction::anchor_output().value);
        if let Some((vout, _)) = p2a_anchor {
            Ok(OutPoint::new(tx.compute_txid(), vout as u32))
        } else {
            Err(BridgeError::P2AAnchorNotFound)
        }
    }

    /// This will just persist the raw tx to the db
    pub async fn send_tx_with_cpfp(&self, tx: Transaction) -> Result<(), BridgeError> {
        let bumped_txid = tx.compute_txid();
        tracing::info!(
            "Bumped txid: {} and script pubkey: {}",
            bumped_txid,
            self.signer.address.script_pubkey()
        );
        let fee_payer_txs = self
            .db
            .get_fee_payer_tx(None, bumped_txid, self.signer.address.script_pubkey())
            .await?;

        if fee_payer_txs.is_empty() {
            return Err(BridgeError::FeePayerTxNotFound);
        }

        // get confirmed fee payer tx
        let (fee_payer_txid, fee_payer_vout, fee_payer_amount, _) = fee_payer_txs
            .iter()
            .find(|(_, _, _, is_confirmed)| *is_confirmed)
            .ok_or(BridgeError::ConfirmedFeePayerTxNotFound)?;

        let p2a_anchor = self.find_p2a_anchor(&tx)?;
        let fee_rate = self.get_fee_rate().await?;

        // Now create the raw tx.
        let child_tx = self.create_child_tx(
            p2a_anchor,
            OutPoint {
                txid: *fee_payer_txid,
                vout: *fee_payer_vout,
            },
            *fee_payer_amount,
            tx.weight(),
            fee_rate,
        )?;

        tracing::info!(
            "bqr submitpackage '[\"{}\", \"{}\"]'",
            hex::encode(bitcoin::consensus::serialize(&tx)),
            hex::encode(bitcoin::consensus::serialize(&child_tx))
        );
        let submit_package_result = self.rpc.client.submit_package(vec![&tx, &child_tx]).await?;
        tracing::info!("Submit package result: {:?}", submit_package_result);
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

    pub async fn apply_new_chain_event(
        &self,
        receiver: &mut Receiver<ChainHeadEvent>,
    ) -> Result<(), BridgeError> {
        loop {
            let event = receiver.recv().await?;
            match event {
                ChainHeadEvent::NewBlock(block_hashes) => {
                    for block in block_hashes {
                        self.apply_block(&block).await?;
                    }
                }
                ChainHeadEvent::Reorg(block_hashes) => {
                    for block in block_hashes {
                        self.apply_reorg(&block).await?;
                    }
                }
            }
        }
    }
}

pub mod chain_head {
    use std::time::Duration;

    use bitcoin::BlockHash;
    use bitcoincore_rpc::RpcApi;
    use tokio::{sync::broadcast, task::JoinHandle, time::sleep};

    use crate::{database::Database, errors::BridgeError, extended_rpc::ExtendedRpc};

    type ChainHeadPollingResult = (
        broadcast::Sender<ChainHeadEvent>,
        JoinHandle<Result<(), BridgeError>>,
    );

    #[derive(Clone, Debug)]
    pub enum ChainHeadEvent {
        NewBlock(Vec<BlockHash>),
        Reorg(Vec<BlockHash>),
    }

    pub fn start_polling(
        db: Database,
        rpc: ExtendedRpc,
        poll_delay: Duration,
    ) -> Result<ChainHeadPollingResult, BridgeError> {
        let (tx, _) = broadcast::channel(100);
        let returned_tx = tx.clone();

        let handle = tokio::spawn(async move {
            loop {
                let mut block_height = rpc.client.get_block_count().await?;
                let mut block_hash = rpc.client.get_block_hash(block_height).await?;
                let mut block_header = rpc.client.get_block_header(&block_hash).await?;

                let mut new_blocks = Vec::new();
                for _ in 0..100 {
                    // if the block is in the db, do nothing
                    let height = db.get_height_from_block_hash(None, block_hash).await?;
                    if height.is_some() {
                        break;
                    }

                    new_blocks.push((block_hash, block_height, block_header.prev_blockhash));
                    block_hash = block_header.prev_blockhash;
                    block_header = rpc.client.get_block_header(&block_hash).await?;
                    block_height -= 1;
                }

                // If we haven't found a match after 100 blocks, the database is too far out of sync
                if new_blocks.len() == 100 {
                    return Err(BridgeError::BlockgazerTooDeep(block_height));
                }

                // check the reorg blocks
                let reorg_blocks = db.delete_chain_head_from_height(None, block_height).await?;

                if !reorg_blocks.is_empty() {
                    tx.send(ChainHeadEvent::Reorg(reorg_blocks))?;
                }

                let block_hashes: Vec<BlockHash> = new_blocks
                    .iter()
                    .map(|(block_hash, _, _)| *block_hash)
                    .collect();

                let mut dbtx = db.begin_transaction().await?;
                for (block_hash, block_height, prev_block_hash) in new_blocks {
                    db.set_chain_head(Some(&mut dbtx), block_hash, prev_block_hash, block_height)
                        .await?;
                }
                dbtx.commit().await?;

                if !block_hashes.is_empty() {
                    tracing::info!("New block hashes: {:?}", block_hashes);
                    tx.send(ChainHeadEvent::NewBlock(block_hashes))?;
                }

                sleep(poll_delay).await;
            }
        });
        Ok((returned_tx, handle))
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
    use std::time::Duration;

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
                SpendableTxIn::new(
                    outpoint,
                    TxOut {
                        value: amount,
                        script_pubkey: address.script_pubkey(),
                    },
                    vec![],
                    Some(spend_info),
                ),
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
    async fn test_create_fee_payer_tx() {
        let (tx_sender, rpc, db, signer, network) = create_test_tx_sender().await;

        // Save the current block height and block hash
        let current_height = rpc.client.get_block_count().await.unwrap();
        let current_block_hash = rpc.client.get_block_hash(current_height).await.unwrap();
        let current_block_header = rpc
            .client
            .get_block_header(&current_block_hash)
            .await
            .unwrap();
        db.set_chain_head(
            None,
            current_block_hash,
            current_block_header.prev_blockhash,
            current_height,
        )
        .await
        .unwrap();

        // Store sender in a variable to keep it alive
        let (sender, _handle) =
            chain_head::start_polling(db.clone(), rpc.clone(), Duration::from_secs(1)).unwrap();

        let mut receiver = sender.subscribe();

        let tx_sender_clone = tx_sender.clone();
        let _chain_event_handle = tokio::spawn(async move {
            tx_sender_clone
                .apply_new_chain_event(&mut receiver)
                .await
                .unwrap();
        });

        let tx = create_bumpable_tx(&rpc, signer, network).await.unwrap();

        let outpoint = tx_sender
            .create_fee_payer_tx(tx.compute_txid(), tx.weight())
            .await
            .unwrap();

        let fee_payer_tx = rpc
            .client
            .get_raw_transaction(&outpoint.txid, None)
            .await
            .unwrap();

        assert!(fee_payer_tx.output[outpoint.vout as usize].value.to_sat() > tx.weight().to_wu());

        // Mine a block and wait for confirmation
        rpc.mine_blocks(1).await.unwrap();

        // Give enough time for the block to be processed and event to be handled
        tokio::time::sleep(Duration::from_secs(2)).await;

        // Send the CPFP transaction
        tx_sender.send_tx_with_cpfp(tx).await.unwrap();

        // Clean shutdown of background tasks
        drop(sender); // This will cause the receiver loop to exit
    }
}
