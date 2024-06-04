//! # Bitcoin Simulator
//!
//! This module is a wrapper for Bitcoin simulators. It tries to simulate what
//! `ExtendedRpc` does.

use crate::errors::BridgeError;
use crate::traits::bitcoin_rpc::BitcoinRPC;
use crate::transaction_builder::TransactionBuilder;
use bitcoin::Amount;
use bitcoin::OutPoint;
use bitcoin::ScriptBuf;
use bitcoin::TxOut;
use bitcoin_simulator::database::Database;
use std::io::Error;
use std::sync::Arc;
use std::sync::Mutex;

#[derive(Clone)]
pub struct BitcoinMockRPC {
    database: Arc<Mutex<Database>>,
}

impl BitcoinRPC for BitcoinMockRPC {
    /// Creates a new Bitcoin simulator database.
    ///
    /// # Parameters
    ///
    /// Function parameters are not used and can be empty values.
    ///
    /// # Panics
    ///
    /// Panics if database connection cannot be established.
    fn new(_url: String, _user: String, _password: String) -> Self {
        let database = Database::connect_temporary_database().unwrap();

        Self {
            database: Arc::new(Mutex::new(database)),
        }
    }

    fn confirmation_blocks(&self, _txid: &bitcoin::Txid) -> Result<u32, BridgeError> {
        unimplemented!()
    }

    fn check_utxo_address_and_amount(
        &self,
        outpoint: &OutPoint,
        address: &ScriptBuf,
        amount_sats: u64,
    ) -> Result<bool, BridgeError> {
        let current_output = match self
            .database
            .lock()
            .unwrap()
            .get_prev_output(outpoint.txid.to_string().as_str(), outpoint.vout)
        {
            Ok(txout) => txout,
            Err(e) => {
                return Err(BridgeError::BitcoinRpcError(
                    bitcoincore_rpc::Error::ReturnedError(e.to_string()),
                ))
            }
        };

        let expected_output = TxOut {
            script_pubkey: address.clone(),
            value: Amount::from_sat(amount_sats),
        };

        Ok(expected_output == current_output)
    }

    fn is_utxo_spent(&self, outpoint: &OutPoint) -> Result<bool, BridgeError> {
        match self
            .database
            .lock()
            .unwrap()
            .check_if_output_is_spent(outpoint.txid.to_string().as_str(), outpoint.vout)
        {
            Ok(r) => Ok(r),
            Err(e) => Err(BridgeError::DatabaseError(sqlx::Error::Io(Error::other(
                e.to_string(),
            )))),
        }
    }

    fn generate_dummy_block(&self) -> Result<Vec<bitcoin::BlockHash>, BridgeError> {
        unimplemented!()
    }

    fn mine_blocks(&self, _block_num: u64) -> Result<(), BridgeError> {
        Ok(())
    }

    fn send_to_address(
        &self,
        address: &bitcoin::Address,
        amount_sats: u64,
    ) -> Result<OutPoint, BridgeError> {
        let txout = TxOut {
            value: Amount::from_sat(amount_sats),
            script_pubkey: address.script_pubkey(),
        };
        let tx = TransactionBuilder::create_btc_tx(Vec::new(), vec![txout]);

        let txid = self.send_raw_transaction(&tx)?;

        Ok(OutPoint { txid, vout: 0 })
    }

    fn get_work_at_block(&self, _blockheight: u64) -> Result<bitcoin::Work, BridgeError> {
        unimplemented!()
    }

    fn get_block_header(
        &self,
        _block_hash: &bitcoin::BlockHash,
    ) -> Result<bitcoin::block::Header, bitcoincore_rpc::Error> {
        unimplemented!()
    }

    fn get_block_hash(
        &self,
        _blockheight: u64,
    ) -> Result<bitcoin::BlockHash, bitcoincore_rpc::Error> {
        unimplemented!()
    }

    fn calculate_total_work_between_blocks(
        &self,
        _start: u64,
        _end: u64,
    ) -> Result<crypto_bigint::U256, BridgeError> {
        unimplemented!()
    }

    fn get_total_work_as_u256(&self) -> Result<crypto_bigint::U256, BridgeError> {
        unimplemented!()
    }

    fn get_total_work(&self) -> Result<bitcoin::Work, BridgeError> {
        unimplemented!()
    }

    fn get_block_height(&self) -> Result<u64, BridgeError> {
        unimplemented!()
    }

    fn fundrawtransaction(
        &self,
        _tx: &bitcoin::Transaction,
        _options: Option<&bitcoincore_rpc::json::FundRawTransactionOptions>,
        _is_witness: Option<bool>,
    ) -> Result<bitcoincore_rpc::json::FundRawTransactionResult, bitcoincore_rpc::Error> {
        unimplemented!()
    }

    fn get_blockchain_info(
        &self,
    ) -> Result<bitcoincore_rpc::json::GetBlockchainInfoResult, bitcoincore_rpc::Error> {
        unimplemented!()
    }

    fn get_block_count(&self) -> Result<u64, bitcoincore_rpc::Error> {
        unimplemented!()
    }

    fn get_best_block_hash(&self) -> Result<bitcoin::BlockHash, bitcoincore_rpc::Error> {
        unimplemented!()
    }

    fn get_raw_transaction(
        &self,
        txid: &bitcoin::Txid,
        _block_hash: Option<&bitcoin::BlockHash>,
    ) -> Result<bitcoin::Transaction, bitcoincore_rpc::Error> {
        Ok(self
            .database
            .lock()
            .unwrap()
            .get_transaction(txid.to_string().as_str())
            .unwrap())
    }

    fn get_transaction(
        &self,
        _txid: &bitcoin::Txid,
        _include_watchonly: Option<bool>,
    ) -> Result<bitcoincore_rpc::json::GetTransactionResult, bitcoincore_rpc::Error> {
        unimplemented!()
    }

    fn send_raw_transaction(
        &self,
        tx: &bitcoin::Transaction,
    ) -> Result<bitcoin::Txid, bitcoincore_rpc::Error> {
        let txid = tx.compute_txid();

        match self
            .database
            .lock()
            .unwrap()
            .insert_transaction_unconditionally(tx)
        {
            Ok(_) => Ok(txid),
            Err(e) => Err(bitcoincore_rpc::Error::ReturnedError(e.to_string())),
        }
    }

    fn get_block(
        &self,
        _block_hash: &bitcoin::BlockHash,
    ) -> Result<bitcoin::Block, bitcoincore_rpc::Error> {
        unimplemented!()
    }

    fn get_raw_transaction_info(
        &self,
        _txid: &bitcoin::Txid,
        _block_hash: Option<&bitcoin::BlockHash>,
    ) -> Result<bitcoincore_rpc::json::GetRawTransactionResult, bitcoincore_rpc::Error> {
        unimplemented!()
    }

    fn check_deposit_utxo(
        &self,
        _tx_builder: &crate::transaction_builder::TransactionBuilder,
        _outpoint: &OutPoint,
        _recovery_taproot_address: &bitcoin::Address<bitcoin::address::NetworkUnchecked>,
        _evm_address: &crate::EVMAddress,
        _amount_sats: u64,
        _confirmation_block_count: u32,
    ) -> Result<(), BridgeError> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{mock::common, transaction_builder::TransactionBuilder};
    use bitcoin::{hashes::Hash, Address, TxIn, Txid, Witness, XOnlyPublicKey};
    use secp256k1::Secp256k1;

    #[test]
    fn new() {
        let config = common::get_test_config("test_config.toml").unwrap();

        let _should_not_panic = BitcoinMockRPC::new(
            config.bitcoin_rpc_url,
            config.bitcoin_rpc_user,
            config.bitcoin_rpc_password,
        );
    }

    /// Tests if sending and retrieving a raw transaction works or not.
    #[test]
    fn raw_transaction() {
        let config = common::get_test_config("test_config.toml").unwrap();
        let rpc = BitcoinMockRPC::new(
            config.bitcoin_rpc_url,
            config.bitcoin_rpc_user,
            config.bitcoin_rpc_password,
        );
        let txb = TransactionBuilder::new(
            config.verifiers_public_keys,
            config.network,
            config.user_takes_after,
            config.min_relay_fee,
        );

        // Insert a new transaction to Bitcoin.
        let txin = TxIn {
            previous_output: OutPoint {
                txid: Txid::from_byte_array([0x45; 32]),
                vout: 0,
            },
            sequence: bitcoin::transaction::Sequence::ENABLE_RBF_NO_LOCKTIME,
            script_sig: ScriptBuf::default(),
            witness: Witness::new(),
        };
        let txout = TxOut {
            value: Amount::from_sat(0),
            script_pubkey: txb.generate_bridge_address().unwrap().0.script_pubkey(),
        };
        let inserted_tx = TransactionBuilder::create_btc_tx(vec![txin], vec![txout]);

        rpc.send_raw_transaction(&inserted_tx).unwrap();

        // Retrieve inserted transaction from Bitcoin.
        let read_tx = rpc
            .get_raw_transaction(&inserted_tx.compute_txid(), None)
            .unwrap();

        assert_eq!(inserted_tx, read_tx);
    }

    #[test]
    fn send_to_address() {
        let config = common::get_test_config("test_config.toml").unwrap();
        let rpc = BitcoinMockRPC::new(
            config.bitcoin_rpc_url,
            config.bitcoin_rpc_user,
            config.bitcoin_rpc_password,
        );

        let secp = Secp256k1::new();
        let xonly_public_key = XOnlyPublicKey::from_slice(&[
            0x78u8, 0x19u8, 0x90u8, 0xd7u8, 0xe2u8, 0x11u8, 0x8cu8, 0xc3u8, 0x61u8, 0xa9u8, 0x3au8,
            0x6fu8, 0xccu8, 0x54u8, 0xceu8, 0x61u8, 0x1du8, 0x6du8, 0xf3u8, 0x81u8, 0x68u8, 0xd6u8,
            0xb1u8, 0xedu8, 0xfbu8, 0x55u8, 0x65u8, 0x35u8, 0xf2u8, 0x20u8, 0x0cu8, 0x4b,
        ])
        .unwrap();
        let address = Address::p2tr(&secp, xonly_public_key, None, config.network);

        let outpoint = rpc.send_to_address(&address, 0x45).unwrap();

        let tx = rpc.get_raw_transaction(&outpoint.txid, None).unwrap();
        assert_eq!(tx.output[0].value.to_sat(), 0x45);
    }
}
