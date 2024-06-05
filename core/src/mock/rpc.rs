//! # Remote Procedure Call Mock Interface
//!
//! This crate mocks Bitcoin's RPC interface. Note that it is not a full mock,
//! rather simplified mock for testing purposes.

use crate::transaction_builder::TransactionBuilder;
use bitcoin::{address::NetworkChecked, consensus::encode, Address, Amount, Transaction, TxOut};
use bitcoin_simulator::database::Database;
use bitcoincore_rpc::{json, RpcApi};

/// Mock Bitcoin RPC client for testing.
pub struct Client {
    database: Database,
}

impl Client {
    pub fn new() -> Self {
        let database = Database::connect_temporary_database().unwrap();

        Self { database }
    }
}

impl RpcApi for Client {
    fn call<T: for<'a> serde::de::Deserialize<'a>>(
        &self,
        cmd: &str,
        args: &[serde_json::Value],
    ) -> bitcoincore_rpc::Result<T> {
        unimplemented!("Unimplemented RPC cmd: {}, with args: {:?}", cmd, args);
    }

    fn get_raw_transaction(
        &self,
        txid: &bitcoin::Txid,
        _block_hash: Option<&bitcoin::BlockHash>,
    ) -> bitcoincore_rpc::Result<bitcoin::Transaction> {
        Ok(self
            .database
            .get_transaction(txid.to_string().as_str())
            .unwrap())
    }

    fn send_raw_transaction<R: bitcoincore_rpc::RawTx>(
        &self,
        tx: R,
    ) -> bitcoincore_rpc::Result<bitcoin::Txid> {
        let tx: Transaction = encode::deserialize_hex(&tx.raw_hex()).unwrap();

        let txid = tx.compute_txid();

        match self.database.insert_transaction_unconditionally(&tx) {
            Ok(_) => Ok(txid),
            Err(e) => Err(bitcoincore_rpc::Error::ReturnedError(e.to_string())),
        }
    }

    fn send_to_address(
        &self,
        address: &Address<NetworkChecked>,
        amount: Amount,
        _comment: Option<&str>,
        _comment_to: Option<&str>,
        _subtract_fee: Option<bool>,
        _replaceable: Option<bool>,
        _confirmation_target: Option<u32>,
        _estimate_mode: Option<json::EstimateMode>,
    ) -> bitcoincore_rpc::Result<bitcoin::Txid> {
        let txout = TxOut {
            value: amount,
            script_pubkey: address.script_pubkey(),
        };
        let tx = TransactionBuilder::create_btc_tx(Vec::new(), vec![txout]);

        let txid = self.send_raw_transaction(&tx)?;

        Ok(txid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{mock::common, transaction_builder::TransactionBuilder};
    use bitcoin::{
        hashes::Hash, Address, Amount, OutPoint, ScriptBuf, TxIn, TxOut, Txid, Witness,
        XOnlyPublicKey,
    };
    use secp256k1::Secp256k1;

    #[test]
    fn new() {
        let _should_not_panic = Client::new();
    }

    /// Tests if sending and retrieving a raw transaction works or not.
    #[test]
    fn raw_transaction() {
        let config = common::get_test_config("test_config.toml").unwrap();
        let rpc = Client::new();
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
        let rpc = Client::new();

        let secp = Secp256k1::new();
        let xonly_public_key = XOnlyPublicKey::from_slice(&[
            0x78u8, 0x19u8, 0x90u8, 0xd7u8, 0xe2u8, 0x11u8, 0x8cu8, 0xc3u8, 0x61u8, 0xa9u8, 0x3au8,
            0x6fu8, 0xccu8, 0x54u8, 0xceu8, 0x61u8, 0x1du8, 0x6du8, 0xf3u8, 0x81u8, 0x68u8, 0xd6u8,
            0xb1u8, 0xedu8, 0xfbu8, 0x55u8, 0x65u8, 0x35u8, 0xf2u8, 0x20u8, 0x0cu8, 0x4b,
        ])
        .unwrap();
        let address = Address::p2tr(&secp, xonly_public_key, None, config.network);

        let txid = rpc
            .send_to_address(
                &address,
                Amount::from_sat(0x45),
                None,
                None,
                None,
                None,
                None,
                None,
            )
            .unwrap();

        let tx = rpc.get_raw_transaction(&txid, None).unwrap();
        assert_eq!(tx.output[0].value.to_sat(), 0x45);
    }
}
