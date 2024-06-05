//! # Remote Procedure Call Mock Interface
//!
//! This crate mocks Bitcoin's RPC interface. Note that it is not a full mock,
//! rather a simplified mock for testing purposes.

use crate::{traits::rpc::RpcApiWrapper, transaction_builder::TransactionBuilder};
use bitcoin::{
    address::NetworkChecked, consensus::encode, hashes::Hash, Address, Amount, Network,
    SignedAmount, Transaction, TxOut, Wtxid, XOnlyPublicKey,
};
use bitcoin_simulator::database::Database;
use bitcoincore_rpc::{
    json::{
        self, GetRawTransactionResult, GetTransactionResult, GetTransactionResultDetail,
        GetTransactionResultDetailCategory, WalletTxInfo,
    },
    RpcApi,
};
use secp256k1::Secp256k1;
use std::sync::{Arc, Mutex};

/// Mock Bitcoin RPC client for testing.
pub struct Client {
    database: Arc<Mutex<Database>>,
}

impl RpcApiWrapper for Client {
    fn new(_url: &str, _auth: bitcoincore_rpc::Auth) -> bitcoincore_rpc::Result<Self> {
        let database = Database::connect_temporary_database().unwrap();

        Ok(Self {
            database: Arc::new(Mutex::new(database)),
        })
    }
}

impl RpcApi for Client {
    /// This function normally talks with Bitcoin network. Therefore, other
    /// functions calls this to send requests. In a mock environment though,
    /// other functions won't be talking to a regulated interface. Rather will
    /// talk with a temporary interfaces, like in-memory databases.
    ///
    /// This is the reason, this function will only throw errors in case of a
    /// function is not -yet- implemented. Tester should implement corresponding
    /// function in this impl block, if this function called for `cmd`.
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
            .lock()
            .unwrap()
            .get_transaction(txid.to_string().as_str())
            .unwrap())
    }

    fn send_raw_transaction<R: bitcoincore_rpc::RawTx>(
        &self,
        tx: R,
    ) -> bitcoincore_rpc::Result<bitcoin::Txid> {
        let tx: Transaction = encode::deserialize_hex(&tx.raw_hex()).unwrap();

        let txid = tx.compute_txid();

        match self
            .database
            .lock()
            .unwrap()
            .insert_transaction_unconditionally(&tx)
        {
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

    fn get_transaction(
        &self,
        txid: &bitcoin::Txid,
        _include_watchonly: Option<bool>,
    ) -> bitcoincore_rpc::Result<json::GetTransactionResult> {
        let raw_tx = self
            .database
            .lock()
            .unwrap()
            .get_transaction(txid.to_string().as_str())
            .unwrap();

        let res = GetTransactionResult {
            info: WalletTxInfo {
                confirmations: 10,
                blockhash: None,
                blockindex: None,
                blocktime: None,
                blockheight: None,
                txid: *txid,
                time: 0,
                timereceived: 0,
                bip125_replaceable: json::Bip125Replaceable::Unknown,
                wallet_conflicts: vec![],
            },
            amount: SignedAmount::ZERO,
            fee: None,
            details: vec![GetTransactionResultDetail {
                address: None,
                category: GetTransactionResultDetailCategory::Send,
                amount: SignedAmount::ZERO,
                label: None,
                vout: 0,
                fee: None,
                abandoned: None,
            }],
            hex: encode::serialize(&raw_tx),
        };

        Ok(res)
    }

    fn get_new_address(
        &self,
        _label: Option<&str>,
        _address_type: Option<json::AddressType>,
    ) -> bitcoincore_rpc::Result<Address<bitcoin::address::NetworkUnchecked>> {
        let secp = Secp256k1::new();
        let xonly_public_key = XOnlyPublicKey::from_slice(&[
            0x78u8, 0x19u8, 0x90u8, 0xd7u8, 0xe2u8, 0x11u8, 0x8cu8, 0xc3u8, 0x61u8, 0xa9u8, 0x3au8,
            0x6fu8, 0xccu8, 0x54u8, 0xceu8, 0x61u8, 0x1du8, 0x6du8, 0xf3u8, 0x81u8, 0x68u8, 0xd6u8,
            0xb1u8, 0xedu8, 0xfbu8, 0x55u8, 0x65u8, 0x35u8, 0xf2u8, 0x20u8, 0x0cu8, 0x4b,
        ])
        .unwrap();

        let address = Address::p2tr(&secp, xonly_public_key, None, Network::Regtest)
            .as_unchecked()
            .to_owned();

        Ok(address)
    }

    fn generate_to_address(
        &self,
        _block_num: u64,
        _address: &Address<NetworkChecked>,
    ) -> bitcoincore_rpc::Result<Vec<bitcoin::BlockHash>> {
        Ok(vec![])
    }

    fn get_raw_transaction_info(
        &self,
        txid: &bitcoin::Txid,
        _block_hash: Option<&bitcoin::BlockHash>,
    ) -> bitcoincore_rpc::Result<json::GetRawTransactionResult> {
        Ok(GetRawTransactionResult {
            in_active_chain: None,
            hex: vec![],
            txid: *txid,
            hash: Wtxid::hash(&[0]),
            size: 0,
            vsize: 0,
            version: 0,
            locktime: 0,
            vin: vec![],
            vout: vec![],
            blockhash: None,
            confirmations: Some(10),
            time: None,
            blocktime: None,
        })
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
        let _should_not_panic = Client::new("", bitcoincore_rpc::Auth::None).unwrap();
    }

    /// Tests if sending and retrieving a raw transaction works or not.
    #[test]
    fn raw_transaction() {
        let config = common::get_test_config("test_config.toml").unwrap();
        let rpc = Client::new("", bitcoincore_rpc::Auth::None).unwrap();
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
        let rpc = Client::new("", bitcoincore_rpc::Auth::None).unwrap();

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
