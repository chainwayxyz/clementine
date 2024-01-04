use std::borrow::BorrowMut;
use std::str::FromStr;

use bitcoin::Address;
use bitcoin::Amount;
use bitcoin::OutPoint;
use bitcoin::ScriptBuf;
use bitcoin::TapLeafHash;
use bitcoin::Transaction;
use bitcoin::TxIn;
use bitcoin::TxOut;
use bitcoin::Txid;
use bitcoin::Witness;
use bitcoin::absolute::Height;
use bitcoin::absolute::LockTime;
use bitcoin::consensus::encode::serialize_hex;
use bitcoin::hashes::Hash;
use bitcoin::hashes::sha256;
use bitcoin::script::Builder;
use bitcoin::secp256k1::All;
use bitcoin::secp256k1::Secp256k1;
use bitcoin::XOnlyPublicKey;
use bitcoin::sighash::SighashCache;
use bitcoin::taproot::LeafVersion;
use bitcoin::taproot::TaprootBuilder;
use bitcoin::taproot::TaprootSpendInfo;
use bitcoin::opcodes::all::*;
use bitcoincore_rpc::Auth;
use bitcoincore_rpc::Client;
use bitcoincore_rpc::RpcApi;
use lazy_static::lazy_static;

use crate::actor::Actor;
use circuit_helpers::config::DUST;
use circuit_helpers::config::FEE;
use circuit_helpers::config::USER_TAKES_AFTER;
use circuit_helpers::config::FED_TAKES_AFTER;

lazy_static! {
    pub static ref INTERNAL_KEY: XOnlyPublicKey = XOnlyPublicKey::from_str("93c7378d96518a75448821c4f7c8f4bae7ce60f804d03d1f0628dd5dd0f5de51").unwrap();
}




pub fn generate_nofn_script(
    verifiers_pks: Vec<XOnlyPublicKey>,
    hash: [u8; 32],
) -> ScriptBuf {
    verifiers_pks.iter().fold(Builder::new(), |builder, vpk| builder.push_x_only_key(&vpk).push_opcode(OP_CHECKSIGVERIFY)).push_opcode(OP_SHA256).push_slice(hash).push_opcode(OP_EQUAL).into_script()
}

// TODO: this is wrong, fix
pub fn generate_timelock_script(actor_pk: XOnlyPublicKey, block_count: u32) -> ScriptBuf {
    Builder::new()
        .push_int(block_count as i64)
        .push_opcode(OP_CSV)
        .push_x_only_key(&actor_pk)
        .push_opcode(OP_CHECKSIG)
        .into_script()
}

pub fn generate_dust_script(eth_address: [u8; 20]) -> ScriptBuf {
    Builder::new()
        .push_opcode(OP_RETURN)
        .push_slice(&eth_address)
        .into_script()
}

pub fn generate_deposit_address(
    secp: &Secp256k1<All>,
    verifiers_pks: Vec<XOnlyPublicKey>,
    user_pk: XOnlyPublicKey,
    hash: [u8; 32],
) -> (Address, TaprootSpendInfo) {
    let script_nofn = generate_nofn_script(verifiers_pks, hash);
    let script_timelock = generate_timelock_script(user_pk, USER_TAKES_AFTER);
    let taproot = TaprootBuilder::new().add_leaf(1, script_nofn.clone()).unwrap().add_leaf(1, script_timelock.clone()).unwrap();
    let tree_info = taproot.finalize(secp, *INTERNAL_KEY).unwrap();
    let address = Address::p2tr(
        secp,
        *INTERNAL_KEY,
        tree_info.merkle_root(),
        bitcoin::Network::Regtest,
    );
    (address, tree_info)
}

pub fn generate_dust_address(
    secp: &Secp256k1<All>,
    eth_address: [u8; 20],
) -> (Address, TaprootSpendInfo) {
    let script = generate_dust_script(eth_address);
    let taproot = TaprootBuilder::new().add_leaf(0, script.clone()).unwrap();
    let tree_info = taproot.finalize(secp, *INTERNAL_KEY).unwrap();
    let address = Address::p2tr(
        secp,
        *INTERNAL_KEY,
        tree_info.merkle_root(),
        bitcoin::Network::Regtest,
    );
    (address, tree_info)
}

pub fn send_to_address(rpc: &Client, address: &Address, amount: u64) -> (Txid, u32) {
    check_balance(&rpc);
    let txid = rpc
        .send_to_address(
            &address,
            Amount::from_sat(amount),
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .unwrap_or_else(|e| panic!("Failed to send to address: {}", e));
    let tx_result = rpc
        .get_transaction(&txid, None)
        .unwrap_or_else(|e| panic!("Failed to get transaction: {}", e));

    let vout = tx_result.details[0].vout;
    
    println!("sent {} to address: {:?}", amount, address);
    println!("sent {} to address: {:?}", tx_result.details[0].amount, tx_result.details[0].address);
    println!("txid: {}", txid);
    println!("txid: {}", hex::encode(tx_result.hex));
    println!("vout: {}", vout);

    check_balance(&rpc);

    (txid, vout)
}

pub fn mine_blocks(rpc: &Client, block_num: u64) {
    let new_address = rpc.get_new_address(None, None).unwrap().assume_checked();
    rpc.generate_to_address(block_num, &new_address).unwrap();
}

pub fn check_balance(rpc: &Client) {
    let balance = rpc.get_balance(None, None).unwrap();
    println!("balance: {}", balance);
}

pub fn do_tx(rpc: &Client, tx: Transaction) {
    let txid = rpc
        .send_raw_transaction(&tx)
        .unwrap_or_else(|e| panic!("Failed to send raw transaction: {}", e));

    let tx_result = rpc
        .get_transaction(&txid, None)
        .unwrap_or_else(|e| panic!("Failed to get transaction: {}", e));

    println!("deposit transaction done");
    println!("txid: {:?}", txid);
    println!("len details: {}", tx_result.details.len());
    println!("vout: {}", tx_result.details[0].vout);
}

pub fn tx_deposit(secp: &Secp256k1<All>, txid: Txid, vout: u32, amount: u64, actor: &Actor, verifiers_pks: Vec<XOnlyPublicKey>, hash: [u8; 32]) -> Transaction {
    let (address, _info) = generate_deposit_address(secp, verifiers_pks, actor.xonly_public_key, hash);
    let (dust_address, _dust_info) = generate_dust_address(secp, actor.evm_address);
    let mut tx = Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: LockTime::from(Height::MIN),
        input: vec![TxIn {
            previous_output: OutPoint {
                txid,
                vout,
            },
            script_sig: ScriptBuf::new(),
            sequence: bitcoin::transaction::Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: vec![
            TxOut {
                script_pubkey: address.script_pubkey(),
                value: Amount::from_sat(amount - DUST - FEE),
            },
            TxOut {
                script_pubkey: dust_address.script_pubkey(),
                value: Amount::from_sat(DUST),
            }
        ],
    };

    let prevouts = vec![TxOut {
        script_pubkey: actor.address.script_pubkey(),
        value: Amount::from_sat(amount),
    }];

    let mut sighash_cache = SighashCache::new(tx.borrow_mut());
    let sig_hash = sighash_cache
        .taproot_key_spend_signature_hash(
            0,
            &bitcoin::sighash::Prevouts::All(&prevouts),
            bitcoin::sighash::TapSighashType::Default,
        )
        .unwrap();

    let sig = actor.sign_with_tweak(sig_hash, None);
    let witness = sighash_cache.witness_mut(0).unwrap();
    witness.push(sig.as_ref());

    tx
}

pub fn tx_bridge() {

}

