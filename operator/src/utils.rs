use std::borrow::BorrowMut;

use bitcoin::opcodes::OP_TRUE;
use bitcoin::sighash::SighashCache;
use bitcoin::{self};

use bitcoin::consensus::Decodable;
use bitcoin::script::Builder;
use bitcoin::taproot::ControlBlock;
use bitcoin::taproot::LeafVersion;
use bitcoin::taproot::TaprootBuilder;
use bitcoin::taproot::TaprootSpendInfo;
use bitcoin::Address;
use bitcoin::Amount;

use bitcoin::ScriptBuf;

use secp256k1::All;
use secp256k1::Secp256k1;
use secp256k1::XOnlyPublicKey;
use serde::de::DeserializeOwned;
use serde::Serialize;

use byteorder::{ByteOrder, LittleEndian};
use hex;

use lazy_static::lazy_static;
use std::str::FromStr;

use crate::script_builder::ScriptBuilder;

lazy_static! {
    pub static ref INTERNAL_KEY: XOnlyPublicKey = XOnlyPublicKey::from_str(
        "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0"
    )
    .unwrap();
}

pub fn char_to_digit(c: char) -> Result<u8, std::num::ParseIntError> {
    u8::from_str_radix(&c.to_string(), 16)
}

pub fn from_hex_to_bytes(input: &str) -> Vec<u8> {
    hex::decode(input).unwrap()
}

pub fn from_hex64_to_bytes32(input: &str) -> [u8; 32] {
    hex::decode(input)
        .unwrap()
        .try_into()
        .expect("Slice with incorrect length")
}

pub fn from_hex_to_u8(input: &str) -> u8 {
    let bytes = hex::decode(input).unwrap();
    bytes[0]
}

pub fn from_le_bytes_to_u32(input: &[u8]) -> u32 {
    LittleEndian::read_u32(input)
}

pub fn from_le_bytes_to_u64(input: &[u8]) -> u64 {
    LittleEndian::read_u64(input)
}

pub fn byte_to_hex(byte: u8) -> String {
    hex::encode([byte])
}

pub fn from_bytes_to_hex(input: &[u8]) -> String {
    hex::encode(input)
}

pub fn parse_hex_to_btc_tx(
    tx_hex: &str,
) -> Result<bitcoin::blockdata::transaction::Transaction, bitcoin::consensus::encode::Error> {
    if let Ok(reader) = hex::decode(tx_hex) {
        bitcoin::blockdata::transaction::Transaction::consensus_decode(&mut &reader[..])
    } else {
        Err(bitcoin::consensus::encode::Error::ParseFailed(
            "Could not decode hex",
        ))
    }
}

pub fn create_control_block(tree_info: TaprootSpendInfo, script: &ScriptBuf) -> ControlBlock {
    tree_info
        .control_block(&(script.clone(), LeafVersion::TapScript))
        .expect("Cannot create control block")
}

pub fn generate_dust_address(
    secp: &Secp256k1<All>,
    evm_address: [u8; 20],
) -> (Address, TaprootSpendInfo) {
    let script = ScriptBuilder::generate_dust_script(&evm_address);
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

pub fn handle_anyone_can_spend_script() -> (ScriptBuf, Amount) {
    let script = Builder::new().push_opcode(OP_TRUE).into_script();
    let script_pubkey = script.to_p2wsh();
    let amount = script.dust_value();
    (script_pubkey, amount)
}

pub fn calculate_amount(depth: usize, value: Amount, fee: Amount) -> Amount {
    (value + fee) * (2u64.pow(depth as u32))
}

pub fn handle_taproot_witness<T: AsRef<[u8]>>(
    tx: &mut bitcoin::Transaction,
    index: usize,
    witness_elements: &Vec<T>,
    script: &ScriptBuf,
    tree_info: &TaprootSpendInfo,
) {
    let mut sighash_cache = SighashCache::new(tx.borrow_mut());
    let witness = sighash_cache.witness_mut(index).unwrap();
    for elem in witness_elements {
        witness.push(elem);
    }
    let spend_control_block = tree_info
        .control_block(&(script.clone(), LeafVersion::TapScript))
        .unwrap();
    witness.push(script);
    witness.push(&spend_control_block.serialize());
}
