use std::io::{self, Write};

use bitcoin;

use bitcoin::Address;
use bitcoin::Amount;
use bitcoin::OutPoint;
use bitcoin::ScriptBuf;
use bitcoin::TxIn;
use bitcoin::TxOut;
use bitcoin::Txid;
use bitcoin::Witness;
use bitcoin::absolute;
use bitcoin::consensus::Decodable;
use bitcoin::opcodes::OP_TRUE;
use bitcoin::opcodes::all::OP_CHECKSIGVERIFY;
use bitcoin::opcodes::all::OP_EQUAL;
use bitcoin::opcodes::all::OP_SHA256;
use bitcoin::opcodes::all::OP_VERIFY;
use bitcoin::script::Builder;
use bitcoin::taproot::ControlBlock;
use bitcoin::taproot::LeafVersion;
use bitcoin::taproot::TaprootBuilder;
use bitcoin::taproot::TaprootSpendInfo;
use bitcoin::transaction::Version;
use bitcoincore_rpc::Client;
use bitcoincore_rpc::RpcApi;
use circuit_helpers::constant::REGTEST;
use secp256k1::All;
use secp256k1::Secp256k1;
use secp256k1::XOnlyPublicKey;
use serde::de::DeserializeOwned;
use serde::Serialize;

use circuit_helpers::core_tx::Transaction;
use circuit_helpers::core_tx::TxInput;
use circuit_helpers::core_tx::TxOutput;

use byteorder::{ByteOrder, LittleEndian};
use hex;

use std::str::FromStr;
use bitcoin::opcodes::all::*;
use lazy_static::lazy_static;

use circuit_helpers::config::USER_TAKES_AFTER;

lazy_static! {
    pub static ref INTERNAL_KEY: XOnlyPublicKey = XOnlyPublicKey::from_str("93c7378d96518a75448821c4f7c8f4bae7ce60f804d03d1f0628dd5dd0f5de51").unwrap();
}

pub fn take_stdin<T: std::str::FromStr>(prompt: &str) -> Result<T, T::Err> {
    print!("{}", prompt);
    io::stdout().flush().unwrap();
    let mut string = String::new();
    io::stdin()
        .read_line(&mut string)
        .expect("Failed to read line");

    string.trim().parse::<T>()
}

pub fn generate_n_of_n_script(verifiers_pks: &Vec<XOnlyPublicKey>, hash: [u8; 32]) -> ScriptBuf {
    let raw_script = generate_n_of_n_script_without_hash(&verifiers_pks);
    let script_buf = convert_scriptbuf_into_builder(raw_script).into_script();
    add_hash_to_script(script_buf, hash)
}

pub fn generate_n_of_n_script_without_hash(verifiers_pks: &Vec<XOnlyPublicKey>) -> ScriptBuf {
    let mut builder = Builder::new();
    for vpk in verifiers_pks {
        builder = builder.push_x_only_key(&vpk).push_opcode(OP_CHECKSIGVERIFY);
    }
    builder = builder.push_opcode(OP_TRUE);
    builder.into_script()
}

pub fn add_hash_to_script(script: ScriptBuf, hash: [u8; 32]) -> ScriptBuf {
    let script_bytes = script.as_bytes().to_vec();
    let mut builder = Builder::from(script_bytes);
    builder = builder.push_opcode(OP_VERIFY);
    builder = builder
        .push_opcode(OP_SHA256)
        .push_slice(hash)
        .push_opcode(OP_EQUAL);
    builder.into_script()
}

pub fn convert_scriptbuf_into_builder(script: ScriptBuf) -> Builder {
    let script_bytes = script.as_bytes().to_vec();
    Builder::from(script_bytes)
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

pub fn from_hex_to_tx<const INPUTS_COUNT: usize, const OUTPUTS_COUNT: usize>(
    input: &str,
) -> Transaction<INPUTS_COUNT, OUTPUTS_COUNT, 221>
where
    [TxInput; INPUTS_COUNT]: Serialize + DeserializeOwned + Copy,
    [TxOutput; OUTPUTS_COUNT]: Serialize + DeserializeOwned + Copy,
{
    let btc_tx = parse_hex_to_btc_tx(input).unwrap();
    let mut tx = Transaction::<INPUTS_COUNT, OUTPUTS_COUNT, 221>::empty();
    tx.version = btc_tx.version.0;
    tx.input_count = btc_tx.input.len() as u8;
    for i in 0..btc_tx.input.len() {
        tx.inputs[i].prev_tx_hash = hex::decode(btc_tx.input[i].previous_output.txid.to_string()).unwrap().try_into().unwrap();
        tx.inputs[i].prev_tx_hash.reverse();
        tx.inputs[i].output_index = btc_tx.input[i].previous_output.vout;
        tx.inputs[i].sequence = btc_tx.input[i].sequence.0;
    }
    tx.output_count = btc_tx.output.len() as u8;
    for i in 0..btc_tx.output.len() {
        tx.outputs[i].value = btc_tx.output[i].value.to_sat();
        tx.outputs[i].taproot_address[..32].copy_from_slice(&btc_tx.output[i].script_pubkey.as_bytes()[2..34]);
    }
    tx.lock_time = btc_tx.lock_time.to_consensus_u32();
    tx 
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

// Dummy function to generate a block with given transactions
pub fn generate_dummy_block(rpc: &Client) -> Vec<bitcoin::BlockHash> {
    // Use `generatetoaddress` or similar RPC method to mine a new block
    // containing the specified transactions
    let address = rpc.get_new_address(None, None).unwrap().assume_checked();
    // txs.iter().for_each(|tx| {
    //     rpc.send_raw_transaction(tx).unwrap();
    // });
    for _ in 0..10 {
        let new_address = rpc.get_new_address(None, None).unwrap().assume_checked();
        let amount = bitcoin::Amount::from_sat(1000); // Specify the amount to send
        rpc
            .send_to_address(&new_address, amount, None, None, None, None, None, None)
            .unwrap();
    }
    rpc.generate_to_address(1, &address).unwrap()
}

pub fn create_btc_tx(tx_ins: Vec<TxIn>, tx_outs: Vec<TxOut>) -> bitcoin::Transaction {
    bitcoin::Transaction {
        version: Version(2),
        lock_time: absolute::LockTime::from_consensus(0),
        input: tx_ins,
        output: tx_outs,
    }
}

pub fn create_tx_ins(utxos: Vec<OutPoint>) -> Vec<TxIn> {
    let mut tx_ins = Vec::new();
    for utxo in utxos {
        tx_ins.push(TxIn {
            previous_output: utxo,
            sequence: bitcoin::transaction::Sequence::ENABLE_RBF_NO_LOCKTIME,
            script_sig: ScriptBuf::default(),
            witness: Witness::new(),
        });
    }
    tx_ins
}

pub fn create_tx_outs(pairs: Vec<(Amount, ScriptBuf)>) -> Vec<TxOut> {
    let mut tx_outs = Vec::new();
    for pair in pairs {
        tx_outs.push(TxOut {
            value: pair.0,
            script_pubkey: pair.1,
        });
    }
    tx_outs
}

pub fn create_taproot_address(secp: &Secp256k1<All>, scripts: Vec<ScriptBuf>) -> (Address, TaprootSpendInfo) {
    let mut taproot_builder = TaprootBuilder::new();
    //depth = log(scripts.len)
    let depth = (scripts.len() as f64).log2() as u8;
    for script in scripts {
        taproot_builder = taproot_builder.add_leaf(depth, script).unwrap();
    }
    let internal_key = *INTERNAL_KEY;
    let tree_info = taproot_builder
        .finalize(&secp, internal_key)
        .unwrap();
    (Address::p2tr(&secp, internal_key, tree_info.merkle_root(), REGTEST), tree_info)
}

pub fn create_control_block(tree_info: TaprootSpendInfo, script: &ScriptBuf) -> ControlBlock {
    tree_info
    .control_block(&(script.clone(), LeafVersion::TapScript))
    .expect("Cannot create control block")
}

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
    let script_nofn = generate_n_of_n_script(&verifiers_pks, hash);
    let script_timelock = generate_timelock_script(user_pk, USER_TAKES_AFTER);
    let taproot = TaprootBuilder::new().add_leaf(1, script_nofn.clone()).unwrap().add_leaf(1, script_timelock.clone()).unwrap();
    let tree_info = taproot.finalize(secp, *INTERNAL_KEY).unwrap();
    let address = Address::p2tr(
        secp,
        *INTERNAL_KEY,
        tree_info.merkle_root(),
        REGTEST,
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
        REGTEST,
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

pub fn handle_anyone_can_spend_script() -> (ScriptBuf, Amount) {
    let script = Builder::new()
        .push_opcode(OP_TRUE)
        .into_script();
    let script_pubkey = script.to_p2wsh();
    let amount = script.dust_value();
    (script_pubkey, amount)
}

pub fn create_kickoff_tx(ins: Vec<OutPoint>, outs: Vec<(Amount, ScriptBuf)>) -> bitcoin::Transaction {
    let tx_ins = create_tx_ins(ins);
    let tx_outs = create_tx_outs(outs);
    create_btc_tx(tx_ins, tx_outs)
}

#[cfg(test)]
mod tests {

    use crate::utils::{from_hex_to_tx, parse_hex_to_btc_tx};

    #[test]
    fn test_from_hex_to_tx() {
        let input = "020000000001025c290bc400f9e1c3f739f8e57ab60355d5a9ac33e9d2c24145b3565aee6bbce00000000000fdffffffa49a9fe38ffe5f5bda8289098e60572caa758c7795983b0008b5e99f01f446de0000000000fdffffff0300e1f50500000000225120df6f4ee3a0a625db6fa6a88176656541f4a63591f8b7174f7054cc52afbeaec800e1f505000000002251208c61eec2e14c785da78dd8ab98797996f866a6aac8c8d2389d77f38c3f4feff122020000000000002251208c61eec2e14c785da78dd8ab98797996f866a6aac8c8d2389d77f38c3f4feff101405de61774dc0275f491eb46561bc1b36148ef30467bf43f2b33796991d61a29a3a4b7e2047712e73fe983806f0d636b64c8a6202490daff202bca521a0faa70ae0140f80f92541832d6d8908df9a57d994b90ee74129c8943a17109da88d49cd1531314d051c8082be3b79d3281edde719ab2fab34fa3dfbe3ad60e5a2ab8a306d43100000000";
        let tx = from_hex_to_tx::<2, 3>(input);
        let tx_id = tx.calculate_txid();
        let hex = hex::encode(tx_id);
        let btc_tx = parse_hex_to_btc_tx(input).unwrap();
        let btc_tx_id = btc_tx.txid();
        let btc_hex = hex::encode(btc_tx_id);
        assert_eq!(btc_hex, hex);
    }
}
