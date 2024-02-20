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

use secp256k1::Secp256k1;
use secp256k1::XOnlyPublicKey;
use secp256k1::{schnorr, All};
use serde::de::DeserializeOwned;
use serde::Serialize;

use circuit_helpers::core_tx::CoreTransaction;
use circuit_helpers::core_tx::TxInput;
use circuit_helpers::core_tx::TxOutput;

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

pub fn from_hex_to_tx<const INPUTS_COUNT: usize, const OUTPUTS_COUNT: usize>(
    input: &str,
) -> CoreTransaction<INPUTS_COUNT, OUTPUTS_COUNT, 221>
where
    [TxInput; INPUTS_COUNT]: Serialize + DeserializeOwned + Copy,
    [TxOutput; OUTPUTS_COUNT]: Serialize + DeserializeOwned + Copy,
{
    let btc_tx = parse_hex_to_btc_tx(input).unwrap();
    let mut tx = CoreTransaction::<INPUTS_COUNT, OUTPUTS_COUNT, 221>::empty();
    tx.version = btc_tx.version.0;
    tx.input_count = btc_tx.input.len() as u8;
    for i in 0..btc_tx.input.len() {
        tx.inputs[i].prev_tx_hash = hex::decode(btc_tx.input[i].previous_output.txid.to_string())
            .unwrap()
            .try_into()
            .unwrap();
        tx.inputs[i].prev_tx_hash.reverse();
        tx.inputs[i].output_index = btc_tx.input[i].previous_output.vout;
        tx.inputs[i].sequence = btc_tx.input[i].sequence.0;
    }
    tx.output_count = btc_tx.output.len() as u8;
    for i in 0..btc_tx.output.len() {
        tx.outputs[i].value = btc_tx.output[i].value.to_sat();
        tx.outputs[i].taproot_address[..32]
            .copy_from_slice(&btc_tx.output[i].script_pubkey.as_bytes()[2..34]);
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

pub fn check_presigns(
    _tx: &bitcoin::Transaction,
    _presigns: Vec<schnorr::Signature>,
    _xonly_public_keys: Vec<XOnlyPublicKey>,
) {
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
    let script = ScriptBuilder::generate_dust_script(evm_address);
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
    witness_elements: Vec<T>,
    script: ScriptBuf,
    tree_info: TaprootSpendInfo,
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

#[cfg(test)]
mod tests {

    use std::borrow::BorrowMut;
  
    use bitcoin::transaction::Version;
    use bitcoin::{absolute, Amount, Sequence, TxOut};
    use bitcoin::{
        sighash::SighashCache, taproot::LeafVersion, OutPoint, ScriptBuf, Transaction, TxIn,
        Witness,
    };
    use circuit_helpers::config::NUM_VERIFIERS;
    use secp256k1::rand::rngs::OsRng;

    use crate::extended_rpc::ExtendedRpc;
    use crate::script_builder::ScriptBuilder;
    use crate::transaction_builder::TransactionBuilder;
    use crate::{
        operator::Operator,
        utils::{from_hex_to_tx, parse_hex_to_btc_tx},
    };

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

    #[test]
    fn test_connector_tree_tx() {
        // ATTENTION: If you want to spend a UTXO using timelock script, the condition is that
        // # in the script < # in the sequence of the tx < # of blocks mined after UTXO appears on the chain
        let rpc = ExtendedRpc::new();
        let operator = Operator::new(&mut OsRng, &rpc, NUM_VERIFIERS as u32);
        // let user = User::new(&mut OsRng, &rpc);
        let resource_utxo = operator
            .rpc
            .send_to_address(&operator.signer.address, 100_000_000);

        let resource_tx = operator
            .rpc
            .get_raw_transaction(&resource_utxo.txid, None)
            .unwrap();

        let utxo_tx_ins = vec![TxIn {
            previous_output: resource_utxo,
            script_sig: ScriptBuf::new(),
            sequence: bitcoin::transaction::Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }];

        println!("utxo_tx_ins: {:?}", utxo_tx_ins);

        let (address, tree_info) = TransactionBuilder::create_connector_tree_node_address(
            &operator.signer.secp,
            operator.signer.xonly_public_key,
            [0u8; 32],
        );

        let utxo_tx_outs = TransactionBuilder::create_tx_outs(vec![(
            Amount::from_sat(99_999_000),
            address.script_pubkey(),
        )]);
        let mut utxo_tx = TransactionBuilder::create_btc_tx(utxo_tx_ins, utxo_tx_outs);
        let sig = operator.signer.sign_taproot_pubkey_spend_tx(
            &mut utxo_tx,
            vec![resource_tx.output[resource_utxo.vout as usize].clone()],
            0,
        );
        let mut sighash_cache = SighashCache::new(utxo_tx.borrow_mut());
        let witness = sighash_cache.witness_mut(0).unwrap();
        witness.push(sig.as_ref());
        let utxo_txid = operator.rpc.send_raw_transaction(&utxo_tx).unwrap();
        println!("utxo_txid: {:?}", utxo_txid);
        let rpc_utxo_tx = operator.rpc.get_raw_transaction(&utxo_txid, None).unwrap();
        println!("rpc_utxo_tx: {:?}", rpc_utxo_tx);
        rpc.mine_blocks(5);
        let mut connector_tree_tx = Transaction {
            version: Version(2),
            lock_time: absolute::LockTime::from_consensus(0),
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: utxo_txid,
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::from_height(3), // Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![
                TxOut {
                    value: Amount::from_sat(49_999_000),
                    script_pubkey: address.script_pubkey(),
                },
                TxOut {
                    value: Amount::from_sat(49_999_000),
                    script_pubkey: address.script_pubkey(),
                },
            ],
        };
        println!("dust value: {:?}", address.script_pubkey().dust_value());
        println!("connector_tree_tx: {:?}", connector_tree_tx);
        println!("connector_tree_txid: {:?}", connector_tree_tx.txid());

        let timelock_script =
            ScriptBuilder::generate_timelock_script(operator.signer.xonly_public_key, 2);
        let sig = operator.signer.sign_taproot_script_spend_tx(
            &mut connector_tree_tx,
            &vec![utxo_tx.output[0].clone()],
            &timelock_script,
            0,
        );
        let spend_control_block = tree_info
            .control_block(&(timelock_script.clone(), LeafVersion::TapScript))
            .expect("Cannot create control block");
        let mut sighash_cache = SighashCache::new(connector_tree_tx.borrow_mut());
        let witness = sighash_cache.witness_mut(0).unwrap();
        witness.push(sig.as_ref());
        witness.push(timelock_script);
        witness.push(&spend_control_block.serialize());

        // let hex_utxo_tx = hex::encode(bytes_utxo_tx.clone());
        rpc.mine_blocks(2);
        rpc.mine_blocks(6);
        let connector_tree_txid = operator
            .rpc
            .send_raw_transaction(&connector_tree_tx)
            .unwrap();
        // let hex_connector_tree_tx = hex::encode(bytes_connector_tree_tx.clone());
        println!("utxo_txid: {:?}", utxo_txid);
        println!("connector_tree_txid: {:?}", connector_tree_txid);
    }
}
