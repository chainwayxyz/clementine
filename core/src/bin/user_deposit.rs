use clementine_circuits::constants::BRIDGE_AMOUNT_SATS;
use clementine_core::config::BridgeConfig;
use clementine_core::transaction_builder::TransactionBuilder;
use clementine_core::{keys, EVMAddress};
fn main() {
    let secp = bitcoin::secp256k1::Secp256k1::new();
    let config = BridgeConfig::new().unwrap();
    let (secret_key, all_xonly_pks) = keys::get_from_file().unwrap();
    let tx_builder = TransactionBuilder::new(all_xonly_pks.clone(), config);

    let (xonly_pk, _) = secret_key.public_key(&secp).x_only_public_key();
    let evm_address: EVMAddress = EVMAddress([1u8; 20]);

    let deposit_address = tx_builder
        .generate_deposit_address(&xonly_pk, &evm_address, BRIDGE_AMOUNT_SATS)
        .unwrap();

    println!("EVM Address: {:?}", hex::encode(evm_address.0));
    println!("User: {:?}", xonly_pk.to_string());
    println!("Deposit address: {:?}", deposit_address);
    // let anyone_can_spend_script = Builder::new()
    //     .push_opcode(opcodes::all::OP_PUSHNUM_1)
    //     .into_script();
    // let locking_script = anyone_can_spend_script.to_p2wsh();
    // let locking_address = Address::p2wsh(&locking_script, Network::Bitcoin);
    // let address = Address::p2wsh(&anyone_can_spend_script, Network::Bitcoin);
    // println!("Locking address: {:?}", locking_address);
    // println!("Locking script: {:?}", locking_script);
    // println!("Address: {:?}", address);
    // println!("Script: {:?}", anyone_can_spend_script);
}
