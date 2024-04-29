use clementine_core::config::BridgeConfig;
use clementine_core::transaction_builder::TransactionBuilder;
use clementine_core::{keys, EVMAddress};
fn main() {
    let secp = bitcoin::secp256k1::Secp256k1::new();
    let config = BridgeConfig::new();
    let (secret_key, all_xonly_pks) = keys::get_from_file().unwrap();
    let tx_builder = TransactionBuilder::new(all_xonly_pks.clone(), config);

    let (xonly_pk, _) = secret_key.public_key(&secp).x_only_public_key();
    let evm_address: EVMAddress = [1u8; 20];

    let deposit_address = tx_builder
        .generate_deposit_address(&xonly_pk, &evm_address, 10000)
        .unwrap();

    println!("EVM Address: {:?}", hex::encode(evm_address));
    println!("User: {:?}", xonly_pk.to_string());
    println!("Deposit address: {:?}", deposit_address);
}
