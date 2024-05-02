use clementine_core::transaction_builder::TransactionBuilder;
use clementine_core::{cli, EVMAddress};
fn main() {
    let secp = bitcoin::secp256k1::Secp256k1::new();
    let config = cli::get_configuration();

    let (xonly_pk, _) = config
        .secret_key
        .clone()
        .public_key(&secp)
        .x_only_public_key();

    let tx_builder = TransactionBuilder::new(config.verifiers_public_keys.clone(), config);

    let evm_address: EVMAddress = [1u8; 20];

    let deposit_address = tx_builder
        .generate_deposit_address(&xonly_pk, &evm_address, 10000)
        .unwrap();

    println!("EVM Address: {:?}", hex::encode(evm_address));
    println!("User: {:?}", xonly_pk.to_string());
    println!("Deposit address: {:?}", deposit_address);
}
