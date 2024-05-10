use bitcoin::Address;
use clementine_circuits::constants::BRIDGE_AMOUNT_SATS;
use clementine_core::config::BridgeConfig;
use clementine_core::transaction_builder::TransactionBuilder;
use clementine_core::EVMAddress;
use musig2::KeyAggContext;
use secp256k1::PublicKey;
fn main() {
    let secp = bitcoin::secp256k1::Secp256k1::new();
    let config = BridgeConfig::new();
    let (xonly_pk, _) = config.secret_key.public_key(&secp).x_only_public_key();
    let address = Address::p2tr(&secp, xonly_pk, None, config.network);
    let pks: Vec<PublicKey> = config
        .verifiers_public_keys
        .clone()
        .iter()
        .map(|xonly_pk| xonly_pk.to_string().parse::<PublicKey>().unwrap())
        .collect();
    let key_agg_ctx = KeyAggContext::new(pks).unwrap();
    let agg_pk: PublicKey = key_agg_ctx.aggregated_pubkey();
    let tx_builder = TransactionBuilder::new(config.verifiers_public_keys.clone(), agg_pk, config);
    let evm_address: EVMAddress = EVMAddress([1u8; 20]);
    let deposit_address = tx_builder
        .generate_deposit_address(&address.as_unchecked(), &evm_address, BRIDGE_AMOUNT_SATS)
        .unwrap();

    println!("EVM Address: {:?}", hex::encode(evm_address.0));
    println!("User: {:?}", xonly_pk.to_string());
    println!("Deposit address: {:?}", deposit_address);
}
