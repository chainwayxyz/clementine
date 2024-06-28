use bitcoin::hashes::{Hash, HashEngine};
use bitcoin::opcodes::all::OP_CHECKSIG;
use bitcoin::script::Builder;
use bitcoin::{Address, Amount, TapTweakHash, TxOut, XOnlyPublicKey};
use clementine_core::actor::Actor;
use clementine_core::extended_rpc::ExtendedRpc;
use clementine_core::mock::common::get_test_config;
use clementine_core::transaction_builder::{CreateTxOutputs, TransactionBuilder};
use clementine_core::utils::handle_taproot_witness_new;

#[tokio::test]
async fn run() {
    let secp = bitcoin::secp256k1::Secp256k1::new();
    let config = get_test_config("test_config_taproot.toml").unwrap();

    let (xonly_pk, _) = config.secret_key.public_key(&secp).x_only_public_key();
    println!("x only pub key: {:?}", xonly_pk);

    let address = Address::p2tr(&secp, xonly_pk, None, config.network);
    println!("address: {:?}", address.to_string());

    let script = address.script_pubkey();
    println!("script: {:?}", hex::encode(script.as_bytes()));

    let tweaked_pk_script: [u8; 32] = script.as_bytes()[2..].try_into().unwrap();
    println!("tweaked pk: {:?}", hex::encode(tweaked_pk_script));

    // calculate tweaked pk, i.e. Q
    let mut hasher = TapTweakHash::engine();
    hasher.input(&xonly_pk.serialize());
    let (q, _) = xonly_pk
        .add_tweak(
            &secp,
            &secp256k1::Scalar::from_be_bytes(TapTweakHash::from_engine(hasher).to_byte_array())
                .unwrap(),
        )
        .unwrap();
    println!("q:          {:?}", hex::encode(q.serialize()));

    let rpc = ExtendedRpc::new(
        config.bitcoin_rpc_url.clone(),
        config.bitcoin_rpc_user.clone(),
        config.bitcoin_rpc_password.clone(),
    );

    let builder = Builder::new();
    let to_pay_script = builder
        .push_x_only_key(&XOnlyPublicKey::from_slice(&tweaked_pk_script).unwrap())
        .push_opcode(OP_CHECKSIG)
        .into_script();

    let (taproot_address, taproot_spend_info) =
        TransactionBuilder::create_taproot_address(vec![to_pay_script.clone()], config.network)
            .unwrap();
    let utxo = rpc.send_to_address(&taproot_address, 1000).unwrap();

    let ins = TransactionBuilder::create_tx_ins(vec![utxo]);

    let tx_outs = vec![TxOut {
        value: Amount::from_sat(330),
        script_pubkey: taproot_address.script_pubkey(),
    }];

    let prevouts = vec![TxOut {
        value: Amount::from_sat(1000),
        script_pubkey: taproot_address.script_pubkey(),
    }];

    let tx = TransactionBuilder::create_btc_tx(ins, tx_outs.clone());

    let signer = Actor::new(config.secret_key, config.network);

    let mut tx_details = CreateTxOutputs {
        tx: tx.clone(),
        prevouts,
        scripts: vec![vec![to_pay_script.clone()]],
        taproot_spend_infos: vec![taproot_spend_info],
    };

    let sig = signer
        .sign_taproot_script_spend_tx_new_tweaked(&mut tx_details, 0, 0)
        .unwrap();

    handle_taproot_witness_new(&mut tx_details, &vec![sig.as_ref()], 0, 0).unwrap();
    let result = rpc.send_raw_transaction(&tx_details.tx).unwrap();

    // let mut sighash_cache = SighashCache::new(tx.clone());
    // let prevouts = vec![utxo.clone()];
    // let sig_hash = sighash_cache
    //     .taproot_key_spend_signature_hash(
    //         0,
    //         &bitcoin::sighash::Prevouts::All(&tx_outs),
    //         bitcoin::sighash::TapSighashType::Default,
    //     )
    //     .unwrap();
    // let signature = signer.sign_with_tweak(sig_hash, None).unwrap();

    // let mut sighash_cache = SighashCache::new(tx.borrow_mut());
    // let witness = sighash_cache.witness_mut(0).unwrap();
    // witness.push(to_pay_script.as_bytes());
    // witness.push(signature.as_ref());

    println!("Result: {:?}", result);
    // println!("Signature: {:?}", signature);

    println!("UTXO: {:?}", utxo);

    // let tx_builder = TransactionBuilder::new(config.verifiers_public_keys.clone(), config);
    // let evm_address: EVMAddress = EVMAddress([1u8; 20]);
    // let deposit_address = tx_builder
    //     .generate_deposit_address(&xonly_pk, &evm_address, BRIDGE_AMOUNT_SATS)
    //     .unwrap();

    // println!("EVM Address: {:?}", hex::encode(evm_address.0));
    // println!("User: {:?}", xonly_pk.to_string());
    // println!("Deposit address: {:?}", deposit_address);
    // let scripts = deposit_address.1.script_map().keys().all(|script| {
    //     println!("Script: {:?}", hex::encode(script.0.as_bytes()));
    //     true
    // });
    // println!("asd: {:?}", deposit_address.1.script_map().keys())
}
