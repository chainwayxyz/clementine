use bitcoin::hashes::{Hash, HashEngine};
use bitcoin::opcodes::all::OP_CHECKSIG;
use bitcoin::script::Builder;
use bitcoin::taproot::Signature;
use bitcoin::{Address, Amount, TapTweakHash, TxOut, XOnlyPublicKey};
use clementine_core::actor::Actor;
use clementine_core::database::common::Database;
use clementine_core::extended_rpc::ExtendedRpc;
use clementine_core::mock::common;
use clementine_core::script_builder;
use clementine_core::transaction_builder::{TransactionBuilder, TxHandler};
use clementine_core::utils::handle_taproot_witness_new;
use clementine_core::{
    create_extended_rpc, create_test_config, create_test_config_with_thread_name,
};
use std::thread;

#[tokio::test]
async fn run() {
    let secp = bitcoin::secp256k1::Secp256k1::new();

    let mut config = create_test_config_with_thread_name!("test_config_taproot.toml");
    let rpc = create_extended_rpc!(config);

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

    let builder = Builder::new();
    let to_pay_script = builder
        .push_x_only_key(&XOnlyPublicKey::from_slice(&tweaked_pk_script).unwrap())
        .push_opcode(OP_CHECKSIG)
        .into_script();

    let (taproot_address, taproot_spend_info) =
        TransactionBuilder::create_taproot_address(&[to_pay_script.clone()], None, config.network);
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

    let mut tx_details = TxHandler {
        tx: tx.clone(),
        prevouts,
        scripts: vec![vec![to_pay_script.clone()]],
        taproot_spend_infos: vec![taproot_spend_info],
    };

    let sig = signer
        .sign_taproot_script_spend_tx_new_tweaked(&mut tx_details, 0, 0)
        .unwrap();

    handle_taproot_witness_new(&mut tx_details, &[sig.as_ref()], 0, Some(0)).unwrap();
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

fn calculate_min_relay_fee(n: u64) -> u64 {
    98 + 57 * n + ((n - 2) / 2)
}
#[tokio::test]
async fn taproot_key_path_spend() {
    let secp = bitcoin::secp256k1::Secp256k1::new();
    let mut config = create_test_config_with_thread_name!("test_config_taproot.toml");
    let rpc = create_extended_rpc!(config);

    let (xonly_pk, _) = config.secret_key.public_key(&secp).x_only_public_key();
    let actor = Actor::new(config.secret_key, config.network);

    let address = Address::p2tr(&secp, xonly_pk, None, config.network);
    const INPUT_AMOUNT: u64 = 600;
    const INPUT_COUNT: u32 = 2;
    let mut inputs = vec![];
    let mut prevouts = vec![];
    for _i in 0..INPUT_COUNT {
        let outpoint = rpc.send_to_address(&address, INPUT_AMOUNT).unwrap();
        println!("Outpoint: {:?}", outpoint);
        inputs.push(outpoint);
        prevouts.push(TxOut {
            script_pubkey: address.script_pubkey(),
            value: Amount::from_sat(INPUT_AMOUNT),
        });
    }
    let txins = TransactionBuilder::create_tx_ins(inputs);
    let anchor = script_builder::anyone_can_spend_txout();

    let mut txouts = TransactionBuilder::create_tx_outs(vec![(
        Amount::from_sat(
            INPUT_AMOUNT * INPUT_COUNT as u64
                - anchor.value.to_sat()
                - calculate_min_relay_fee(INPUT_COUNT as u64)
                - 1,
        ),
        address.script_pubkey(),
    )]);
    txouts.push(anchor);
    let mut tx = TransactionBuilder::create_btc_tx(txins, txouts);
    for i in 0..INPUT_COUNT {
        let sig = actor
            .sign_taproot_pubkey_spend_tx(&mut tx, &prevouts, i as usize)
            .unwrap();
        tx.input[i as usize].witness.push(sig.as_ref());
    }

    let txid = rpc.send_raw_transaction(&tx).unwrap();
    println!("txid: {:?}", txid);
    let base_size = tx.base_size();
    let total_size = tx.total_size();

    println!("base_size: {:?}", base_size);
    println!("total_size: {:?}", total_size);
    println!("input_count: {:?}", tx.input.len());
    println!("output_count: {:?}", tx.output.len());
    println!("vsize: {:?}", tx.vsize());
}

#[tokio::test]
async fn taproot_key_path_spend_2() {
    let mut config = create_test_config_with_thread_name!("test_config_taproot.toml");
    let rpc = create_extended_rpc!(config);

    let actor = Actor::new(config.secret_key, config.network);

    let address = actor.address.clone();

    let operator_commitment = rpc.send_to_address(&address, 10_000_000).unwrap();
    let leaf = rpc.send_to_address(&address, 330).unwrap();

    let txouts = TransactionBuilder::create_tx_outs(vec![(
        Amount::from_sat(9_000_000),
        address.script_pubkey(),
    )]);

    let txins = TransactionBuilder::create_tx_ins(vec![operator_commitment, leaf]);
    let prevouts = vec![
        TxOut {
            script_pubkey: address.script_pubkey(),
            value: Amount::from_sat(10_000_000),
        },
        TxOut {
            script_pubkey: address.script_pubkey(),
            value: Amount::from_sat(330),
        },
    ];

    let mut tx = TransactionBuilder::create_btc_tx(txins, txouts);
    for i in 0..2 {
        let sig = actor
            .sign_taproot_pubkey_spend_tx_with_sighash(
                &mut tx,
                &prevouts,
                i as usize,
                Some(bitcoin::sighash::TapSighashType::None),
            )
            .unwrap();
        tx.input[i as usize].witness.push(
            Signature {
                signature: sig,
                sighash_type: bitcoin::sighash::TapSighashType::None,
            }
            .to_vec(),
        );
    }

    println!("tx: {:?}", tx);

    tx.output.push(TxOut {
        script_pubkey: address.script_pubkey(),
        value: Amount::from_sat(1_000_000),
    });
    let txid = rpc.send_raw_transaction(&tx).unwrap();

    println!("txid: {:?}", txid);
}
