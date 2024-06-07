use bitcoin::consensus::Encodable;
use bitcoin::hashes::Hash;
use bitcoin::hex::buf_encoder::OutBytes;
use bitcoin::{Address, Amount, OutPoint, TxOut, Txid};
use bitcoincore_rpc::{Auth, RawTx};
use clementine_circuits::constants::BRIDGE_AMOUNT_SATS;
use clementine_core::actor::Actor;
use clementine_core::config::BridgeConfig;
use clementine_core::extended_rpc::ExtendedRpc;
use clementine_core::transaction_builder::TransactionBuilder;
use clementine_core::utils::handle_taproot_witness_new;
use clementine_core::{cli, EVMAddress};
pub const DATA_LENGTH: usize = 396_000;
pub const FEE: usize = 100_000;
fn main() {
    let secp = bitcoin::secp256k1::Secp256k1::new();
    let config = cli::get_configuration();
    println!("config: {:?}", config);
    let rpc = ExtendedRpc::new(
        config.bitcoin_rpc_url.clone(),
        Auth::UserPass(
            config.bitcoin_rpc_user.clone(),
            config.bitcoin_rpc_password.clone(),
        ),
    );
    let (xonly_pk, _) = config.secret_key.public_key(&secp).x_only_public_key();
    let actor = Actor::new(config.secret_key, config.network);
    let tx_builder = TransactionBuilder::new(config.verifiers_public_keys.clone(), config);
    let mut data: Vec<u8> = Vec::new();
    for _ in 0..DATA_LENGTH {
        data.push(49u8);
    }
    let res1 = tx_builder
        .create_data_inscription_commit_address(&xonly_pk, &data)
        .unwrap();
    let mut resource_txid_hex =
        hex::decode("d0897ce2483df074da1ad52e93dce7b0e2468936f846b8668ce89e25e11c9567").unwrap();
    resource_txid_hex.reverse();
    let resource_txid = Txid::from_byte_array(resource_txid_hex.try_into().unwrap());

    let resource_utxo = OutPoint {
        txid: resource_txid,
        vout: 0,
    };
    println!("resource_utxo: {:?}", resource_utxo);
    let prevouts1 = vec![TxOut {
        value: Amount::from_sat(100_000_000),
        script_pubkey: actor.address.script_pubkey(),
    }];
    let mut tx1_outs = Vec::new();
    for _ in 0..100 {
        let tx1_out = TxOut {
            value: Amount::from_sat(999_000),
            script_pubkey: res1.0.script_pubkey(),
        };
        tx1_outs.push(tx1_out);
    }
    let tx1_ins = TransactionBuilder::create_tx_ins(vec![resource_utxo]);
    let mut tx_1 = TransactionBuilder::create_btc_tx(tx1_ins, tx1_outs);
    println!("user taproot address: {:?}", actor.address);
    println!("tx1: {:?}", tx_1);
    let sig = actor
        .sign_taproot_pubkey_spend_tx(&mut tx_1, &prevouts1, 0)
        .unwrap();
    println!("sig: {:?}", sig);
    tx_1.input[0].witness.push(sig.as_ref());
    println!("tx1 final: {:?}", tx_1);
    let tx1_hex = tx_1.raw_hex();
    println!("tx1_hex: {:?}", tx1_hex);
    // let tx1_txid = rpc.send_raw_transaction(&tx_1).unwrap();
    // println!("tx1_txid: {:?}", tx1_txid);

    for idx in 0..100 {
        let tx1_utxo = OutPoint {
            txid: tx_1.txid(),
            vout: idx,
        };
        let mut res2 = tx_builder
            .create_data_inscription_reveal_tx(tx1_utxo, &xonly_pk, &actor.address, data.clone())
            .unwrap();
        // println!("res2: {:?}", res2);
        let sig = actor
            .sign_taproot_script_spend_tx_new(&mut res2, 0, 0)
            .unwrap();
        println!("sig: {:?}", sig);
        let mut witness_elements = Vec::new();
        witness_elements.push(sig.as_ref());
        handle_taproot_witness_new(&mut res2, &witness_elements, 0, 0).unwrap();
        let _tx2_hex = res2.tx.raw_hex();
        let reveal_txid = rpc.send_raw_transaction(&res2.tx).unwrap();
        println!("reveal_txid: {:?}", reveal_txid);
    }
    // println!("tx2_hex: {:?}", tx2_hex);
    // println!("tx2: {:?}", res2.tx);
    // let prevouts2 = vec![TxOut {
    //     value: Amount::from_sat(99_000_000),
    //     script_pubkey: res1.0.script_pubkey(),
    // }];
    // let tx2_out = TxOut {
    //     value: Amount::from_sat(90_000_000),
    //     script_pubkey: actor.address.script_pubkey(),
    // };
    // let tx2_ins = TransactionBuilder::create_tx_ins(vec![tx1_utxo]);
    // let mut tx_2 = TransactionBuilder::create_btc_tx(tx2_ins, vec![tx2_out]);
}
