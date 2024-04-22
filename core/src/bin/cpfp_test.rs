use std::{borrow::BorrowMut, str::FromStr};

use bitcoin::{
    script::Builder, sighash::SighashCache, Address, Amount, OutPoint, ScriptBuf, Transaction,
    TxIn, TxOut, Txid,
};
use bitcoincore_rpc::json::FundRawTransactionOptions;
use clementine_core::{
    actor::Actor, extended_rpc::ExtendedRpc, keys, script_builder::ScriptBuilder,
    transaction_builder::TransactionBuilder,
};

fn main() {
    let rpc = ExtendedRpc::new();
    let (secret_key, all_xonly_pks) = keys::get_from_file().unwrap();
    let actor = Actor::new(secret_key);

    println!("{:?}", actor.address);

    let txid = "8f03d09b8bf9d00479199651be1d31462cf382af2236a6517dfbec60f49c22cd";
    let txid = Txid::from_str(txid).expect("Invalid Txid");
    let cpfp_utxo = OutPoint {
        txid: txid,
        vout: 1,
    };

    // let txid2 = "e27a63c76d8ec26b7a29cf0eb522b2630c6f3c987e0bb36aae8dd77f6f3ad0b9";
    // let txid2 = Txid::from_str(txid2).expect("Invalid Txid");
    // let actor_utxo = OutPoint {
    //     txid: txid2,
    //     vout: 0,
    // };

    // // println!("{:?}", cpfp_utxo);

    // // let outpoint2 = rpc.send_to_address(&actor.address, 7000).expect("Error sending to address");
    // // println!("{:?}", outpoint2);

    // let txins = TransactionBuilder::create_tx_ins(vec![cpfp_utxo, actor_utxo]);
    // let anyone_can_spend_txout = ScriptBuilder::anyone_can_spend_txout();
    // let prevouts = vec![
    //     anyone_can_spend_txout.clone(),
    //     TxOut {
    //         value: Amount::from_sat(7000),
    //         script_pubkey: actor.address.script_pubkey(),
    //     },
    // ];
    // let mut tx = TransactionBuilder::create_btc_tx(txins, vec![anyone_can_spend_txout]);
    // tx.input[0].witness.push([0x51]);
    // // let mut sighash_cache = SighashCache::new(tx.borrow_mut());
    // // let witness = sighash_cache.witness_mut(1).unwrap();

    // let sig = actor
    //     .sign_taproot_pubkey_spend_tx(&mut tx, &prevouts, 1)
    //     .unwrap();
    // let mut sighash_cache = SighashCache::new(tx.borrow_mut());
    // let witness = sighash_cache.witness_mut(1).unwrap();
    // witness.push(sig.as_ref());

    // println!("{:?}", tx.clone());

    // let txid = rpc.send_raw_transaction(&tx).unwrap();
    // println!("TXID = {:?}", txid);

    // // let options =  FundRawTransactionOptions {
    // //     add_inputs: None,
    // //     change_address: None,
    // //     change_position: None,
    // //     change_type: None,
    // //     include_watching: None,
    // //     lock_unspents: None,
    // //     fee_rate: Some(Amount::from_sat(20)),
    // //     subtract_fee_from_outputs: None,
    // //     replaceable: None,
    // //     conf_target: None,
    // //     estimate_mode: None,
    // // };

    // // println!("{:?}", tx.clone());

    // // let result = rpc.fundrawtransaction(&tx, Some(&options), Some(false));
    // // println!("{:?}", result);
}
