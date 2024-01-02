use std::borrow::BorrowMut;

use bitcoin::{
    absolute::{Height, LockTime},
    hashes::Hash,
    secp256k1::{rand::{self, rngs::OsRng}, All, Keypair, Message, Secp256k1},
    sighash::SighashCache,
    Address, Amount, OutPoint, ScriptBuf, TapTweakHash, Transaction, TxIn, TxOut, Witness,
    XOnlyPublicKey,
};
use bitcoincore_rpc::{Auth, Client, RpcApi};
use operator::{user::deposit_tx, actor::Actor};

pub fn f() {
    let rpc = Client::new(
        "http://localhost:18443/wallet/admin",
        Auth::UserPass("admin".to_string(), "admin".to_string()),
    )
    .unwrap_or_else(|e| panic!("Failed to connect to Bitcoin RPC: {}", e));

    let amt: u64 = 100_000_000;
    let fee: u64 = 1000;
    let dust_limit: u64 = 546;

    let secp: Secp256k1<All> = Secp256k1::new();
    let mut rng = rand::thread_rng();
    let (sk, _pk) = secp.generate_keypair(&mut rng);
    let (sk2, _pk2) = secp.generate_keypair(&mut rng);
    let keypair = Keypair::from_secret_key(&secp, &sk);
    let keypair2 = Keypair::from_secret_key(&secp, &sk2);
    let (xonly, _parity) = XOnlyPublicKey::from_keypair(&keypair);
    let (xonly2, _parity2) = XOnlyPublicKey::from_keypair(&keypair2);
    let address = Address::p2tr(&secp, xonly, None, bitcoin::Network::Regtest);
    let address2 = Address::p2tr(&secp, xonly2, None, bitcoin::Network::Regtest);

    let input1_txid = rpc
        .send_to_address(
            &address,
            Amount::from_sat(amt + 31 * amt + fee),
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .unwrap_or_else(|e| panic!("Failed to send to address: {}", e));

    let input1_tx = rpc
        .get_transaction(&input1_txid, None)
        .unwrap_or_else(|e| panic!("Failed to get transaction: {}", e));

    let input2_txid = rpc
        .send_to_address(
            &address,
            Amount::from_sat(dust_limit),
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .unwrap_or_else(|e| panic!("Failed to send to address: {}", e));

    let input2_tx = rpc
        .get_transaction(&input1_txid, None)
        .unwrap_or_else(|e| panic!("Failed to get transaction: {}", e));

    let outputs = vec![
        TxOut {
            script_pubkey: address2.script_pubkey(),
            value: Amount::from_sat(amt),
        }, // Withdrawal
        TxOut {
            script_pubkey: address.script_pubkey(),
            value: Amount::from_sat(31 * amt),
        }, // Change
        TxOut {
            script_pubkey: address.script_pubkey(),
            value: Amount::from_sat(dust_limit),
        }, // Dust for ordering
    ];
    let inputs = vec![
        TxIn {
            previous_output: OutPoint {
                txid: input1_txid,
                vout: input1_tx.details[0].vout,
            },
            script_sig: ScriptBuf::new(),
            sequence: bitcoin::transaction::Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        },
        TxIn {
            previous_output: OutPoint {
                txid: input2_txid,
                vout: input2_tx.details[0].vout,
            },
            script_sig: ScriptBuf::new(),
            sequence: bitcoin::transaction::Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        },
    ];

    let prevouts = vec![
        TxOut {
            script_pubkey: address.script_pubkey(),
            value: Amount::from_sat(amt + 31 * amt + fee),
        },
        TxOut {
            script_pubkey: address.script_pubkey(),
            value: Amount::from_sat(dust_limit),
        },
    ];

    let mut withdraw_tx = Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: LockTime::from(Height::MIN),
        input: inputs.clone(),
        output: outputs.clone(),
    };

    let mut sighash_cache = SighashCache::new(withdraw_tx.borrow_mut());

    let sig_hash1 = sighash_cache
        .taproot_key_spend_signature_hash(
            0,
            &bitcoin::sighash::Prevouts::All(&prevouts),
            bitcoin::sighash::TapSighashType::Default,
        )
        .unwrap();

    let sig_hash2 = sighash_cache
        .taproot_key_spend_signature_hash(
            1,
            &bitcoin::sighash::Prevouts::All(&prevouts),
            bitcoin::sighash::TapSighashType::Default,
        )
        .unwrap();

    let signature1 = secp.sign_schnorr_with_rng(
        &Message::from_digest_slice(sig_hash1.as_byte_array()).expect("should be hash"),
        &keypair
            .add_xonly_tweak(
                &secp,
                &TapTweakHash::from_key_and_tweak(xonly, None).to_scalar(),
            )
            .unwrap(),
        &mut rand::thread_rng(),
    );

    let signature2 = secp.sign_schnorr_with_rng(
        &Message::from_digest_slice(sig_hash2.as_byte_array()).expect("should be hash"),
        &keypair
            .add_xonly_tweak(
                &secp,
                &TapTweakHash::from_key_and_tweak(xonly, None).to_scalar(),
            )
            .unwrap(),
        &mut rand::thread_rng(),
    );

    let witness = sighash_cache.witness_mut(0).unwrap();
    witness.push(signature1.as_ref());
    let witness = sighash_cache.witness_mut(1).unwrap();
    witness.push(signature2.as_ref());

    let txid = rpc
        .send_raw_transaction(&withdraw_tx)
        .unwrap_or_else(|e| panic!("Failed to send raw transaction: {}", e));

    println!("Transaction sent: {}", txid)
}

fn main() {

    let rpc = Client::new(
        "http://localhost:18443/wallet/admin",
        Auth::UserPass("admin".to_string(), "admin".to_string()),
    )
    .unwrap_or_else(|e| panic!("Failed to connect to Bitcoin RPC: {}", e));

    let mut verifiers = Vec::new();
    for _ in 0..10 {
        let verifier = Actor::new(&mut OsRng);
        verifiers.push(verifier);
    }


}
