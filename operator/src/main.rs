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

    let secp: Secp256k1<All> = Secp256k1::new();

    let alex = Actor::new();

    let nov = 10;
    let verifiers = (0..nov).map(|_| Actor::new()).collect::<Vec<Actor>>();
    let verifiers_pks = verifiers.iter().map(|v| v.xonly_public_key).collect::<Vec<XOnlyPublicKey>>();

    let mut rng = rand::thread_rng();
    let preimage = rng.gen::<[u8; 32]>();
    let hash = sha256::Hash::hash(&preimage).to_byte_array();

    let (txid, vout) = send_to_address(&rpc, &alex.address, 10000);

    let tx_d = tx_deposit(&secp, txid, vout, 10000, &alex, verifiers_pks, hash);
    // do_tx(&rpc, tx_d);
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
