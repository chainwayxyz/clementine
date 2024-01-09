use std::borrow::BorrowMut;

use bitcoin::{
    absolute::{Height, LockTime},
    hashes::{sha256, Hash},
    secp256k1::{
        rand::{self, rngs::OsRng, Rng},
        All, Keypair, Message, Secp256k1,
    },
    sighash::SighashCache,
    Address, Amount, OutPoint, ScriptBuf, TapTweakHash, Transaction, TxIn, TxOut, Witness,
    XOnlyPublicKey,
};
use bitcoincore_rpc::{Auth, Client, RpcApi};
use operator::{
    actor::Actor, transactions::tx_deposit, proof::withdrawals::pay_withdrawals, operator::Operator, verifier::Verifier, user::User,
};
use circuit_helpers::config::{NUM_VERIFIERS, BRIDGE_AMOUNT_SATS};

pub fn f() {
    let rpc = Client::new(
        "http://localhost:18443/wallet/admin",
        Auth::UserPass("admin".to_string(), "admin".to_string()),
    )
    .unwrap_or_else(|e| panic!("Failed to connect to Bitcoin RPC: {}", e));

    let secp: Secp256k1<All> = Secp256k1::new();

    let alex = Actor::new(&mut OsRng);

    let nov = 10;
    let verifiers = (0..nov)
        .map(|_| Actor::new(&mut OsRng))
        .collect::<Vec<Actor>>();
    let verifiers_pks = verifiers
        .iter()
        .map(|v| v.xonly_public_key)
        .collect::<Vec<XOnlyPublicKey>>();

    let preimage = rand::thread_rng().gen::<[u8; 32]>();
    let hash = sha256::Hash::hash(&preimage).to_byte_array();

    let (txid, vout) = operator::transactions::send_to_address(&rpc, &alex.address, 10000);

    let tx_d = tx_deposit(&secp, txid, vout, 10000, &alex, verifiers_pks, hash);
    // do_tx(&rpc, tx_d);
}



fn main() {
    let rpc = Client::new(
        "http://localhost:18443/wallet/admin",
        Auth::UserPass("admin".to_string(), "admin".to_string()),
    )
    .unwrap_or_else(|e| panic!("Failed to connect to Bitcoin RPC: {}", e));
    let mut operator = Operator::new(&mut OsRng, &rpc);
    let user = User::new(&mut OsRng, &rpc);
    let mut verifiers = operator.verifiers.clone();
    verifiers.push(operator.signer.xonly_public_key.clone());

    let mut verifiers_evm_addresses = operator.verifier_evm_addresses.clone();
    verifiers_evm_addresses.push(operator.signer.evm_address);

    let (utxo, hash, return_address) =
        user.deposit_tx(&user.rpc, BRIDGE_AMOUNT_SATS, &user.secp, verifiers);
    rpc.generate_to_address(1, &operator.signer.address)
        .unwrap();
    let signatures = operator.new_deposit(utxo, hash, return_address, user.signer.evm_address);

    let fund = operator.preimage_revealed(user.reveal_preimage(), utxo, return_address);
    println!("fund: {:?}", fund);
    operator.move_single_bridge_fund(fund);
    // TEST IF SIGNATURES ARE VALID
    // operator.preimage_revealed(preimage, txid);

    let bridge_funds: Vec<bitcoin::Txid> = Vec::new();

    // let (block_hash_vec, deposit_txs, withdrawal_addresses) =
    //     mock_lightclient(&mut OsRng, &rpc, verifiers, 100, 5, 3);

    // println!("Hello, world!");

    // let withdrawal_block_hash = pay_withdrawals(&rpc, withdrawal_addresses);

}
