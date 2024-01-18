use std::sync::{Arc, Mutex};

use bitcoin::secp256k1::rand::rngs::OsRng;
use bitcoincore_rpc::{Auth, Client, RpcApi};
use circuit_helpers::config::{BRIDGE_AMOUNT_SATS, NUM_ROUNDS, NUM_USERS, NUM_VERIFIERS};
use operator::{
    operator::Operator, user::User, verifier::Verifier,
};

fn main() {
    // let mut bridge_funds: Vec<bitcoin::Txid> = Vec::new();
    // let rpc = Client::new(
    //     "http://localhost:18443/wallet/admin",
    //     Auth::UserPass("admin".to_string(), "admin".to_string()),
    // )
    // .unwrap_or_else(|e| panic!("Failed to connect to Bitcoin RPC: {}", e));
    // let operator = Arc::new(Mutex::new(Operator::new(&mut OsRng, &rpc)));
    // // let mut operator = Operator::new(&mut OsRng, &rpc);
    // let mut users = Vec::new();
    // for _ in 0..NUM_USERS {
    //     users.push(User::new(&mut OsRng, &rpc));
    // }

    // let mut verifiers = Vec::new();
    // for _ in 0..NUM_VERIFIERS {
    //     let verifier = Verifier::new(&mut OsRng, &rpc, operator.clone());
    //     verifiers.push(verifier);
    // }

    // let mut operator_borrow = operator.lock().unwrap();
    // for verifier in &verifiers {
    //     operator_borrow.add_verifier(verifier);
    // }
    // let verifiers_pks = operator_borrow.get_all_verifiers();
    // for mut verifier in verifiers {
    //     verifier.set_verifiers(verifiers_pks.clone());
    // }
    // println!("verifiers_pks in main: {:?}", verifiers_pks);

    // let mut verifiers_evm_addresses = operator_borrow.verifier_evm_addresses.clone();
    // verifiers_evm_addresses.push(operator_borrow.signer.evm_address);
    // let mut utxo_vec = Vec::new();
    // let mut return_addresses = Vec::new();

    // for i in 0..NUM_USERS {
    //     let user = &users[i];
    //     println!("verifiers_pks in for: {:?}", verifiers_pks);
    //     let (mut utxo, mut hash, mut return_address) =
    //         user.deposit_tx(&user.rpc, BRIDGE_AMOUNT_SATS, &user.secp, verifiers_pks.clone());
    //     bridge_funds.push(utxo.txid);
    //     return_addresses.push(return_address);
    //     utxo_vec.push(utxo);
    //     rpc.generate_to_address(1, &operator_borrow.signer.address)
    //         .unwrap();
    //     let signatures = operator_borrow.new_deposit(utxo, i as u32, hash, return_address, user.signer.evm_address);
    // }

    // let mut fund = operator_borrow.preimage_revealed(users[9].reveal_preimage(), utxos[9], return_addresses[9]);
    // for i in 0..NUM_ROUNDS {
    //     fund = operator_borrow.move_single_bridge_fund(utxos[9].txid, fund);
    //     println!("fund moving in round {i}: {:?}", fund);
    // }
    // TEST IF SIGNATURES ARE VALID
    // operator.preimage_revealed(preimage, txid);

    // let (block_hash_vec, deposit_txs, withdrawal_addresses) =
    //     mock_lightclient(&mut OsRng, &rpc, verifiers, 100, 5, 3);

    // println!("Hello, world!");

    // let withdrawal_block_hash = pay_withdrawals(&rpc, withdrawal_addresses);
}
