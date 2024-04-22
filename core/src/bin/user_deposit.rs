use clementine_core::{extended_rpc::ExtendedRpc, user::User};
use clementine_core::{keys, EVMAddress};
fn main() {
    let rpc = ExtendedRpc::new();
    let (secret_key, all_xonly_pks) = keys::get_from_file().unwrap();

    let user = User::new(rpc.clone(), all_xonly_pks.clone(), secret_key);
    let evm_address: EVMAddress = [1u8; 20];
    let address = user.get_deposit_address(evm_address).unwrap();

    println!("EVM Address: {:?}", hex::encode(evm_address));
    println!("User: {:?}", user.signer.xonly_public_key.to_string());
    println!("Deposit address: {:?}", address);
}
