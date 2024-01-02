use bitcoin::{secp256k1::Secp256k1, Amount, block};
use bitcoincore_rpc::{Client, Auth, RpcApi};

use crate::{actor::Actor, user::deposit_tx};

pub fn mock_lightclient(num_blocks: u32, num_deposits: u32, num_withdrawals: u32, n: u32) -> (Vec<block::BlockHash>, Vec<bitcoin::Txid>, Vec<bitcoin::Txid>) {
    let rpc = Client::new(
        "http://localhost:18443/wallet/admin",
        Auth::UserPass("admin".to_string(), "admin".to_string()),
    )
    .unwrap_or_else(|e| panic!("Failed to connect to Bitcoin RPC: {}", e));

    let mut depositors: Vec<Actor> = Vec::new();
    for i in 0..num_deposits {
        depositors.push(Actor::new_with_seed(i as u64));
        rpc.generate_to_address(1, &depositors[i as usize].address).unwrap();
    }

    let mut withdrawers: Vec<Actor> = Vec::new();
    for i in 0..num_withdrawals {
        withdrawers.push(Actor::new_with_seed(i as u64));
    }


    let other = Actor::new();
    let amount: u64 = 10_000_000;
    let secp = Secp256k1::new();
    let mut verifiers = Vec::new();
    for i in 0..n {
        verifiers.push(Actor::new_with_seed(i as u64));
    }

    let mut deposit_txs = Vec::new();
    for i in 0..num_deposits {
        let deposit_tx_id = deposit_tx(
            &rpc,
            depositors[i as usize].clone(),
            [i as u8; 32],
            &other,
            10_000_000,
            &secp,
            &verifiers
        );
        deposit_txs.push(deposit_tx_id);
    }

    let mut withdrawal_txs = Vec::new();

    for i in 0..num_withdrawals {
        let withdrawal_tx_id = rpc
            .send_to_address(
                &withdrawers[i as usize].address,
                Amount::from_sat(amount),
                None,
                None,
                None,
                None,
                None,
                None,
            )
            .unwrap_or_else(|e| panic!("Failed to send to address: {}", e));
        withdrawal_txs.push(withdrawal_tx_id);
    }

    let mut miners = Vec::new();
    for i in 0..n {
        miners.push(Actor::new_with_seed(i as u64));
    }

    let mut block_hash_vec = Vec::new();
    for i in 0..num_blocks {
        block_hash_vec.push(rpc.generate_to_address(1, &miners[i as usize].address).unwrap()[0]);
    }

    return (block_hash_vec, deposit_txs, withdrawal_txs);

}

#[cfg(test)]

mod tests {
    use super::*;

    #[test]
    fn test_mock_lightclient() {
        let (block_hash_vec, deposit_txs, withdrawal_txs) = mock_lightclient(10, 10, 10, 10);
        println!("block_hash_vec: {:?}", block_hash_vec);
        println!("deposit_txs: {:?}", deposit_txs);
        println!("withdrawal_txs: {:?}", withdrawal_txs);
    }
    
}