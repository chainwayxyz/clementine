use bitcoin::{
    block,
    secp256k1::{rand::RngCore, Secp256k1},
    Amount,
};
use bitcoincore_rpc::{Client, RpcApi};

use crate::{actor::Actor, user::deposit_tx};

pub fn mock_lightclient<R: RngCore>(
    rng: &mut R,
    rpc: &Client,
    num_blocks: u32,
    num_deposits: u32,
    num_withdrawals: u32,
    n: u32,
) -> (
    Vec<block::BlockHash>,
    Vec<bitcoin::Txid>,
    Vec<bitcoin::Address>,
) {

    let mut depositors: Vec<Actor> = Vec::new();
    for _ in 0..num_deposits {
        depositors.push(Actor::new(rng));
    }

    let mut withdrawers: Vec<Actor> = Vec::new();
    for _ in 0..num_withdrawals {
        withdrawers.push(Actor::new(rng));
    }

    let other = Actor::new(rng);
    let amount: u64 = 100_000_000;
    let secp = Secp256k1::new();
    let mut verifiers = Vec::new();
    for _ in 0..n {
        verifiers.push(Actor::new(rng));
    }

    for i in 0..num_deposits {
        rpc
            .send_to_address(
                &depositors[i as usize].address.clone(),
                Amount::from_sat(amount),
                None,
                None,
                None,
                None,
                None,
                None,
            )
            .unwrap_or_else(|e| panic!("Failed to send to address: {}", e));
    }

    let mut deposit_txs = Vec::new();
    for i in 0..num_deposits {
        let deposit_tx_id = deposit_tx(
            &rpc,
            depositors[i as usize].clone(),
            [i as u8; 32],
            &other,
            amount,
            &secp,
            &verifiers,
        );
        deposit_txs.push(deposit_tx_id);
    }

    let mut withdrawal_txs = Vec::new();
    let mut withdraw_addresses = Vec::new();
    for i in 0..num_withdrawals {
        let withdrawal_tx_id = rpc
            .send_to_address(
                &withdrawers[i as usize].address.clone(),
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
        withdraw_addresses.push(withdrawers[i as usize].address.clone());
    }

    let mut miners = Vec::new();
    for _ in 0..num_blocks {
        miners.push(Actor::new(rng));
    }

    let mut block_hash_vec = Vec::new();
    for i in 0..num_blocks {
        block_hash_vec.push(
            rpc.generate_to_address(1, &miners[i as usize].address)
                .unwrap()[0],
        );
    }

    return (block_hash_vec, deposit_txs, withdraw_addresses);
}

#[cfg(test)]

mod tests {
    use bitcoin::secp256k1::rand::rngs::OsRng;
    use bitcoincore_rpc::Auth;

    use super::*;

    #[test]
    fn test_mock_lightclient() {
        let num_blocks = 10;
        let num_deposits = 10;
        let num_withdrawals = 10;
        let n = 3;
        let rpc = Client::new(
            "http://localhost:18443/wallet/admin",
            Auth::UserPass("admin".to_string(), "admin".to_string()),
        )
        .unwrap_or_else(|e| panic!("Failed to connect to Bitcoin RPC: {}", e));
        let (block_hash_vec, deposit_txs, withdrawal_addresses) =
            mock_lightclient(&mut OsRng, &rpc, num_blocks, num_deposits, num_withdrawals, n);

        // Asert block_hash_vec len,
        // Assert every block hash has correct prev block hash,
        // Assert deposit_txs len,
        // Assert withdrawal_addresses len,
        // Assert every deposit_tx happened in some block,
        assert_eq!(block_hash_vec.len(), 10);
        for i in 1..10 {
            assert_eq!(
                rpc.get_block_header_info(&block_hash_vec[i as usize])
                    .unwrap()
                    .previous_block_hash.unwrap(),
                block_hash_vec[(i - 1) as usize]
            );
        }
        assert_eq!(deposit_txs.len(), 10);
        assert_eq!(withdrawal_addresses.len(), 10);
        for i in 0..10 {
            rpc.get_raw_transaction(&deposit_txs[i as usize], None).unwrap_or_else(|e| {
                panic!(
                    "Failed to get raw transaction: {}, txid: {}",
                    e, deposit_txs[i as usize]
                )
            });
        }
        println!("block_hash_vec: {:?}", block_hash_vec);
        println!("deposit_txs: {:?}", deposit_txs);
        println!("withdrawal_txs: {:?}", withdrawal_addresses);
    }
}
