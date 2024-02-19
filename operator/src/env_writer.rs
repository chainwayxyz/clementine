use bitcoin::{Block, Transaction, Txid};
use circuit_helpers::env::Environment;
use secp256k1::hashes::Hash;
use std::marker::PhantomData;

use crate::bitcoin_merkle::BitcoinMerkleTree;

pub struct ENVWriter<E: Environment> {
    _marker: PhantomData<E>,
}

impl<E: Environment> ENVWriter<E> {
    pub fn write_tx_to_env(tx: Transaction) {
        E::write_i32(tx.version.0);
        E::write_u32(tx.input.len() as u32);
        E::write_u32(tx.output.len() as u32);
        E::write_u32(tx.lock_time.to_consensus_u32());
        for input in tx.input.iter() {
            let mut prev_txid: [u8; 32] = hex::decode(input.previous_output.txid.to_string())
                .unwrap()
                .try_into()
                .unwrap();
            prev_txid.reverse();
            E::write_32bytes(prev_txid);
            E::write_u32(input.previous_output.vout);
            E::write_u32(input.sequence.0);
        }
        for output in tx.output.iter() {
            E::write_u64(output.value.to_sat());
            E::write_32bytes(output.script_pubkey.as_bytes()[2..34].try_into().unwrap());
        }
    }

    pub fn write_bitcoin_merkle_path(txid: Txid, block: &Block) {
        let tx_id_array = block
            .txdata
            .iter()
            .map(|tx| tx.txid())
            .collect::<Vec<Txid>>();

        // find the index of the txid in tx_id_array vector or give error "txid not found in block txids"
        let index = tx_id_array.iter().position(|&r| r == txid).unwrap();
        E::write_u32(index as u32);
        let tx_id_bytes_vec = tx_id_array
            .iter()
            .map(|tx_id| {
                let bytes = tx_id.to_byte_array();
                // bytes.reverse();
                bytes.try_into().unwrap()
            })
            .collect::<Vec<[u8; 32]>>();
        let merkle_tree = BitcoinMerkleTree::new(tx_id_bytes_vec);
        let merkle_path = merkle_tree.get_idx_path(index as u32);
        E::write_u32(merkle_path.len() as u32);
        for node in merkle_path {
            E::write_32bytes(node);
        }
    }
}

impl<E: Environment> ENVWriter<E> {
    pub fn new() -> Self {
        ENVWriter {
            _marker: PhantomData,
        }
    }
}

// write tests for circuits
#[cfg(test)]
mod tests {
    use bitcoin::Txid;
    use bitcoincore_rpc::RpcApi;
    use circuit_helpers::bitcoin::{
        read_and_verify_bitcoin_merkle_path, read_tx_and_calculate_txid,
    };
    use secp256k1::hashes::Hash;

    use crate::{
        env_writer::ENVWriter,
        extended_rpc::ExtendedRpc,
        mock_env::MockEnvironment,
        utils::{from_hex_to_tx, parse_hex_to_btc_tx},
    };

    use operator_circuit::{GUEST_ELF, GUEST_ID};
    use risc0_zkvm::{default_prover, ExecutorEnv};

    #[test]
    fn test_tx() {
        let input = "020000000001025c290bc400f9e1c3f739f8e57ab60355d5a9ac33e9d2c24145b3565aee6bbce00000000000fdffffffa49a9fe38ffe5f5bda8289098e60572caa758c7795983b0008b5e99f01f446de0000000000fdffffff0300e1f50500000000225120df6f4ee3a0a625db6fa6a88176656541f4a63591f8b7174f7054cc52afbeaec800e1f505000000002251208c61eec2e14c785da78dd8ab98797996f866a6aac8c8d2389d77f38c3f4feff122020000000000002251208c61eec2e14c785da78dd8ab98797996f866a6aac8c8d2389d77f38c3f4feff101405de61774dc0275f491eb46561bc1b36148ef30467bf43f2b33796991d61a29a3a4b7e2047712e73fe983806f0d636b64c8a6202490daff202bca521a0faa70ae0140f80f92541832d6d8908df9a57d994b90ee74129c8943a17109da88d49cd1531314d051c8082be3b79d3281edde719ab2fab34fa3dfbe3ad60e5a2ab8a306d43100000000";
        let btc_tx = parse_hex_to_btc_tx(input).unwrap();
        let btc_tx_id = btc_tx.txid();
        ENVWriter::<MockEnvironment>::write_tx_to_env(btc_tx);
        let tx_id = read_tx_and_calculate_txid::<MockEnvironment>();
        assert_eq!(btc_tx_id, Txid::from_byte_array(tx_id));
    }

    #[test]
    fn test_bitcoin_merkle_path() {
        // TODO: Change this test to not use the rpc
        let rpc = ExtendedRpc::new();

        // TODO: Make 2 dummy transactions and add them to the blockchain

        let block_hash = rpc.generate_dummy_block()[0];
        let block = rpc.inner.get_block(&block_hash).unwrap();
        let tx = block.txdata[1].clone();
        let tx_id = tx.txid();
        ENVWriter::<MockEnvironment>::write_bitcoin_merkle_path(tx_id, &block);
        let merkle_root = block.compute_merkle_root();
        if (merkle_root.is_none()) {
            panic!("Merkle root is none");
        }
        let merkle_root = merkle_root.unwrap();

        let found_merkle_root =
            read_and_verify_bitcoin_merkle_path::<MockEnvironment>(tx_id.to_byte_array());
        assert_eq!(merkle_root.to_byte_array(), found_merkle_root);
    }

    #[test]
    fn test_bitcoin_merkle_path_fail() {
        // TODO: Change this test to not use the rpc
        let rpc = ExtendedRpc::new();

        // TODO: Make 2 dummy transactions and add them to the blockchain

        let block_hash = rpc.generate_dummy_block()[0];
        let block = rpc.inner.get_block(&block_hash).unwrap();
        let tx = block.txdata[0].clone();
        let tx_id = tx.txid();
        let wrong_tx_id = block.txdata[1].txid();
        ENVWriter::<MockEnvironment>::write_bitcoin_merkle_path(tx_id, &block);
        let merkle_root = block.compute_merkle_root();
        if (merkle_root.is_none()) {
            panic!("Merkle root is none");
        }
        let merkle_root = merkle_root.unwrap();

        let found_merkle_root =
            read_and_verify_bitcoin_merkle_path::<MockEnvironment>(wrong_tx_id.to_byte_array());
        assert_ne!(merkle_root.to_byte_array(), found_merkle_root);
    }

    #[test]
    #[ignore]
    fn test_proving() {
        let input = "020000000001025c290bc400f9e1c3f739f8e57ab60355d5a9ac33e9d2c24145b3565aee6bbce00000000000fdffffffa49a9fe38ffe5f5bda8289098e60572caa758c7795983b0008b5e99f01f446de0000000000fdffffff0300e1f50500000000225120df6f4ee3a0a625db6fa6a88176656541f4a63591f8b7174f7054cc52afbeaec800e1f505000000002251208c61eec2e14c785da78dd8ab98797996f866a6aac8c8d2389d77f38c3f4feff122020000000000002251208c61eec2e14c785da78dd8ab98797996f866a6aac8c8d2389d77f38c3f4feff101405de61774dc0275f491eb46561bc1b36148ef30467bf43f2b33796991d61a29a3a4b7e2047712e73fe983806f0d636b64c8a6202490daff202bca521a0faa70ae0140f80f92541832d6d8908df9a57d994b90ee74129c8943a17109da88d49cd1531314d051c8082be3b79d3281edde719ab2fab34fa3dfbe3ad60e5a2ab8a306d43100000000";
        let btc_tx = parse_hex_to_btc_tx(input).unwrap();
        let btc_tx_id = btc_tx.txid();
        ENVWriter::<MockEnvironment>::write_tx_to_env(btc_tx);
        let env = MockEnvironment::output_env();
        let prover = default_prover();
        let receipt = prover.prove_elf(env, GUEST_ELF).unwrap();
        let tx_id: [u8; 32] = receipt.journal.decode().unwrap();
        assert_eq!(btc_tx_id, Txid::from_byte_array(tx_id));
        // This code is working
    }
}
