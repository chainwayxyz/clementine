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
    use bitcoin::{Block, Txid};
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

    use bitcoin::consensus::encode::{deserialize, serialize};
    use operator_circuit::{GUEST_ELF, GUEST_ID};
    use risc0_zkvm::{default_prover, ExecutorEnv};

    #[test]
    fn test_tx() {
        MockEnvironment::reset_mock_env();
        let input = "020000000001025c290bc400f9e1c3f739f8e57ab60355d5a9ac33e9d2c24145b3565aee6bbce00000000000fdffffffa49a9fe38ffe5f5bda8289098e60572caa758c7795983b0008b5e99f01f446de0000000000fdffffff0300e1f50500000000225120df6f4ee3a0a625db6fa6a88176656541f4a63591f8b7174f7054cc52afbeaec800e1f505000000002251208c61eec2e14c785da78dd8ab98797996f866a6aac8c8d2389d77f38c3f4feff122020000000000002251208c61eec2e14c785da78dd8ab98797996f866a6aac8c8d2389d77f38c3f4feff101405de61774dc0275f491eb46561bc1b36148ef30467bf43f2b33796991d61a29a3a4b7e2047712e73fe983806f0d636b64c8a6202490daff202bca521a0faa70ae0140f80f92541832d6d8908df9a57d994b90ee74129c8943a17109da88d49cd1531314d051c8082be3b79d3281edde719ab2fab34fa3dfbe3ad60e5a2ab8a306d43100000000";
        let btc_tx = parse_hex_to_btc_tx(input).unwrap();
        let btc_tx_id = btc_tx.txid();
        ENVWriter::<MockEnvironment>::write_tx_to_env(btc_tx);
        let tx_id = read_tx_and_calculate_txid::<MockEnvironment>();
        assert_eq!(btc_tx_id, Txid::from_byte_array(tx_id));
    }

    #[test]
    fn test_bitcoin_merkle_path() {
        MockEnvironment::reset_mock_env();
        // Mainnet block 00000000b0c5a240b2a61d2e75692224efd4cbecdf6eaf4cc2cf477ca7c270e7
        let some_block = "010000004ddccd549d28f385ab457e98d1b11ce80bfea2c5ab93015ade4973e400000000bf4473e53794beae34e64fccc471dace6ae544180816f89591894e0f417a914cd74d6e49ffff001d323b3a7b0201000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0804ffff001d026e04ffffffff0100f2052a0100000043410446ef0102d1ec5240f0d061a4246c1bdef63fc3dbab7733052fbbf0ecd8f41fc26bf049ebb4f9527f374280259e7cfa99c48b0e3f39c51347a19a5819651503a5ac00000000010000000321f75f3139a013f50f315b23b0c9a2b6eac31e2bec98e5891c924664889942260000000049483045022100cb2c6b346a978ab8c61b18b5e9397755cbd17d6eb2fe0083ef32e067fa6c785a02206ce44e613f31d9a6b0517e46f3db1576e9812cc98d159bfdaf759a5014081b5c01ffffffff79cda0945903627c3da1f85fc95d0b8ee3e76ae0cfdc9a65d09744b1f8fc85430000000049483045022047957cdd957cfd0becd642f6b84d82f49b6cb4c51a91f49246908af7c3cfdf4a022100e96b46621f1bffcf5ea5982f88cef651e9354f5791602369bf5a82a6cd61a62501fffffffffe09f5fe3ffbf5ee97a54eb5e5069e9da6b4856ee86fc52938c2f979b0f38e82000000004847304402204165be9a4cbab8049e1af9723b96199bfd3e85f44c6b4c0177e3962686b26073022028f638da23fc003760861ad481ead4099312c60030d4cb57820ce4d33812a5ce01ffffffff01009d966b01000000434104ea1feff861b51fe3f5f8a3b12d0f4712db80e919548a80839fc47c6a21e66d957e9c5d8cd108c7a2d2324bad71f9904ac0ae7336507d785b17a2c115e427a32fac00000000";
        let block: Block = deserialize(&hex::decode(some_block).unwrap()).unwrap();
        let expected_merkle_root = block.compute_merkle_root().unwrap().to_byte_array();
        for tx in block.txdata.iter() {
            ENVWriter::<MockEnvironment>::write_bitcoin_merkle_path(tx.txid(), &block);
            let found_merkle_root =
                read_and_verify_bitcoin_merkle_path::<MockEnvironment>(tx.txid().to_byte_array());
            assert_eq!(expected_merkle_root, found_merkle_root);
        }
    }

    #[test]
    #[ignore]
    fn test_proving() {
        MockEnvironment::reset_mock_env();
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
