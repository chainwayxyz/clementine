use bitcoin::{Block, MerkleBlock, Transaction, TxMerkleNode, Txid};
use circuit_helpers::env::Environment;
use secp256k1::hashes::Hash;
use std::marker::PhantomData;

use crate::errors::BridgeError;

pub struct ENVWriter<E: Environment> {
    _marker: PhantomData<E>,
}

impl<E: Environment> ENVWriter<E> {
    pub fn write_tx_to_env(tx: &Transaction) {
        E::write_i32(tx.version.0);
        E::write_u32(tx.input.len() as u32);
        E::write_u32(tx.output.len() as u32);
        E::write_u32(tx.lock_time.to_consensus_u32());
        for input in tx.input.iter() {
            let prev_txid = input.previous_output.txid.as_byte_array();
            E::write_32bytes(*prev_txid);
            E::write_u32(input.previous_output.vout);
            E::write_u32(input.sequence.0);
            let script_sig_bytes = input.script_sig.as_bytes();
            E::write_u32(script_sig_bytes.len() as u32);
            let chunk_num = script_sig_bytes.len() as u32 / 32;
            let remainder = script_sig_bytes.len() as u32 % 32;
            for i in 0..chunk_num {
                E::write_32bytes(
                    script_sig_bytes[i as usize * 32..(i + 1) as usize * 32]
                        .try_into()
                        .unwrap(),
                );
            }
            if remainder > 0 {
                let padded = [0u8; 32];
                let mut padded_bytes = script_sig_bytes[chunk_num as usize * 32..].to_vec();
                padded_bytes.extend_from_slice(&padded[0..(32 - remainder) as usize]);
                E::write_32bytes(padded_bytes.try_into().unwrap());
            }
        }
        for output in tx.output.iter() {
            E::write_u64(output.value.to_sat());
            let output_script_pk = output.script_pubkey.as_bytes();
            // println!("Output ScriptPubKey len: {:?}", output_script_pk.len());
            if output_script_pk.len() == 34
                && output_script_pk[0] == 81u8
                && output_script_pk[1] == 32u8
            {
                E::write_u32(0); // 0 for taproot
                E::write_32bytes(output_script_pk[2..34].try_into().unwrap());
            } else {
                let script_pk_len = output_script_pk.len() as u32;
                E::write_u32(script_pk_len);
                let chunk_num = script_pk_len / 32;
                let remainder = script_pk_len % 32;
                for i in 0..chunk_num {
                    E::write_32bytes(
                        output_script_pk[i as usize * 32..(i + 1) as usize * 32]
                            .try_into()
                            .unwrap(),
                    );
                }
                if remainder > 0 {
                    let padded = [0u8; 32];
                    let mut padded_bytes = output_script_pk[chunk_num as usize * 32..].to_vec();
                    padded_bytes.extend_from_slice(&padded[0..(32 - remainder) as usize]);
                    E::write_32bytes(padded_bytes.try_into().unwrap());
                }
            }
        }
    }

    pub fn write_bitcoin_merkle_path(txid: Txid, block: &Block) -> Result<(), BridgeError> {
        let tx_ids = block
            .txdata
            .iter()
            .map(|tx| tx.txid())
            .collect::<Vec<Txid>>();

        // find the index of the txid in tx_id_array vector or give error "txid not found in block txids"
        let index = tx_ids
            .iter()
            .position(|&r| r == txid)
            .ok_or(BridgeError::TxidNotFound)?;
        E::write_u32(index as u32);

        let length = tx_ids.len();
        let depth = (length - 1).ilog(2) + 1;
        E::write_u32(depth);

        // merkle hashes list is a bit different from what we want, a merkle path, so need to do sth based on bits
        // length of merkle hashes for one txid is typically depth + 1, at least for the left half of the tree
        // we extract the merkle path which is of length "depth" from it
        let merkle_block = MerkleBlock::from_block_with_predicate(block, |t| *t == txid);
        let mut merkle_hashes = merkle_block
            .txn
            .hashes()
            .iter()
            .map(Some)
            .collect::<Vec<Option<&TxMerkleNode>>>();

        // fill the remaining path elements with None s, this indicates that last node should be duplicated
        while merkle_hashes.len() < depth as usize + 1 {
            merkle_hashes.push(None);
        }
        let mut merkle_path = Vec::new();
        for bit in (0..merkle_hashes.len() - 1)
            .rev()
            .map(|n: usize| (index >> n) & 1)
        {
            let i = if bit == 1 { 0 } else { merkle_hashes.len() - 1 };
            merkle_path.push(merkle_hashes[i]);
            merkle_hashes.remove(i);
        }

        // bits of path indicator determines if the next tree node should be read from env or be the copy of last node
        let mut path_indicator = 0_u32;

        // this list may contain less than depth elements, which is normally the size of a merkle path
        let mut merkle_path_to_be_sent = Vec::new();

        for node in merkle_path {
            path_indicator <<= 1;
            match node {
                Some(txmn) => merkle_path_to_be_sent.push(txmn),
                None => path_indicator += 1,
            }
        }

        merkle_path_to_be_sent.reverse();

        E::write_u32(path_indicator);

        for node in merkle_path_to_be_sent {
            E::write_32bytes(*node.as_byte_array());
        }
        Ok(())
    }
}

impl<E: Environment> Default for ENVWriter<E> {
    fn default() -> Self {
        Self::new()
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
    use std::sync::Mutex;
    lazy_static::lazy_static! {
        static ref SHARED_STATE: Mutex<i32> = Mutex::new(0);
    }

    use bitcoin::{block::Header, consensus::deserialize, Block, Txid};
    use circuit_helpers::{
        bitcoin::{read_and_verify_bitcoin_merkle_path, read_tx_and_calculate_txid},
        bridge::{read_blocks_and_add_to_merkle_tree, read_blocks_and_calculate_work},
        env::Environment,
        incremental_merkle::IncrementalMerkleTree,
    };
    // use operator_circuit::GUEST_ELF;

    use secp256k1::hashes::Hash;

    use crate::{
        env_writer::ENVWriter,
        errors::BridgeError,
        mock_env::MockEnvironment,
        utils::{json_to_raw, parse_hex_to_btc_tx},
    };

    fn test_block_merkle_path(block: Block) -> Result<(), BridgeError> {
        let expected_merkle_root = block.compute_merkle_root().unwrap().to_byte_array();
        for tx in block.txdata.iter() {
            ENVWriter::<MockEnvironment>::write_bitcoin_merkle_path(tx.txid(), &block)?;
            let found_merkle_root =
                read_and_verify_bitcoin_merkle_path::<MockEnvironment>(tx.txid().to_byte_array());
            assert_eq!(expected_merkle_root, found_merkle_root);
        }
        Ok(())
    }

    #[test]
    fn test_tx() {
        let mut _num = SHARED_STATE.lock().unwrap();

        MockEnvironment::reset_mock_env();
        let input = "020000000001025c290bc400f9e1c3f739f8e57ab60355d5a9ac33e9d2c24145b3565aee6bbce00000000000fdffffffa49a9fe38ffe5f5bda8289098e60572caa758c7795983b0008b5e99f01f446de0000000000fdffffff0300e1f50500000000225120df6f4ee3a0a625db6fa6a88176656541f4a63591f8b7174f7054cc52afbeaec800e1f505000000002251208c61eec2e14c785da78dd8ab98797996f866a6aac8c8d2389d77f38c3f4feff122020000000000002251208c61eec2e14c785da78dd8ab98797996f866a6aac8c8d2389d77f38c3f4feff101405de61774dc0275f491eb46561bc1b36148ef30467bf43f2b33796991d61a29a3a4b7e2047712e73fe983806f0d636b64c8a6202490daff202bca521a0faa70ae0140f80f92541832d6d8908df9a57d994b90ee74129c8943a17109da88d49cd1531314d051c8082be3b79d3281edde719ab2fab34fa3dfbe3ad60e5a2ab8a306d43100000000";
        let btc_tx = parse_hex_to_btc_tx(input).unwrap();
        let btc_tx_id = btc_tx.txid();
        ENVWriter::<MockEnvironment>::write_tx_to_env(&btc_tx);
        let tx_id = read_tx_and_calculate_txid::<MockEnvironment>(None, None);
        assert_eq!(btc_tx_id, Txid::from_byte_array(tx_id));
    }

    #[test]
    fn test_bitcoin_merkle_path() {
        let mut _num = SHARED_STATE.lock().unwrap();

        MockEnvironment::reset_mock_env();
        // // Mainnet block 00000000b0c5a240b2a61d2e75692224efd4cbecdf6eaf4cc2cf477ca7c270e7
        // let some_block = "010000004ddccd549d28f385ab457e98d1b11ce80bfea2c5ab93015ade4973e400000000bf4473e53794beae34e64fccc471dace6ae544180816f89591894e0f417a914cd74d6e49ffff001d323b3a7b0201000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0804ffff001d026e04ffffffff0100f2052a0100000043410446ef0102d1ec5240f0d061a4246c1bdef63fc3dbab7733052fbbf0ecd8f41fc26bf049ebb4f9527f374280259e7cfa99c48b0e3f39c51347a19a5819651503a5ac00000000010000000321f75f3139a013f50f315b23b0c9a2b6eac31e2bec98e5891c924664889942260000000049483045022100cb2c6b346a978ab8c61b18b5e9397755cbd17d6eb2fe0083ef32e067fa6c785a02206ce44e613f31d9a6b0517e46f3db1576e9812cc98d159bfdaf759a5014081b5c01ffffffff79cda0945903627c3da1f85fc95d0b8ee3e76ae0cfdc9a65d09744b1f8fc85430000000049483045022047957cdd957cfd0becd642f6b84d82f49b6cb4c51a91f49246908af7c3cfdf4a022100e96b46621f1bffcf5ea5982f88cef651e9354f5791602369bf5a82a6cd61a62501fffffffffe09f5fe3ffbf5ee97a54eb5e5069e9da6b4856ee86fc52938c2f979b0f38e82000000004847304402204165be9a4cbab8049e1af9723b96199bfd3e85f44c6b4c0177e3962686b26073022028f638da23fc003760861ad481ead4099312c60030d4cb57820ce4d33812a5ce01ffffffff01009d966b01000000434104ea1feff861b51fe3f5f8a3b12d0f4712db80e919548a80839fc47c6a21e66d957e9c5d8cd108c7a2d2324bad71f9904ac0ae7336507d785b17a2c115e427a32fac00000000";
        // let block1: Block = deserialize(&hex::decode(some_block).unwrap()).unwrap();
        // test_block_merkle_path(block1);

        // let segwit_block2 = include_bytes!("../tests/data/mainnet_block_000000000000000000000c835b2adcaedc20fdf6ee440009c249452c726dafae.raw").to_vec();
        // let block2: Block = deserialize(&segwit_block2).unwrap();
        // test_block_merkle_path(block2);

        // let segwit_block3 = include_bytes!("../tests/data/mainnet_block_00000000000000000000edfe523d5e2993781d2305f51218ebfc236a250792d6.raw").to_vec();
        // let block3: Block = deserialize(&segwit_block3).unwrap();
        // test_block_merkle_path(block3);

        let segwit_block4 = include_bytes!("../tests/data/testnet_block_000000000000045e0b1660b6445b5e5c5ab63c9a4f956be7e1e69be04fa4497b.raw").to_vec();
        let block4: Block = deserialize(&segwit_block4).unwrap();
        test_block_merkle_path(block4).unwrap();
    }

    #[test]
    fn test_all_txids_in_block() {
        let mut _num = SHARED_STATE.lock().unwrap();

        MockEnvironment::reset_mock_env();
        let segwit_block = include_bytes!("../tests/data/mainnet_block_000000000000000000000c835b2adcaedc20fdf6ee440009c249452c726dafae.raw").to_vec();
        let block: Block = deserialize(&segwit_block).unwrap();

        for (_i, tx) in block.txdata.iter().enumerate() {
            MockEnvironment::reset_mock_env();
            ENVWriter::<MockEnvironment>::write_tx_to_env(tx);
            let tx_id = read_tx_and_calculate_txid::<MockEnvironment>(None, None);
            assert_eq!(tx.txid(), Txid::from_byte_array(tx_id));
        }
    }

    #[test]
    fn test_all_txids_input_outputs() {
        let mut _num = SHARED_STATE.lock().unwrap();

        MockEnvironment::reset_mock_env();
        let segwit_block = include_bytes!("../tests/data/mainnet_block_00000000000000000000edfe523d5e2993781d2305f51218ebfc236a250792d6.raw").to_vec();
        let block: Block = deserialize(&segwit_block).unwrap();

        for (_i, tx) in block.txdata.iter().enumerate() {
            for output in tx.output.iter() {
                MockEnvironment::reset_mock_env();
                let script_pubkey = output.script_pubkey.as_bytes();
                if script_pubkey.len() == 34 && script_pubkey[0] == 81u8 && script_pubkey[1] == 32u8
                {
                    ENVWriter::<MockEnvironment>::write_tx_to_env(tx);
                    let tx_id = read_tx_and_calculate_txid::<MockEnvironment>(
                        None,
                        Some((
                            output.value.to_sat(),
                            script_pubkey[2..34].try_into().unwrap(),
                        )),
                    );
                    assert_eq!(tx.txid(), Txid::from_byte_array(tx_id));
                }
            }
        }

        for (_i, tx) in block.txdata.iter().enumerate() {
            for input in tx.input.iter() {
                MockEnvironment::reset_mock_env();
                let txid = input.previous_output.txid.to_byte_array();
                let vout = input.previous_output.vout;
                ENVWriter::<MockEnvironment>::write_tx_to_env(tx);
                let tx_id = read_tx_and_calculate_txid::<MockEnvironment>(Some((txid, vout)), None);
                assert_eq!(tx.txid(), Txid::from_byte_array(tx_id));
            }
        }
    }

    #[test]
    fn test_read_blocks_and_add_to_merkle_tree() {
        let mut _num = SHARED_STATE.lock().unwrap();
        MockEnvironment::reset_mock_env();
        let headers_hex = [
            "010000006fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000982051fd1e4ba744bbbe680e1fee14677ba1a3c3540bf7b1cdb606e857233e0e61bc6649ffff001d01e36299",
            "010000004860eb18bf1b1620e37e9490fc8a427514416fd75159ab86688e9a8300000000d5fdcc541e25de1c7a5addedf24858b8bb665c9f36ef744ee42c316022c90f9bb0bc6649ffff001d08d2bd61",
            "01000000bddd99ccfda39da1b108ce1a5d70038d0a967bacb68b6b63065f626a0000000044f672226090d85db9a9f2fbfe5f0f9609b387af7be5b7fbb7a1767c831c9e995dbe6649ffff001d05e0ed6d",
            "010000004944469562ae1c2c74d9a535e00b6f3e40ffbad4f2fda3895501b582000000007a06ea98cd40ba2e3288262b28638cec5337c1456aaf5eedc8e9e5a20f062bdf8cc16649ffff001d2bfee0a9",
            "0100000085144a84488ea88d221c8bd6c059da090e88f8a2c99690ee55dbba4e00000000e11c48fecdd9e72510ca84f023370c9a38bf91ac5cae88019bee94d24528526344c36649ffff001d1d03e477",
            "01000000fc33f596f822a0a1951ffdbf2a897b095636ad871707bf5d3162729b00000000379dfb96a5ea8c81700ea4ac6b97ae9a9312b2d4301a29580e924ee6761a2520adc46649ffff001d189c4c97",
            "010000008d778fdc15a2d3fb76b7122a3b5582bea4f21f5a0c693537e7a03130000000003f674005103b42f984169c7d008370967e91920a6a5d64fd51282f75bc73a68af1c66649ffff001d39a59c86",
            "010000004494c8cf4154bdcc0720cd4a59d9c9b285e4b146d45f061d2b6c967100000000e3855ed886605b6d4a99d5fa2ef2e9b0b164e63df3c4136bebf2d0dac0f1f7a667c86649ffff001d1c4b5666",
            "01000000c60ddef1b7618ca2348a46e868afc26e3efc68226c78aa47f8488c4000000000c997a5e56e104102fa209c6a852dd90660a20b2d9c352423edce25857fcd37047fca6649ffff001d28404f53",
            "010000000508085c47cc849eb80ea905cc7800a3be674ffc57263cf210c59d8d00000000112ba175a1e04b14ba9e7ea5f76ab640affeef5ec98173ac9799a852fa39add320cd6649ffff001d1e2de565",
            "01000000e915d9a478e3adf3186c07c61a22228b10fd87df343c92782ecc052c000000006e06373c80de397406dc3d19c90d71d230058d28293614ea58d6a57f8f5d32f8b8ce6649ffff001d173807f8"
        ];
        let headers: Vec<Header> = headers_hex
            .iter()
            .map(|h| deserialize(&hex::decode(h).unwrap()).unwrap())
            .collect();
        println!("headers: {:?}", headers);
        MockEnvironment::write_u32(headers.len() as u32);
        for header in headers.iter() {
            let version = header.version.to_consensus();
            let merkle_root = header.merkle_root.as_byte_array();
            let time = header.time;
            let bits = header.bits.to_consensus();
            let nonce = header.nonce;
            // println!("version: {:?}", version);
            // println!("merkle_root: {:?}", merkle_root);
            // println!("time: {:?}", time);
            // println!("bits: {:?}", bits);
            // println!("nonce: {:?}", nonce);
            MockEnvironment::write_i32(version);
            MockEnvironment::write_32bytes(*merkle_root);
            MockEnvironment::write_u32(time);
            MockEnvironment::write_u32(bits);
            MockEnvironment::write_u32(nonce);
        }
        let mut incremental_merkle_tree = IncrementalMerkleTree::<32>::new();
        let start_block_hash = headers[0].prev_blockhash.to_byte_array();
        // println!("start_block_hash: {:?}", start_block_hash);
        let res = read_blocks_and_add_to_merkle_tree::<MockEnvironment>(
            start_block_hash,
            &mut incremental_merkle_tree,
        );
        println!("res: {:?}", res);
    }

    #[test]
    fn test_read_blocks_and_calculate_work() {
        let mut _num = SHARED_STATE.lock().unwrap();
        MockEnvironment::reset_mock_env();
        let headers_hex = [
            "010000006fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000982051fd1e4ba744bbbe680e1fee14677ba1a3c3540bf7b1cdb606e857233e0e61bc6649ffff001d01e36299",
            "010000004860eb18bf1b1620e37e9490fc8a427514416fd75159ab86688e9a8300000000d5fdcc541e25de1c7a5addedf24858b8bb665c9f36ef744ee42c316022c90f9bb0bc6649ffff001d08d2bd61",
            "01000000bddd99ccfda39da1b108ce1a5d70038d0a967bacb68b6b63065f626a0000000044f672226090d85db9a9f2fbfe5f0f9609b387af7be5b7fbb7a1767c831c9e995dbe6649ffff001d05e0ed6d",
            "010000004944469562ae1c2c74d9a535e00b6f3e40ffbad4f2fda3895501b582000000007a06ea98cd40ba2e3288262b28638cec5337c1456aaf5eedc8e9e5a20f062bdf8cc16649ffff001d2bfee0a9",
            "0100000085144a84488ea88d221c8bd6c059da090e88f8a2c99690ee55dbba4e00000000e11c48fecdd9e72510ca84f023370c9a38bf91ac5cae88019bee94d24528526344c36649ffff001d1d03e477",
            "01000000fc33f596f822a0a1951ffdbf2a897b095636ad871707bf5d3162729b00000000379dfb96a5ea8c81700ea4ac6b97ae9a9312b2d4301a29580e924ee6761a2520adc46649ffff001d189c4c97",
            "010000008d778fdc15a2d3fb76b7122a3b5582bea4f21f5a0c693537e7a03130000000003f674005103b42f984169c7d008370967e91920a6a5d64fd51282f75bc73a68af1c66649ffff001d39a59c86",
            "010000004494c8cf4154bdcc0720cd4a59d9c9b285e4b146d45f061d2b6c967100000000e3855ed886605b6d4a99d5fa2ef2e9b0b164e63df3c4136bebf2d0dac0f1f7a667c86649ffff001d1c4b5666",
            "01000000c60ddef1b7618ca2348a46e868afc26e3efc68226c78aa47f8488c4000000000c997a5e56e104102fa209c6a852dd90660a20b2d9c352423edce25857fcd37047fca6649ffff001d28404f53",
            "010000000508085c47cc849eb80ea905cc7800a3be674ffc57263cf210c59d8d00000000112ba175a1e04b14ba9e7ea5f76ab640affeef5ec98173ac9799a852fa39add320cd6649ffff001d1e2de565",
            "01000000e915d9a478e3adf3186c07c61a22228b10fd87df343c92782ecc052c000000006e06373c80de397406dc3d19c90d71d230058d28293614ea58d6a57f8f5d32f8b8ce6649ffff001d173807f8"
        ];
        let headers: Vec<Header> = headers_hex
            .iter()
            .map(|h| deserialize(&hex::decode(h).unwrap()).unwrap())
            .collect();
        println!("headers: {:?}", headers);
        MockEnvironment::write_u32(headers.len() as u32);
        for header in headers.iter() {
            let version = header.version.to_consensus();
            let merkle_root = header.merkle_root.as_byte_array();
            let time = header.time;
            let bits = header.bits.to_consensus();
            let nonce = header.nonce;
            MockEnvironment::write_i32(version);
            MockEnvironment::write_32bytes(*merkle_root);
            MockEnvironment::write_u32(time);
            MockEnvironment::write_u32(bits);
            MockEnvironment::write_u32(nonce);
        }
        let start_block_hash = headers[0].prev_blockhash.to_byte_array();
        let res = read_blocks_and_calculate_work::<MockEnvironment>(start_block_hash);
        println!("res: {:?}", res);
    }

    #[test]
    fn test_convert_json_to_raw() {
        let json_file_path = "./tests/data/blockhash_1.json";
        let raw_file_path = "./tests/data/blockhash_1.raw";

        // Convert the .json file to a .raw file
        json_to_raw(json_file_path, raw_file_path).unwrap();

        println!("Conversion completed successfully.");
    }

    // #[test]
    // #[ignore]
    // fn test_proving() {
    //     let mut _num = SHARED_STATE.lock().unwrap();

    //     MockEnvironment::reset_mock_env();
    //     let input = "020000000001025c290bc400f9e1c3f739f8e57ab60355d5a9ac33e9d2c24145b3565aee6bbce00000000000fdffffffa49a9fe38ffe5f5bda8289098e60572caa758c7795983b0008b5e99f01f446de0000000000fdffffff0300e1f50500000000225120df6f4ee3a0a625db6fa6a88176656541f4a63591f8b7174f7054cc52afbeaec800e1f505000000002251208c61eec2e14c785da78dd8ab98797996f866a6aac8c8d2389d77f38c3f4feff122020000000000002251208c61eec2e14c785da78dd8ab98797996f866a6aac8c8d2389d77f38c3f4feff101405de61774dc0275f491eb46561bc1b36148ef30467bf43f2b33796991d61a29a3a4b7e2047712e73fe983806f0d636b64c8a6202490daff202bca521a0faa70ae0140f80f92541832d6d8908df9a57d994b90ee74129c8943a17109da88d49cd1531314d051c8082be3b79d3281edde719ab2fab34fa3dfbe3ad60e5a2ab8a306d43100000000";
    //     let btc_tx = parse_hex_to_btc_tx(input).unwrap();
    //     let btc_tx_id = btc_tx.txid();
    //     ENVWriter::<MockEnvironment>::write_tx_to_env(&btc_tx);
    //     let env = MockEnvironment::output_env();
    //     let prover = default_prover();
    //     let receipt = prover.prove_elf(env, GUEST_ELF).unwrap();
    //     let tx_id: [u8; 32] = receipt.journal.decode().unwrap();
    //     assert_eq!(btc_tx_id, Txid::from_byte_array(tx_id));
    //     // This code is working
    // }
}
