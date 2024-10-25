/// TODO: This could be moved to builder crate.
use crate::{errors::BridgeError, merkle::MerkleTree};
use bitcoin::{
    block::Header, consensus::serialize, Block, MerkleBlock, Transaction, TxMerkleNode, Txid,
};
use bitcoin::{Wtxid, XOnlyPublicKey};
use clementine_circuits::double_sha256_hash;
use clementine_circuits::env::Environment;
use secp256k1::hashes::Hash;
use std::marker::PhantomData;

pub struct ENVWriter<E: Environment> {
    _marker: PhantomData<E>,
}

impl<E: Environment> ENVWriter<E> {
    pub fn write_block_header_without_prev(header: &Header) {
        let version = header.version.to_consensus();
        let merkle_root = header.merkle_root.as_byte_array();
        let time = header.time;
        let bits = header.bits.to_consensus();
        let nonce = header.nonce;
        E::write_i32(version);
        E::write_32bytes(*merkle_root);
        E::write_u32(time);
        E::write_u32(bits);
        E::write_u32(nonce);
    }

    pub fn write_block_header_without_mt_root(header: &Header) {
        let version = header.version.to_consensus();
        let prev_blockhash = header.prev_blockhash.as_byte_array();
        let time = header.time;
        let bits = header.bits.to_consensus();
        let nonce = header.nonce;
        E::write_i32(version);
        E::write_32bytes(*prev_blockhash);
        E::write_u32(time);
        E::write_u32(bits);
        E::write_u32(nonce);
    }

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

    /// Pretty long and complicated merkle path extraction function to convert rust bitcoins merkleBlock to a flatten single merkle path
    /// Need to simplify this
    pub fn get_merkle_path_from_merkle_block(
        mb: MerkleBlock,
    ) -> Result<(Vec<TxMerkleNode>, u32), BridgeError> {
        let mut matches: Vec<Txid> = vec![];
        let mut index: Vec<u32> = vec![];
        mb.extract_matches(&mut matches, &mut index)?;

        if matches.len() != 1 {
            return Err(BridgeError::MerkleProofError);
        }

        if index.len() != 1 {
            return Err(BridgeError::MerkleProofError);
        }

        let txid = matches[0];
        let index = index[0];
        let length = mb.txn.num_transactions();
        let depth = (length - 1).ilog(2) + 1;

        let mut merkle_hashes = mb
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
                Some(txmn) => merkle_path_to_be_sent.push(*txmn),
                None => path_indicator += 1,
            }
        }

        merkle_path_to_be_sent.reverse();

        let mut hash = txid.to_byte_array();
        let mut current_index = index;
        let mut reader_pointer = 0;

        for _ in 0..depth {
            let node = if path_indicator & 1 == 1 {
                merkle_path_to_be_sent.insert(reader_pointer, TxMerkleNode::from_byte_array(hash));
                reader_pointer += 1;
                hash
            } else {
                let node = merkle_path_to_be_sent[reader_pointer];
                reader_pointer += 1;
                *node.as_byte_array()
            };
            path_indicator >>= 1;
            hash = if current_index & 1 == 0 {
                double_sha256_hash!(&hash, &node)
            } else {
                double_sha256_hash!(&node, &hash)
            };
            current_index /= 2;
        }

        Ok((merkle_path_to_be_sent, index))
    }

    pub fn write_bitcoin_merkle_path(txid: Txid, block: &Block) -> Result<(), BridgeError> {
        let merkle_block = MerkleBlock::from_block_with_predicate(block, |t| *t == txid);

        let (merkle_path_to_be_sent, index) =
            ENVWriter::<E>::get_merkle_path_from_merkle_block(merkle_block)?;

        E::write_u32(index);

        E::write_u32(merkle_path_to_be_sent.len() as u32);

        for node in merkle_path_to_be_sent {
            E::write_32bytes(*node.as_byte_array());
        }
        Ok(())
    }

    pub fn write_witness_merkle_path(txid: Txid, block: &Block) -> Result<(), BridgeError> {
        let mut wtxid = Txid::all_zeros();
        let hashes = block
            .txdata
            .iter()
            .enumerate()
            .map(|(i, t)| {
                let ctxid = t.compute_txid();
                let cwtxid = t.compute_wtxid();
                if ctxid == txid {
                    wtxid = Txid::from_raw_hash(cwtxid.to_raw_hash());
                }
                if i == 0 {
                    // Replace the first hash with zeroes.
                    Txid::from_raw_hash(Wtxid::all_zeros().to_raw_hash())
                } else {
                    Txid::from_raw_hash(cwtxid.to_raw_hash())
                }
            })
            .collect::<Vec<Txid>>();
        let witness_root = block.witness_root().unwrap();
        let dummy_header = Header {
            version: block.header.version,
            prev_blockhash: block.header.prev_blockhash,
            merkle_root: TxMerkleNode::from_raw_hash(witness_root.to_raw_hash()),
            time: block.header.time,
            bits: block.header.bits,
            nonce: block.header.nonce,
        };
        let merkle_block =
            MerkleBlock::from_header_txids_with_predicate(&dummy_header, &hashes, |t| *t == wtxid);

        let (merkle_path_to_be_sent, index) =
            ENVWriter::<E>::get_merkle_path_from_merkle_block(merkle_block)?;

        E::write_u32(index);

        E::write_u32(merkle_path_to_be_sent.len() as u32);

        for node in merkle_path_to_be_sent {
            E::write_32bytes(*node.as_byte_array());
        }
        Ok(())
    }

    pub fn write_merkle_tree_proof<const DEPTH: usize>(
        leaf: [u8; 32],
        index: Option<u32>,
        mt: &MerkleTree<DEPTH>,
    ) {
        let found_index = match index {
            Some(i) => i,
            None => {
                let idx = mt
                    .index_of(leaf)
                    .expect("Leaf not found in the Merkle tree");
                E::write_u32(idx);
                idx
            }
        };
        let path = mt.path(found_index);
        for elem in path {
            E::write_32bytes(elem);
        }
    }

    pub fn write_blocks(block_headers: Vec<Header>) {
        E::write_u32(block_headers.len() as u32);
        for header in block_headers.iter() {
            ENVWriter::<E>::write_block_header_without_prev(header);
        }
    }

    pub fn write_blocks_and_add_to_merkle_tree<const DEPTH: usize>(
        block_headers: Vec<Header>,
        blockhashes_mt: &mut MerkleTree<DEPTH>,
    ) {
        E::write_u32(block_headers.len() as u32);
        tracing::debug!(
            "WROTE block_headers.len(): {:?}",
            block_headers.len() as u32
        );
        for header in block_headers.iter() {
            ENVWriter::<E>::write_block_header_without_prev(header);
            // tracing::debug!("WROTE block header without prev: {:?}", header);
            blockhashes_mt.add(serialize(&header.block_hash()).try_into().unwrap());
        }
    }

    pub fn write_preimages(operator_pk: XOnlyPublicKey, preimages: &Vec<[u8; 32]>) {
        let num_preimages = preimages.len() as u32;
        E::write_u32(num_preimages);
        let operator_pk_bytes: [u8; 32] = operator_pk.serialize();
        E::write_32bytes(operator_pk_bytes);
        for preimage in preimages {
            E::write_32bytes(*preimage);
        }
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

// TODO: write tests for circuits
#[cfg(test)]
mod tests {
    use crate::{
        env_writer::ENVWriter, errors::BridgeError, merkle::MerkleTree, mock::env::MockEnvironment,
    };
    use bitcoin::{
        block::Header,
        consensus::{deserialize, serialize},
        Block, Txid,
    };
    use clementine_circuits::{
        bitcoin::{read_and_verify_bitcoin_merkle_path, read_tx_and_calculate_txid},
        bridge::{read_blocks_and_add_to_merkle_tree, read_merkle_tree_proof},
        env::Environment,
        incremental_merkle::IncrementalMerkleTree,
    };
    use crypto_bigint::U256;
    use risc0_zkvm::{default_prover, ProverOpts, Receipt};
    use secp256k1::hashes::Hash;
    use std::sync::Mutex;
    use verifier_circuit::{GUEST_ELF, GUEST_ID};

    lazy_static::lazy_static! {
        static ref SHARED_STATE: Mutex<i32> = Mutex::new(0);
    }

    fn test_block_merkle_path(block: Block) -> Result<(), BridgeError> {
        let expected_merkle_root = block.compute_merkle_root().unwrap().to_byte_array();
        for tx in block.txdata.iter() {
            let ctxid = tx.compute_txid();
            ENVWriter::<MockEnvironment>::write_bitcoin_merkle_path(ctxid, &block)?;
            let found_merkle_root =
                read_and_verify_bitcoin_merkle_path::<MockEnvironment>(ctxid.to_byte_array());
            assert_eq!(expected_merkle_root, found_merkle_root);
        }
        Ok(())
    }

    fn test_witness_merkle_path(block: Block) -> Result<(), BridgeError> {
        let expected_merkle_root = block.witness_root().unwrap().to_byte_array();
        for tx in block.txdata.iter() {
            if tx.is_coinbase() {
                continue;
            }
            ENVWriter::<MockEnvironment>::write_witness_merkle_path(tx.compute_txid(), &block)?;
            let found_merkle_root = read_and_verify_bitcoin_merkle_path::<MockEnvironment>(
                tx.compute_wtxid().to_byte_array(),
            );
            assert_eq!(expected_merkle_root, found_merkle_root);
        }
        Ok(())
    }

    // #[test]
    // fn test_tx() {
    //     let mut _num = SHARED_STATE.lock().unwrap();

    //     MockEnvironment::reset_mock_env();
    //     let input = "020000000001025c290bc400f9e1c3f739f8e57ab60355d5a9ac33e9d2c24145b3565aee6bbce00000000000fdffffffa49a9fe38ffe5f5bda8289098e60572caa758c7795983b0008b5e99f01f446de0000000000fdffffff0300e1f50500000000225120df6f4ee3a0a625db6fa6a88176656541f4a63591f8b7174f7054cc52afbeaec800e1f505000000002251208c61eec2e14c785da78dd8ab98797996f866a6aac8c8d2389d77f38c3f4feff122020000000000002251208c61eec2e14c785da78dd8ab98797996f866a6aac8c8d2389d77f38c3f4feff101405de61774dc0275f491eb46561bc1b36148ef30467bf43f2b33796991d61a29a3a4b7e2047712e73fe983806f0d636b64c8a6202490daff202bca521a0faa70ae0140f80f92541832d6d8908df9a57d994b90ee74129c8943a17109da88d49cd1531314d051c8082be3b79d3281edde719ab2fab34fa3dfbe3ad60e5a2ab8a306d43100000000";
    //     let btc_tx = parse_hex_to_btc_tx(input).unwrap();
    //     let btc_tx_id = btc_tx.compute_txid();
    //     ENVWriter::<MockEnvironment>::write_tx_to_env(&btc_tx);
    //     let tx_id = read_tx_and_calculate_txid::<MockEnvironment>(None, None);
    //     assert_eq!(btc_tx_id, Txid::from_byte_array(tx_id));
    // }

    #[test]
    fn test_bitcoin_merkle_path() {
        let mut _num = SHARED_STATE.lock().unwrap();

        MockEnvironment::reset_mock_env();
        // Mainnet block 00000000b0c5a240b2a61d2e75692224efd4cbecdf6eaf4cc2cf477ca7c270e7
        // let some_block = "010000004ddccd549d28f385ab457e98d1b11ce80bfea2c5ab93015ade4973e400000000bf4473e53794beae34e64fccc471dace6ae544180816f89591894e0f417a914cd74d6e49ffff001d323b3a7b0201000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0804ffff001d026e04ffffffff0100f2052a0100000043410446ef0102d1ec5240f0d061a4246c1bdef63fc3dbab7733052fbbf0ecd8f41fc26bf049ebb4f9527f374280259e7cfa99c48b0e3f39c51347a19a5819651503a5ac00000000010000000321f75f3139a013f50f315b23b0c9a2b6eac31e2bec98e5891c924664889942260000000049483045022100cb2c6b346a978ab8c61b18b5e9397755cbd17d6eb2fe0083ef32e067fa6c785a02206ce44e613f31d9a6b0517e46f3db1576e9812cc98d159bfdaf759a5014081b5c01ffffffff79cda0945903627c3da1f85fc95d0b8ee3e76ae0cfdc9a65d09744b1f8fc85430000000049483045022047957cdd957cfd0becd642f6b84d82f49b6cb4c51a91f49246908af7c3cfdf4a022100e96b46621f1bffcf5ea5982f88cef651e9354f5791602369bf5a82a6cd61a62501fffffffffe09f5fe3ffbf5ee97a54eb5e5069e9da6b4856ee86fc52938c2f979b0f38e82000000004847304402204165be9a4cbab8049e1af9723b96199bfd3e85f44c6b4c0177e3962686b26073022028f638da23fc003760861ad481ead4099312c60030d4cb57820ce4d33812a5ce01ffffffff01009d966b01000000434104ea1feff861b51fe3f5f8a3b12d0f4712db80e919548a80839fc47c6a21e66d957e9c5d8cd108c7a2d2324bad71f9904ac0ae7336507d785b17a2c115e427a32fac00000000";
        // let block1: Block = deserialize(&hex::decode(some_block).unwrap()).unwrap();
        // test_block_merkle_path(block1).unwrap();

        // let segwit_block2 = include_bytes!("../tests/data/mainnet_block_000000000000000000000c835b2adcaedc20fdf6ee440009c249452c726dafae.raw").to_vec();
        // let block2: Block = deserialize(&segwit_block2).unwrap();
        // test_block_merkle_path(block2).unwrap();

        // let segwit_block3 = include_bytes!("../tests/data/mainnet_block_00000000000000000000edfe523d5e2993781d2305f51218ebfc236a250792d6.raw").to_vec();
        // let block3: Block = deserialize(&segwit_block3).unwrap();
        // test_block_merkle_path(block3).unwrap();

        let segwit_block4 = include_bytes!("../tests/data/testnet_block_000000000000045e0b1660b6445b5e5c5ab63c9a4f956be7e1e69be04fa4497b.raw").to_vec();
        let block4: Block = deserialize(&segwit_block4).unwrap();
        test_block_merkle_path(block4).unwrap();
    }

    #[test]
    fn test_bitcoin_witness_merkle_path() {
        let mut _num = SHARED_STATE.lock().unwrap();

        MockEnvironment::reset_mock_env();
        // Mainnet block 00000000b0c5a240b2a61d2e75692224efd4cbecdf6eaf4cc2cf477ca7c270e7
        // let some_block = "010000004ddccd549d28f385ab457e98d1b11ce80bfea2c5ab93015ade4973e400000000bf4473e53794beae34e64fccc471dace6ae544180816f89591894e0f417a914cd74d6e49ffff001d323b3a7b0201000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0804ffff001d026e04ffffffff0100f2052a0100000043410446ef0102d1ec5240f0d061a4246c1bdef63fc3dbab7733052fbbf0ecd8f41fc26bf049ebb4f9527f374280259e7cfa99c48b0e3f39c51347a19a5819651503a5ac00000000010000000321f75f3139a013f50f315b23b0c9a2b6eac31e2bec98e5891c924664889942260000000049483045022100cb2c6b346a978ab8c61b18b5e9397755cbd17d6eb2fe0083ef32e067fa6c785a02206ce44e613f31d9a6b0517e46f3db1576e9812cc98d159bfdaf759a5014081b5c01ffffffff79cda0945903627c3da1f85fc95d0b8ee3e76ae0cfdc9a65d09744b1f8fc85430000000049483045022047957cdd957cfd0becd642f6b84d82f49b6cb4c51a91f49246908af7c3cfdf4a022100e96b46621f1bffcf5ea5982f88cef651e9354f5791602369bf5a82a6cd61a62501fffffffffe09f5fe3ffbf5ee97a54eb5e5069e9da6b4856ee86fc52938c2f979b0f38e82000000004847304402204165be9a4cbab8049e1af9723b96199bfd3e85f44c6b4c0177e3962686b26073022028f638da23fc003760861ad481ead4099312c60030d4cb57820ce4d33812a5ce01ffffffff01009d966b01000000434104ea1feff861b51fe3f5f8a3b12d0f4712db80e919548a80839fc47c6a21e66d957e9c5d8cd108c7a2d2324bad71f9904ac0ae7336507d785b17a2c115e427a32fac00000000";
        // let block1: Block = deserialize(&hex::decode(some_block).unwrap()).unwrap();
        // test_witness_merkle_path(block1).unwrap();

        // let segwit_block2 = include_bytes!("../tests/data/mainnet_block_000000000000000000000c835b2adcaedc20fdf6ee440009c249452c726dafae.raw").to_vec();
        // let block2: Block = deserialize(&segwit_block2).unwrap();
        // test_witness_merkle_path(block2).unwrap();

        // let segwit_block3 = include_bytes!("../tests/data/mainnet_block_00000000000000000000edfe523d5e2993781d2305f51218ebfc236a250792d6.raw").to_vec();
        // let block3: Block = deserialize(&segwit_block3).unwrap();
        // test_witness_merkle_path(block3).unwrap();

        let segwit_block4 = include_bytes!("../tests/data/testnet_block_000000000000045e0b1660b6445b5e5c5ab63c9a4f956be7e1e69be04fa4497b.raw").to_vec();
        let block4: Block = deserialize(&segwit_block4).unwrap();
        test_witness_merkle_path(block4).unwrap();
    }

    #[test]
    fn test_all_txids_in_block() {
        let mut _num = SHARED_STATE.lock().unwrap();

        MockEnvironment::reset_mock_env();
        let segwit_block = include_bytes!("../tests/data/mainnet_block_000000000000000000000c835b2adcaedc20fdf6ee440009c249452c726dafae.raw").to_vec();
        let block: Block = deserialize(&segwit_block).unwrap();

        for tx in block.txdata.iter() {
            MockEnvironment::reset_mock_env();
            ENVWriter::<MockEnvironment>::write_tx_to_env(tx);
            let tx_id = read_tx_and_calculate_txid::<MockEnvironment>(None, None);
            assert_eq!(tx.compute_txid(), Txid::from_byte_array(tx_id));
        }
    }

    #[test]
    fn test_all_txids_input_outputs() {
        let mut _num = SHARED_STATE.lock().unwrap();

        MockEnvironment::reset_mock_env();
        let segwit_block = include_bytes!("../tests/data/mainnet_block_00000000000000000000edfe523d5e2993781d2305f51218ebfc236a250792d6.raw").to_vec();
        let block: Block = deserialize(&segwit_block).unwrap();

        for tx in block.txdata.iter() {
            for output in tx.output.iter() {
                MockEnvironment::reset_mock_env();
                let script_pubkey = output.script_pubkey.as_bytes();
                if script_pubkey.len() == 34 && script_pubkey[0] == 81u8 && script_pubkey[1] == 32u8
                {
                    ENVWriter::<MockEnvironment>::write_tx_to_env(tx);
                    let tx_id = read_tx_and_calculate_txid::<MockEnvironment>(
                        None,
                        Some((
                            Some(output.value.to_sat()),
                            script_pubkey[2..34].try_into().unwrap(),
                        )),
                    );
                    assert_eq!(tx.compute_txid(), Txid::from_byte_array(tx_id));
                }
            }
        }

        for tx in block.txdata.iter() {
            for input in tx.input.iter() {
                MockEnvironment::reset_mock_env();
                let txid = input.previous_output.txid.to_byte_array();
                let vout = input.previous_output.vout;
                ENVWriter::<MockEnvironment>::write_tx_to_env(tx);
                let tx_id = read_tx_and_calculate_txid::<MockEnvironment>(Some((txid, vout)), None);
                assert_eq!(tx.compute_txid(), Txid::from_byte_array(tx_id));
            }
        }
    }

    #[test]
    fn test_write_and_read_blocks_and_add_to_merkle_tree() {
        let mut _num = SHARED_STATE.lock().unwrap();
        MockEnvironment::reset_mock_env();
        let mainnet_first_11_blocks =
            include_bytes!("../tests/data/mainnet_first_11_blocks.raw").to_vec();

        let headers: Vec<Header> = deserialize(&mainnet_first_11_blocks).unwrap();
        let start_block_hash = headers[0].prev_blockhash.to_byte_array();

        let mut write_mt = MerkleTree::<32>::new();
        ENVWriter::<MockEnvironment>::write_blocks_and_add_to_merkle_tree(
            headers.clone(),
            &mut write_mt,
        );

        let mut read_imt = IncrementalMerkleTree::<32>::new();
        let res = read_blocks_and_add_to_merkle_tree::<MockEnvironment>(
            start_block_hash,
            &mut read_imt,
            4, // MAX_BLOCK_HANDLE_OPS
        );

        let mut test_mt = MerkleTree::<32>::new();

        for header in headers {
            test_mt.add(serialize(&header.block_hash()).try_into().unwrap());
        }

        // Make sure merkle trees are set up correctly
        assert_eq!(read_imt.root, test_mt.root());
        assert_eq!(write_mt.root(), test_mt.root());

        // Make sure the result is correct
        assert_eq!(
            (
                U256::from(47245361163u64),
                [
                    68u8, 148u8, 200u8, 207u8, 65u8, 84u8, 189u8, 204u8, 7u8, 32u8, 205u8, 74u8,
                    89u8, 217u8, 201u8, 178u8, 133u8, 228u8, 177u8, 70u8, 212u8, 95u8, 6u8, 29u8,
                    43u8, 108u8, 150u8, 113u8, 0u8, 0u8, 0u8, 0u8
                ],
                [
                    115u8, 48u8, 215u8, 173u8, 242u8, 97u8, 198u8, 152u8, 145u8, 230u8, 171u8, 8u8,
                    54u8, 125u8, 149u8, 126u8, 116u8, 212u8, 4u8, 75u8, 197u8, 217u8, 205u8, 6u8,
                    214u8, 86u8, 190u8, 151u8, 0u8, 0u8, 0u8, 0u8
                ]
            ),
            res
        )
    }

    #[ignore]
    #[test]
    fn test_write_and_read_blocks_and_calculate_work() {
        let mut _num = SHARED_STATE.lock().unwrap();
        MockEnvironment::reset_mock_env();
        let mainnet_blocks_from_832000_to_833096 =
            include_bytes!("../tests/data/mainnet_blocks_from_832000_to_833096.raw").to_vec();

        let headers: Vec<Header> = deserialize(&mainnet_blocks_from_832000_to_833096).unwrap();
        let genesis_block_hash = headers[0].prev_blockhash.to_byte_array();

        MockEnvironment::write_32bytes(genesis_block_hash); // Write the geneis block hash first.

        MockEnvironment::write_u32(1); // this is the genesis proof

        MockEnvironment::write_u32x8(GUEST_ID);
        MockEnvironment::write_u32(0);

        ENVWriter::<MockEnvironment>::write_blocks(headers[0..540].to_vec());

        let env = MockEnvironment::output_env().build().unwrap();
        let prover = default_prover();
        let prover_opts = ProverOpts::succinct();
        let prove_info = prover
            .prove_with_opts(env, GUEST_ELF, &prover_opts)
            .unwrap();
        let (method_id, genesis_block_hash, offset, blockhash, pow): (
            [u32; 8],
            [u8; 32],
            u32,
            [u8; 32],
            [u8; 32],
        ) = prove_info.receipt.journal.decode().unwrap();
        // let blockhash = prove_info.receipt.journal.decode().unwrap();
        println!("offset: {:?}", offset);
        println!("blockhash: {:?}", blockhash);
        println!("pow: {:?}", pow);
        // println!("receipt: {:?}", prove_info.receipt);
        println!("guest id: {:?}", GUEST_ID);
        println!("method_id: {:?}", method_id);
        // save the receipt to a file
        let receipt = serde_json::to_string(&prove_info.receipt).unwrap();
        // write to a file with filename blockhash.json
        std::fs::write(format!("{}.json", hex::encode(blockhash)), receipt).unwrap();

        // read the receipt from the file
        let receipt: Receipt = serde_json::from_str(
            &std::fs::read_to_string(format!("{}.json", hex::encode(blockhash))).unwrap(),
        )
        .unwrap();

        MockEnvironment::reset_mock_env();

        MockEnvironment::write_32bytes(genesis_block_hash); // Write the geneis block hash first.

        MockEnvironment::write_u32(0); // this is not the genesis proof
        MockEnvironment::write_u32x8(GUEST_ID);
        MockEnvironment::write_u32(offset);
        MockEnvironment::write_32bytes(blockhash);
        MockEnvironment::write_32bytes(pow);
        MockEnvironment::write_u32(500); // offset we need
        ENVWriter::<MockEnvironment>::write_blocks(headers[540..1080].to_vec());
        let mut env = MockEnvironment::output_env();
        let env = env.add_assumption(receipt).build().unwrap();
        let prove_info = prover
            .prove_with_opts(env, GUEST_ELF, &prover_opts)
            .unwrap();
        let (method_id, _genesis_block_hash, offset, blockhash, pow): (
            [u32; 8],
            [u8; 32],
            u32,
            [u8; 32],
            [u8; 32],
        ) = prove_info.receipt.journal.decode().unwrap();
        // let blockhash: [u8; 32] = prove_info.receipt.journal.decode().unwrap();
        println!("offset: {:?}", offset);
        println!("blockhash: {:?}", blockhash);
        println!("pow: {:?}", pow);
        println!("method_id: {:?}", method_id);
        println!("GUEST ID: {:?}", GUEST_ID);

        // println!("receipt.journal: {:?}", prove_info.receipt.serialize());
        // assert_eq!(btc_tx_id, Txid::from_byte_array(tx_id));
    }

    #[ignore]
    #[test]
    fn test_write_and_read_merkle_tree_proof() {
        let mut _num = SHARED_STATE.lock().unwrap();
        MockEnvironment::reset_mock_env();
        let mut test_mt = MerkleTree::<32>::new();
        let mut read_imt = IncrementalMerkleTree::<32>::new();
        let mainnet_blocks_from_832000_to_833096 =
            include_bytes!("../tests/data/mainnet_blocks_from_832000_to_833096.raw").to_vec();

        let headers: Vec<Header> = deserialize(&mainnet_blocks_from_832000_to_833096).unwrap();
        let mut serialized_headers = Vec::new();
        for header in headers.iter() {
            serialized_headers.push(serialize(&header.block_hash()).try_into().unwrap());
            test_mt.add(serialize(&header.block_hash()).try_into().unwrap());
            read_imt.add(serialize(&header.block_hash()).try_into().unwrap());
        }

        // Making sure merkle trees are set correctly
        assert_eq!(test_mt.root(), read_imt.root);

        // Testing write and read merkle tree proof
        // First write with indices
        for (i, &header) in serialized_headers.iter().enumerate().take(headers.len()) {
            ENVWriter::<MockEnvironment>::write_merkle_tree_proof(header, Some(i as u32), &test_mt);
        }
        // Then read with indices
        for (i, &header) in serialized_headers.iter().enumerate().take(headers.len()) {
            let calculated_root =
                read_merkle_tree_proof::<MockEnvironment, 32>(header, Some(i as u32));
            assert_eq!(test_mt.root(), calculated_root);
        }

        // Second write without indices
        for &header in serialized_headers.iter().take(headers.len()) {
            ENVWriter::<MockEnvironment>::write_merkle_tree_proof(header, None, &test_mt);
        }
        // Then read without indices
        for header in serialized_headers.into_iter().take(headers.len()) {
            let calculated_root = read_merkle_tree_proof::<MockEnvironment, 32>(header, None);
            assert_eq!(test_mt.root(), calculated_root);
        }
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
    //     let env = MockEnvironment::output_env().build().unwrap();
    //     let prover = default_prover();
    //     let receipt = prover.prove(env, GUEST_ELF).unwrap();
    //     let tx_id: [u8; 32] = receipt.receipt.journal.decode().unwrap();
    //     println!("tx_id: {:?}", tx_id);
    //     assert_eq!(btc_tx_id, Txid::from_byte_array(tx_id));
    //     // This code is working
    // }
}
