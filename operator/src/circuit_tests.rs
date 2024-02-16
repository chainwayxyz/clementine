use bitcoin::Transaction;
use circuit_helpers::env::Environment;
use secp256k1::hashes::Hash;

fn main() {
    println!("Hello, world!");
    return;
}

pub fn write_tx_to_env<E: Environment>(tx: Transaction) {
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

// write tests for circuits
#[cfg(test)]
mod tests {
    use bitcoin::Txid;
    use circuit_helpers::bitcoin::read_tx_and_calculate_txid;
    use secp256k1::hashes::Hash;

    use crate::{
        mock_env::MockEnvironment,
        utils::{from_hex_to_tx, parse_hex_to_btc_tx},
    };

    use super::write_tx_to_env;

    use operator_circuit::{GUEST_ELF, GUEST_ID};
    use risc0_zkvm::{default_prover, ExecutorEnv};

    #[test]
    fn test_tx() {
        let input = "020000000001025c290bc400f9e1c3f739f8e57ab60355d5a9ac33e9d2c24145b3565aee6bbce00000000000fdffffffa49a9fe38ffe5f5bda8289098e60572caa758c7795983b0008b5e99f01f446de0000000000fdffffff0300e1f50500000000225120df6f4ee3a0a625db6fa6a88176656541f4a63591f8b7174f7054cc52afbeaec800e1f505000000002251208c61eec2e14c785da78dd8ab98797996f866a6aac8c8d2389d77f38c3f4feff122020000000000002251208c61eec2e14c785da78dd8ab98797996f866a6aac8c8d2389d77f38c3f4feff101405de61774dc0275f491eb46561bc1b36148ef30467bf43f2b33796991d61a29a3a4b7e2047712e73fe983806f0d636b64c8a6202490daff202bca521a0faa70ae0140f80f92541832d6d8908df9a57d994b90ee74129c8943a17109da88d49cd1531314d051c8082be3b79d3281edde719ab2fab34fa3dfbe3ad60e5a2ab8a306d43100000000";
        let btc_tx = parse_hex_to_btc_tx(input).unwrap();
        let btc_tx_id = btc_tx.txid();
        write_tx_to_env::<MockEnvironment>(btc_tx);
        let tx_id = read_tx_and_calculate_txid::<MockEnvironment>();
        assert_eq!(btc_tx_id, Txid::from_byte_array(tx_id));
    }

    #[test]
    fn test_proving() {
        // let input = "020000000001025c290bc400f9e1c3f739f8e57ab60355d5a9ac33e9d2c24145b3565aee6bbce00000000000fdffffffa49a9fe38ffe5f5bda8289098e60572caa758c7795983b0008b5e99f01f446de0000000000fdffffff0300e1f50500000000225120df6f4ee3a0a625db6fa6a88176656541f4a63591f8b7174f7054cc52afbeaec800e1f505000000002251208c61eec2e14c785da78dd8ab98797996f866a6aac8c8d2389d77f38c3f4feff122020000000000002251208c61eec2e14c785da78dd8ab98797996f866a6aac8c8d2389d77f38c3f4feff101405de61774dc0275f491eb46561bc1b36148ef30467bf43f2b33796991d61a29a3a4b7e2047712e73fe983806f0d636b64c8a6202490daff202bca521a0faa70ae0140f80f92541832d6d8908df9a57d994b90ee74129c8943a17109da88d49cd1531314d051c8082be3b79d3281edde719ab2fab34fa3dfbe3ad60e5a2ab8a306d43100000000";
        // let btc_tx = parse_hex_to_btc_tx(input).unwrap();
        // let btc_tx_id = btc_tx.txid();
        // println!("Expected txid: {:?}", btc_tx_id);
        // write_tx_to_env::<MockEnvironment>(btc_tx);
        // read_tx_and_calculate_txid::<MockEnvironment>();
        // let env = MockEnvironment::output_env();
        // println!("env generated");
        // let prover = default_prover();
        // let receipt = prover.prove_elf(env, GUEST_ELF).unwrap();
        // println!("Waiting for receipt");
        // let tx_id: [u8; 32] = receipt.journal.decode().unwrap();
        // assert_eq!(btc_tx_id, Txid::from_byte_array(tx_id));
    
    }
}
