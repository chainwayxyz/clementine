#[cfg(test)]
mod tests {

    use bridge_core::utils::*;
    use bridge_core::core_tx::*;
    use bridge_core::btc::*;
    use bridge_core::vector::*;
    use risc0_zkvm::ExecutorEnv;
    use risc0_zkvm::guest::env;

    use crate::bitcoin::parse_hex_to_btc_tx;

    #[test]
    fn test_env() {
        println!("test env");
        env_logger::init();
        println!("init env");
        let mut env = ExecutorEnv::builder();
        println!("builder env");
        env.write(&3).unwrap();
        println!("write env");
        let env_read: u32 = env::read();
        println!("read env");
        println!("{:?}", env_read);
    }

    #[test]
    fn test_from_hex_to_tx_calculate_tx_id() {
        let input = "020000000001025c290bc400f9e1c3f739f8e57ab60355d5a9ac33e9d2c24145b3565aee6bbce00000000000fdffffffa49a9fe38ffe5f5bda8289098e60572caa758c7795983b0008b5e99f01f446de0000000000fdffffff0300e1f50500000000225120df6f4ee3a0a625db6fa6a88176656541f4a63591f8b7174f7054cc52afbeaec800e1f505000000002251208c61eec2e14c785da78dd8ab98797996f866a6aac8c8d2389d77f38c3f4feff122020000000000002251208c61eec2e14c785da78dd8ab98797996f866a6aac8c8d2389d77f38c3f4feff101405de61774dc0275f491eb46561bc1b36148ef30467bf43f2b33796991d61a29a3a4b7e2047712e73fe983806f0d636b64c8a6202490daff202bca521a0faa70ae0140f80f92541832d6d8908df9a57d994b90ee74129c8943a17109da88d49cd1531314d051c8082be3b79d3281edde719ab2fab34fa3dfbe3ad60e5a2ab8a306d43100000000";
        let tx = from_hex_to_tx::<2, 3>(input);
        println!("{:?}", tx);
        let tx_id = tx.calculate_txid();
        let hex = hex::encode(tx_id);
        println!("{:?}", hex);
        let btc_tx = parse_hex_to_btc_tx(input).unwrap();
        let btc_tx_id = btc_tx.txid();
        let btc_hex = hex::encode(btc_tx_id);
        println!("{:?}", btc_hex);
        assert_eq!(btc_hex, hex);
    }

    #[test]
    fn test_char_array_to_str() {
        let mut output_buffer = [0u8; 2048];
        let input_array = ['a'; 2048];
        let size = 2048;
        let result = char_array_to_str(&mut output_buffer, &input_array, size).unwrap();
        println!("{:?}", result);
    }

    #[test]
    fn test_vector() {
        let mut vec = Vector::new();
        vec.push(1);
        vec.push(2);
        vec.push(3);
        println!("{:?}", vec);
    }
    
}