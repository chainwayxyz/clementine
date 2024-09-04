// //! # Deposit and Withdraw Flow Test
// //!
// //! This testss checks if basic deposit and withdraw operations are OK or not.

use bitcoin::consensus::deserialize;
use bitcoin::consensus::encode::deserialize_hex;
use bitcoin::{Address, Amount, OutPoint, TxOut};
use clementine_core::extended_rpc::ExtendedRpc;
use clementine_core::servers::{create_aggregator_server, create_verifiers_and_operators};
use clementine_core::traits::rpc::AggregatorClient;
use clementine_core::{create_test_config_with_thread_name, ByteArray66, UTXO};
use clementine_core::{
    create_extended_rpc, errors::BridgeError, traits::rpc::OperatorRpcClient, user::User,
};
use common::run_single_deposit;
use secp256k1::SecretKey;

mod common;

#[tokio::test]
async fn test_deposit() -> Result<(), BridgeError> {
    match run_single_deposit("test_config.toml").await {
        Ok((_, _, _, deposit_outpoint)) => {
            // tracing::debug!("Verifiers: {:#?}", verifiers);
            // tracing::debug!("Operators: {:#?}", operators);
            tracing::debug!("Deposit outpoint: {:#?}", deposit_outpoint);
            Ok(())
        }
        Err(e) => {
            tracing::error!("Error: {:?}", e);
            Err(e)
        }
    }
}

#[tokio::test]
async fn test_honest_operator_takes_refund() {
    // let mut config = create_test_config_with_thread_name!("test_config_flow.toml");
    let (_verifiers, operators, mut config, deposit_outpoint) =
        run_single_deposit("test_config.toml").await.unwrap();
    let rpc = create_extended_rpc!(config);

    let secp = bitcoin::secp256k1::Secp256k1::new();
    let user_sk = SecretKey::from_slice(&[12u8; 32]).unwrap();
    let user = User::new(rpc.clone(), user_sk, config.clone());
    let withdrawal_address = Address::p2tr(
        &secp,
        user_sk.x_only_public_key(&secp).0,
        None,
        config.network,
    );
    let (empty_utxo, withdrawal_tx_out, user_sig) =
        user.generate_withdrawal_sig(withdrawal_address).unwrap();
    let withdrawal_provide_txid = operators[0]
        .0
        .new_withdrawal_sig_rpc(0, user_sig, empty_utxo, withdrawal_tx_out)
        .await
        .unwrap();
    println!("Withdrawal provide: {:?}", withdrawal_provide_txid);
    let txs_to_be_sent = operators[0]
        .0
        .withdrawal_proved_on_citrea_rpc(0, deposit_outpoint)
        .await
        .unwrap();
    tracing::debug!("txs_to_be_sent: {:#?}", txs_to_be_sent);

    for tx in txs_to_be_sent.iter().take(txs_to_be_sent.len() - 1) {
        let outpoint = rpc.send_raw_transaction(tx.clone()).unwrap();
        tracing::debug!("outpoint: {:#?}", outpoint);
    }
    rpc.mine_blocks(config.operator_takes_after as u64).unwrap();
    // send the last tx
    rpc.send_raw_transaction(txs_to_be_sent.last().unwrap().clone())
        .unwrap();
}

#[tokio::test]
async fn test_aggregator() {
    let deposit_outpoint: OutPoint =
    deserialize_hex("3f3a8e89541fe269e8ab36f70eeacc7cff3ede08fef2cec689aa44125c8ab422:1").unwrap();
    let kickoff_utxos: Vec<UTXO> = vec![
      UTXO {
        outpoint: deserialize_hex("fa6dcd0558331ba0a7d9a27bf94b20656b3090430902e875907bcfa823a38744:0").unwrap(),
        txout: TxOut {
          value: Amount::from_sat(100000),
          script_pubkey: deserialize_hex("5120b23da6d2e0390018b953f7d74e3582da4da30fd0fd157cc84a2d2753003d1ca3").unwrap()
        }
      },
      UTXO {
        outpoint: deserialize_hex("6f45488d33bec4b8a6d4a487713ba835a73faec3c91c079328abc18719314b8a:0").unwrap(),
        txout: TxOut {
          value: Amount::from_sat(100000),
          script_pubkey: deserialize_hex("51202ba7624eb001a94e358ebd0ab125d507ac965e780684dc27bc14a4fde262b31c").unwrap()
        }
      },
      UTXO{
        outpoint: deserialize_hex("4f64a93e182837a838e27e92661f1b9faeb22735dece64d1026d3437c283be66:0").unwrap(),
        txout: TxOut {
          value: Amount::from_sat(100000),
          script_pubkey: deserialize_hex("51201705dd472480320989f1a399b9a71fb397b437605f9b718ddbe058815467b6d8").unwrap()
        }
      }
    ];
    let agg_nonces: Vec<ByteArray66> = vec![
          ByteArray66(hex::decode("034bc37f0be6e93a2f19170c7a4b07f63897cdff075ed088a643ca945acaa86fa60392d477a293910ea446987a2e0c8107bfc4b93cedcb2ad4478e61b30cd3fca475").unwrap().try_into().unwrap()),
          ByteArray66(hex::decode("0300094f1709f1bb03480416881a26bdfba518026c835d33e7f07d014d8e87d08c0240af9fd3d90a98498414ebd89609e830e5f4a4f460024634bdf43d5d3c960d30").unwrap().try_into().unwrap()),
          ByteArray66(hex::decode("02a335c0f789d254314be6c7120672502c1d9984442df69822cc2ce0cb0569066503ba13952c17bf279350a900950e2935c3db59bdfbc97fddd44085f22a9027f5f1").unwrap().try_into().unwrap()),
        ];
    let partial_sigs: Vec<Vec<[u8; 32]>> = vec![
        vec![
            [
                84, 161, 42, 156, 102, 132, 71, 150, 15, 132, 114, 41, 164, 143, 99, 73, 35, 105,
                136, 180, 237, 149, 197, 127, 109, 50, 214, 237, 4, 97, 29, 14,
            ],
            [
                239, 19, 76, 138, 74, 122, 211, 221, 234, 63, 99, 224, 139, 255, 140, 244, 205,
                217, 168, 46, 133, 35, 113, 151, 31, 150, 254, 87, 7, 165, 255, 169,
            ],
            [
                133, 104, 109, 16, 57, 94, 37, 212, 136, 15, 141, 103, 228, 209, 138, 107, 214,
                197, 50, 152, 99, 130, 69, 137, 175, 96, 238, 112, 209, 93, 178, 52,
            ],
        ],
        vec![
            [
                216, 223, 60, 254, 79, 110, 148, 175, 136, 14, 11, 79, 89, 243, 201, 39, 115, 212,
                216, 245, 176, 130, 209, 23, 161, 55, 173, 19, 203, 151, 237, 218,
            ],
            [
                67, 68, 148, 184, 189, 90, 8, 164, 37, 173, 223, 94, 139, 184, 84, 125, 30, 228,
                79, 102, 24, 36, 184, 50, 56, 225, 146, 213, 103, 41, 5, 152,
            ],
            [
                251, 166, 71, 73, 251, 98, 125, 234, 126, 168, 141, 132, 9, 254, 104, 28, 66, 20,
                71, 254, 163, 183, 43, 159, 150, 97, 49, 109, 133, 32, 160, 185,
            ],
        ],
        vec![
            [
                223, 139, 180, 167, 9, 78, 19, 133, 19, 145, 215, 253, 177, 179, 248, 140, 26, 177,
                159, 189, 227, 224, 62, 147, 95, 241, 1, 121, 222, 152, 200, 26,
            ],
            [
                115, 126, 63, 250, 83, 51, 119, 47, 185, 120, 188, 3, 138, 75, 38, 82, 233, 47,
                130, 247, 118, 215, 228, 156, 162, 20, 145, 42, 133, 180, 27, 202,
            ],
            [
                136, 61, 144, 53, 169, 248, 59, 86, 124, 87, 42, 29, 165, 41, 142, 9, 76, 110, 219,
                137, 139, 30, 40, 38, 195, 240, 175, 181, 76, 68, 94, 29,
            ],
        ],
        vec![
            [
                74, 154, 25, 12, 38, 41, 46, 74, 33, 213, 138, 16, 53, 72, 23, 70, 9, 137, 10, 96,
                48, 89, 209, 226, 70, 221, 150, 127, 44, 106, 155, 89,
            ],
            [
                46, 40, 163, 211, 86, 143, 144, 11, 19, 208, 118, 4, 247, 166, 87, 118, 182, 100,
                121, 53, 254, 18, 83, 29, 15, 96, 159, 237, 22, 246, 126, 116,
            ],
            [
                42, 161, 179, 217, 58, 242, 92, 225, 142, 77, 102, 207, 234, 239, 146, 11, 120,
                144, 232, 208, 100, 26, 111, 117, 11, 95, 66, 159, 71, 0, 0, 145,
            ],
        ],
        vec![
            [
                105, 14, 46, 133, 112, 234, 47, 57, 193, 40, 93, 241, 156, 155, 52, 199, 29, 21,
                126, 24, 228, 209, 135, 101, 82, 13, 243, 243, 81, 27, 54, 39,
            ],
            [
                15, 193, 158, 241, 190, 5, 59, 107, 236, 167, 117, 152, 136, 37, 60, 159, 10, 214,
                202, 186, 144, 37, 130, 239, 112, 114, 150, 62, 136, 128, 176, 42,
            ],
            [
                147, 58, 8, 109, 184, 244, 83, 102, 116, 78, 165, 214, 34, 153, 134, 21, 115, 240,
                88, 249, 228, 172, 72, 179, 242, 65, 187, 186, 163, 178, 174, 63,
            ],
        ],
        vec![
            [
                30, 255, 75, 21, 134, 231, 6, 17, 188, 184, 3, 120, 252, 195, 93, 186, 209, 110,
                122, 81, 57, 64, 82, 12, 248, 110, 167, 153, 190, 155, 213, 116,
            ],
            [
                228, 148, 78, 230, 104, 240, 110, 37, 161, 51, 52, 215, 86, 156, 117, 237, 92, 55,
                238, 4, 116, 232, 125, 43, 228, 166, 103, 195, 71, 12, 96, 177,
            ],
            [
                87, 187, 160, 13, 200, 188, 3, 120, 106, 65, 248, 1, 98, 171, 150, 240, 34, 168,
                93, 165, 107, 95, 104, 71, 126, 25, 184, 10, 233, 179, 29, 10,
            ],
        ],
        vec![
            [
                170, 125, 37, 31, 236, 225, 167, 80, 125, 188, 255, 28, 17, 184, 245, 147, 56, 173,
                116, 135, 78, 87, 75, 9, 22, 229, 27, 10, 222, 244, 71, 108,
            ],
            [
                84, 35, 79, 49, 225, 38, 252, 102, 157, 141, 113, 18, 177, 22, 238, 135, 18, 240,
                104, 206, 32, 45, 96, 247, 162, 33, 238, 34, 47, 249, 189, 90,
            ],
            [
                220, 1, 200, 165, 28, 230, 86, 245, 98, 157, 26, 199, 166, 207, 173, 189, 119, 19,
                70, 105, 51, 98, 108, 223, 4, 249, 125, 118, 202, 194, 250, 245,
            ],
        ],
    ];
    let (_, _, aggregator) =
        create_verifiers_and_operators("test_config.toml").await;

    let result = aggregator.0.aggregate_slash_or_take_sigs_rpc(deposit_outpoint, kickoff_utxos, agg_nonces, partial_sigs).await.unwrap();
    println!("{:?}", result);

    
}
