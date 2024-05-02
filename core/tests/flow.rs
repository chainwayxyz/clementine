use bitcoin::Address;
use bitcoincore_rpc::Auth;
use clementine_circuits::constants::BRIDGE_AMOUNT_SATS;
use clementine_core::config::BridgeConfig;
use clementine_core::extended_rpc::ExtendedRpc;
use clementine_core::traits::rpc::OperatorRpcClient;
use clementine_core::transaction_builder::TransactionBuilder;
use clementine_core::{start_operator_and_verifiers, EVMAddress};

#[tokio::test]
async fn test_should_deposit_and_withdraw() {
    let base_path = env!("CARGO_MANIFEST_DIR");
    let config_path = format!("{}/tests/data/test_config_1.toml", base_path);
    let config = BridgeConfig::try_parse_file(config_path.into()).unwrap();

    tracing::debug!("Config: {:?}", config);
    tracing::debug!("Verifiers public keys: {:?}", config.verifiers_public_keys);

    let (operator_client, operator_handler, results) =
        start_operator_and_verifiers(config.clone()).await;
    let secp = bitcoin::secp256k1::Secp256k1::new();
    let (xonly_pk, _) = config.secret_key.public_key(&secp).x_only_public_key();
    tracing::debug!("Verifiers public keys: {:?}", config.verifiers_public_keys);
    let tx_builder = TransactionBuilder::new(config.verifiers_public_keys.clone(), config.clone());

    let evm_addresses = vec![
        EVMAddress([1u8; 20]),
        EVMAddress([2u8; 20]),
        EVMAddress([3u8; 20]),
        EVMAddress([4u8; 20]),
    ];

    let deposit_addresses = evm_addresses
        .iter()
        .map(|evm_address| {
            tx_builder
                .generate_deposit_address(&xonly_pk, evm_address, BRIDGE_AMOUNT_SATS)
                .unwrap()
                .0
        })
        .collect::<Vec<_>>();

    println!("User: {:?}", xonly_pk.to_string());

    tracing::debug!(
        "Config: {:?} {:?} {:?}",
        config.bitcoin_rpc_url,
        config.bitcoin_rpc_user,
        config.bitcoin_rpc_password
    );

    let rpc = ExtendedRpc::new(
        config.bitcoin_rpc_url.clone(),
        Auth::UserPass(
            config.bitcoin_rpc_user.clone(),
            config.bitcoin_rpc_password.clone(),
        ),
    );

    for (idx, deposit_address) in deposit_addresses.iter().enumerate() {
        let deposit_utxo = rpc
            .send_to_address(&deposit_address, BRIDGE_AMOUNT_SATS)
            .unwrap();
        println!("Deposit UTXO: {:?}", deposit_utxo);
        rpc.mine_blocks(18).unwrap();
        let output = operator_client
            .new_deposit_rpc(deposit_utxo, xonly_pk, evm_addresses[idx])
            .await
            .unwrap();
        println!("Output: {:?}", output);
    }

    let withdrawal_address = Address::p2tr(&secp, xonly_pk, None, config.network);

    let withdraw_txid = operator_client
        .new_withdrawal_direct_rpc(0, withdrawal_address.as_unchecked().clone())
        .await
        .unwrap();
    tracing::debug!("Withdrawal TXID: {:?}", withdraw_txid);

    // get the tx details from rpc with txid
    // check wheter it has an output with the withdrawal address

    let op_res = operator_handler.is_stopped();
    let ver_res = results
        .iter()
        .all(|(_, verifier_handler)| verifier_handler.is_stopped());
    assert!(!(op_res || ver_res));
    let op_res = operator_handler.stop().unwrap();
    let mut ver_res = Vec::new();
    for (_, verifier_handler) in results {
        ver_res.push(verifier_handler.stop().unwrap());
    }
    println!("Operator stopped: {:?}", op_res);
    for (i, res) in ver_res.iter().enumerate() {
        println!("Verifier {} stopped: {:?}", i, res);
    }
    println!("All servers stopped");
}
