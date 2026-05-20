use crate::actor::Actor;
use crate::bitvm_client::SECP;
use crate::builder::address::create_taproot_address;
use crate::builder::transaction::custom::{
    builder as custom_builder, current_tx as custom_current_tx, input as custom_input,
    named_leaf_descriptor, output as custom_output, output_from_script_leaves,
    sign_with_actor as sign_custom_with_actor, spendable_from_script_leaves,
};
use crate::test::common::*;
use bitcoin::Amount;
use bitcoincore_rpc::RpcApi;
use tx_builder::script::ScriptLeaf;
use tx_builder::scripts::CheckSig;

#[tokio::test]
async fn create_address_and_transaction_then_sign_transaction() {
    let mut config = create_test_config_with_thread_name().await;
    let regtest = create_regtest_rpc(&mut config).await;
    let rpc = regtest.rpc().clone();

    let (xonly_pk, _) = config.secret_key.public_key(&SECP).x_only_public_key();

    // Prepare script and address.
    let script = ScriptLeaf::CheckSig(CheckSig::new(xonly_pk));
    let (taproot_address, _) = create_taproot_address(
        &[script.to_script_buf()],
        Some(xonly_pk),
        config.protocol_paramset().network,
    );

    // Create a new transaction.
    let utxo = rpc
        .send_to_address(&taproot_address, Amount::from_sat(1000))
        .await
        .unwrap();

    let input = spendable_from_script_leaves(
        0,
        utxo,
        Amount::from_sat(1000),
        vec![script.clone()],
        Some(xonly_pk),
        config.protocol_paramset().network,
    );
    let (_, output) = output_from_script_leaves(
        0,
        Amount::from_sat(330),
        vec![script],
        Some(xonly_pk),
        config.protocol_paramset().network,
    );
    let mut tx_handler = custom_builder(0)
        .add_input(
            custom_input(0),
            input,
            bitcoin::Sequence::ENABLE_RBF_NO_LOCKTIME,
            named_leaf_descriptor(0, 0, bitcoin::TapSighashType::Default),
        )
        .add_output(custom_output(0), output)
        .finalize();

    // Signer should be able to sign the new transaction.
    let signer = Actor::new(config.secret_key, config.protocol_paramset().network);

    sign_custom_with_actor(&signer, &mut tx_handler).expect("failed to sign transaction");

    rpc.mine_blocks(1).await.unwrap();

    // New transaction should be OK to send.
    rpc.send_raw_transaction(custom_current_tx(&tx_handler))
        .await
        .unwrap();
}
