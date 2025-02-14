use bitcoin::{Amount, TxOut};
use bitcoincore_rpc::RpcApi;
use clementine_core::actor::Actor;
use clementine_core::builder::script::{CheckSig, SpendPath, SpendableScript};
use clementine_core::builder::transaction::input::SpendableTxIn;
use clementine_core::builder::transaction::output::UnspentTxOut;
use clementine_core::builder::transaction::{TransactionType, TxHandlerBuilder, DEFAULT_SEQUENCE};
use clementine_core::builder::{self};
use clementine_core::extended_rpc::ExtendedRpc;
use clementine_core::rpc::clementine::NormalSignatureKind;
use clementine_core::utils::SECP;
use clementine_core::{config::BridgeConfig, database::Database, utils::initialize_logger};
use std::sync::Arc;

mod common;

#[tokio::test]

async fn create_address_and_transaction_then_sign_transaction() {
    let mut config = create_test_config_with_thread_name!(None);
    let regtest = create_regtest_rpc!(config);
    let rpc = regtest.rpc().clone();

    let (xonly_pk, _) = config.secret_key.public_key(&SECP).x_only_public_key();

    // Prepare script and address.
    let script = Arc::new(CheckSig::new(
        // bitcoin::XOnlyPublicKey::from_slice(&tweaked_pk_script).unwrap(),
        xonly_pk,
    ));
    let scripts: Vec<Arc<dyn SpendableScript>> = vec![script.clone()];
    let (taproot_address, taproot_spend_info) = builder::address::create_taproot_address(
        &scripts
            .iter()
            .map(|s| s.to_script_buf())
            .collect::<Vec<_>>(),
        None,
        config.network,
    );

    // Create a new transaction.
    let utxo = rpc
        .send_to_address(&taproot_address, Amount::from_sat(1000))
        .await
        .unwrap();

    let mut builder = TxHandlerBuilder::new(TransactionType::Dummy);
    builder = builder.add_input(
        NormalSignatureKind::NotStored,
        SpendableTxIn::new(
            utxo,
            TxOut {
                value: Amount::from_sat(1000),
                script_pubkey: taproot_address.script_pubkey(),
            },
            scripts.clone(),
            Some(taproot_spend_info.clone()),
        ),
        SpendPath::ScriptSpend(0),
        DEFAULT_SEQUENCE,
    );

    builder = builder.add_output(UnspentTxOut::new(
        TxOut {
            value: Amount::from_sat(330),
            script_pubkey: taproot_address.script_pubkey(),
        },
        scripts,
        Some(taproot_spend_info),
    ));

    let mut tx_handler = builder.finalize();

    // Signer should be able to sign the new transaction.
    let signer = Actor::new(
        config.secret_key,
        config.winternitz_secret_key,
        config.network,
    );

    signer
        .tx_sign_and_fill_sigs(&mut tx_handler, &[])
        .expect("failed to sign transaction");

    rpc.mine_blocks(1).await.unwrap();

    // New transaction should be OK to send.
    rpc.client
        .send_raw_transaction(tx_handler.get_cached_tx())
        .await
        .unwrap();
}
