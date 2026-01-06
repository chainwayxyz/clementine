//! TxSender integration tests restored from main branch
//! Adapted to work with TxSenderTxBuilder trait

use bitcoin::hashes::Hash;
use bitcoin::transaction::Version;
use bitcoin::{Amount, FeeRate, TxOut};
use bitcoincore_rpc::json::GetRawTransactionResult;
use bitcoincore_rpc::RpcApi;
use std::ops::Mul;
use std::sync::Arc;
use std::time::Duration;

use serde_json::json;
use wiremock::matchers::{body_partial_json, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use crate::actor::{Actor, TweakCache};
use crate::bitcoin_syncer::BitcoinSyncer;
use crate::bitvm_client::SECP;
use crate::builder;
use crate::builder::script::{CheckSig, SpendPath, SpendableScript};
use crate::builder::transaction::input::SpendableTxIn;
use crate::builder::transaction::op_return_txout;
use crate::builder::transaction::output::UnspentTxOut;
use crate::builder::transaction::{TxHandlerBuilder, DEFAULT_SEQUENCE};
use crate::config::protocol::ProtocolParamset;
use crate::constants::MIN_TAPROOT_AMOUNT;
use crate::database::Database;
use crate::extended_bitcoin_rpc::ExtendedBitcoinRpc;
use crate::rpc::clementine::tagged_signature::SignatureId;
use crate::rpc::clementine::{NormalSignatureKind, NumberedSignatureKind};
use crate::task::{IntoTask, TaskExt};
use crate::test::common::tx_utils::{create_bg_tx_sender, create_bumpable_tx};
use crate::test::common::{
    create_regtest_rpc, create_test_config_with_thread_name, poll_until_condition,
};
use crate::tx_sender::TxSender;
use crate::tx_sender_ext::{CoreTxBuilder, TxSenderClientExt};
use crate::utils::RbfSigningInfo;
use clementine_errors::BridgeError;
use clementine_primitives::TransactionType;
use clementine_utils::FeePayingType;

type TxSenderWithCore = TxSender<Actor, Database, CoreTxBuilder>;

#[tokio::test]
async fn test_try_to_send_duplicate() -> Result<(), BridgeError> {
    let mut config = create_test_config_with_thread_name().await;
    let regtest = create_regtest_rpc(&mut config).await;
    let rpc = regtest.rpc().clone();

    rpc.mine_blocks(1).await.unwrap();

    let (client, _tx_sender, _cancel_txs, rpc, db, signer, network) =
        create_bg_tx_sender(config).await;

    let tx = create_bumpable_tx(&rpc, &signer, network, FeePayingType::CPFP, false)
        .await
        .unwrap();

    let mut dbtx = db.begin_transaction().await.unwrap();
    let tx_id1 = client
        .insert_try_to_send(
            Some(&mut dbtx),
            None,
            &tx,
            FeePayingType::CPFP,
            None,
            &[],
            &[],
            &[],
            &[],
        )
        .await
        .unwrap();
    let tx_id2 = client
        .insert_try_to_send(
            Some(&mut dbtx),
            None,
            &tx,
            FeePayingType::CPFP,
            None,
            &[],
            &[],
            &[],
            &[],
        )
        .await
        .unwrap();
    dbtx.commit().await.unwrap();

    poll_until_condition(
        async || {
            rpc.mine_blocks(1).await.unwrap();

            match rpc.get_raw_transaction_info(&tx.compute_txid(), None).await {
                Ok(tx_result) => {
                    if let Some(conf) = tx_result.confirmations {
                        return Ok(conf > 0);
                    }
                    Ok(false)
                }
                Err(_) => Ok(false),
            }
        },
        Some(Duration::from_secs(30)),
        Some(Duration::from_millis(100)),
    )
    .await
    .expect("Tx was not confirmed in time");

    poll_until_condition(
        async || {
            let (_, _, _, tx_id1_seen_block_id, _) =
                db.get_try_to_send_tx(None, tx_id1).await.unwrap();
            let (_, _, _, tx_id2_seen_block_id, _) =
                db.get_try_to_send_tx(None, tx_id2).await.unwrap();

            Ok(tx_id2_seen_block_id.is_some() && tx_id1_seen_block_id.is_some())
        },
        Some(Duration::from_secs(5)),
        Some(Duration::from_millis(100)),
    )
    .await
    .expect("Tx was not confirmed in time");

    Ok(())
}

#[tokio::test]
async fn get_fee_rate() {
    let mut config = create_test_config_with_thread_name().await;
    let regtest = create_regtest_rpc(&mut config).await;
    let rpc = regtest.rpc().clone();
    let db = Database::new(&config).await.unwrap();

    let amount = Amount::from_sat(100_000);
    let signer = Actor::new(config.secret_key, config.protocol_paramset().network);
    let (xonly_pk, _) = config.secret_key.public_key(&SECP).x_only_public_key();

    let tx_sender = TxSenderWithCore::new(
        signer.clone(),
        rpc.clone(),
        db,
        "tx_sender".into(),
        config.protocol_paramset(),
        config.tx_sender_limits.clone(),
        config.mempool_config(),
    );

    let scripts: Vec<Arc<dyn SpendableScript>> = vec![Arc::new(CheckSig::new(xonly_pk)).clone()];
    let (taproot_address, taproot_spend_info) = builder::address::create_taproot_address(
        &scripts
            .iter()
            .map(|s| s.to_script_buf())
            .collect::<Vec<_>>(),
        None,
        config.protocol_paramset().network,
    );

    let input_utxo = rpc.send_to_address(&taproot_address, amount).await.unwrap();

    let input_builder = TxHandlerBuilder::new(TransactionType::Dummy).add_input(
        NormalSignatureKind::NotStored,
        SpendableTxIn::new(
            input_utxo,
            TxOut {
                value: amount,
                script_pubkey: taproot_address.script_pubkey(),
            },
            scripts.clone(),
            Some(taproot_spend_info.clone()),
        ),
        SpendPath::ScriptSpend(0),
        DEFAULT_SEQUENCE,
    );

    let mut will_fail_handler = input_builder
        .clone()
        .add_output(UnspentTxOut::new(
            TxOut {
                value: amount,
                script_pubkey: taproot_address.script_pubkey(),
            },
            scripts.clone(),
            Some(taproot_spend_info.clone()),
        ))
        .finalize();

    let mut tweak_cache = TweakCache::default();
    signer
        .tx_sign_and_fill_sigs(&mut will_fail_handler, &[], Some(&mut tweak_cache))
        .unwrap();

    rpc.mine_blocks(1).await.unwrap();
    let mempool_info = rpc.get_mempool_info().await.unwrap();
    tracing::info!("Mempool info: {:?}", mempool_info);

    let will_fail_tx = will_fail_handler.get_cached_tx();

    if mempool_info.mempool_min_fee.to_sat() > 0 {
        assert!(rpc.send_raw_transaction(will_fail_tx).await.is_err());
    }

    let fee_rate = tx_sender.get_fee_rate().await.unwrap();
    tracing::info!("Fee rate: {:?}", fee_rate);
    assert!(fee_rate.to_sat_per_kwu() > 0);
}

#[tokio::test]
async fn test_get_fee_rate_mempool_higher_than_rpc_uses_rpc() {
    let mock_rpc_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/"))
        .and(body_partial_json(json!({
            "method": "estimatesmartfee"
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "feerate": 0.00002,
                "blocks": 1
            }
        })))
        .mount(&mock_rpc_server)
        .await;

    Mock::given(method("POST"))
        .and(path("/"))
        .and(body_partial_json(json!({
            "method": "ping"
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": null
        })))
        .mount(&mock_rpc_server)
        .await;

    let mock_mempool_server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/fees/recommended"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "fastestFee": 3,
            "halfHourFee": 2,
            "hourFee": 1
        })))
        .mount(&mock_mempool_server)
        .await;

    let mock_rpc = ExtendedBitcoinRpc::connect(
        mock_rpc_server.uri(),
        secrecy::SecretString::new("test_user".into()),
        secrecy::SecretString::new("test_password".into()),
        None,
    )
    .await
    .unwrap();

    let mut config = create_test_config_with_thread_name().await;
    let network = bitcoin::Network::Bitcoin;
    let paramset = ProtocolParamset {
        network,
        ..ProtocolParamset::default()
    };

    let mempool_space_uri = mock_mempool_server.uri() + "/";

    config.protocol_paramset = Box::leak(Box::new(paramset));
    config.mempool_api_host = Some(mempool_space_uri);
    config.mempool_api_endpoint = Some("api/v1/fees/recommended".into());

    let db = Database::new(&config).await.unwrap();
    let signer = Actor::new(config.secret_key, config.protocol_paramset.network);

    let tx_sender = TxSenderWithCore::new(
        signer,
        mock_rpc,
        db,
        "test_tx_sender".into(),
        config.protocol_paramset(),
        config.tx_sender_limits.clone(),
        config.mempool_config(),
    );

    let fee_rate = tx_sender.get_fee_rate().await.unwrap();
    assert_eq!(fee_rate, FeeRate::from_sat_per_kwu(500));
}

#[tokio::test]
async fn test_hard_cap() {
    let mock_rpc_server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/"))
        .and(body_partial_json(json!({
            "method": "estimatesmartfee"
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "feerate": 0.00500,
                "blocks": 1
            }
        })))
        .mount(&mock_rpc_server)
        .await;

    Mock::given(method("POST"))
        .and(path("/"))
        .and(body_partial_json(json!({
            "method": "ping"
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": null
        })))
        .mount(&mock_rpc_server)
        .await;

    let mock_mempool_server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/fees/recommended"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "fastestFee": 500,
            "halfHourFee": 499,
            "hourFee": 498
        })))
        .mount(&mock_mempool_server)
        .await;

    let mock_rpc = ExtendedBitcoinRpc::connect(
        mock_rpc_server.uri(),
        secrecy::SecretString::new("test_user".into()),
        secrecy::SecretString::new("test_password".into()),
        None,
    )
    .await
    .unwrap();

    let mut config = create_test_config_with_thread_name().await;
    let network = bitcoin::Network::Bitcoin;
    let paramset = ProtocolParamset {
        network,
        ..ProtocolParamset::default()
    };

    let mempool_space_uri = mock_mempool_server.uri() + "/";

    config.protocol_paramset = Box::leak(Box::new(paramset));
    config.mempool_api_host = Some(mempool_space_uri);
    config.mempool_api_endpoint = Some("api/v1/fees/recommended".into());

    let db = Database::new(&config).await.unwrap();
    let signer = Actor::new(config.secret_key, config.protocol_paramset.network);

    let tx_sender = TxSenderWithCore::new(
        signer,
        mock_rpc,
        db,
        "test_tx_sender".into(),
        config.protocol_paramset(),
        config.tx_sender_limits.clone(),
        config.mempool_config(),
    );

    let fee_rate = tx_sender.get_fee_rate().await.unwrap();
    assert_eq!(
        fee_rate,
        FeeRate::from_sat_per_kwu(
            config
                .tx_sender_limits
                .fee_rate_hard_cap
                .mul(1000)
                .div_ceil(4)
        )
    );
}

#[tokio::test]
async fn test_get_fee_rate_rpc_higher_than_mempool() {
    let mock_rpc_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/"))
        .and(body_partial_json(json!({
            "method": "estimatesmartfee"
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "feerate": 0.00005,
                "blocks": 1
            }
        })))
        .mount(&mock_rpc_server)
        .await;

    Mock::given(method("POST"))
        .and(path("/"))
        .and(body_partial_json(json!({
            "method": "ping"
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": null
        })))
        .mount(&mock_rpc_server)
        .await;

    let mock_mempool_server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/fees/recommended"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "fastestFee": 4,
            "halfHourFee": 3,
            "hourFee": 2
        })))
        .mount(&mock_mempool_server)
        .await;

    let mock_rpc = ExtendedBitcoinRpc::connect(
        mock_rpc_server.uri(),
        secrecy::SecretString::new("test_user".into()),
        secrecy::SecretString::new("test_password".into()),
        None,
    )
    .await
    .unwrap();

    let mut config = create_test_config_with_thread_name().await;
    let network = bitcoin::Network::Bitcoin;
    let paramset = ProtocolParamset {
        network,
        ..ProtocolParamset::default()
    };

    let mempool_space_uri = mock_mempool_server.uri() + "/";

    config.protocol_paramset = Box::leak(Box::new(paramset));
    config.mempool_api_host = Some(mempool_space_uri);
    config.mempool_api_endpoint = Some("api/v1/fees/recommended".into());

    let db = Database::new(&config).await.unwrap();
    let signer = Actor::new(config.secret_key, config.protocol_paramset.network);

    let tx_sender = TxSenderWithCore::new(
        signer,
        mock_rpc,
        db,
        "test_tx_sender".into(),
        config.protocol_paramset(),
        config.tx_sender_limits.clone(),
        config.mempool_config(),
    );

    let fee_rate = tx_sender.get_fee_rate().await.unwrap();
    assert_eq!(fee_rate, FeeRate::from_sat_per_kwu(1000));
}

#[tokio::test]
async fn test_get_fee_rate_rpc_failure_mempool_fallback() {
    let mock_rpc_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/"))
        .and(body_partial_json(json!({
            "method": "estimatesmartfee"
        })))
        .respond_with(ResponseTemplate::new(500).set_body_json(json!({
            "jsonrpc": "2.0",
            "id": 1,
            "error": {
                "code": -32603,
                "message": "Internal error"
            }
        })))
        .mount(&mock_rpc_server)
        .await;

    Mock::given(method("POST"))
        .and(path("/"))
        .and(body_partial_json(json!({
            "method": "ping"
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": null
        })))
        .mount(&mock_rpc_server)
        .await;

    let mock_mempool_server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/fees/recommended"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "fastestFee": 10,
            "halfHourFee": 9,
            "hourFee": 8
        })))
        .mount(&mock_mempool_server)
        .await;

    let mock_rpc = ExtendedBitcoinRpc::connect(
        mock_rpc_server.uri(),
        secrecy::SecretString::new("test_user".into()),
        secrecy::SecretString::new("test_password".into()),
        None,
    )
    .await
    .unwrap();

    let mut config = create_test_config_with_thread_name().await;
    let network = bitcoin::Network::Bitcoin;
    let paramset = ProtocolParamset {
        network,
        ..ProtocolParamset::default()
    };

    let mempool_space_uri = mock_mempool_server.uri() + "/";

    config.protocol_paramset = Box::leak(Box::new(paramset));
    config.mempool_api_host = Some(mempool_space_uri);
    config.mempool_api_endpoint = Some("api/v1/fees/recommended".into());

    let db = Database::new(&config).await.unwrap();
    let signer = Actor::new(config.secret_key, config.protocol_paramset.network);

    let tx_sender = TxSenderWithCore::new(
        signer,
        mock_rpc,
        db,
        "test_tx_sender".into(),
        config.protocol_paramset(),
        config.tx_sender_limits.clone(),
        config.mempool_config(),
    );

    let fee_rate = tx_sender.get_fee_rate().await.unwrap();
    assert_eq!(fee_rate, FeeRate::from_sat_per_kwu(2500));
}

#[tokio::test]
async fn test_get_fee_rate_mempool_space_timeout() {
    let mock_rpc_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/"))
        .and(body_partial_json(json!({
            "method": "estimatesmartfee"
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "feerate": 0.00008,
                "blocks": 1
            }
        })))
        .mount(&mock_rpc_server)
        .await;

    Mock::given(method("POST"))
        .and(path("/"))
        .and(body_partial_json(json!({
            "method": "ping"
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": null
        })))
        .mount(&mock_rpc_server)
        .await;

    let mock_mempool_server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/fees/recommended"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_delay(Duration::from_secs(10))
                .set_body_json(json!({
                    "fastestFee": 2,
                    "halfHourFee": 1,
                    "hourFee": 1
                })),
        )
        .mount(&mock_mempool_server)
        .await;

    let mock_rpc = ExtendedBitcoinRpc::connect(
        mock_rpc_server.uri(),
        secrecy::SecretString::new("test_user".into()),
        secrecy::SecretString::new("test_password".into()),
        None,
    )
    .await
    .unwrap();

    let mut config = create_test_config_with_thread_name().await;
    let network = bitcoin::Network::Bitcoin;
    let paramset = ProtocolParamset {
        network,
        ..ProtocolParamset::default()
    };

    let mempool_space_uri = mock_mempool_server.uri() + "/";

    config.protocol_paramset = Box::leak(Box::new(paramset));
    config.mempool_api_host = Some(mempool_space_uri);
    config.mempool_api_endpoint = Some("api/v1/fees/recommended".into());

    let db = Database::new(&config).await.unwrap();
    let signer = Actor::new(config.secret_key, config.protocol_paramset.network);

    let tx_sender = TxSenderWithCore::new(
        signer,
        mock_rpc,
        db,
        "test_tx_sender".into(),
        config.protocol_paramset(),
        config.tx_sender_limits.clone(),
        config.mempool_config(),
    );

    let fee_rate = tx_sender.get_fee_rate().await.unwrap();
    assert_eq!(fee_rate, FeeRate::from_sat_per_kwu(2000));
}

#[tokio::test]
async fn test_get_fee_rate_rpc_timeout() {
    let mock_rpc_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/"))
        .and(body_partial_json(json!({
            "method": "estimatesmartfee"
        })))
        .respond_with(
            ResponseTemplate::new(200)
                .set_delay(Duration::from_secs(31))
                .set_body_json(json!({
                    "jsonrpc": "2.0",
                    "id": 1,
                    "result": {
                        "feerate": 0.00002,
                        "blocks": 1
                    }
                })),
        )
        .mount(&mock_rpc_server)
        .await;

    Mock::given(method("POST"))
        .and(path("/"))
        .and(body_partial_json(json!({
            "method": "ping"
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": null
        })))
        .mount(&mock_rpc_server)
        .await;

    let mock_mempool_server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/fees/recommended"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "fastestFee": 8,
            "halfHourFee": 1,
            "hourFee": 1
        })))
        .mount(&mock_mempool_server)
        .await;

    let mock_rpc = ExtendedBitcoinRpc::connect(
        mock_rpc_server.uri(),
        secrecy::SecretString::new("test_user".into()),
        secrecy::SecretString::new("test_password".into()),
        None,
    )
    .await
    .unwrap();

    let mut config = create_test_config_with_thread_name().await;
    let network = bitcoin::Network::Bitcoin;
    let paramset = ProtocolParamset {
        network,
        ..ProtocolParamset::default()
    };

    let mempool_space_uri = mock_mempool_server.uri() + "/";

    config.protocol_paramset = Box::leak(Box::new(paramset));
    config.mempool_api_host = Some(mempool_space_uri);
    config.mempool_api_endpoint = Some("api/v1/fees/recommended".into());

    let db = Database::new(&config).await.unwrap();
    let signer = Actor::new(config.secret_key, config.protocol_paramset.network);

    let tx_sender = TxSenderWithCore::new(
        signer,
        mock_rpc,
        db,
        "test_tx_sender".into(),
        config.protocol_paramset(),
        config.tx_sender_limits.clone(),
        config.mempool_config(),
    );

    let fee_rate = tx_sender.get_fee_rate().await.unwrap();
    assert_eq!(fee_rate, FeeRate::from_sat_per_kwu(2000));
}

#[tokio::test]
async fn test_rpc_retry_after_failures() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use wiremock::{Request, Respond};

    struct RpcSeqResponder {
        n: Arc<AtomicUsize>,
    }
    impl Respond for RpcSeqResponder {
        fn respond(&self, _req: &Request) -> ResponseTemplate {
            let i = self.n.fetch_add(1, Ordering::SeqCst);
            match i {
                0 => ResponseTemplate::new(500).set_body_json(json!({
                    "jsonrpc":"2.0","id":1,"error":{"code":-1,"message":"Connection error 1"}
                })),
                1 => ResponseTemplate::new(500).set_body_json(json!({
                    "jsonrpc":"2.0","id":1,"error":{"code":-1,"message":"Connection error 2"}
                })),
                _ => ResponseTemplate::new(200).set_body_json(json!({
                    "jsonrpc":"2.0","id":1,"result":{"feerate":0.00003,"blocks":1}
                })),
            }
        }
    }

    let mock_rpc_server = MockServer::start().await;
    let counter = Arc::new(AtomicUsize::new(0));

    Mock::given(method("POST"))
        .and(path("/"))
        .and(body_partial_json(json!({
            "method": "estimatesmartfee"
        })))
        .respond_with(RpcSeqResponder { n: counter.clone() })
        .mount(&mock_rpc_server)
        .await;

    Mock::given(method("POST"))
        .and(path("/"))
        .and(body_partial_json(json!({"method": "ping"})))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": null
        })))
        .mount(&mock_rpc_server)
        .await;

    let mock_mempool_server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/fees/recommended"))
        .respond_with(ResponseTemplate::new(500))
        .mount(&mock_mempool_server)
        .await;

    let mock_rpc = ExtendedBitcoinRpc::connect(
        mock_rpc_server.uri(),
        secrecy::SecretString::new("test_user".into()),
        secrecy::SecretString::new("test_password".into()),
        None,
    )
    .await
    .unwrap();

    let mut config = create_test_config_with_thread_name().await;
    let network = bitcoin::Network::Bitcoin;
    let paramset = ProtocolParamset {
        network,
        ..ProtocolParamset::default()
    };

    let mempool_space_uri = mock_mempool_server.uri() + "/";
    config.protocol_paramset = Box::leak(Box::new(paramset));
    config.mempool_api_host = Some(mempool_space_uri);
    config.mempool_api_endpoint = Some("api/v1/fees/recommended".into());

    let db = Database::new(&config).await.unwrap();
    let signer = Actor::new(config.secret_key, config.protocol_paramset.network);

    let tx_sender = TxSenderWithCore::new(
        signer,
        mock_rpc,
        db,
        "test_tx_sender".into(),
        config.protocol_paramset(),
        config.tx_sender_limits.clone(),
        config.mempool_config(),
    );

    let fee_rate = tx_sender.get_fee_rate().await.unwrap();
    assert_eq!(fee_rate, FeeRate::from_sat_per_kwu(750));
}

#[tokio::test]
async fn test_mempool_retry_after_failures() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use wiremock::{Request, Respond};

    let mock_rpc_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/"))
        .and(body_partial_json(json!({"method": "estimatesmartfee"})))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "feerate": 0.00009,
                "blocks": 1
            }
        })))
        .expect(1)
        .mount(&mock_rpc_server)
        .await;

    Mock::given(method("POST"))
        .and(path("/"))
        .and(body_partial_json(json!({"method": "ping"})))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": null
        })))
        .mount(&mock_rpc_server)
        .await;

    struct SeqResponder {
        n: Arc<AtomicUsize>,
    }

    impl Respond for SeqResponder {
        fn respond(&self, _req: &Request) -> ResponseTemplate {
            let i = self.n.fetch_add(1, Ordering::SeqCst);
            match i {
                0 => ResponseTemplate::new(500),
                1 => ResponseTemplate::new(503),
                2 => ResponseTemplate::new(500),
                _ => ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "fastestFee": 6,
                    "halfHourFee": 4,
                    "hourFee": 3
                })),
            }
        }
    }

    let mock_mempool_server = MockServer::start().await;

    let counter = Arc::new(AtomicUsize::new(0));
    Mock::given(method("GET"))
        .and(path("/api/v1/fees/recommended"))
        .respond_with(SeqResponder { n: counter.clone() })
        .mount(&mock_mempool_server)
        .await;

    let mock_rpc = ExtendedBitcoinRpc::connect(
        mock_rpc_server.uri(),
        secrecy::SecretString::new("test_user".into()),
        secrecy::SecretString::new("test_password".into()),
        None,
    )
    .await
    .unwrap();

    let mut config = create_test_config_with_thread_name().await;
    let network = bitcoin::Network::Bitcoin;
    let paramset = ProtocolParamset {
        network,
        ..ProtocolParamset::default()
    };

    let mempool_space_uri = mock_mempool_server.uri() + "/";
    config.protocol_paramset = Box::leak(Box::new(paramset));
    config.mempool_api_host = Some(mempool_space_uri);
    config.mempool_api_endpoint = Some("api/v1/fees/recommended".into());

    let db = Database::new(&config).await.unwrap();
    let signer = Actor::new(config.secret_key, config.protocol_paramset.network);

    let tx_sender = TxSenderWithCore::new(
        signer,
        mock_rpc,
        db,
        "test_tx_sender".into(),
        config.protocol_paramset(),
        config.tx_sender_limits.clone(),
        config.mempool_config(),
    );

    let fee_rate = tx_sender.get_fee_rate().await.unwrap();
    assert_eq!(fee_rate, FeeRate::from_sat_per_kwu(1500));
}

// ====== RBF Tests (restored from main:core/src/tx_sender/rbf.rs) ======

async fn create_local_tx_sender(
    rpc: ExtendedBitcoinRpc,
) -> (
    TxSenderWithCore,
    BitcoinSyncer,
    ExtendedBitcoinRpc,
    Database,
    Actor,
    bitcoin::Network,
) {
    use bitcoin::secp256k1::SecretKey;
    let sk = SecretKey::new(&mut rand::thread_rng());
    let network = bitcoin::Network::Regtest;
    let actor = Actor::new(sk, network);

    let config = create_test_config_with_thread_name().await;

    let db = Database::new(&config).await.unwrap();

    let tx_sender = TxSenderWithCore::new(
        actor.clone(),
        rpc.clone(),
        db.clone(),
        "tx_sender".into(),
        config.protocol_paramset(),
        config.tx_sender_limits.clone(),
        config.mempool_config(),
    );

    (
        tx_sender,
        BitcoinSyncer::new(db.clone(), rpc.clone(), config.protocol_paramset)
            .await
            .unwrap(),
        rpc,
        db,
        actor,
        network,
    )
}

pub async fn create_rbf_tx(
    rpc: &ExtendedBitcoinRpc,
    signer: &Actor,
    network: bitcoin::Network,
    requires_initial_funding: bool,
) -> Result<bitcoin::Transaction, BridgeError> {
    let (address, spend_info) =
        builder::address::create_taproot_address(&[], Some(signer.xonly_public_key), network);

    let amount = Amount::from_sat(100000);
    let outpoint = rpc.send_to_address(&address, amount).await?;

    rpc.mine_blocks(1).await?;

    let version = Version::TWO;

    let mut txhandler = TxHandlerBuilder::new(TransactionType::Dummy)
        .with_version(version)
        .add_input(
            if !requires_initial_funding {
                SignatureId::from(NormalSignatureKind::Challenge)
            } else {
                SignatureId::from((NumberedSignatureKind::WatchtowerChallenge, 0i32))
            },
            SpendableTxIn::new(
                outpoint,
                TxOut {
                    value: amount,
                    script_pubkey: address.script_pubkey(),
                },
                vec![],
                Some(spend_info),
            ),
            SpendPath::KeySpend,
            DEFAULT_SEQUENCE,
        )
        .add_output(UnspentTxOut::from_partial(TxOut {
            value: if requires_initial_funding {
                amount // do not add any fee if we want to test initial funding
            } else {
                amount - MIN_TAPROOT_AMOUNT * 3
            },
            script_pubkey: address.script_pubkey(),
        }))
        .finalize();

    signer
        .tx_sign_and_fill_sigs(&mut txhandler, &[], None)
        .unwrap();

    let tx = txhandler.get_cached_tx().clone();
    Ok(tx)
}

async fn create_challenge_tx(
    rpc: &ExtendedBitcoinRpc,
    signer: &Actor,
    network: bitcoin::Network,
) -> Result<bitcoin::Transaction, BridgeError> {
    use clementine_primitives::NON_STANDARD_V3;

    let (address, spend_info) =
        builder::address::create_taproot_address(&[], Some(signer.xonly_public_key), network);

    let amount = MIN_TAPROOT_AMOUNT;
    let outpoint = rpc.send_to_address(&address, amount).await?;

    rpc.mine_blocks(1).await?;

    let version = NON_STANDARD_V3;

    let mut txhandler = TxHandlerBuilder::new(TransactionType::Challenge)
        .with_version(version)
        .add_input(
            SignatureId::from(NormalSignatureKind::Challenge),
            SpendableTxIn::new(
                outpoint,
                TxOut {
                    value: amount,
                    script_pubkey: address.script_pubkey(),
                },
                vec![],
                Some(spend_info),
            ),
            SpendPath::KeySpend,
            DEFAULT_SEQUENCE,
        )
        .add_output(UnspentTxOut::from_partial(TxOut {
            value: Amount::from_btc(1.0).unwrap(),
            script_pubkey: address.script_pubkey(),
        }))
        .add_output(UnspentTxOut::from_partial(op_return_txout(b"TEST")))
        .finalize();

    signer
        .tx_sign_and_fill_sigs(&mut txhandler, &[], None)
        .unwrap();

    let tx = txhandler.get_cached_tx().clone();
    Ok(tx)
}

#[tokio::test]
async fn test_send_challenge_tx() -> Result<(), BridgeError> {
    let mut config = create_test_config_with_thread_name().await;
    let rpc = create_regtest_rpc(&mut config).await;

    let (tx_sender, btc_sender, rpc, db, signer, network) =
        create_local_tx_sender(rpc.rpc().clone()).await;
    let pair = btc_sender.into_task().cancelable_loop();
    pair.0.into_bg();

    let tx = create_challenge_tx(&rpc, &signer, network).await?;

    let mut dbtx = db.begin_transaction().await?;
    let try_to_send_id = tx_sender
        .client()
        .insert_try_to_send(
            Some(&mut dbtx),
            None,
            &tx,
            FeePayingType::RBF,
            None,
            &[],
            &[],
            &[],
            &[],
        )
        .await?;
    dbtx.commit().await?;

    let current_fee_rate = tx_sender.get_fee_rate().await?;

    tx_sender
        .send_rbf_tx(try_to_send_id, tx.clone(), None, current_fee_rate, None)
        .await
        .expect("RBF should succeed");

    let tx_debug_info = tx_sender
        .client()
        .debug_tx(try_to_send_id)
        .await
        .expect("Transaction should have debug info");

    rpc.get_tx_of_txid(&bitcoin::Txid::from_byte_array(
        tx_debug_info.txid.unwrap().txid.try_into().unwrap(),
    ))
    .await
    .expect("Transaction should be in mempool");

    Ok(())
}

#[tokio::test]
async fn test_send_rbf() -> Result<(), BridgeError> {
    let mut config = create_test_config_with_thread_name().await;
    let rpc = create_regtest_rpc(&mut config).await;

    let (tx_sender, btc_sender, rpc, db, signer, network) =
        create_local_tx_sender(rpc.rpc().clone()).await;
    let pair = btc_sender.into_task().cancelable_loop();
    pair.0.into_bg();

    let tx = create_rbf_tx(&rpc, &signer, network, false).await?;

    let mut dbtx = db.begin_transaction().await?;
    let try_to_send_id = tx_sender
        .client()
        .insert_try_to_send(
            Some(&mut dbtx),
            None,
            &tx,
            FeePayingType::RBF,
            Some(RbfSigningInfo {
                vout: 0,
                tweak_merkle_root: None,
                #[cfg(test)]
                annex: None,
                #[cfg(test)]
                additional_taproot_output_count: None,
            }),
            &[],
            &[],
            &[],
            &[],
        )
        .await?;
    dbtx.commit().await?;

    let current_fee_rate = tx_sender.get_fee_rate().await?;

    tx_sender
        .send_rbf_tx(
            try_to_send_id,
            tx.clone(),
            None,
            current_fee_rate,
            Some(RbfSigningInfo {
                vout: 0,
                tweak_merkle_root: None,
                #[cfg(test)]
                annex: None,
                #[cfg(test)]
                additional_taproot_output_count: None,
            }),
        )
        .await
        .expect("RBF should succeed");

    let tx_debug_info = tx_sender
        .client()
        .debug_tx(try_to_send_id)
        .await
        .expect("Transaction should have debug info");

    rpc.get_tx_of_txid(&bitcoin::Txid::from_byte_array(
        tx_debug_info.txid.unwrap().txid.try_into().unwrap(),
    ))
    .await
    .expect("Transaction should be in mempool");

    Ok(())
}

#[tokio::test]
async fn test_send_no_funding_tx() -> Result<(), BridgeError> {
    let mut config = create_test_config_with_thread_name().await;
    let rpc = create_regtest_rpc(&mut config).await;

    let (tx_sender, btc_sender, rpc, db, signer, network) =
        create_local_tx_sender(rpc.rpc().clone()).await;
    let pair = btc_sender.into_task().cancelable_loop();
    pair.0.into_bg();

    let tx = create_rbf_tx(&rpc, &signer, network, false).await?;

    let mut dbtx = db.begin_transaction().await?;
    let try_to_send_id = tx_sender
        .client()
        .insert_try_to_send(
            Some(&mut dbtx),
            None,
            &tx,
            FeePayingType::NoFunding,
            None,
            &[],
            &[],
            &[],
            &[],
        )
        .await?;
    dbtx.commit().await?;

    tx_sender
        .send_no_funding_tx(try_to_send_id, tx.clone(), None)
        .await
        .expect("Already funded should succeed");

    tx_sender
        .send_no_funding_tx(try_to_send_id, tx.clone(), None)
        .await
        .expect("Should not return error if sent again");

    let tx_debug_info = tx_sender
        .client()
        .debug_tx(try_to_send_id)
        .await
        .expect("Transaction should have debug info");

    rpc.get_tx_of_txid(&bitcoin::Txid::from_byte_array(
        tx_debug_info.txid.unwrap().txid.try_into().unwrap(),
    ))
    .await
    .expect("Transaction should be in mempool");

    tx_sender
        .send_no_funding_tx(try_to_send_id, tx.clone(), None)
        .await
        .expect("Should not return error if sent again but still in mempool");

    Ok(())
}

#[tokio::test]
async fn test_bg_send_rbf() -> Result<(), BridgeError> {
    let mut config = create_test_config_with_thread_name().await;
    let regtest = create_regtest_rpc(&mut config).await;
    let rpc = regtest.rpc().clone();

    rpc.mine_blocks(1).await.unwrap();

    let (client, _tx_sender, _cancel_txs, rpc, db, signer, network) =
        create_bg_tx_sender(config).await;

    let tx = create_rbf_tx(&rpc, &signer, network, false).await.unwrap();

    let mut dbtx = db.begin_transaction().await.unwrap();
    client
        .insert_try_to_send(
            Some(&mut dbtx),
            None,
            &tx,
            FeePayingType::RBF,
            Some(RbfSigningInfo {
                vout: 0,
                tweak_merkle_root: None,
                #[cfg(test)]
                annex: None,
                #[cfg(test)]
                additional_taproot_output_count: None,
            }),
            &[],
            &[],
            &[],
            &[],
        )
        .await
        .unwrap();
    dbtx.commit().await.unwrap();

    poll_until_condition(
        async || {
            rpc.mine_blocks(1).await.unwrap();

            let tx_result = rpc.get_raw_transaction_info(&tx.compute_txid(), None).await;

            Ok(matches!(tx_result, Ok(GetRawTransactionResult {
                confirmations: Some(confirmations),
                ..
            }) if confirmations > 0))
        },
        Some(Duration::from_secs(30)),
        Some(Duration::from_millis(100)),
    )
    .await
    .expect("Tx was not confirmed in time");

    Ok(())
}

#[tokio::test]
async fn test_send_with_initial_funding_rbf() -> Result<(), BridgeError> {
    let mut config = create_test_config_with_thread_name().await;
    let rpc = create_regtest_rpc(&mut config).await;

    let (tx_sender, btc_sender, rpc, db, signer, network) =
        create_local_tx_sender(rpc.rpc().clone()).await;
    let pair = btc_sender.into_task().cancelable_loop();
    pair.0.into_bg();

    // Create a bumpable transaction that requires initial funding
    let tx = create_rbf_tx(&rpc, &signer, network, true).await?;

    // Insert the transaction into the database
    let mut dbtx = db.begin_transaction().await?;
    let try_to_send_id = tx_sender
        .client()
        .insert_try_to_send(
            Some(&mut dbtx),
            None,
            &tx,
            FeePayingType::RBF,
            Some(RbfSigningInfo {
                vout: 0,
                tweak_merkle_root: None,
                #[cfg(test)]
                annex: None,
                #[cfg(test)]
                additional_taproot_output_count: None,
            }),
            &[],
            &[],
            &[],
            &[],
        )
        .await?;
    dbtx.commit().await?;

    let current_fee_rate = tx_sender.get_fee_rate().await?;

    // Test send_rbf_tx
    tx_sender
        .send_rbf_tx(
            try_to_send_id,
            tx.clone(),
            None,
            current_fee_rate,
            Some(RbfSigningInfo {
                vout: 0,
                tweak_merkle_root: None,
                #[cfg(test)]
                annex: None,
                #[cfg(test)]
                additional_taproot_output_count: None,
            }),
        )
        .await
        .expect("RBF should succeed");

    // Verify that the transaction was fee-bumped
    let tx_debug_info = tx_sender
        .client()
        .debug_tx(try_to_send_id)
        .await
        .expect("Transaction should have debug info");

    // Get the actual transaction from the mempool
    let sent_tx = rpc
        .get_tx_of_txid(&bitcoin::Txid::from_byte_array(
            tx_debug_info.txid.unwrap().txid.try_into().unwrap(),
        ))
        .await
        .expect("Transaction should be in mempool");

    // Check that the transaction has new input (wallet added funding)
    assert_eq!(sent_tx.input.len(), 2);

    Ok(())
}

#[tokio::test]
async fn test_send_without_info_rbf() -> Result<(), BridgeError> {
    // This is the case with no initial funding required, corresponding to the Challenge transaction.

    let mut config = create_test_config_with_thread_name().await;
    let rpc = create_regtest_rpc(&mut config).await;

    let (tx_sender, btc_sender, rpc, db, signer, network) =
        create_local_tx_sender(rpc.rpc().clone()).await;
    let pair = btc_sender.into_task().cancelable_loop();
    pair.0.into_bg();

    // Create a bumpable transaction
    let tx = create_rbf_tx(&rpc, &signer, network, false).await?;

    // Insert the transaction into the database
    let mut dbtx = db.begin_transaction().await?;
    let try_to_send_id = tx_sender
        .client()
        .insert_try_to_send(
            Some(&mut dbtx),
            None,
            &tx,
            FeePayingType::RBF,
            None,
            &[],
            &[],
            &[],
            &[],
        )
        .await?;
    dbtx.commit().await?;

    let current_fee_rate = tx_sender.get_fee_rate().await?;

    // Test send_rbf_tx with no signing info
    tx_sender
        .send_rbf_tx(try_to_send_id, tx.clone(), None, current_fee_rate, None)
        .await
        .expect("RBF should succeed");

    // Verify that the transaction was fee-bumped
    let tx_debug_info = tx_sender
        .client()
        .debug_tx(try_to_send_id)
        .await
        .expect("Transaction should have debug info");

    // Get the actual transaction from the mempool
    rpc.get_tx_of_txid(&bitcoin::Txid::from_byte_array(
        tx_debug_info.txid.unwrap().txid.try_into().unwrap(),
    ))
    .await
    .expect("Transaction should be in mempool");

    Ok(())
}

#[tokio::test]
async fn test_bump_rbf_after_sent() -> Result<(), BridgeError> {
    let mut config = create_test_config_with_thread_name().await;
    let rpc = create_regtest_rpc(&mut config).await;

    let (tx_sender, btc_sender, rpc, db, signer, network) =
        create_local_tx_sender(rpc.rpc().clone()).await;
    let pair = btc_sender.into_task().cancelable_loop();
    pair.0.into_bg();

    // Create a bumpable transaction
    let tx = create_rbf_tx(&rpc, &signer, network, true).await?;

    // Insert the transaction into the database
    let mut dbtx = db.begin_transaction().await?;
    let try_to_send_id = tx_sender
        .client()
        .insert_try_to_send(
            Some(&mut dbtx),
            None,
            &tx,
            FeePayingType::RBF,
            None,
            &[],
            &[],
            &[],
            &[],
        )
        .await?;
    dbtx.commit().await?;

    let current_fee_rate = tx_sender.get_fee_rate().await?;

    // Create initial TX
    tx_sender
        .send_rbf_tx(
            try_to_send_id,
            tx.clone(),
            None,
            current_fee_rate,
            Some(RbfSigningInfo {
                vout: 0,
                tweak_merkle_root: None,
                #[cfg(test)]
                annex: None,
                #[cfg(test)]
                additional_taproot_output_count: None,
            }),
        )
        .await
        .expect("RBF should succeed");

    // Verify that the transaction was saved in db
    let tx_debug_info = tx_sender
        .client()
        .debug_tx(try_to_send_id)
        .await
        .expect("Transaction should have debug info");

    // Verify that TX is in mempool
    let initial_txid = tx_debug_info.txid.unwrap().txid;
    rpc.get_tx_of_txid(&bitcoin::Txid::from_byte_array(
        initial_txid.clone().try_into().unwrap(),
    ))
    .await
    .expect("Transaction should be in mempool");

    // Increase fee rate
    let higher_fee_rate = current_fee_rate.checked_mul(2).unwrap();

    tokio::time::sleep(Duration::from_secs(1)).await;

    // try to send tx with a bumped fee.
    tx_sender
        .send_rbf_tx(
            try_to_send_id,
            tx.clone(),
            None,
            higher_fee_rate,
            Some(RbfSigningInfo {
                vout: 0,
                tweak_merkle_root: None,
                #[cfg(test)]
                annex: None,
                #[cfg(test)]
                additional_taproot_output_count: None,
            }),
        )
        .await
        .expect("RBF should succeed");

    // Verify that the transaction was saved in db
    let tx_debug_info = tx_sender
        .client()
        .debug_tx(try_to_send_id)
        .await
        .expect("Transaction should have debug info");

    // Verify that TX is in mempool
    let changed_txid = tx_debug_info.txid.unwrap().txid;
    rpc.get_tx_of_txid(&bitcoin::Txid::from_byte_array(
        changed_txid.clone().try_into().unwrap(),
    ))
    .await
    .expect("Transaction should be in mempool");

    // Verify that tx has changed.
    assert_ne!(
        changed_txid, initial_txid,
        "Transaction should have been bumped"
    );

    Ok(())
}
