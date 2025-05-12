use bitcoin::{BlockHash, Transaction, XOnlyPublicKey};
use clementine_core::actor::Actor;
use clementine_core::bitvm_client::ClementineBitVMPublicKeys;
use clementine_core::builder::transaction::sign::get_kickoff_utxos_to_sign;
use clementine_core::builder::transaction::{
    DepositInfo, KickoffData, TransactionType, TxHandlerBuilder,
};
use clementine_core::citrea::mock::MockCitreaClient;
use clementine_core::config::BridgeConfig;
use clementine_core::rpc::clementine::clementine_operator_client::ClementineOperatorClient;
use clementine_core::rpc::clementine::clementine_verifier_client::ClementineVerifierClient;
use clementine_core::rpc::clementine::{SignedTxsWithType, TransactionRequest};
use clementine_core::test::common::*;
use criterion::async_executor::AsyncExecutor;
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use futures::future::try_join_all;
use std::hint::black_box;
use tokio::sync::mpsc;

async fn deposit(num_round_txs: usize) {
    let mut config = create_test_config_with_thread_name().await;
    let WithProcessCleanup(_, ref rpc, _, _) = create_regtest_rpc(&mut config).await;

    let mut paramset = config.protocol_paramset().clone();
    paramset.num_round_txs = num_round_txs;
    config.protocol_paramset = Box::leak(Box::new(paramset));

    let (verifiers, operators, _, _cleanup, deposit_params, _, deposit_blockhash, _) =
        run_single_deposit::<MockCitreaClient>(&mut config, rpc.clone(), None)
            .await
            .unwrap();
}

fn criterion_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("deposit");
    group.sample_size(10);

    let groups = std::env::var("BENCH_NUM_ROUND_TX").unwrap_or("10,20,30,40".to_string());
    let num_round_txs: Vec<usize> = groups.split(',').map(|s| s.parse().unwrap()).collect();

    // Aim is to reach 200 round txs
    for num_round_tx in num_round_txs.iter() {
        group.bench_with_input(
            BenchmarkId::from_parameter(num_round_tx),
            &num_round_tx,
            |b, &s| {
                let runtime = tokio::runtime::Builder::new_multi_thread()
                    .enable_all()
                    .build()
                    .unwrap();
                b.to_async(runtime).iter(|| deposit(*s));
            },
        );
    }
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
