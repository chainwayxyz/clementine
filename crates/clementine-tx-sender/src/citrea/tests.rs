#![cfg(all(feature = "citrea", feature = "testing"))]

use bitcoin::Txid;
use bitcoincore_rpc::RpcApi;
use clementine_primitives::FeeRateKvb;
use rand::RngCore;
use tx_sender_types::{ActivationState, TrackRequest, TrackResponse, TrackStatus};

use crate::citrea::{CitreaTxRequest, TransactionKind};
use crate::task::TxSenderTaskInternal;
use crate::test_utils::create_test_environment;
use crate::TxSender;

/// Helper to insert a single Citrea raw tx row for the given transaction kind
/// using `TxSenderClient::send_citrea_tx`, and return its `insertion_id`.
async fn insert_single_citrea_row_with_body_size(
    tx_sender: &TxSender,
    kind: TransactionKind,
    body_size: usize,
) -> i64 {
    use crate::client::TxSenderClient;

    let mut body = vec![0u8; body_size];
    rand::thread_rng().fill_bytes(&mut body);

    let raw = match kind {
        TransactionKind::Complete => CitreaTxRequest::BatchProof {
            bytes: body.clone(),
            chunk_size: None,
        },
        TransactionKind::BatchProofMethodId => CitreaTxRequest::BatchProofMethodId(body.clone()),
        TransactionKind::SequencerCommitment => CitreaTxRequest::SequencerCommitment(body.clone()),
        other => panic!("unsupported TransactionKind for single row helper: {other:?}",),
    };

    let client = TxSenderClient::new(tx_sender.db.clone());
    client.send_citrea_tx(raw).await.unwrap()
}

async fn insert_single_citrea_row(tx_sender: &TxSender, kind: TransactionKind) -> i64 {
    insert_single_citrea_row_with_body_size(tx_sender, kind, 32).await
}

/// Helper to insert a chunked Citrea raw tx group.
async fn insert_chunked_citrea_rows(tx_sender: &TxSender) -> i64 {
    use crate::client::TxSenderClient;

    let mut chunks = Vec::new();
    for _ in 0..3 {
        let mut body = vec![0u8; 64];
        rand::thread_rng().fill_bytes(&mut body);
        chunks.push(body);
    }
    let bytes = chunks.concat();

    let client = TxSenderClient::new(tx_sender.db.clone());
    client
        .send_citrea_tx(CitreaTxRequest::BatchProof {
            bytes,
            chunk_size: Some(64),
        })
        .await
        .unwrap()
}

/// Returns the commit txid and all try_to_send_ids for the given insertion_id.
///
/// For single-body insertions there will be at most one `try_to_send_id`.
/// For chunked insertions, there can be multiple `try_to_send_id`s (one per
/// non-aggregate row sharing the same insertion group).
async fn get_citrea_commit_and_try_to_send_ids(
    tx_sender: &TxSender,
    insertion_id: i64,
) -> (Txid, Vec<u32>) {
    use crate::db::wrapper::OutPointDB;
    use sqlx::Row;

    let rows = sqlx::query(
        "SELECT commit_outpoint, try_to_send_id \
         FROM tx_sender_citrea_raw_tx_queue \
         WHERE insertion_id = $1 AND body IS NOT NULL \
         ORDER BY id ASC",
    )
    .bind(insertion_id)
    .fetch_all(tx_sender.db.pool())
    .await
    .unwrap();

    assert!(
        !rows.is_empty(),
        "expected at least one citrea row for insertion_id={insertion_id}"
    );

    let mut commit_txid: Option<Txid> = None;
    let mut try_to_send_ids = Vec::new();

    for row in rows {
        let commit_outpoint: Option<OutPointDB> = row.get("commit_outpoint");
        let commit_outpoint = commit_outpoint
            .expect("commit_outpoint should be set for all citrea rows")
            .0;

        match commit_txid {
            None => commit_txid = Some(commit_outpoint.txid),
            Some(txid) => {
                assert_eq!(
                    txid, commit_outpoint.txid,
                    "all citrea rows for the same insertion_id must share the same commit txid"
                );
            }
        }

        let try_to_send_id: Option<i32> = row.get("try_to_send_id");
        if let Some(id) = try_to_send_id {
            try_to_send_ids.push(u32::try_from(id).unwrap());
        }
    }

    (
        commit_txid.expect("commit_txid must be set"),
        try_to_send_ids,
    )
}

struct CitreaAggregateRow {
    body: Vec<u8>,
    commit_outpoint: Option<bitcoin::OutPoint>,
    try_to_send_id: Option<u32>,
}

async fn get_citrea_aggregate_row(tx_sender: &TxSender, insertion_id: i64) -> CitreaAggregateRow {
    use crate::db::wrapper::OutPointDB;
    use sqlx::Row;

    let row = sqlx::query(
        "SELECT body, commit_outpoint, try_to_send_id \
         FROM tx_sender_citrea_raw_tx_queue \
         WHERE insertion_id = $1 AND transaction_kind = 1 \
         LIMIT 1",
    )
    .bind(insertion_id)
    .fetch_one(tx_sender.db.pool())
    .await
    .unwrap();

    let body: Option<Vec<u8>> = row.get("body");
    let commit_outpoint: Option<OutPointDB> = row.get("commit_outpoint");
    let try_to_send_id: Option<i32> = row.get("try_to_send_id");

    CitreaAggregateRow {
        body: body.unwrap_or_default(),
        commit_outpoint: commit_outpoint.map(|op| op.0),
        try_to_send_id: try_to_send_id.map(|id| id as u32),
    }
}

#[tokio::test]
async fn citrea_tracking_single_row_lifecycle() {
    let (config, _db, rpc_env) = create_test_environment(true, true).await;
    let rpc_env = rpc_env.expect("RPC environment must be created");
    let tx_sender = TxSender::new(config).await.unwrap();

    let insertion_id = insert_single_citrea_row(&tx_sender, TransactionKind::Complete).await;

    match tx_sender
        .tracker()
        .track_request(TrackRequest::CommitReveal { insertion_id })
        .await
        .unwrap()
    {
        TrackResponse::CommitReveal(track) => {
            assert_eq!(track.status, TrackStatus::Pending);
            assert!(track.commit_tx.is_none());
            assert!(track.aggregate_commit_tx.is_none());
            assert_eq!(track.reveals.len(), 1);
            assert!(track.reveals[0].submission.is_none());
        }
        other => panic!("unexpected tracking response: {other:?}"),
    }

    let mut task = TxSenderTaskInternal::new(tx_sender.clone());
    task.run_once().await.unwrap();

    match tx_sender
        .tracker()
        .track_request(TrackRequest::CommitReveal { insertion_id })
        .await
        .unwrap()
    {
        TrackResponse::CommitReveal(track) => {
            assert_eq!(track.status, TrackStatus::InProgress);
            assert!(track.commit_tx.is_some());
            assert!(track.aggregate_commit_tx.is_none());
            assert_eq!(track.reveals.len(), 1);
            assert!(track.reveals[0]
                .submission
                .as_ref()
                .is_some_and(|reveal| reveal.activation == ActivationState::Active));
            assert!(track.aggregate_reveal_submission.is_none());
        }
        other => panic!("unexpected tracking response: {other:?}"),
    }

    rpc_env
        .rpc()
        .mine_blocks(tx_sender.finality_depth.into())
        .await
        .unwrap();
    task.run_once().await.unwrap();
    task.run_once().await.unwrap();

    match tx_sender
        .tracker()
        .track_request(TrackRequest::CommitReveal { insertion_id })
        .await
        .unwrap()
    {
        TrackResponse::CommitReveal(track) => {
            assert_eq!(track.status, TrackStatus::Finalized);
            assert!(track.commit_tx.is_some());
            assert!(track.aggregate_commit_tx.is_none());
            assert_eq!(track.reveals.len(), 1);
            assert!(track.reveals[0].submission.as_ref().is_some_and(|reveal| {
                reveal.status == TrackStatus::Finalized
                    && reveal.activation == ActivationState::Active
                    && reveal.tx_info.mined_at_height.is_some()
            }));
            assert!(track.aggregate_reveal_submission.is_none());
        }
        other => panic!("unexpected tracking response: {other:?}"),
    }
}

#[tokio::test]
async fn citrea_tracking_chunked_exposes_pre_aggregate_progress() {
    let (config, _db, rpc_env) = create_test_environment(true, true).await;
    let rpc_env = rpc_env.expect("RPC environment must be created");
    let tx_sender = TxSender::new(config).await.unwrap();

    let insertion_id = insert_chunked_citrea_rows(&tx_sender).await;
    let mut task = TxSenderTaskInternal::new(tx_sender.clone());
    task.run_once().await.unwrap();

    match tx_sender
        .tracker()
        .track_request(TrackRequest::CommitReveal { insertion_id })
        .await
        .unwrap()
    {
        TrackResponse::CommitReveal(track) => {
            assert_eq!(track.status, TrackStatus::InProgress);
            assert!(track.commit_tx.is_some());
            assert!(track.aggregate_commit_tx.is_none());
            assert_eq!(track.reveals.len(), 3);
            assert!(track.reveals.iter().all(|reveal| reveal
                .submission
                .as_ref()
                .is_some_and(|track| track.activation == ActivationState::Active)));
            assert!(track.aggregate_reveal_submission.is_none());
        }
        other => panic!("unexpected tracking response: {other:?}"),
    }

    rpc_env
        .rpc()
        .mine_blocks(tx_sender.finality_depth.into())
        .await
        .unwrap();
    task.run_once().await.unwrap();

    match tx_sender
        .tracker()
        .track_request(TrackRequest::CommitReveal { insertion_id })
        .await
        .unwrap()
    {
        TrackResponse::CommitReveal(track) => {
            assert_eq!(track.status, TrackStatus::InProgress);
            assert!(track
                .commit_tx
                .as_ref()
                .is_some_and(|tx| tx.mined_at_height.is_some()));
            assert!(track.aggregate_commit_tx.is_none());
            assert!(track.aggregate_reveal_submission.is_none());
            assert!(track.reveals.iter().all(|reveal| reveal
                .submission
                .as_ref()
                .is_some_and(|track| track.activation == ActivationState::Active)));
        }
        other => panic!("unexpected tracking response: {other:?}"),
    }
}

/// Calculates the fee rate of a transaction in sat/kvB (satoshis per kilovbyte).
async fn calculate_feerate_sat_per_kvb(tx_sender: &TxSender, tx: &bitcoin::Transaction) -> u64 {
    use bitcoin::Weight;

    let fee = tx_sender.get_tx_fee(tx).await.unwrap();
    let weight: Weight = tx.weight();
    let vbytes = weight.to_vbytes_ceil();

    // fee_rate_sat_per_kvb = fee_sat * 1000 / vbytes
    fee.to_sat().saturating_mul(1000).div_ceil(vbytes)
}

/// Calculates the package fee rate of two transactions (e.g. parent+child) in sat/kvB.
async fn calculate_package_feerate_sat_per_kvb(
    tx_sender: &TxSender,
    parent: &bitcoin::Transaction,
    child: &bitcoin::Transaction,
) -> u64 {
    let parent_fee = tx_sender.get_tx_fee(parent).await.unwrap();
    let child_fee = tx_sender.get_tx_fee(child).await.unwrap();

    let total_fee_sat = parent_fee.to_sat().saturating_add(child_fee.to_sat());
    let total_vbytes = (parent.weight() + child.weight()).to_vbytes_ceil();

    // fee_rate_sat_per_kvb = fee_sat * 1000 / vbytes
    total_fee_sat.saturating_mul(1000).div_ceil(total_vbytes)
}

#[tokio::test]
async fn citrea_complete_tx_flow_commits_and_mines_with_min_feerate() {
    let (config, _db, rpc_env) = create_test_environment(true, true).await;
    let rpc_env = rpc_env.expect("RPC environment must be created");

    let tx_sender = TxSender::new(config).await.unwrap();

    // Insert a Complete (type 0) Citrea row.
    let insertion_id = insert_single_citrea_row(&tx_sender, TransactionKind::Complete).await;

    // Run a single txsender iteration.
    let mut task = TxSenderTaskInternal::new(tx_sender.clone());
    task.run_once().await.unwrap();

    // After run_once, commit tx and at least one reveal try_to_send_id must exist.
    let (commit_txid, try_to_send_ids) =
        get_citrea_commit_and_try_to_send_ids(&tx_sender, insertion_id).await;
    let try_to_send_id = *try_to_send_ids
        .first()
        .expect("at least one reveal try_to_send_id must be set");

    // Reveal RBF tx should be registered in txsender_rbf_txids.
    let reveal_txid = tx_sender
        .db
        .get_last_rbf_txid(None, try_to_send_id)
        .await
        .unwrap()
        .expect("reveal RBF txid must exist");

    let commit_tx = tx_sender.rpc.get_tx_of_txid(&commit_txid).await.unwrap();
    let reveal_tx = tx_sender.rpc.get_tx_of_txid(&reveal_txid).await.unwrap();

    // Sanity: reveal spends the commit output.
    assert!(
        !reveal_tx.input.is_empty(),
        "reveal tx must have at least one input"
    );
    assert_eq!(
        reveal_tx.input[0].previous_output.txid, commit_txid,
        "reveal tx must spend the commit tx output"
    );

    let commit_feerate = calculate_feerate_sat_per_kvb(&tx_sender, &commit_tx).await;
    let reveal_feerate = calculate_feerate_sat_per_kvb(&tx_sender, &reveal_tx).await;
    let target_feerate = tx_sender.get_fee_rate().await.unwrap().to_sat_per_kvb();
    let max_feerate = target_feerate.saturating_mul(101).saturating_div(100);
    assert!(
        commit_feerate >= target_feerate && commit_feerate <= max_feerate,
        "expected commit feerate between {target_feerate} and {max_feerate} sat/kvB, got {commit_feerate}"
    );
    assert!(
        reveal_feerate >= target_feerate && reveal_feerate <= max_feerate,
        "expected reveal feerate between {target_feerate} and {max_feerate} sat/kvB, got {reveal_feerate}"
    );

    // Mine a block and ensure the commit tx is confirmed.
    rpc_env.rpc().mine_blocks(1).await.unwrap();
    let confirmations = rpc_env
        .rpc()
        .confirmation_blocks(&commit_txid)
        .await
        .unwrap();
    assert!(
        confirmations >= 1,
        "expected commit tx to be confirmed, got {confirmations} confirmations"
    );

    // Reveal tx must also be confirmed.
    let reveal_confirmations = rpc_env
        .rpc()
        .confirmation_blocks(&reveal_txid)
        .await
        .unwrap();
    assert!(
        reveal_confirmations >= 1,
        "expected reveal tx to be confirmed, got {reveal_confirmations} confirmations"
    );
}

#[tokio::test]
async fn citrea_chunks_tx_flow_commits_and_mines_with_min_feerate() {
    let (config, _db, rpc_env) = create_test_environment(true, true).await;
    let rpc_env = rpc_env.expect("RPC environment must be created");

    let tx_sender = TxSender::new(config).await.unwrap();

    // Insert a chunked Citrea group (type 2 + aggregate).
    let insertion_id = insert_chunked_citrea_rows(&tx_sender).await;

    let mut task = TxSenderTaskInternal::new(tx_sender.clone());
    task.run_once().await.unwrap();

    let (commit_txid, try_to_send_ids) =
        get_citrea_commit_and_try_to_send_ids(&tx_sender, insertion_id).await;
    assert!(
        !try_to_send_ids.is_empty(),
        "at least one reveal try_to_send_id must be set"
    );

    // For chunked insertions there can be multiple reveal txs; verify all of them
    // and collect their txids for later confirmation checks.
    let mut reveal_txids = Vec::new();
    for try_to_send_id in &try_to_send_ids {
        let reveal_txid = tx_sender
            .db
            .get_last_rbf_txid(None, *try_to_send_id)
            .await
            .unwrap()
            .expect("reveal RBF txid must exist");
        reveal_txids.push(reveal_txid);

        let reveal_tx = tx_sender.rpc.get_tx_of_txid(&reveal_txid).await.unwrap();

        assert!(
            !reveal_tx.input.is_empty(),
            "reveal tx must have at least one input"
        );
        assert_eq!(
            reveal_tx.input[0].previous_output.txid, commit_txid,
            "reveal tx must spend the commit tx output"
        );

        let reveal_feerate = calculate_feerate_sat_per_kvb(&tx_sender, &reveal_tx).await;
        let target_feerate = tx_sender.get_fee_rate().await.unwrap().to_sat_per_kvb();
        let max_feerate = target_feerate.saturating_mul(101).saturating_div(100);
        assert!(
            reveal_feerate >= target_feerate && reveal_feerate <= max_feerate,
            "expected reveal feerate between {target_feerate} and {max_feerate} sat/kvB, got {reveal_feerate}"
        );
    }

    let commit_tx = tx_sender.rpc.get_tx_of_txid(&commit_txid).await.unwrap();
    let commit_feerate = calculate_feerate_sat_per_kvb(&tx_sender, &commit_tx).await;
    let target_feerate = tx_sender.get_fee_rate().await.unwrap().to_sat_per_kvb();
    let max_feerate = target_feerate.saturating_mul(101).saturating_div(100);
    assert!(
        commit_feerate >= target_feerate && commit_feerate <= max_feerate,
        "expected commit feerate between {target_feerate} and {max_feerate} sat/kvB, got {commit_feerate}"
    );

    rpc_env.rpc().mine_blocks(1).await.unwrap();
    let confirmations = rpc_env
        .rpc()
        .confirmation_blocks(&commit_txid)
        .await
        .unwrap();
    assert!(
        confirmations >= 1,
        "expected commit tx to be confirmed, got {confirmations} confirmations"
    );

    for reveal_txid in reveal_txids {
        let reveal_confirmations = rpc_env
            .rpc()
            .confirmation_blocks(&reveal_txid)
            .await
            .unwrap();
        assert!(
            reveal_confirmations >= 1,
            "expected reveal tx to be confirmed, got {reveal_confirmations} confirmations"
        );
    }

    // Run once to sync confirmations, then again to send aggregate.
    task.run_once().await.unwrap();
    task.run_once().await.unwrap();

    let aggregate_row = get_citrea_aggregate_row(&tx_sender, insertion_id).await;
    assert!(
        !aggregate_row.body.is_empty(),
        "aggregate body should be set"
    );
    let aggregate_commit_outpoint = aggregate_row
        .commit_outpoint
        .expect("aggregate commit_outpoint must be set");
    let aggregate_try_to_send_id = aggregate_row
        .try_to_send_id
        .expect("aggregate try_to_send_id must be set");

    let aggregate_reveal_txid = tx_sender
        .db
        .get_last_rbf_txid(None, aggregate_try_to_send_id)
        .await
        .unwrap()
        .expect("aggregate reveal RBF txid must exist");
    let aggregate_reveal_tx = tx_sender
        .rpc
        .get_tx_of_txid(&aggregate_reveal_txid)
        .await
        .unwrap();
    assert_eq!(
        aggregate_reveal_tx.input[0].previous_output, aggregate_commit_outpoint,
        "aggregate reveal tx must spend the aggregate commit outpoint"
    );

    // Invalidate last 2 blocks and ensure aggregate sending is still correct after reorg.
    let tip_height = rpc_env.rpc().get_current_chain_height().await.unwrap();
    let last_block_hash = rpc_env
        .rpc()
        .get_block_hash(tip_height as u64)
        .await
        .unwrap();
    let prev_block_hash = rpc_env
        .rpc()
        .get_block_hash((tip_height - 1) as u64)
        .await
        .unwrap();
    rpc_env
        .rpc()
        .invalidate_block(&last_block_hash)
        .await
        .unwrap();
    rpc_env
        .rpc()
        .invalidate_block(&prev_block_hash)
        .await
        .unwrap();

    rpc_env.rpc().mine_blocks(2).await.unwrap();
    task.run_once().await.unwrap();
    task.run_once().await.unwrap();

    let aggregate_row = get_citrea_aggregate_row(&tx_sender, insertion_id).await;
    assert!(
        !aggregate_row.body.is_empty(),
        "aggregate body should be set after reorg"
    );
    let aggregate_commit_outpoint = aggregate_row
        .commit_outpoint
        .expect("aggregate commit_outpoint must be set after reorg");
    let aggregate_try_to_send_id = aggregate_row
        .try_to_send_id
        .expect("aggregate try_to_send_id must be set after reorg");

    let aggregate_reveal_txid = tx_sender
        .db
        .get_last_rbf_txid(None, aggregate_try_to_send_id)
        .await
        .unwrap()
        .expect("aggregate reveal RBF txid must exist after reorg");
    let aggregate_reveal_tx = tx_sender
        .rpc
        .get_tx_of_txid(&aggregate_reveal_txid)
        .await
        .unwrap();
    assert_eq!(
        aggregate_reveal_tx.input[0].previous_output, aggregate_commit_outpoint,
        "aggregate reveal tx must spend the aggregate commit outpoint after reorg"
    );
}

#[tokio::test]
async fn citrea_batch_proof_method_id_tx_flow_commits_and_mines_with_min_feerate() {
    let (config, _db, rpc_env) = create_test_environment(true, true).await;
    let rpc_env = rpc_env.expect("RPC environment must be created");

    let tx_sender = TxSender::new(config).await.unwrap();

    let insertion_id =
        insert_single_citrea_row(&tx_sender, TransactionKind::BatchProofMethodId).await;

    let mut task = TxSenderTaskInternal::new(tx_sender.clone());
    task.run_once().await.unwrap();

    let (commit_txid, try_to_send_ids) =
        get_citrea_commit_and_try_to_send_ids(&tx_sender, insertion_id).await;
    let try_to_send_id = *try_to_send_ids
        .first()
        .expect("at least one reveal try_to_send_id must be set");

    let reveal_txid = tx_sender
        .db
        .get_last_rbf_txid(None, try_to_send_id)
        .await
        .unwrap()
        .expect("reveal RBF txid must exist");

    let commit_tx = tx_sender.rpc.get_tx_of_txid(&commit_txid).await.unwrap();
    let reveal_tx = tx_sender.rpc.get_tx_of_txid(&reveal_txid).await.unwrap();

    assert!(
        !reveal_tx.input.is_empty(),
        "reveal tx must have at least one input"
    );
    assert_eq!(
        reveal_tx.input[0].previous_output.txid, commit_txid,
        "reveal tx must spend the commit tx output"
    );

    let commit_feerate = calculate_feerate_sat_per_kvb(&tx_sender, &commit_tx).await;
    let reveal_feerate = calculate_feerate_sat_per_kvb(&tx_sender, &reveal_tx).await;
    let target_feerate = tx_sender.get_fee_rate().await.unwrap().to_sat_per_kvb();
    let max_feerate = target_feerate.saturating_mul(101).saturating_div(100);
    assert!(
        commit_feerate >= target_feerate && commit_feerate <= max_feerate,
        "expected commit feerate between {target_feerate} and {max_feerate} sat/kvB, got {commit_feerate}"
    );
    assert!(
        reveal_feerate >= target_feerate && reveal_feerate <= max_feerate,
        "expected reveal feerate between {target_feerate} and {max_feerate} sat/kvB, got {reveal_feerate}"
    );

    rpc_env.rpc().mine_blocks(1).await.unwrap();
    let confirmations = rpc_env
        .rpc()
        .confirmation_blocks(&commit_txid)
        .await
        .unwrap();
    assert!(
        confirmations >= 1,
        "expected commit tx to be confirmed, got {confirmations} confirmations"
    );

    let reveal_confirmations = rpc_env
        .rpc()
        .confirmation_blocks(&reveal_txid)
        .await
        .unwrap();
    assert!(
        reveal_confirmations >= 1,
        "expected reveal tx to be confirmed, got {reveal_confirmations} confirmations"
    );
}

#[tokio::test]
async fn citrea_sequencer_commitment_tx_flow_commits_and_mines_with_min_feerate() {
    let (config, _db, rpc_env) = create_test_environment(true, true).await;
    let rpc_env = rpc_env.expect("RPC environment must be created");

    let tx_sender = TxSender::new(config).await.unwrap();

    let insertion_id =
        insert_single_citrea_row(&tx_sender, TransactionKind::SequencerCommitment).await;

    let mut task = TxSenderTaskInternal::new(tx_sender.clone());
    task.run_once().await.unwrap();

    let (commit_txid, try_to_send_ids) =
        get_citrea_commit_and_try_to_send_ids(&tx_sender, insertion_id).await;
    let try_to_send_id = *try_to_send_ids
        .first()
        .expect("at least one reveal try_to_send_id must be set");

    let reveal_txid = tx_sender
        .db
        .get_last_rbf_txid(None, try_to_send_id)
        .await
        .unwrap()
        .expect("reveal RBF txid must exist");

    let commit_tx = tx_sender.rpc.get_tx_of_txid(&commit_txid).await.unwrap();
    let reveal_tx = tx_sender.rpc.get_tx_of_txid(&reveal_txid).await.unwrap();

    assert!(
        !reveal_tx.input.is_empty(),
        "reveal tx must have at least one input"
    );
    assert_eq!(
        reveal_tx.input[0].previous_output.txid, commit_txid,
        "reveal tx must spend the commit tx output"
    );

    let commit_feerate = calculate_feerate_sat_per_kvb(&tx_sender, &commit_tx).await;
    let reveal_feerate = calculate_feerate_sat_per_kvb(&tx_sender, &reveal_tx).await;
    let target_feerate = tx_sender.get_fee_rate().await.unwrap().to_sat_per_kvb();
    let max_feerate = target_feerate.saturating_mul(101).saturating_div(100);
    assert!(
        commit_feerate >= target_feerate && commit_feerate <= max_feerate,
        "expected commit feerate between {target_feerate} and {max_feerate} sat/kvB, got {commit_feerate}"
    );
    assert!(
        reveal_feerate >= target_feerate && reveal_feerate <= max_feerate,
        "expected reveal feerate between {target_feerate} and {max_feerate} sat/kvB, got {reveal_feerate}"
    );

    rpc_env.rpc().mine_blocks(1).await.unwrap();
    let confirmations = rpc_env
        .rpc()
        .confirmation_blocks(&commit_txid)
        .await
        .unwrap();
    assert!(
        confirmations >= 1,
        "expected commit tx to be confirmed, got {confirmations} confirmations"
    );

    let reveal_confirmations = rpc_env
        .rpc()
        .confirmation_blocks(&reveal_txid)
        .await
        .unwrap();
    assert!(
        reveal_confirmations >= 1,
        "expected reveal tx to be confirmed, got {reveal_confirmations} confirmations"
    );
}

#[tokio::test]
async fn citrea_reveal_rbf_bumpfee_increases_feerate_and_mines() {
    let (mut config, _db, rpc_env) = create_test_environment(true, true).await;
    let rpc_env = rpc_env.expect("RPC environment must be created");

    // make min_bump higher than 1 sat/vb for this test so that if btc node used is <v30 (min 1 sat/vb increment by default), it doesn't fail
    config.limits.min_bump_kvb = 1234;

    let tx_sender = TxSender::new(config).await.unwrap();

    // Single Complete row to exercise RBFWtxidGrind reveal path.
    let insertion_id = insert_single_citrea_row(&tx_sender, TransactionKind::Complete).await;

    // First run_once: creates commit + reveal entry and initial RBF tx.
    let mut task = TxSenderTaskInternal::new(tx_sender.clone());
    task.run_once().await.unwrap();

    // Fetch commit and try_to_send_id for the reveal.
    let (commit_txid, try_to_send_ids) =
        get_citrea_commit_and_try_to_send_ids(&tx_sender, insertion_id).await;
    let try_to_send_id = *try_to_send_ids
        .first()
        .expect("at least one try_to_send_id should be set");

    // Original RBF txid and its feerate.
    let original_txid = tx_sender
        .db
        .get_last_rbf_txid(None, try_to_send_id)
        .await
        .unwrap()
        .expect("initial RBF txid should exist");
    let commit_tx = tx_sender.rpc.get_tx_of_txid(&commit_txid).await.unwrap();
    let original_tx = tx_sender.rpc.get_tx_of_txid(&original_txid).await.unwrap();
    let original_feerate = calculate_feerate_sat_per_kvb(&tx_sender, &original_tx).await;
    let target_feerate_before_bump = tx_sender.get_fee_rate().await.unwrap().to_sat_per_kvb();
    let max_feerate_before_bump = target_feerate_before_bump
        .saturating_mul(101)
        .saturating_div(100);
    assert!(
        original_feerate >= target_feerate_before_bump
            && original_feerate <= max_feerate_before_bump,
        "expected original feerate between {target_feerate_before_bump} and {max_feerate_before_bump} sat/kvB before bump, got {original_feerate}"
    );

    let current_tip = tx_sender.rpc.get_current_chain_height().await.unwrap();

    // First bump attempt: set target below previous + min_bump_kvb; expect no bump.
    let min_bump_kvb = tx_sender.tx_sender_limits.min_bump_kvb;
    let lower_target = FeeRateKvb::from_sat_per_kvb(
        original_feerate
            .saturating_add(min_bump_kvb)
            .saturating_sub(11),
    );

    tx_sender
        .try_to_send_unconfirmed_txs(lower_target, current_tip, false)
        .await
        .unwrap();

    let not_bumped_txid = tx_sender
        .db
        .get_last_rbf_txid(None, try_to_send_id)
        .await
        .unwrap()
        .expect("RBF txid should still exist");
    assert_eq!(
        not_bumped_txid, original_txid,
        "expected no bump when below previous + min_bump_kvb"
    );

    // Second bump attempt: set target above previous + min_bump_kvb; expect a bump.
    let higher_feerate = FeeRateKvb::from_sat_per_kvb(
        original_feerate
            .saturating_add(min_bump_kvb)
            .saturating_add(11),
    );

    tx_sender
        .try_to_send_unconfirmed_txs(higher_feerate, current_tip, false)
        .await
        .unwrap();

    let bumped_txid = tx_sender
        .db
        .get_last_rbf_txid(None, try_to_send_id)
        .await
        .unwrap()
        .expect("bumped RBF txid should exist");
    assert_ne!(bumped_txid, original_txid, "expected a new RBF txid");

    let bumped_tx = tx_sender.rpc.get_tx_of_txid(&bumped_txid).await.unwrap();
    // bump should also take into account the commit transaction, so we calculate effective feerate of the package (commit+reveal)
    let bumped_feerate =
        calculate_package_feerate_sat_per_kvb(&tx_sender, &commit_tx, &bumped_tx).await;

    assert!(
        bumped_feerate > original_feerate,
        "expected bumped feerate ({bumped_feerate}) to be greater than original ({original_feerate})"
    );
    let target_feerate = higher_feerate.to_sat_per_kvb();
    let max_feerate = target_feerate.saturating_mul(101).saturating_div(100);
    assert!(
        bumped_feerate <= max_feerate && bumped_feerate >= target_feerate,
        "expected bumped package feerate (commit+reveal) <= {max_feerate} sat/kvB (1% above target {target_feerate}), got {bumped_feerate}"
    );

    // Mine a block and ensure bumped tx is confirmed.
    rpc_env.rpc().mine_blocks(1).await.unwrap();
    let confirmations = rpc_env
        .rpc()
        .confirmation_blocks(&bumped_txid)
        .await
        .unwrap();
    assert!(
        confirmations >= 1,
        "expected bumped tx to be confirmed, got {confirmations} confirmations"
    );
}

#[tokio::test]
async fn citrea_large_body_tx_flow_commits_and_mines_with_min_feerate() {
    let (config, _db, rpc_env) = create_test_environment(true, true).await;
    let rpc_env = rpc_env.expect("RPC environment must be created");

    let tx_sender = TxSender::new(config).await.unwrap();

    // Insert a Citrea row with a large body (~390k bytes).
    let insertion_id =
        insert_single_citrea_row_with_body_size(&tx_sender, TransactionKind::Complete, 390_000)
            .await;

    // Run a single txsender iteration to create commit + reveal.
    let mut task = TxSenderTaskInternal::new(tx_sender.clone());
    task.run_once().await.unwrap();

    let (commit_txid, try_to_send_ids) =
        get_citrea_commit_and_try_to_send_ids(&tx_sender, insertion_id).await;
    let try_to_send_id = *try_to_send_ids
        .first()
        .expect("at least one reveal try_to_send_id must be set");

    // Reveal RBF tx should be registered and spend the commit output.
    let reveal_txid = tx_sender
        .db
        .get_last_rbf_txid(None, try_to_send_id)
        .await
        .unwrap()
        .expect("reveal RBF txid must exist");

    let commit_tx = tx_sender.rpc.get_tx_of_txid(&commit_txid).await.unwrap();
    let reveal_tx = tx_sender.rpc.get_tx_of_txid(&reveal_txid).await.unwrap();

    assert!(
        !reveal_tx.input.is_empty(),
        "reveal tx must have at least one input"
    );
    assert_eq!(
        reveal_tx.input[0].previous_output.txid, commit_txid,
        "reveal tx must spend the commit tx output"
    );

    // Fee calculation should still be sane for large bodies.
    let commit_feerate = calculate_feerate_sat_per_kvb(&tx_sender, &commit_tx).await;
    let reveal_feerate = calculate_feerate_sat_per_kvb(&tx_sender, &reveal_tx).await;
    let target_feerate = tx_sender.get_fee_rate().await.unwrap().to_sat_per_kvb();
    let max_feerate = target_feerate.saturating_mul(101).saturating_div(100);
    assert!(
        commit_feerate >= target_feerate && commit_feerate <= max_feerate,
        "expected commit feerate between {target_feerate} and {max_feerate} sat/kvB for large-body commit tx, got {commit_feerate}"
    );
    assert!(
        reveal_feerate >= target_feerate && reveal_feerate <= max_feerate,
        "expected reveal feerate between {target_feerate} and {max_feerate} sat/kvB for large-body reveal tx, got {reveal_feerate}"
    );

    tracing::info!(
        "reveal feerate: {reveal_feerate}, reveal tx weight: {}, commit feerate: {commit_feerate}, commit tx weight: {}",
        reveal_tx.weight(),
        commit_tx.weight()
    );

    // Mine a block and ensure both commit and reveal txs are confirmed.
    rpc_env.rpc().mine_blocks(1).await.unwrap();
    let confirmations = rpc_env
        .rpc()
        .confirmation_blocks(&commit_txid)
        .await
        .unwrap();
    assert!(
        confirmations >= 1,
        "expected commit tx to be confirmed, got {confirmations} confirmations"
    );

    let reveal_confirmations = rpc_env
        .rpc()
        .confirmation_blocks(&reveal_txid)
        .await
        .unwrap();
    assert!(
        reveal_confirmations >= 1,
        "expected reveal tx to be confirmed, got {reveal_confirmations} confirmations"
    );
}
