#![cfg(all(feature = "citrea", feature = "testing"))]

use bitcoin::{FeeRate, Txid};
use rand::RngCore;

use crate::citrea::{RawTxData, TransactionKind};
use crate::task::TxSenderTaskInternal;
use crate::test_utils::create_test_environment;
use crate::TxSender;

/// Helper to insert a single Citrea raw tx row for the given transaction kind
/// using `TxSenderClient::send_citrea_tx`, and return its `insertion_id`.
async fn insert_single_citrea_row(tx_sender: &TxSender, kind: TransactionKind) -> i64 {
    use crate::client::TxSenderClient;
    use sqlx::Row;

    let mut body = vec![0u8; 32];
    rand::thread_rng().fill_bytes(&mut body);

    let raw = match kind {
        TransactionKind::Complete => RawTxData::BatchProof(body.clone()),
        TransactionKind::BatchProofMethodId => RawTxData::BatchProofMethodId(body.clone()),
        TransactionKind::SequencerCommitment => RawTxData::SequencerCommitment(body.clone()),
        other => panic!("unsupported TransactionKind for single row helper: {other:?}",),
    };

    let client = TxSenderClient::new(tx_sender.db.clone());
    client.send_citrea_tx(raw).await.unwrap();

    // Look up the row we just inserted to get its insertion_id.
    let row = sqlx::query(
        "SELECT insertion_id \
         FROM tx_sender_citrea_raw_tx_queue \
         WHERE body = $1 \
         ORDER BY id DESC \
         LIMIT 1",
    )
    .bind(&body)
    .fetch_one(tx_sender.db.pool())
    .await
    .unwrap();

    row.get("insertion_id")
}

/// Helper to insert a chunked Citrea raw tx group.
async fn insert_chunked_citrea_rows(tx_sender: &TxSender) -> i64 {
    use crate::client::TxSenderClient;
    use sqlx::Row;

    let mut chunks = Vec::new();
    for _ in 0..3 {
        let mut body = vec![0u8; 64];
        rand::thread_rng().fill_bytes(&mut body);
        chunks.push(body);
    }

    let client = TxSenderClient::new(tx_sender.db.clone());
    client
        .send_citrea_tx(RawTxData::Chunks(chunks.clone()))
        .await
        .unwrap();

    // All chunk rows in the group share the same insertion_id; get it from one of them.
    let row = sqlx::query(
        "SELECT insertion_id \
         FROM tx_sender_citrea_raw_tx_queue \
         WHERE body = $1 \
         ORDER BY id ASC \
         LIMIT 1",
    )
    .bind(&chunks[0])
    .fetch_one(tx_sender.db.pool())
    .await
    .unwrap();

    row.get("insertion_id")
}

/// Returns the commit txid and optional try_to_send_id for the given insertion_id.
async fn get_citrea_commit_and_try_to_send_id(
    tx_sender: &TxSender,
    insertion_id: i64,
) -> (Txid, Option<u32>) {
    use crate::db::wrapper::OutPointDB;
    use sqlx::Row;

    let row = sqlx::query(
        "SELECT commit_outpoint, try_to_send_id \
         FROM tx_sender_citrea_raw_tx_queue \
         WHERE insertion_id = $1 AND body IS NOT NULL \
         ORDER BY id ASC \
         LIMIT 1",
    )
    .bind(insertion_id)
    .fetch_one(tx_sender.db.pool())
    .await
    .unwrap();

    let commit_outpoint: Option<OutPointDB> = row.get("commit_outpoint");
    let commit_outpoint = commit_outpoint.expect("commit_outpoint should be set").0;
    let try_to_send_id: Option<i32> = row.get("try_to_send_id");

    (
        commit_outpoint.txid,
        try_to_send_id.map(|v| u32::try_from(v).unwrap()),
    )
}

/// Calculates the fee rate of a transaction in sat/vB.
async fn calculate_feerate_sat_per_vb(tx_sender: &TxSender, tx: &bitcoin::Transaction) -> u64 {
    use bitcoin::Weight;

    let fee = tx_sender.get_tx_fee(tx).await.unwrap();
    let weight: Weight = tx.weight();
    let vbytes = weight.to_vbytes_ceil();

    // fee_rate_sat_per_vb = fee_sat * 1000 / (weight_wu) where weight_wu = vbytes * 4
    (fee.to_sat() * 1000) / (vbytes * 4)
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

    // After run_once, commit tx and reveal try_to_send_id must exist.
    let (commit_txid, maybe_try_to_send_id) =
        get_citrea_commit_and_try_to_send_id(&tx_sender, insertion_id).await;
    let try_to_send_id = maybe_try_to_send_id.expect("reveal try_to_send_id must be set");

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

    let feerate = calculate_feerate_sat_per_vb(&tx_sender, &commit_tx).await;
    // On regtest we expect at least 1 sat/vB by default.
    assert!(feerate >= 1, "expected feerate >= 1 sat/vB, got {feerate}");

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

    let (commit_txid, maybe_try_to_send_id) =
        get_citrea_commit_and_try_to_send_id(&tx_sender, insertion_id).await;
    let try_to_send_id = maybe_try_to_send_id.expect("reveal try_to_send_id must be set");

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

    let feerate = calculate_feerate_sat_per_vb(&tx_sender, &commit_tx).await;
    assert!(feerate >= 1, "expected feerate >= 1 sat/vB, got {feerate}");

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
async fn citrea_batch_proof_method_id_tx_flow_commits_and_mines_with_min_feerate() {
    let (config, _db, rpc_env) = create_test_environment(true, true).await;
    let rpc_env = rpc_env.expect("RPC environment must be created");

    let tx_sender = TxSender::new(config).await.unwrap();

    let insertion_id =
        insert_single_citrea_row(&tx_sender, TransactionKind::BatchProofMethodId).await;

    let mut task = TxSenderTaskInternal::new(tx_sender.clone());
    task.run_once().await.unwrap();

    let (commit_txid, maybe_try_to_send_id) =
        get_citrea_commit_and_try_to_send_id(&tx_sender, insertion_id).await;
    let try_to_send_id = maybe_try_to_send_id.expect("reveal try_to_send_id must be set");

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

    let feerate = calculate_feerate_sat_per_vb(&tx_sender, &commit_tx).await;
    assert!(feerate >= 1, "expected feerate >= 1 sat/vB, got {feerate}");

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

    let (commit_txid, maybe_try_to_send_id) =
        get_citrea_commit_and_try_to_send_id(&tx_sender, insertion_id).await;
    let try_to_send_id = maybe_try_to_send_id.expect("reveal try_to_send_id must be set");

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

    let feerate = calculate_feerate_sat_per_vb(&tx_sender, &commit_tx).await;
    assert!(feerate >= 1, "expected feerate >= 1 sat/vB, got {feerate}");

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
    use clementine_utils::FeePayingType;

    let (config, _db, rpc_env) = create_test_environment(true, true).await;
    let rpc_env = rpc_env.expect("RPC environment must be created");

    let tx_sender = TxSender::new(config).await.unwrap();

    // Single Complete row to exercise RBFWtxidGrind reveal path.
    let insertion_id = insert_single_citrea_row(&tx_sender, TransactionKind::Complete).await;

    // First run_once: creates commit + reveal entry and initial RBF tx.
    let mut task = TxSenderTaskInternal::new(tx_sender.clone());
    task.run_once().await.unwrap();

    // Fetch commit and try_to_send_id for the reveal.
    let (_commit_txid, maybe_try_to_send_id) =
        get_citrea_commit_and_try_to_send_id(&tx_sender, insertion_id).await;
    let try_to_send_id = maybe_try_to_send_id.expect("try_to_send_id should be set");

    // Original RBF txid and its feerate.
    let original_txid = tx_sender
        .db
        .get_last_rbf_txid(None, try_to_send_id)
        .await
        .unwrap()
        .expect("initial RBF txid should exist");
    let original_tx = tx_sender.rpc.get_tx_of_txid(&original_txid).await.unwrap();
    let original_feerate = calculate_feerate_sat_per_vb(&tx_sender, &original_tx).await;

    // Load try_to_send row details to call send_rbf_tx manually with higher feerate.
    let (tx_metadata, tx, fee_paying_type, _seen_at_height, rbf_signing_info) = tx_sender
        .db
        .get_try_to_send_tx(None, try_to_send_id)
        .await
        .unwrap();
    assert!(matches!(
        fee_paying_type,
        FeePayingType::RbfWtxidGrind | FeePayingType::RBF
    ));

    let current_tip = tx_sender.rpc.get_current_chain_height().await.unwrap();

    // Bump fee: choose a clearly higher target feerate.
    let higher_feerate =
        FeeRate::from_sat_per_vb((original_feerate + 5).max(2)).expect("valid fee rate");

    tx_sender
        .send_rbf_tx(
            try_to_send_id,
            tx,
            tx_metadata,
            higher_feerate,
            rbf_signing_info.as_ref().cloned(),
            current_tip,
            matches!(fee_paying_type, FeePayingType::RbfWtxidGrind),
        )
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
    let bumped_feerate = calculate_feerate_sat_per_vb(&tx_sender, &bumped_tx).await;

    assert!(
        bumped_feerate > original_feerate,
        "expected bumped feerate ({bumped_feerate}) to be greater than original ({original_feerate})"
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
