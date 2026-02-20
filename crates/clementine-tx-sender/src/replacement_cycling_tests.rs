use std::time::Duration;

use bitcoin::absolute::LockTime;
use bitcoin::sighash::{Prevouts, SighashCache};
use bitcoin::taproot;
use bitcoin::{Amount, OutPoint, ScriptBuf, TapSighashType, Transaction, TxIn, TxOut, Txid};
use bitcoincore_rpc::json::SignRawTransactionInput;
use bitcoincore_rpc::{Auth, Client, RpcApi};
use clementine_extended_rpc::ExtendedBitcoinRpc;
use clementine_primitives::NON_STANDARD_V3;
use clementine_utils::sign::TapTweakData;
use clementine_utils::FeePayingType;
use secrecy::ExposeSecret;
use tempfile::TempDir;

use crate::task::TxSenderTaskInternal;
use crate::test_utils::{create_test_environment, get_available_port};
use crate::{TxSender, DEFAULT_SEQUENCE};

const P2A_ANCHOR_SCRIPT_HEX: &str = "51024e73";
const ATTACKER_WALLET_NAME: &str = "attacker";
const ATTACK_ROUNDS: usize = 4;
const ATTACKER_INPUT_AMOUNT_SAT: u64 = 300_000;
const ATTACK_CHILD_FEE_SAT: u64 = 20_000;
const ATTACK_EVICT_FEE_SAT: u64 = 30_000;
const RELAY_WAIT_TRIES: usize = 300;

struct PeerNode {
    process: Option<std::process::Child>,
    rpc: ExtendedBitcoinRpc,
    p2p_port: u16,
    _data_dir: TempDir,
}

impl Drop for PeerNode {
    fn drop(&mut self) {
        if let Some(mut process) = self.process.take() {
            let _ = process.kill();
            let _ = process.wait();
        }
    }
}

fn p2a_anchor_txout() -> TxOut {
    TxOut {
        value: Amount::ZERO,
        script_pubkey: ScriptBuf::from_hex(P2A_ANCHOR_SCRIPT_HEX).expect("valid anchor script"),
    }
}

async fn tx_is_in_mempool(rpc: &clementine_extended_rpc::ExtendedBitcoinRpc, txid: Txid) -> bool {
    rpc.get_raw_mempool()
        .await
        .expect("getrawmempool must work")
        .contains(&txid)
}

async fn find_child_spending_anchor(
    rpc: &clementine_extended_rpc::ExtendedBitcoinRpc,
    parent_txid: Txid,
    anchor_vout: u32,
) -> Option<Txid> {
    let txids = rpc
        .get_raw_mempool()
        .await
        .expect("getrawmempool must work");
    for txid in txids {
        if txid == parent_txid {
            continue;
        }

        let tx = rpc
            .get_raw_transaction(&txid, None)
            .await
            .expect("getrawtransaction must work");
        if tx.input.iter().any(|input| {
            input.previous_output.txid == parent_txid && input.previous_output.vout == anchor_vout
        }) {
            return Some(txid);
        }
    }
    None
}

async fn get_child_spending_anchor(
    rpc: &clementine_extended_rpc::ExtendedBitcoinRpc,
    parent_txid: Txid,
    anchor_vout: u32,
) -> Option<Transaction> {
    let child_txid = find_child_spending_anchor(rpc, parent_txid, anchor_vout).await?;
    Some(
        rpc.get_raw_transaction(&child_txid, None)
            .await
            .expect("getrawtransaction must work"),
    )
}

async fn wait_until_peer_has_txs(
    rpc: &ExtendedBitcoinRpc,
    txids: &[Txid],
    tries: usize,
) -> std::result::Result<(), String> {
    for _ in 0..tries {
        let mempool = rpc
            .get_raw_mempool()
            .await
            .expect("peer getrawmempool must work");
        if txids.iter().all(|txid| mempool.contains(txid)) {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let mempool = rpc
        .get_raw_mempool()
        .await
        .expect("peer getrawmempool must work");
    let missing: Vec<Txid> = txids
        .iter()
        .copied()
        .filter(|txid| !mempool.contains(txid))
        .collect();
    Err(format!(
        "missing txids in peer mempool after {tries} tries: {missing:?}"
    ))
}

async fn wait_for_peering(a: &ExtendedBitcoinRpc, b: &ExtendedBitcoinRpc, tries: usize) {
    for _ in 0..tries {
        let a_has_peer = a
            .get_peer_info()
            .await
            .map(|peers| !peers.is_empty())
            .unwrap_or(false);
        let b_has_peer = b
            .get_peer_info()
            .await
            .map(|peers| !peers.is_empty())
            .unwrap_or(false);
        if a_has_peer && b_has_peer {
            return;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    panic!("nodes did not become peers in time");
}

async fn wait_for_peer_chain_sync(
    primary: &ExtendedBitcoinRpc,
    peer: &ExtendedBitcoinRpc,
    tries: usize,
) -> bool {
    for _ in 0..tries {
        let primary_info = primary
            .get_blockchain_info()
            .await
            .expect("primary getblockchaininfo must work");
        let peer_info = peer
            .get_blockchain_info()
            .await
            .expect("peer getblockchaininfo must work");
        if !peer_info.initial_block_download && peer_info.blocks >= primary_info.blocks {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    false
}

async fn spawn_peer_node(
    rpc_user: secrecy::SecretString,
    rpc_password: secrecy::SecretString,
) -> PeerNode {
    let data_dir = TempDir::new().expect("peer bitcoind tempdir must be created");
    let p2p_port = get_available_port();
    let rpc_port = get_available_port();

    let args = vec![
        "-regtest".to_string(),
        format!("-datadir={}", data_dir.path().display()),
        "-listen=1".to_string(),
        format!("-port={p2p_port}"),
        format!("-rpcport={rpc_port}"),
        format!("-rpcuser={}", rpc_user.expose_secret()),
        format!("-rpcpassword={}", rpc_password.expose_secret()),
        "-txindex=1".to_string(),
        "-whitelist=noban@127.0.0.1".to_string(),
        "-fallbackfee=0.00001".to_string(),
        "-rpcallowip=0.0.0.0/0".to_string(),
    ];

    let process = std::process::Command::new("bitcoind")
        .args(&args)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("peer bitcoind should start");

    let rpc_url = format!("http://127.0.0.1:{rpc_port}");
    let mut attempts = 0usize;
    let rpc = loop {
        match ExtendedBitcoinRpc::connect(
            rpc_url.clone(),
            rpc_user.clone(),
            rpc_password.clone(),
            None,
        )
        .await
        {
            Ok(rpc) => break rpc,
            Err(_) => {
                attempts += 1;
                assert!(attempts < 30, "peer bitcoind rpc failed to start");
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        }
    };

    PeerNode {
        process: Some(process),
        rpc,
        p2p_port,
        _data_dir: data_dir,
    }
}

fn build_zero_fee_parent_tx(
    tx_sender: &TxSender,
    funding_outpoint: OutPoint,
    funding_txout: TxOut,
) -> Transaction {
    let anchor = p2a_anchor_txout();
    let change_value = funding_txout
        .value
        .checked_sub(anchor.value)
        .expect("funding amount must cover anchor");

    let mut parent_tx = Transaction {
        version: NON_STANDARD_V3,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: funding_outpoint,
            script_sig: ScriptBuf::new(),
            sequence: DEFAULT_SEQUENCE,
            witness: bitcoin::Witness::new(),
        }],
        output: vec![
            TxOut {
                value: change_value,
                script_pubkey: tx_sender.address().script_pubkey(),
            },
            anchor,
        ],
    };

    let prevouts = vec![funding_txout];
    let sighash = SighashCache::new(&parent_tx)
        .taproot_key_spend_signature_hash(0, &Prevouts::All(&prevouts), TapSighashType::Default)
        .expect("parent sighash must be computed");
    let sig = tx_sender
        .signer
        .sign_with_tweak_data(sighash, TapTweakData::KeyPath(None))
        .expect("parent input must be signable");
    let tr_sig = taproot::Signature {
        signature: sig,
        sighash_type: TapSighashType::Default,
    };
    parent_tx.input[0].witness = bitcoin::Witness::p2tr_key_spend(&tr_sig);

    parent_tx
}

async fn build_and_sign_attacker_anchor_child(
    attacker_rpc: &Client,
    parent_txid: Txid,
    anchor_vout: u32,
    anchor_txout: &TxOut,
    attacker_input: OutPoint,
    fee_sat: u64,
) -> Transaction {
    let attacker_change_address = attacker_rpc
        .get_new_address(None, None)
        .await
        .expect("attacker change address must be generated")
        .assume_checked();

    let total_in = anchor_txout.value + Amount::from_sat(ATTACKER_INPUT_AMOUNT_SAT);
    let output_value = total_in
        .checked_sub(Amount::from_sat(fee_sat))
        .expect("attack child fee must be covered by inputs");

    let child_tx = Transaction {
        version: NON_STANDARD_V3,
        lock_time: LockTime::ZERO,
        input: vec![
            TxIn {
                previous_output: OutPoint {
                    txid: parent_txid,
                    vout: anchor_vout,
                },
                script_sig: ScriptBuf::new(),
                sequence: DEFAULT_SEQUENCE,
                witness: bitcoin::Witness::new(),
            },
            TxIn {
                previous_output: attacker_input,
                script_sig: ScriptBuf::new(),
                sequence: DEFAULT_SEQUENCE,
                witness: bitcoin::Witness::new(),
            },
        ],
        output: vec![TxOut {
            value: output_value,
            script_pubkey: attacker_change_address.script_pubkey(),
        }],
    };

    let anchor_prevout = SignRawTransactionInput {
        txid: parent_txid,
        vout: anchor_vout,
        script_pub_key: anchor_txout.script_pubkey.clone(),
        redeem_script: None,
        amount: Some(anchor_txout.value),
    };

    attacker_rpc
        .sign_raw_transaction_with_wallet(&child_tx, Some(&[anchor_prevout]), None)
        .await
        .expect("attacker child signing must succeed")
        .transaction()
        .expect("attacker child must deserialize")
}

async fn build_and_sign_attacker_anchorless_replacement(
    attacker_rpc: &Client,
    attacker_input: OutPoint,
    fee_sat: u64,
) -> Transaction {
    let attacker_change_address = attacker_rpc
        .get_new_address(None, None)
        .await
        .expect("attacker change address must be generated")
        .assume_checked();

    let output_value = Amount::from_sat(ATTACKER_INPUT_AMOUNT_SAT)
        .checked_sub(Amount::from_sat(fee_sat))
        .expect("replacement fee must be covered by input");

    let tx = Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: attacker_input,
            script_sig: ScriptBuf::new(),
            sequence: DEFAULT_SEQUENCE,
            witness: bitcoin::Witness::new(),
        }],
        output: vec![TxOut {
            value: output_value,
            script_pubkey: attacker_change_address.script_pubkey(),
        }],
    };

    attacker_rpc
        .sign_raw_transaction_with_wallet(&tx, None, None)
        .await
        .expect("attacker replacement signing must succeed")
        .transaction()
        .expect("attacker replacement must deserialize")
}

async fn enqueue_parent_and_wait_for_package(
    tx_sender: &TxSender,
    task: &mut TxSenderTaskInternal,
) -> (Txid, u32, TxOut) {
    let parent_funding_outpoint = tx_sender
        .rpc
        .send_to_address(tx_sender.address(), Amount::from_sat(400_000))
        .await
        .expect("parent funding tx should be sent");
    tx_sender
        .rpc
        .mine_blocks(1)
        .await
        .expect("parent funding tx should confirm");

    let parent_funding_txout = tx_sender
        .rpc
        .get_txout_from_outpoint(&parent_funding_outpoint)
        .await
        .expect("parent funding txout should be available");

    let parent_tx =
        build_zero_fee_parent_tx(tx_sender, parent_funding_outpoint, parent_funding_txout);
    let parent_txid = parent_tx.compute_txid();
    let anchor_vout = tx_sender.find_p2a_vout(&parent_tx).unwrap() as u32;
    let anchor_txout = parent_tx.output[anchor_vout as usize].clone();

    let mut dbtx = tx_sender.db.begin_transaction().await.unwrap();
    tx_sender
        .client()
        .insert_try_to_send(&mut dbtx, None, &parent_tx, FeePayingType::CPFP, None, &[])
        .await
        .unwrap();
    tx_sender.db.commit_transaction(dbtx).await.unwrap();

    let mut parent_and_child_live = false;
    for _ in 0..12 {
        task.run_once().await.unwrap();
        if tx_is_in_mempool(&tx_sender.rpc, parent_txid).await
            && find_child_spending_anchor(&tx_sender.rpc, parent_txid, anchor_vout)
                .await
                .is_some()
        {
            parent_and_child_live = true;
            break;
        }
        tx_sender.rpc.mine_blocks(1).await.unwrap();
    }
    assert!(
        parent_and_child_live,
        "failed to bootstrap parent+child package in mempool"
    );

    (parent_txid, anchor_vout, anchor_txout)
}

#[tokio::test]
async fn cpfp_replacement_cycling_rebroadcasts_parent_after_periodic_mining() {
    let (mut config, _db, rpc_env) = create_test_environment(true, true).await;
    let rpc_env = rpc_env.expect("RPC environment must be created");

    let base_rpc_url = config.bitcoin_rpc.url.clone();
    config.bitcoin_rpc.url = format!("{}/wallet/admin", base_rpc_url.trim_end_matches('/'));
    let rpc_user = config.bitcoin_rpc.user.clone();
    let rpc_password = config.bitcoin_rpc.password.clone();

    let tx_sender = TxSender::new(config).await.unwrap();
    tx_sender.db.run_migrations().await.unwrap();
    let mut task = TxSenderTaskInternal::new(tx_sender.clone());
    let peer_node = spawn_peer_node(rpc_user.clone(), rpc_password.clone()).await;
    tx_sender
        .rpc
        .add_node(&format!("127.0.0.1:{}", peer_node.p2p_port))
        .await
        .expect("primary node should add peer node");
    wait_for_peering(&tx_sender.rpc, &peer_node.rpc, 30).await;
    let _ = wait_for_peer_chain_sync(&tx_sender.rpc, &peer_node.rpc, 300).await;

    rpc_env
        .rpc()
        .create_wallet(ATTACKER_WALLET_NAME, None, None, None, None)
        .await
        .expect("attacker wallet should be created");
    let attacker_wallet_url = format!(
        "{}/wallet/{}",
        base_rpc_url.trim_end_matches('/'),
        ATTACKER_WALLET_NAME
    );
    let attacker_rpc = Client::new(
        &attacker_wallet_url,
        Auth::UserPass(
            rpc_user.expose_secret().to_string(),
            rpc_password.expose_secret().to_string(),
        ),
    )
    .await
    .expect("attacker rpc client must connect");

    let attacker_funding_address = attacker_rpc
        .get_new_address(None, None)
        .await
        .expect("attacker funding address must be generated")
        .assume_checked();
    let mut attacker_inputs = Vec::with_capacity(ATTACK_ROUNDS);
    for _ in 0..ATTACK_ROUNDS {
        let outpoint = tx_sender
            .rpc
            .send_to_address(
                &attacker_funding_address,
                Amount::from_sat(ATTACKER_INPUT_AMOUNT_SAT),
            )
            .await
            .expect("attacker funding tx should be sent");
        attacker_inputs.push(outpoint);
    }
    tx_sender
        .rpc
        .mine_blocks(1)
        .await
        .expect("attacker funding txs should confirm");

    let (parent_txid, anchor_vout, anchor_txout) =
        enqueue_parent_and_wait_for_package(&tx_sender, &mut task).await;
    let initial_child = get_child_spending_anchor(&tx_sender.rpc, parent_txid, anchor_vout)
        .await
        .expect("initial txsender child must exist");
    let initial_child_txid = initial_child.compute_txid();
    let mut previous_child_txid = initial_child_txid;
    let mut previous_child_wtxid = initial_child.compute_wtxid();
    wait_until_peer_has_txs(
        &peer_node.rpc,
        &[parent_txid, initial_child_txid],
        RELAY_WAIT_TRIES,
    )
    .await
    .unwrap_or_else(|err| panic!("initial parent+child package was not relayed to peer: {err}"));

    let mut rounds_with_parent_inclusion = 0usize;
    for (round, attacker_input) in attacker_inputs.into_iter().enumerate() {
        let txsender_child_txid =
            find_child_spending_anchor(&tx_sender.rpc, parent_txid, anchor_vout)
                .await
                .expect("txsender child should spend parent anchor before attack");

        let attacker_child = build_and_sign_attacker_anchor_child(
            &attacker_rpc,
            parent_txid,
            anchor_vout,
            &anchor_txout,
            attacker_input,
            ATTACK_CHILD_FEE_SAT,
        )
        .await;
        tx_sender
            .rpc
            .send_raw_transaction(&attacker_child)
            .await
            .expect("attacker anchor child should replace txsender child");
        let attacker_child_txid = attacker_child.compute_txid();

        wait_until_peer_has_txs(&peer_node.rpc, &[attacker_child_txid], RELAY_WAIT_TRIES)
            .await
            .unwrap_or_else(|err| {
                panic!("round {round}: attacker child was not relayed to peer: {err}")
            });

        assert!(
            !tx_is_in_mempool(&tx_sender.rpc, txsender_child_txid).await,
            "round {round}: expected txsender child to be replaced by attacker child",
        );
        assert!(
            !tx_is_in_mempool(&peer_node.rpc, txsender_child_txid).await,
            "round {round}: expected peer mempool to evict txsender child after attacker child relay",
        );

        let attacker_anchorless = build_and_sign_attacker_anchorless_replacement(
            &attacker_rpc,
            attacker_input,
            ATTACK_EVICT_FEE_SAT,
        )
        .await;
        let attacker_anchorless_txid = attacker_anchorless.compute_txid();
        tx_sender
            .rpc
            .send_raw_transaction(&attacker_anchorless)
            .await
            .expect("attacker anchorless replacement should be accepted");

        assert!(
            !tx_is_in_mempool(&tx_sender.rpc, attacker_child_txid).await,
            "round {round}: expected attacker anchor child to be replaced by anchorless tx",
        );

        wait_until_peer_has_txs(
            &peer_node.rpc,
            &[attacker_anchorless_txid],
            RELAY_WAIT_TRIES,
        )
        .await
        .unwrap_or_else(|err| {
            panic!("round {round}: attacker anchorless replacement was not relayed to peer: {err}")
        });

        tx_sender
            .rpc
            .mine_blocks(1)
            .await
            .expect("block mining should succeed");
        let _ = wait_for_peer_chain_sync(&tx_sender.rpc, &peer_node.rpc, 120).await;

        let mut reentered = false;
        for _ in 0..8 {
            task.run_once().await.unwrap();
            if tx_is_in_mempool(&tx_sender.rpc, parent_txid).await
                && find_child_spending_anchor(&tx_sender.rpc, parent_txid, anchor_vout)
                    .await
                    .is_some()
            {
                reentered = true;
                break;
            }
        }

        assert!(
            reentered,
            "round {round}: expected parent+child package to re-enter mempool after mining",
        );

        let reentered_child = get_child_spending_anchor(&tx_sender.rpc, parent_txid, anchor_vout)
            .await
            .expect("reentered txsender child must exist");
        let reentered_child_txid = reentered_child.compute_txid();
        let reentered_child_wtxid = reentered_child.compute_wtxid();

        assert_eq!(
            reentered_child_txid, previous_child_txid,
            "round {round}: expected reentered child to keep the same txid",
        );
        assert_ne!(
            reentered_child_wtxid, previous_child_wtxid,
            "round {round}: expected reentered child to have a different wtxid",
        );
        previous_child_txid = reentered_child_txid;
        previous_child_wtxid = reentered_child_wtxid;

        wait_until_peer_has_txs(
            &peer_node.rpc,
            &[parent_txid, reentered_child_txid],
            RELAY_WAIT_TRIES,
        )
        .await
        .unwrap_or_else(|err| {
            panic!("round {round}: reentered parent+child was not relayed to peer: {err}")
        });

        let peer_child = peer_node
            .rpc
            .get_raw_transaction(&reentered_child_txid, None)
            .await
            .expect("peer should return relayed child tx");
        assert_eq!(
            peer_child.compute_wtxid(),
            reentered_child_wtxid,
            "round {round}: peer child wtxid should match primary reentered child",
        );

        rounds_with_parent_inclusion += 1;
    }

    assert_eq!(
        rounds_with_parent_inclusion, ATTACK_ROUNDS,
        "expected parent inclusion (mempool or confirmed) in each replacement-cycling round"
    );
}
