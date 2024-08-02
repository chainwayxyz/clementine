//! # Demo BitVM challenge part tests
//! This tests check if the BitVM challenge part works as expected.
//! The BitVM challenge is a challenge where the operator must make a series of commitments
//! in a given time frame. If the operator fails to make the commitments, the verifier can
//! burn the funds. The operator must make the commitments in a given time frame, and the
//! last commitment must go to a checking conditions address that the verifier can spend from
//! after the time frame is over.

use bitcoin::hashes::Hash;
use bitcoin::taproot::{LeafVersion, TaprootBuilder};
use bitcoin::{Address, Amount, OutPoint, ScriptBuf, Transaction, TxOut};
use bitcoincore_rpc::RawTx;
use clementine_core::actor::Actor;
use clementine_core::config::BridgeConfig;
use clementine_core::extended_rpc::ExtendedRpc;
use clementine_core::mock::common;
use clementine_core::transaction_builder::{TransactionBuilder, TxHandlers};
use clementine_core::utils::handle_taproot_pubkey_spend_witness;
use clementine_core::{
    create_extended_rpc, create_test_config, create_test_config_with_thread_name,
};
use clementine_core::database::common::Database;
use clementine_core::{script_builder, utils};
use secp256k1::schnorr::Signature;
use secp256k1::Message;
use std::{thread, vec};

pub type OperatorCommitsTxHandlers = TxHandlers;
pub type VerifierBurnsTxHandlers = TxHandlers;
pub type OperatorPresign = Signature;
pub type VerifierPresign = Signature;
pub type PresignPair = (VerifierPresign, OperatorPresign);
pub type VerifierBurnsPresignPair = PresignPair;
pub type OperatorCommitsPresignPair = PresignPair;
pub const NUM_COMMIT_TX: usize = 4;
pub const CHALLENGER_TAKES_AFTER: u32 = 5;

#[derive(Clone, Debug)]
pub struct BitVMSequence {
    // Transaction that starts the whole sequence. Uses a source_UTXO from the verifier (challenger),
    // and creates two new UTXOs, one is to the address where the operator must make the first commitment
    // and the other is to the address where the verifier (challenger) is able to spend from in 1008 blocks.
    // Therefore, operator must complete all commitment transactions in 1008 blocks time (approx. 1 week),
    // and the last transaction must go to the address with the checking conditions for the verifier.
    pub start_tx: Transaction,
    // Transaction tuples that contain the commitment transactions and the burning transactions for each
    // step of the sequence.
    // IDEA: Instead of making these transactions sequentially, why not just do them all at once in parallel?
    // QUESTION: How do we make sure that at one step the operator does not spend the on-chain UTXO to
    // somewhere else?
    pub tx_details_pair_vec: Vec<CommitOrBurnTxPairs>,
    // Signatures that the operator and the verifier (challenger) must provide for each verifier_burns
    // transaction. This allows verifier to burn at any of the steps should 1008 blocks pass without the
    // operator completing the commitments and sending the last transaction to the the checking conditions
    // address.
    pub sigs: Vec<(OperatorCommitsPresignPair, VerifierBurnsPresignPair)>,
}

#[derive(Clone, Debug)]
pub struct CommitOrBurnTxPairs {
    pub commit_tx_details: OperatorCommitsTxHandlers,
    pub burn_tx_details: VerifierBurnsTxHandlers,
}

#[tokio::test]
async fn test_bitvm_1() {
    let mut config = create_test_config_with_thread_name!("test_config_bitvm_1.toml");
    let rpc = create_extended_rpc!(config);

    // Create operator and verifier (challenger) entities.
    let verifier = Actor::new(
        config.all_secret_keys.clone().unwrap()[0],
        config.network,
    );
    let operator = Actor::new(config.secret_key, config.network);

    // Calculate the verifier_address.
    let verifier_taproot_address = Address::p2tr(
        &utils::SECP,
        config.verifiers_public_keys[0],
        None,
        config.network,
    );

    // Verifier puts his source_utxo on-chain. This UTXO is the starting point of the whole sequence.
    let verifier_source_utxo = rpc
        .send_to_address(&verifier_taproot_address, 20_000)
        .unwrap();
    let verifier_source_prevout_from_utxo = rpc.get_txout_from_utxo(&verifier_source_utxo).unwrap();
    println!("Verifier Source TxOut RPC: {:?}", verifier_source_prevout_from_utxo);

    // Operator and the Verifier agree on the bitvm scripts that will be used in the sequence.
    let mut bitvm_script_vec: Vec<ScriptBuf> = Vec::new();
    for _ in 0..NUM_COMMIT_TX {
        bitvm_script_vec.push(script_builder::generate_dummy_commit_script(
            &config.verifiers_public_keys,
        ));
    }
    // This is the last script. It is the script that has the checking conditions and generates the final address.
    // TODO: Change this
    bitvm_script_vec.push(script_builder::generate_dummy_commit_script(
        &config.verifiers_public_keys,
    ));

    // Create the BitVM sequence with the given BitVM scripts.
    let mut bitvm_setup: BitVMSequence = create_bitvm_sequence(
        NUM_COMMIT_TX,
        bitvm_script_vec,
        verifier_source_utxo,
        &operator,
        &verifier,
        &config,
    );
    println!("BitVM Setup Completed: {:?}", bitvm_setup);

    // Some needed scripts.
    // TODO: Find a way to handle all the structs in a more elegant way (less cloning, smaller function signatures etc.).
    let challenger_takes_after_script = script_builder::generate_challenger_takes_after_script(
        &config.verifiers_public_keys[0],
        CHALLENGER_TAKES_AFTER,
    );
    let musig_script = script_builder::generate_script_n_of_n(&config.verifiers_public_keys);

    let verifier_sig = verifier
        .sign_taproot_pubkey_spend_tx(
            &mut bitvm_setup.start_tx,
            &vec![verifier_source_prevout_from_utxo],
            0,
        )
        .unwrap();
    handle_taproot_pubkey_spend_witness(&mut bitvm_setup.start_tx, verifier_sig, 0).unwrap();
    let start_challenge_txid = rpc.send_raw_transaction(&bitvm_setup.start_tx).unwrap();
    println!("Start Challenge TX: {:?}", bitvm_setup.start_tx);
    println!("Start Challenge TXID: {:?}", start_challenge_txid);

    rpc.mine_blocks(7).unwrap();
    let verifier_sig = verifier
        .sign_taproot_script_spend_tx_new(
            &mut bitvm_setup.tx_details_pair_vec[0].burn_tx_details,
            1,
            0,
        )
        .unwrap();

    let control_block_verifier_burns = bitvm_setup.tx_details_pair_vec[0]
        .burn_tx_details
        .taproot_spend_infos[1]
        .control_block(&(
            challenger_takes_after_script.clone(),
            LeafVersion::TapScript,
        ))
        .unwrap();
    bitvm_setup.tx_details_pair_vec[0].burn_tx_details.tx.input[1]
        .witness
        .push(verifier_sig.serialize());
    bitvm_setup.tx_details_pair_vec[0].burn_tx_details.tx.input[1]
        .witness
        .push(challenger_takes_after_script);
    bitvm_setup.tx_details_pair_vec[0].burn_tx_details.tx.input[1]
        .witness
        .push(control_block_verifier_burns.serialize());
    // TODO: Here, we use two different scripts to create the taproot address of operator commitments.
    // In the optimistic case, this results in additional 32 bytes of data in the witness. Maybe change
    // this to a single script, since both people know the scripts anyway?
    let control_block_musig = bitvm_setup.tx_details_pair_vec[0]
        .burn_tx_details
        .taproot_spend_infos[0]
        .control_block(&(musig_script.clone(), LeafVersion::TapScript))
        .unwrap();
    let verifier_musig = bitvm_setup.sigs[0].1 .0;
    let operator_musig = bitvm_setup.sigs[0].1 .1;

    bitvm_setup.tx_details_pair_vec[0].burn_tx_details.tx.input[0]
        .witness
        .push(operator_musig.serialize());
    bitvm_setup.tx_details_pair_vec[0].burn_tx_details.tx.input[0]
        .witness
        .push(verifier_musig.serialize());
    bitvm_setup.tx_details_pair_vec[0].burn_tx_details.tx.input[0]
        .witness
        .push(musig_script);
    bitvm_setup.tx_details_pair_vec[0].burn_tx_details.tx.input[0]
        .witness
        .push(control_block_musig.serialize());
    
    let verifier_burns_txid =
        rpc.send_raw_transaction(&bitvm_setup.tx_details_pair_vec[0].burn_tx_details.tx);
    println!("Verifier Burns TXID: {:?}", verifier_burns_txid);
}

#[tokio::test]
async fn test_bitvm_2() {
    let mut config = create_test_config_with_thread_name!("test_config_bitvm_2.toml");
    let rpc = create_extended_rpc!(config);

    // Create operator and verifier (challenger) entities.
    let verifier = Actor::new(
        config.all_secret_keys.clone().unwrap()[0],
        config.network,
    );
    let operator = Actor::new(config.secret_key, config.network);

    // Calculate the verifier_address.
    let verifier_taproot_address = Address::p2tr(
        &utils::SECP,
        config.verifiers_public_keys[0],
        None,
        config.network,
    );

    // Verifier puts his source_utxo on-chain. This UTXO is the starting point of the whole sequence.
    let verifier_source_utxo = rpc
        .send_to_address(&verifier_taproot_address, 20_000)
        .unwrap();
    let verifier_source_prevout_from_utxo = rpc.get_txout_from_utxo(&verifier_source_utxo).unwrap();
    println!("Verifier Source TxOut RPC: {:?}", verifier_source_prevout_from_utxo);

    // Operator and the Verifier agree on the bitvm scripts that will be used in the sequence.
    let mut bitvm_script_vec: Vec<ScriptBuf> = Vec::new();
    for _ in 0..NUM_COMMIT_TX {
        bitvm_script_vec.push(script_builder::generate_dummy_commit_script(
            &config.verifiers_public_keys,
        ));
    }
    // This is the last script. It is the script that has the checking conditions and generates the final address.
    // TODO: Change this
    bitvm_script_vec.push(script_builder::generate_dummy_commit_script(
        &config.verifiers_public_keys,
    ));

    // Create the BitVM sequence with the given BitVM scripts.
    let mut bitvm_setup: BitVMSequence = create_bitvm_sequence(
        NUM_COMMIT_TX,
        bitvm_script_vec,
        verifier_source_utxo,
        &operator,
        &verifier,
        &config,
    );
    // println!("BitVM Setup Completed: {:?}", bitvm_setup);

    // Some needed scripts.
    // TODO: Find a way to handle all the structs in a more elegant way (less cloning, smaller function signatures etc.).
    let verifier_sig = verifier
        .sign_taproot_pubkey_spend_tx(
            &mut bitvm_setup.start_tx,
            &vec![verifier_source_prevout_from_utxo],
            0,
        )
        .unwrap();
    handle_taproot_pubkey_spend_witness(&mut bitvm_setup.start_tx, verifier_sig, 0).unwrap();
    let start_challenge_txid = rpc.send_raw_transaction(&bitvm_setup.start_tx).unwrap();
    println!("Start Challenge TX: {:?}", bitvm_setup.start_tx);
    println!("Start Challenge TXID: {:?}", start_challenge_txid);
    // let mut start_utxo = OutPoint {
    //     txid: bitvm_setup.start_tx.compute_txid(),
    //     vout: 0,
    // };
    for i in 0..NUM_COMMIT_TX {
        let operator_commits_script =
            bitvm_setup.tx_details_pair_vec[i].commit_tx_details.scripts[0][0].clone();
        let control_block_operator_commits = bitvm_setup.tx_details_pair_vec[i]
            .commit_tx_details
            .taproot_spend_infos[0]
            .control_block(&(
                operator_commits_script.clone(),
                LeafVersion::TapScript,
            ))
            .unwrap();
        println!("Control Block Musig: {:?}", control_block_operator_commits);
        let verifier_sig_operator_commits = bitvm_setup.sigs[i].0 .0;
        let operator_sig_operator_commits = bitvm_setup.sigs[i].0 .1;
        println!("Verifier Musig: {:?}", verifier_sig_operator_commits);
        println!("Operator Musig: {:?}", operator_sig_operator_commits);
        bitvm_setup.tx_details_pair_vec[i]
            .commit_tx_details
            .tx
            .input[0]
            .witness
            .push(operator_sig_operator_commits.serialize());
        bitvm_setup.tx_details_pair_vec[i]
            .commit_tx_details
            .tx
            .input[0]
            .witness
            .push(verifier_sig_operator_commits.serialize());
        bitvm_setup.tx_details_pair_vec[i]
            .commit_tx_details
            .tx
            .input[0]
            .witness
            .push(operator_commits_script);
        bitvm_setup.tx_details_pair_vec[i]
            .commit_tx_details
            .tx
            .input[0]
            .witness
            .push(control_block_operator_commits.serialize());
        println!(
            "Operator Sending Commit TX...: {:?}",
            bitvm_setup.tx_details_pair_vec[i]
                .commit_tx_details
                .tx
                .raw_hex()
        );
        println!("TX Now Sending Raw: {:?}", bitvm_setup.tx_details_pair_vec[i].commit_tx_details.tx.raw_hex());
        let operator_commits_txid = rpc
            .send_raw_transaction(&bitvm_setup.tx_details_pair_vec[i].commit_tx_details.tx)
            .unwrap();
        println!("Operator Commits TXID: {:?}", operator_commits_txid);
        // start_utxo = OutPoint {
        //     txid: operator_commits_txid,
        //     vout: 0,
        // };
    }
}

fn create_bitvm_sequence(
    num_tx: usize,
    bitvm_scripts: Vec<ScriptBuf>,
    source_utxo: OutPoint,
    operator: &Actor,
    verifier: &Actor,
    config: &BridgeConfig,
) -> BitVMSequence {
    assert!(num_tx == bitvm_scripts.len() - 1);
    let mut tx_vec: Vec<CommitOrBurnTxPairs> = Vec::new();
    let mut sig_tuple_vec: Vec<(OperatorCommitsPresignPair, VerifierBurnsPresignPair)> = Vec::new();
    let verifier_starts_tx =
        create_verifier_starts_tx(source_utxo, bitvm_scripts[0].clone(), config);
    let mut start_utxo = OutPoint {
        txid: verifier_starts_tx.compute_txid(),
        vout: 0,
    };
    println!("Starting Start UTXO: {:?}", start_utxo);
    let verifier_takes_after_utxo = OutPoint {
        txid: verifier_starts_tx.compute_txid(),
        vout: 1,
    };
    let mut prev_txout = verifier_starts_tx.output[0].clone();

    for i in 0..num_tx {
        let mut verifier_burns_tx_details: TxHandlers = create_verifier_burns_tx(
            start_utxo,
            prev_txout.clone(),
            verifier_takes_after_utxo,
            verifier,
            bitvm_scripts[i].clone(),
            config,
        );

        let verifier_burns_verifier_presign = verifier
            .sign_taproot_script_spend_tx_new(&mut verifier_burns_tx_details, 0, 1)
            .unwrap();
        let verifier_burns_operator_presign = operator
            .sign_taproot_script_spend_tx_new(&mut verifier_burns_tx_details, 0, 1)
            .unwrap();
        let verifier_burns_sig_pair: VerifierBurnsPresignPair = (
            verifier_burns_verifier_presign,
            verifier_burns_operator_presign,
        );

        let mut operator_commits_tx_details: TxHandlers = create_operator_commits_tx(
            start_utxo,
            prev_txout.clone(),
            config,
            bitvm_scripts[i].clone(),
            bitvm_scripts[i + 1].clone(),
        );
        let operator_commits_verifier_presign = verifier
            .sign_taproot_script_spend_tx_new(&mut operator_commits_tx_details, 0, 0)
            .unwrap();
        let operator_commits_operator_presign = operator
            .sign_taproot_script_spend_tx_new(&mut operator_commits_tx_details, 0, 0)
            .unwrap();
        let operator_commits_sig_pair: OperatorCommitsPresignPair = (
            operator_commits_verifier_presign,
            operator_commits_operator_presign,
        );

        sig_tuple_vec.push((operator_commits_sig_pair, verifier_burns_sig_pair));
        let tx_pair = CommitOrBurnTxPairs {
            commit_tx_details: operator_commits_tx_details.clone(),
            burn_tx_details: verifier_burns_tx_details,
        };
        tx_vec.push(tx_pair);
        start_utxo = OutPoint {
            txid: operator_commits_tx_details.tx.compute_txid(),
            vout: 0,
        };
        println!("Start UTXO Changed: {:?}", start_utxo);
        prev_txout = operator_commits_tx_details.tx.output[0].clone();
    }

    BitVMSequence {
        start_tx: verifier_starts_tx,
        tx_details_pair_vec: tx_vec,
        sigs: sig_tuple_vec,
    }
}

fn create_verifier_burns_tx(
    commit_utxo: OutPoint,
    commit_prevout: TxOut,
    burn_utxo: OutPoint,
    verifier: &Actor,
    bitvm_script: ScriptBuf,
    config: &BridgeConfig,
) -> TxHandlers {
    // Calculate the dummy_commit_address and dummy_commit_tree_info
    let musig_script = script_builder::generate_script_n_of_n(&config.verifiers_public_keys);

    let (dummy_commit_address, dummy_commit_tree_info) = TransactionBuilder::create_taproot_address(vec![bitvm_script.clone(), musig_script.clone()], config.network).unwrap();

    let address_to_verify = dummy_commit_address.script_pubkey();
    println!("Address to Verify: {:?}", address_to_verify);
    println!("Commit UTXO: {:?}", commit_utxo);
    println!("Burn UTXO: {:?}", burn_utxo);
    println!("Commit Prevout: {:?}", commit_prevout);

    // Calculate the challenger_takes_after_address and challenger_takes_after_tree_info
    let challenger_takes_after_script = script_builder::generate_challenger_takes_after_script(
        &config.verifiers_public_keys[0],
        CHALLENGER_TAKES_AFTER,
    );

    let (challenger_takes_after_address, challenger_takes_after_tree_info) = TransactionBuilder::create_taproot_address(vec![challenger_takes_after_script.clone()], config.network).unwrap();

    let second_prevout = TxOut {
        value: challenger_takes_after_address
            .script_pubkey()
            .minimal_non_dust(),
        script_pubkey: challenger_takes_after_address.script_pubkey(),
    };
    let prevouts = vec![commit_prevout.clone(), second_prevout];
    let txins = TransactionBuilder::create_tx_ins_with_sequence_flag(
        vec![commit_utxo, burn_utxo],
        (CHALLENGER_TAKES_AFTER + 1) as u16,
        vec![false, true],
    );
    let txouts = TransactionBuilder::create_tx_outs(
        vec![(commit_prevout.value, verifier.address.script_pubkey())],
        None,
    );
    let tx = TransactionBuilder::create_btc_tx(txins, txouts);
    let taproot_spend_infos = vec![dummy_commit_tree_info, challenger_takes_after_tree_info];

    TxHandlers {
        tx,
        prevouts,
        scripts: vec![
            vec![bitvm_script, musig_script],
            vec![challenger_takes_after_script],
        ],
        taproot_spend_infos,
    }
}

fn create_operator_commits_tx(
    start_utxo: OutPoint,
    start_prevout: TxOut,
    config: &BridgeConfig,
    prev_bitvm_script: ScriptBuf,
    next_bitvm_script: ScriptBuf,
) -> TxHandlers {
    // Calculate the dummy_commit_address
    let musig_script = script_builder::generate_script_n_of_n(&config.verifiers_public_keys);
    let (dummy_commit_address, dummy_commit_tree_info) = TransactionBuilder::create_taproot_address(vec![next_bitvm_script, musig_script.clone()], config.network).unwrap();
    let txins = TransactionBuilder::create_tx_ins(vec![start_utxo]);
    let txouts = TransactionBuilder::create_tx_outs(
        vec![(
            Amount::from_sat(Amount::to_sat(start_prevout.value) - 500),
            dummy_commit_address.script_pubkey(),
        )],
        None,
    );
    let tx = TransactionBuilder::create_btc_tx(txins, txouts);
    let prevouts = vec![start_prevout];
    let scripts = vec![vec![prev_bitvm_script, musig_script]];
    let taproot_spend_infos = vec![dummy_commit_tree_info];
    TxHandlers {
        tx,
        prevouts,
        scripts,
        taproot_spend_infos,
    }
}

fn create_verifier_starts_tx(
    source_utxo: OutPoint,
    first_script: ScriptBuf,
    config: &BridgeConfig,
) -> Transaction {
    let txins = TransactionBuilder::create_tx_ins(vec![source_utxo]);

    // Calculate the dummy_commit_address
    let musig_script = script_builder::generate_script_n_of_n(&config.verifiers_public_keys);
    let (dummy_commit_address, _) = TransactionBuilder::create_taproot_address(
        vec![first_script, musig_script],
        config.network,
    ).unwrap();

    // Calculate the challenger_takes_after_address
    let challenger_takes_after_script = script_builder::generate_challenger_takes_after_script(
        &config.verifiers_public_keys[0],
        CHALLENGER_TAKES_AFTER,
    );
    let (challenger_takes_after_address, _) = TransactionBuilder::create_taproot_address(
        vec![challenger_takes_after_script],
        config.network,
    ).unwrap();

    let anyone_can_spend_txout = script_builder::anyone_can_spend_txout();

    let txouts = TransactionBuilder::create_tx_outs(
        vec![
            (
                Amount::from_sat(19000),
                dummy_commit_address.script_pubkey(),
            ),
            (
                challenger_takes_after_address
                    .script_pubkey()
                    .minimal_non_dust(),
                challenger_takes_after_address.script_pubkey(),
            ),
        ],
        Some(anyone_can_spend_txout),
    );
    let tx = TransactionBuilder::create_btc_tx(txins, txouts);
    tx
}
