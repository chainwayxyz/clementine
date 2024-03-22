use clementine_circuits::bridge::bridge_proof;
use clementine_circuits::constants::{MAX_BLOCK_HANDLE_OPS, NUM_ROUNDS};
use clementine_core::constants::{NUM_USERS, NUM_VERIFIERS, PERIOD_BLOCK_COUNT};
use clementine_core::errors::BridgeError;
use clementine_core::mock_env::MockEnvironment;
use clementine_core::traits::verifier::VerifierConnector;
use clementine_core::verifier::Verifier;
use clementine_core::EVMAddress;
use clementine_core::{extended_rpc::ExtendedRpc, operator::Operator, user::User};
use crypto_bigint::rand_core::OsRng;
use secp256k1::rand::rngs::StdRng;
use secp256k1::rand::SeedableRng;
use secp256k1::XOnlyPublicKey;
use std::env;
use std::str::FromStr;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{fmt, EnvFilter};

fn test_flow() -> Result<(), BridgeError> {
    let rpc = ExtendedRpc::new();

    let secp = bitcoin::secp256k1::Secp256k1::new();

    let seed: [u8; 32] = [0u8; 32];
    let mut seeded_rng = StdRng::from_seed(seed);
    let rng = &mut OsRng;

    let (all_sks, all_xonly_pks): (Vec<_>, Vec<_>) = (0..NUM_VERIFIERS + 1)
        .map(|_| {
            let (sk, pk) = secp.generate_keypair(rng);
            (sk, XOnlyPublicKey::from(pk))
        })
        .unzip();

    let mut verifiers: Vec<Box<dyn VerifierConnector>> = Vec::new();
    for i in 0..NUM_VERIFIERS {
        // let rpc = ExtendedRpc::new();
        let verifier = Verifier::new(rpc.clone(), all_xonly_pks.clone(), all_sks[i])?;
        // Convert the Verifier instance into a boxed trait object
        verifiers.push(Box::new(verifier) as Box<dyn VerifierConnector>);
    }

    let mut operator = Operator::new(
        rpc.clone(),
        all_xonly_pks.clone(),
        all_sks[NUM_VERIFIERS],
        verifiers,
    )?;

    let users: Vec<_> = (0..NUM_USERS)
        .map(|_| {
            let (sk, _) = secp.generate_keypair(rng);
            User::new(rpc.clone(), all_xonly_pks.clone(), sk)
        })
        .collect();

    // Initial setup for connector roots
    let (
        first_source_utxo,
        start_blockheight,
        connector_tree_hashes,
        period_relative_block_heights,
        _claim_proof_merkle_trees,
    ) = operator.initial_setup(&mut seeded_rng).unwrap();

    // let mut connector_tree_source_sigs = Vec::new();

    for verifier in &mut operator.verifier_connector {
        let _sigs = verifier.connector_roots_created(
            &connector_tree_hashes,
            &first_source_utxo,
            start_blockheight,
            period_relative_block_heights.clone(),
        );
        // connector_tree_source_sigs.push(sigs);
    }

    // presigns_from_all_verifiers:!("connector roots created, verifiers agree");
    // In the end, create BitVM

    for current_period in 0..NUM_ROUNDS {
        tracing::debug!("Current period: {}", current_period);
        // every user makes a deposit.
        for i in 0..NUM_USERS {
            let user = &users[i];
            let evm_address: EVMAddress = [0; 20];
            let (deposit_utxo, deposit_return_address, user_evm_address, user_sig) =
                user.deposit_tx(evm_address).unwrap();
            rpc.mine_blocks(6)?;
            operator.new_deposit(
                deposit_utxo,
                &deposit_return_address,
                &user_evm_address,
                user_sig,
            )?;
            // rpc.mine_blocks(1)?;
        }

        // make 3 withdrawals
        for i in 0..3 {
            operator.new_withdrawal(users[i].signer.address.clone())?;
            // rpc.mine_blocks(1)?;
        }

        // PERIOD = 50 BLOCKS, FLOW PRODUCES 24 BLOCKS PERIOD, 3 BLOCKS TO HANDLE OPERATIONS, MINE 23 BLOCKS
        // TODO: CHANGE THIS
        rpc.mine_blocks((PERIOD_BLOCK_COUNT - 24 - MAX_BLOCK_HANDLE_OPS) as u64)?;

        operator.inscribe_connector_tree_preimages()?;

        // MINE 3 BLOCKS TO MOVE ON TO THE NEW PERIOD
        // TODO: CHANGE THIS
        rpc.mine_blocks(MAX_BLOCK_HANDLE_OPS as u64)?;

        tracing::debug!("Proving for Period: {}", current_period);

        let challenge = operator.verifier_connector[0].challenge_operator(current_period as u8)?;
        MockEnvironment::reset_mock_env();
        operator.prove::<MockEnvironment>(challenge)?;
        bridge_proof::<MockEnvironment>();
    }

    tracing::info!("Bridge proof done");

    Ok(())
}

/// Default initialization of logging
pub fn initialize_logging() {
    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(
            EnvFilter::from_str(
                &env::var("RUST_LOG").unwrap_or_else(|_| "debug,bitcoincore_rpc=info".to_string()),
            )
            .unwrap(),
        )
        .init();
}

fn main() {
    initialize_logging();
    test_flow().unwrap();
}
