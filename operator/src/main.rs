use circuit_helpers::bridge::bridge_proof;
use circuit_helpers::constants::MAX_BLOCK_HANDLE_OPS;
use crypto_bigint::rand_core::OsRng;
use operator::constants::{NUM_USERS, NUM_VERIFIERS};
use operator::errors::BridgeError;
use operator::mock_env::MockEnvironment;
use operator::traits::verifier::VerifierConnector;
use operator::verifier::Verifier;
use operator::EVMAddress;
use operator::{extended_rpc::ExtendedRpc, operator::Operator, user::User};
use secp256k1::rand::rngs::StdRng;
use secp256k1::rand::SeedableRng;
use secp256k1::XOnlyPublicKey;

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

    // println!("connector roots created, verifiers agree");
    // In the end, create BitVM

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
        rpc.mine_blocks(1)?;
    }

    // make 3 withdrawals
    for i in 0..3 {
        operator.new_withdrawal(users[i].signer.address.clone())?;
        rpc.mine_blocks(1)?;
    }
    rpc.mine_blocks((period_relative_block_heights[0] - MAX_BLOCK_HANDLE_OPS - 30).into())?;

    operator.inscribe_connector_tree_preimages()?;

    rpc.mine_blocks(15)?;

    let challenge = verifiers[0].challenge_operator(0, [0u8; 32])?;

    operator.prove::<MockEnvironment>(Some(challenge))?;
    bridge_proof::<MockEnvironment>(None);

    Ok(())
}

fn main() {
    test_flow().unwrap();
}
