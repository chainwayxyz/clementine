use bitcoin::hashes::Hash;
use bitcoin::BlockHash;
use clementine_circuits::constants::{MAX_BLOCK_HANDLE_OPS, NUM_ROUNDS};
use clementine_core::constants::{NUM_USERS, NUM_VERIFIERS, PERIOD_BLOCK_COUNT};
use clementine_core::errors::BridgeError;
use clementine_core::mock_env::MockEnvironment;
use clementine_core::traits::verifier::VerifierConnector;
use clementine_core::verifier::Verifier;
use clementine_core::EVMAddress;
use clementine_core::{extended_rpc::ExtendedRpc, operator::Operator, user::User};
use crypto_bigint::rand_core::OsRng;
use crypto_bigint::U256;
use operator_circuit::GUEST_ELF;
use risc0_zkvm::default_prover;
use secp256k1::rand::rngs::StdRng;
use secp256k1::rand::SeedableRng;
use secp256k1::XOnlyPublicKey;
use std::env;
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{fmt, EnvFilter};
lazy_static::lazy_static! {
    static ref SHARED_STATE: Mutex<i32> = Mutex::new(0);
}

async fn test_flow() -> Result<(), BridgeError> {
    let rpc = ExtendedRpc::new();

    let secp = bitcoin::secp256k1::Secp256k1::new();

    let seed: [u8; 32] = [0u8; 32];
    let mut seeded_rng = StdRng::from_seed(seed);
    let (all_sks, all_xonly_pks): (Vec<_>, Vec<_>) = (0..NUM_VERIFIERS + 1)
        .map(|_| {
            let (sk, pk) = secp.generate_keypair(&mut seeded_rng);
            (sk, XOnlyPublicKey::from(pk))
        })
        .unzip();

    let user_sk = secp.generate_keypair(&mut seeded_rng).0;
    let user = User::new(rpc.clone(), all_xonly_pks.clone(), user_sk);
    let evm_address: EVMAddress = [1u8; 20];
    println!("EVM Address: {:?}", hex::encode(evm_address));
    println!("User: {:?}", user.signer.xonly_public_key.to_string());
    let address = user.get_deposit_address(evm_address).unwrap();
    println!("Deposit address: {:?}", address);
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

#[tokio::main]
async fn main() {
    initialize_logging();
    test_flow().await.unwrap();
}
