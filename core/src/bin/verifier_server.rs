use bitcoin::{Address, OutPoint};
use clementine_core::traits::verifier::VerifierConnector;
use clementine_core::EVMAddress;
use clementine_core::{constants::NUM_VERIFIERS, extended_rpc::ExtendedRpc, verifier::Verifier};
use crypto_bigint::rand_core::OsRng;
use dotenv::dotenv;
use jsonrpsee::{server::Server, RpcModule};
use secp256k1::rand::{rngs::StdRng, SeedableRng};
use secp256k1::XOnlyPublicKey;
use std::str::FromStr;
use std::{env, net::SocketAddr};

fn load_config() -> (Vec<u8>, Vec<u8>) {
    dotenv().ok();

    let secret_key = env::var("SECRET_KEY")
        .expect("SECRET_KEY must be set in .env")
        .into_bytes();

    // Dummy implementation for all_xonly_pks, replace with actual file reading logic
    let all_xonly_pks = vec![];

    (all_xonly_pks, secret_key)
}

#[tokio::main]
async fn main() {
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

    // Initialization of Verifier, RPC, etc. goes here

    let server = Server::builder()
        .build("127.0.0.1:0".parse::<SocketAddr>().unwrap())
        .await
        .unwrap();
    let mut module = RpcModule::new(()); // Use appropriate context

    let verifier = Verifier::new(rpc, all_xonly_pks, all_sks[0]).unwrap();

    // Define your RPC methods
    module
        .register_async_method("new_deposit", move |_params, _ctx| {
            let verifier_clone = verifier.clone(); // Assuming Verifier is Clone
            async move {
                // Call the appropriate method on the Verifier instance
                verifier_clone
                    .new_deposit(
                        // Pass the required parameters
                        // Replace with actual values
                        OutPoint::default(),
                        &XOnlyPublicKey::from_slice(&[0; 32]).unwrap(),
                        0,
                        &[0u8; 20],
                        &Address::from_str("tb1qg9yq").unwrap().assume_checked(),
                    )
                    .await
                    .unwrap();
            }
        })
        .unwrap();
    let handle = server.start(module);

    // In this example we don't care about doing shutdown so let's it run forever.
    // You may use the `ServerHandle` to shut it down or manage it yourself.
    tokio::spawn(handle.stopped());
}
