//! # Citrea Related Utilities

use crate::musig2::AggregateFromPublicKeys;
use crate::{config::BridgeConfig, errors::BridgeError};
use bitcoin::secp256k1::PublicKey;
use citrea_e2e::{
    bitcoin::BitcoinNode,
    config::{BatchProverConfig, EmptyConfig, LightClientProverConfig, SequencerConfig},
    framework::TestFramework,
    node::{Node, NodeKind},
};
pub use client_mock::*;
use jsonrpsee::http_client::HttpClient;
pub use parameters::*;
pub use requests::*;

mod client_mock;
mod parameters;
mod requests;

/// Calculates bridge params dynamically with the N-of-N public key which
/// calculated from the verifier secret keys in `BridgeConfig::default`.
pub fn get_bridge_params() -> String {
    let config = BridgeConfig::default();

    let verifiers_secret_keys = config.test_params.all_verifiers_secret_keys;
    let secp = bitcoin::secp256k1::Secp256k1::new();
    let verifiers_public_keys: Vec<PublicKey> = verifiers_secret_keys
        .iter()
        .map(|sk| PublicKey::from_secret_key(&secp, sk))
        .collect();

    let nofn_xonly_pk =
        bitcoin::XOnlyPublicKey::from_musig2_pks(verifiers_public_keys.clone(), None)
            .unwrap()
            .to_string();

    let bridge_params = format!(
        "000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000000c00000000000000000000000000000000000000000000000008ac7230489e80000000000000000000000000000000000000000000000000000000000000000002d4120{}ac006306636974726561140000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000016800000000000000000000000000000000000000000000000000000000000000", nofn_xonly_pk
    );

    tracing::info!("Bridge params: {}", bridge_params);

    bridge_params
}

/// Citrea e2e hardcoded EVM secret keys.
pub const SECRET_KEYS: [&str; 10] = [
    "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
    "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d",
    "0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a",
    "0x7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6",
    "0x47e179ec197488593b187f80a00eb0da91f1b9d0b13f8733639f19c30a34926a",
    "0x8b3a350cf5c34c9194ca85829a2df0ec3153be0318b5e2d3348e872092edffba",
    "0x92db14e403b83dfe3df233f83dfa3a0d7096f21ca9b0d6d6b8d88b2b4ec1564e",
    "0x4bbbf85ce3377467afe5d46f804f221813b2bb87f24d81f60f1fcdbf7cbf4356",
    "0xdbda1821b80551c9d65939329250298aa3472ba22feea921c0cf5d620ea67b97",
    "0x2a871d0798f97d79848a013d4936a73bf4cc922c825d33c1cf7073dff6d409c6",
];

/// Citrea e2e hardcoded EVM addresses.
pub const EVM_ADDRESSES: [&str; 10] = [
    "f39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
    "70997970C51812dc3A010C7d01b50e0d17dc79C8",
    "3C44CdDdB6a900fa2b585dd299e03d12FA4293BC",
    "90F79bf6EB2c4f870365E785982E1f101E93b906",
    "15d34AAf54267DB7D7c367839AAf71A00a2C6A65",
    "9965507D1a55bcC2695C58ba16FB37d819B0A4dc",
    "976EA74026E726554dB657fA54763abd0C3a0aa9",
    "14dC79964da2C08b23698B3D3cc7Ca32193d9955",
    "23618e81E3f5cdF7f54C3d65f7FBc0aBf5B21E8f",
    "a0Ee7A142d267C1f36714E4a8F75612F20a79720",
];

/// Starts typical nodes with typical configs for a test that needs Citrea.
pub async fn start_citrea(
    sequencer_config: SequencerConfig,
    f: &mut TestFramework,
) -> citrea_e2e::Result<(
    &Node<SequencerConfig>,
    &mut Node<EmptyConfig>,
    Option<&Node<LightClientProverConfig>>,
    Option<&Node<BatchProverConfig>>,
    &BitcoinNode,
)> {
    let sequencer = f.sequencer.as_ref().expect("Sequencer is present");
    let full_node = f.full_node.as_mut().expect("Full node is present");
    let batch_prover = f.batch_prover.as_ref();
    let light_client_prover = f.light_client_prover.as_ref();
    let da = f.bitcoin_nodes.get(0).expect("There is a bitcoin node");

    let min_soft_confirmations_per_commitment = sequencer_config.max_l2_blocks_per_commitment;

    if sequencer_config.test_mode {
        for _ in 0..min_soft_confirmations_per_commitment {
            sequencer.client.send_publish_batch_request().await?;
        }
    }
    sequencer
        .wait_for_l2_height(min_soft_confirmations_per_commitment, None)
        .await?;
    println!("Sequencer is ready");

    Ok((sequencer, full_node, light_client_prover, batch_prover, da))
}

/// Updates given config with the values set by the Citrea e2e.
pub fn update_config_with_citrea_e2e_values(
    config: &mut BridgeConfig,
    da: &citrea_e2e::bitcoin::BitcoinNode,
    sequencer: &citrea_e2e::node::Node<SequencerConfig>,
    light_client_prover: Option<(&str, u16)>,
) {
    config.bitcoin_rpc_user = da.config.rpc_user.clone().into();
    config.bitcoin_rpc_password = da.config.rpc_password.clone().into();
    config.bitcoin_rpc_url = format!(
        "http://127.0.0.1:{}/wallet/{}",
        da.config.rpc_port,
        NodeKind::Bitcoin // citrea-e2e internal.
    );

    let citrea_url = format!(
        "http://{}:{}",
        sequencer.config.rollup.rpc.bind_host, sequencer.config.rollup.rpc.bind_port
    );
    config.citrea_rpc_url = citrea_url;

    if let Some(light_client_prover) = light_client_prover {
        let citrea_light_client_prover_url =
            format!("http://{}:{}", light_client_prover.0, light_client_prover.1);
        config.citrea_light_client_prover_url = citrea_light_client_prover_url;
    } else {
        let citrea_light_client_prover_url = format!("http://{}:{}", "127.0.0.1", 8080); // Dummy value
        config.citrea_light_client_prover_url = citrea_light_client_prover_url;
    }
}

pub async fn wait_until_lc_contract_updated(
    client: &HttpClient,
    block_height: u64,
) -> Result<(), BridgeError> {
    let mut attempts = 0;
    let max_attempts = 600;

    while attempts < max_attempts {
        let block_number = block_number(client).await?;
        if block_number >= block_height as u32 {
            break;
        }
        attempts += 1;
        tokio::time::sleep(std::time::Duration::from_millis(1000)).await;
    }
    Ok(())
}
