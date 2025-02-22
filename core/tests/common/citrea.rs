use bitcoin::Network;
use citrea_e2e::{
    bitcoin::BitcoinNode,
    config::{EmptyConfig, SequencerConfig},
    framework::TestFramework,
    node::Node,
};
use clementine_core::config::BridgeConfig;

pub async fn start_citrea(
    sequencer_config: SequencerConfig,
    f: &mut TestFramework,
) -> citrea_e2e::Result<(&Node<SequencerConfig>, &mut Node<EmptyConfig>, &BitcoinNode)> {
    let sequencer: &Node<SequencerConfig> = f.sequencer.as_ref().expect("Sequencer is present");
    let full_node: &mut Node<citrea_e2e::config::EmptyConfig> =
        f.full_node.as_mut().expect("Full node is present");
    let da: &citrea_e2e::bitcoin::BitcoinNode =
        f.bitcoin_nodes.get(0).expect("There is a bitcoin node");

    let min_soft_confirmations_per_commitment =
        sequencer_config.min_soft_confirmations_per_commitment;

    for _ in 0..min_soft_confirmations_per_commitment {
        sequencer.client.send_publish_batch_request().await?;
    }

    // Wait for blob inscribe tx to be in mempool
    da.wait_mempool_len(1, None).await?;

    da.generate(citrea_e2e::bitcoin::DEFAULT_FINALITY_DEPTH)
        .await?;

    full_node
        .wait_for_l2_height(min_soft_confirmations_per_commitment, None)
        .await?;

    Ok((sequencer, full_node, da))
}

pub fn update_config_with_citrea_e2e_da(
    config: &mut BridgeConfig,
    da: &citrea_e2e::bitcoin::BitcoinNode,
) {
    config.bitcoin_rpc_password = da.config.rpc_password.clone();
    config.bitcoin_rpc_user = da.config.rpc_user.clone();
    config.bitcoin_rpc_password = da.config.rpc_password.clone();
    config.bitcoin_rpc_url = format!(
        "http://127.0.0.1:{}/wallet/{}",
        da.config.rpc_port,
        NodeKind::Bitcoin // citrea-e2e internal.
    );
}
