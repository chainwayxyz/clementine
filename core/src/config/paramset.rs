use bitcoin::{Amount, Network};

pub const WATCHTOWER_CHALLENGE_MESSAGE_LENGTH: u32 = 480;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ProtocolParamsetName {
    Mainnet,
    Regtest,
    Testnet,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ProtocolParamset {
    pub network: Network,
}
