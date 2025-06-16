pub mod constants;
pub mod hashes;
pub mod zkvm;

pub const NETWORK_TYPE: &str = {
    #[cfg(test)]
    {
        "testnet4"
    }
    #[cfg(not(test))]
    {
        match option_env!("BITCOIN_NETWORK") {
            Some(network) if matches!(network.as_bytes(), b"mainnet") => "mainnet",
            Some(network) if matches!(network.as_bytes(), b"testnet4") => "testnet4",
            Some(network) if matches!(network.as_bytes(), b"signet") => "signet",
            Some(network) if matches!(network.as_bytes(), b"regtest") => "regtest",
            None => "testnet4",
            _ => panic!("Invalid network type"),
        }
    }
};

// Then your function becomes simpler
pub const fn get_network() -> &'static str {
    NETWORK_TYPE
}
