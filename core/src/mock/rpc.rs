//! # RPC Related Mocks and Test Utilities

// #[cfg_attr(feature = "mock_rpc", mock_rpc)]

/// Creates an [`ExtendedRpc`] struct from either the real Bitcoin RPC or mock
/// RPC.
///
/// # Parameters
///
/// - `config`: Mutable `BridgeConfig` structure.
/// - `db_name`: If mock is used, this will be it's database name. If not used
///    can be dummy value.
#[cfg(feature = "mock_rpc")]
#[macro_export]
macro_rules! create_extended_rpc {
    ($config:expr) => {{
        println!("Using Mock RPC for testing...");
        let handle = std::thread::current()
            .name()
            .unwrap()
            .split(":")
            .last()
            .unwrap()
            .to_owned();

        $config.bitcoin.rpc_url = handle.to_string();

        ExtendedRpc::<bitcoin_mock_rpc::Client>::new(
            $config.bitcoin.rpc_url.clone(),
            $config.bitcoin.rpc_user.clone(),
            $config.bitcoin.rpc_password.clone(),
        )
    }};
}
/// Creates an [`ExtendedRpc`] struct from either the real Bitcoin RPC or mock
/// RPC.
///
/// # Parameters
///
/// - `config`: Mutable `BridgeConfig` structure.
/// - `db_name`: If mock is used, this will be it's database name. If not used
///   can be dummy value.
#[cfg(not(feature = "mock_rpc"))]
#[macro_export]
macro_rules! create_extended_rpc {
    ($config:expr) => {{
        println!("Using Bitcoin regtest for testing...");

        // Mutation for consistency with above defined macro
        $config.bitcoin.rpc_url = $config.bitcoin.rpc_url.clone();

        ExtendedRpc::<bitcoincore_rpc::Client>::new(
            $config.bitcoin.rpc_url.clone(),
            $config.bitcoin.rpc_user.clone(),
            $config.bitcoin.rpc_password.clone(),
        )
    }};
}
