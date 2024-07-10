//! # RPC Related Mocks and Test Utilities

// #[cfg_attr(feature = "mock_rpc", mock_rpc)]

/// Creates an [`ExtendedRpc`] struct from either the real Bitcoin RPC or mock
/// RPC.
///
/// # Parameters
///
/// - `config`: Mutable `BridgeConfig` structure.
/// - `db_name`: If mock is used, this will be it's database name. If not used
/// can be dummy value.
#[cfg(feature = "mock_rpc")]
#[macro_export]
macro_rules! create_extended_rpc {
    ($config:expr, $db_name:expr) => {{
        println!("Using Mock RPC for testing...");

        $config.bitcoin_rpc_url = $db_name.to_string();

        ExtendedRpc::<bitcoin_mock_rpc::Client>::new(
            $config.bitcoin_rpc_url.clone(),
            $config.bitcoin_rpc_user.clone(),
            $config.bitcoin_rpc_password.clone(),
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
/// can be dummy value.
#[cfg(not(feature = "mock_rpc"))]
#[macro_export]
macro_rules! create_extended_rpc {
    ($config:expr, $db_name:expr) => {{
        println!("Using Bitcoin regtest for testing...");

        // Just to match other mutable macro:
        $config.bitcoin_rpc_url = $config.bitcoin_rpc_url;

        ExtendedRpc::<bitcoincore_rpc::Client>::new(
            $config.bitcoin_rpc_url.clone(),
            $config.bitcoin_rpc_user.clone(),
            $config.bitcoin_rpc_password.clone(),
        )
    }};
}
