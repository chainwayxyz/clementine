use clementine_core::{
    cli, extended_rpc::ExtendedRpc, servers::create_operator_and_verifiers,
    traits::bitcoin_rpc::BitcoinRPC,
};

/// ```bash
/// curl -X POST http://127.0.0.1:3434 -H "Content-Type: application/json" -d '{
///     "jsonrpc": "2.0",
///     "method": "operator_new_deposit",
///     "params": {
///         "start_utxo": "2964713fecf26d6eec7df4420bed1e09de1bdab2cacd24a1c8c0afd70c8a5371:3",
///         "recovery_taproot_address": "781990d7e2118cc361a93a6fcc54ce611d6df38168d6b1edfb556535f2200c4b",
///         "evm_address": "0101010101010101010101010101010101010101"
///     },
///     "id": 1
///     }'
/// ```
#[tokio::main]
async fn main() {
    let config = cli::get_configuration();
    let rpc = ExtendedRpc::new(
        config.bitcoin_rpc_url.clone(),
        config.bitcoin_rpc_user.clone(),
        config.bitcoin_rpc_password.clone(),
    );

    let (operator_client, operator_handle, _verifiers) =
        create_operator_and_verifiers(config, rpc).await;

    println!("Operator server started. {:?}", operator_client);

    operator_handle.stopped().await;
}
