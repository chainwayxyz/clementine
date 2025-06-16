use crate::create_minimal_config;
use crate::utils::parameters::get_citrea_safe_withdraw_params;
use crate::utils::requests::deposit;
use bitcoin::secp256k1::schnorr;
use bitcoincore_rpc::RpcApi;
use clap::Subcommand;
use clementine_core::{
    citrea::{CitreaClient, CitreaClientT},
    extended_rpc, UTXO,
};
use std::str::FromStr;

#[derive(Subcommand)]
pub enum CitreaCommands {
    /// Make a deposit to Citrea for a tx with given txid
    Deposit {
        #[arg(long)]
        lcp_url: String,
        #[arg(long)]
        bitcoin_rpc_url: String,
        #[arg(long)]
        bitcoin_rpc_user: String,
        #[arg(long)]
        bitcoin_rpc_password: String,
        #[arg(long)]
        txid: String,
    },
    /// Makes a safe withdrawal from Citrea
    SafeWithdraw {
        #[arg(long)]
        bitcoin_rpc_url: String,
        #[arg(long)]
        bitcoin_rpc_user: String,
        #[arg(long)]
        bitcoin_rpc_password: String,
        #[arg(long)]
        withdrawal_dust_utxo_txid: String,
        #[arg(long)]
        withdrawal_dust_utxo_vout: u32,
        #[arg(long)]
        payout_output_txid: String,
        #[arg(long)]
        payout_output_vout: u32,
        #[arg(long)]
        signature: String,
    },
}

pub async fn handle_citrea_call(url: String, command: CitreaCommands) {
    println!("Connecting to verifier at {}", url);
    let config = create_minimal_config();

    match command {
        CitreaCommands::Deposit {
            lcp_url,
            bitcoin_rpc_url,
            bitcoin_rpc_user,
            bitcoin_rpc_password,
            txid,
        } => {
            let extended_rpc = extended_rpc::ExtendedRpc::connect(
                bitcoin_rpc_url,
                bitcoin_rpc_user,
                bitcoin_rpc_password,
            )
            .await
            .expect("Failed to connect to Bitcoin RPC");
            let tx = extended_rpc
                .get_tx_of_txid(&bitcoin::Txid::from_str(&txid).expect("Failed to parse txid"))
                .await
                .expect("Failed to get tx of txid");
            let block_hash = extended_rpc
                .get_blockhash_of_tx(&tx.compute_txid())
                .await
                .expect("Failed to get block hash");
            let block = extended_rpc
                .client
                .get_block(&block_hash)
                .await
                .expect("Failed to get block");
            let block_height = block
                .bip34_block_height()
                .expect("Failed to get block height");

            let citrea_client = CitreaClient::new(url, lcp_url, config.citrea_chain_id, None)
                .await
                .expect("Failed to create Citrea client");

            deposit(
                &extended_rpc,
                citrea_client.client,
                block,
                block_height
                    .try_into()
                    .expect("Failed to convert block height"),
                tx,
            )
            .await
            .expect("Failed to deposit to Citrea");
            println!("Deposit to Citrea completed successfully");
        }
        CitreaCommands::SafeWithdraw {
            bitcoin_rpc_url,
            bitcoin_rpc_user,
            bitcoin_rpc_password,
            withdrawal_dust_utxo_txid,
            withdrawal_dust_utxo_vout,
            payout_output_txid,
            payout_output_vout,
            signature,
        } => {
            let extended_rpc = extended_rpc::ExtendedRpc::connect(
                bitcoin_rpc_url,
                bitcoin_rpc_user,
                bitcoin_rpc_password,
            )
            .await
            .expect("Failed to connect to Bitcoin RPC");

            // create utxo from withdrawal_dust_utxo_txid and withdrawal_dust_utxo_vout
            let outpoint = bitcoin::OutPoint {
                txid: bitcoin::Txid::from_str(&withdrawal_dust_utxo_txid)
                    .expect("Failed to parse withdrawal dust utxo txid"),
                vout: withdrawal_dust_utxo_vout,
            };
            let txout = extended_rpc
                .get_txout_from_outpoint(&outpoint)
                .await
                .expect("Failed to get txout from outpoint");
            let withdrawal_dust_utxo = UTXO { outpoint, txout };

            let outpoint = bitcoin::OutPoint {
                txid: bitcoin::Txid::from_str(&payout_output_txid)
                    .expect("Failed to parse payout utxo txid"),
                vout: payout_output_vout,
            };
            let payout_output = extended_rpc
                .get_txout_from_outpoint(&outpoint)
                .await
                .expect("Failed to get txout from outpoint");

            let signature =
                schnorr::Signature::from_str(&signature).expect("Failed to parse signature");

            let ret = get_citrea_safe_withdraw_params(
                &extended_rpc,
                withdrawal_dust_utxo,
                payout_output,
                signature,
            )
            .await
            .expect("Failed to get Citrea safe withdraw params");

            println!("Citrea safe withdraw params: {:?}", ret);
        }
    }
}
