use crate::create_minimal_config;
use clap::Subcommand;
use clementine_core::rpc::clementine::{
    self, clementine_operator_client::ClementineOperatorClient, deposit::DepositData, Actors,
    BaseDeposit, Deposit, Empty, Outpoint,
};
use tonic::Request;

#[derive(Subcommand)]
pub enum OperatorCommands {
    /// Get deposit keys
    GetDepositKeys {
        #[arg(long)]
        deposit_outpoint_txid: String,
        #[arg(long)]
        deposit_outpoint_vout: u32,
    },
    /// Get operator parameters
    GetParams,
    /// Withdraw funds
    Withdraw {
        #[arg(long)]
        withdrawal_id: u32,
        #[arg(long)]
        input_signature: String,
        #[arg(long)]
        input_outpoint_txid: String,
        #[arg(long)]
        input_outpoint_vout: u32,
        #[arg(long)]
        output_script_pubkey: String,
        #[arg(long)]
        output_amount: u64,
    },
    /// Get vergen build information
    Vergen,
    // Add other operator commands as needed
}

pub async fn handle_operator_call(url: String, command: OperatorCommands) {
    let config = create_minimal_config();
    let mut operator =
        clementine_core::rpc::get_clients(vec![url], ClementineOperatorClient::new, &config, true)
            .await
            .expect("Exists")[0]
            .clone();

    match command {
        OperatorCommands::GetDepositKeys {
            deposit_outpoint_txid,
            deposit_outpoint_vout,
        } => {
            println!(
                "Getting deposit keys for outpoint {}:{}",
                deposit_outpoint_txid, deposit_outpoint_vout
            );
            let params = clementine_core::rpc::clementine::DepositParams {
                security_council: Some(clementine::SecurityCouncil {
                    pks: vec![],
                    threshold: 0,
                }),
                deposit: Some(Deposit {
                    deposit_outpoint: Some(Outpoint {
                        txid: Some(clementine::Txid {
                            txid: hex::decode(deposit_outpoint_txid)
                                .expect("Failed to decode txid"),
                        }),
                        vout: deposit_outpoint_vout,
                    }),
                    deposit_data: Some(DepositData::BaseDeposit(BaseDeposit {
                        evm_address: vec![1; 20],
                        recovery_taproot_address: String::new(),
                    })),
                }),
                actors: Some(Actors::default()),
            };

            let response = operator
                .get_deposit_keys(Request::new(params))
                .await
                .expect("Failed to make a request");
            println!("Get deposit keys response: {:?}", response);
        }
        OperatorCommands::GetParams => {
            let params = operator
                .get_params(Empty {})
                .await
                .expect("Failed to make a request");
            println!("Operator params: {:?}", params);
        }
        OperatorCommands::Withdraw {
            withdrawal_id,
            input_signature,
            input_outpoint_txid,
            input_outpoint_vout,
            output_script_pubkey,
            output_amount,
        } => {
            println!("Processing withdrawal with id {}", withdrawal_id);

            let params = clementine_core::rpc::clementine::WithdrawParams {
                withdrawal_id,
                input_signature: input_signature.as_bytes().to_vec(),
                input_outpoint: Some(Outpoint {
                    txid: Some(clementine_core::rpc::clementine::Txid {
                        txid: hex::decode(input_outpoint_txid).expect("Failed to decode txid"),
                    }),
                    vout: input_outpoint_vout,
                }),
                output_script_pubkey: output_script_pubkey.as_bytes().to_vec(),
                output_amount,
            };
            operator
                .withdraw(Request::new(params))
                .await
                .expect("Failed to make a request");
        }
        OperatorCommands::Vergen => {
            let params = Empty {};
            let response = operator
                .vergen(Request::new(params))
                .await
                .expect("Failed to make a request");
            println!("Vergen response:\n{}", response.into_inner().response);
        }
    }
}
