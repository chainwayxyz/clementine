#[derive(Subcommand)]
pub enum VerifierCommands {
    /// Get verifier parameters
    GetParams,
    /// Generate nonces
    NonceGen {
        #[arg(long)]
        num_nonces: u32,
    },
    /// Get vergen build information
    Vergen,
    // /// Set verifier public keys
    // SetVerifiers {
    //     #[arg(long, num_args = 1.., value_delimiter = ',')]
    //     public_keys: Vec<String>,
    // },
    // Add other verifier commands as needed
}

pub async fn handle_verifier_call(url: String, command: VerifierCommands) {
    println!("Connecting to verifier at {}", url);
    let config = create_minimal_config();
    let mut verifier =
        clementine_core::rpc::get_clients(vec![url], ClementineVerifierClient::new, &config, true)
            .await
            .expect("Exists")[0]
            .clone();

    match command {
        VerifierCommands::GetParams => {
            let params = verifier
                .get_params(Empty {})
                .await
                .expect("Failed to make a request");
            println!("Verifier params: {:?}", params);
        }
        VerifierCommands::NonceGen { num_nonces } => {
            let params = clementine_core::rpc::clementine::NonceGenRequest { num_nonces };
            let response = verifier
                .nonce_gen(Request::new(params))
                .await
                .expect("Failed to make a request");
            println!("Noncegen response: {:?}", response);
        }
        VerifierCommands::Vergen => {
            let params = Empty {};
            let response = verifier
                .vergen(Request::new(params))
                .await
                .expect("Failed to make a request");
            println!("Vergen response:\n{}", response.into_inner().response);
        }
    }
}
