use clap::Parser;
use clementine_core::config::BridgeConfig;
use crypto_bigint::rand_core::OsRng;
use secp256k1::PublicKey;
use secp256k1::SecretKey;
use std::str::FromStr;

/// This program processes an array of port numbers provided via command line.
#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Cli {
    /// A TOML formatted configuration file to be used
    #[clap(short, long, value_parser)]
    config_file: String,
    /// A comma-separated list of port numbers
    #[clap(short, long, value_parser)]
    ports: String,
    /// Folder path to store the configuration files
    #[clap(short, long, value_parser)]
    folder: String,
}

fn main() {
    let cli = Cli::parse();

    let ports: Vec<u16> = cli
        .ports
        .split(',')
        .map(|s| u16::from_str(s.trim()).expect("Failed to parse port"))
        .collect();

    let num_verifiers = ports.len();

    let secp: secp256k1::Secp256k1<secp256k1::All> = bitcoin::secp256k1::Secp256k1::new();
    let rng = &mut OsRng;

    let (secret_keys, public_keys): (Vec<SecretKey>, Vec<PublicKey>) = (0..num_verifiers)
        .map(|_| {
            let secret_key = secp256k1::SecretKey::new(rng);
            let public_key = secp256k1::PublicKey::from_secret_key(&secp, &secret_key);
            (secret_key, public_key)
        })
        .unzip();

    let cur_config = BridgeConfig::try_parse_file(cli.config_file.into()).unwrap();

    for i in 0..num_verifiers {
        let mut new_config = BridgeConfig {
            secret_key: secret_keys[i],
            verifiers_public_keys: public_keys.clone(),
            num_verifiers,
            port: ports[i],
            ..cur_config.clone()
        };
        if i == num_verifiers - 1 {
            new_config.verifier_endpoints = Some(
                ports[0..ports.len() - 1]
                    .iter()
                    .map(|p| format!("http://{}:{}", cur_config.host, p))
                    .collect(),
            );
        }
        // save the configuration file
        let file_name = format!("{}/config_{}.toml", cli.folder, i);

        toml::to_string_pretty(&new_config)
            .map(|s| std::fs::write(file_name.clone(), s).unwrap())
            .unwrap();
        if i < num_verifiers - 1 {
            println!("cargo run --bin verifier {}", file_name);
        } else {
            println!("cargo run --bin operator {}", file_name);
        }
    }
    println!(
        "VERIFIER_PKS={}",
        public_keys
            .iter()
            .map(|pk| pk.to_string())
            .collect::<Vec<String>>()
            .join(",")
    );
    println!(
        "OPERATOR_URL=http://{}:{}",
        cur_config.host,
        ports[num_verifiers - 1]
    );
}
