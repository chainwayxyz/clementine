use risc0_binfmt::compute_image_id;
use risc0_build::{embed_methods_with_options, DockerOptionsBuilder, GuestOptionsBuilder};
use std::{collections::HashMap, env, fs};

fn main() {
    // Build environment variables
    println!("cargo:rerun-if-env-changed=SKIP_GUEST_BUILD");
    println!("cargo:rerun-if-env-changed=REPR_GUEST_BUILD");
    println!("cargo:rerun-if-env-changed=OUT_DIR");

    // Compile time constant environment variables
    println!("cargo:rerun-if-env-changed=BITCOIN_NETWORK");
    println!("cargo:rerun-if-env-changed=TEST_SKIP_GUEST_BUILD");

    // Check if we should skip the guest build for tests
    if let Ok("1" | "true") = env::var("TEST_SKIP_GUEST_BUILD").as_deref() {
        println!("cargo:warning=Skipping guest build in test. Exiting");
        return;
    }

    let network = env::var("BITCOIN_NETWORK").unwrap_or_else(|_| {
        println!("cargo:warning=BITCOIN_NETWORK not set, defaulting to 'mainnet'");
        "mainnet".to_string()
    });

    let bridge_circuit_mode = env::var("BRIDGE_CIRCUIT_MODE").unwrap_or_else(|_| {
        println!("cargo:warning=BUILD_TYPE not set, defaulting to 'test'");
        "test".to_string()
    });

    let is_repr_guest_build = match env::var("REPR_GUEST_BUILD") {
        Ok(value) => match value.as_str() {
            "1" | "true" => {
                println!("cargo:warning=REPR_GUEST_BUILD is set to true");
                true
            }
            "0" | "false" => {
                println!("cargo:warning=REPR_GUEST_BUILD is set to false");
                false
            }
            _ => {
                println!("cargo:warning=Invalid value for REPR_GUEST_BUILD: '{}'. Expected '0', '1', 'true', or 'false'. Defaulting to false.", value);
                false
            }
        },
        Err(env::VarError::NotPresent) => {
            println!("cargo:warning=REPR_GUEST_BUILD not set. Defaulting to false.");
            false
        }
        Err(env::VarError::NotUnicode(_)) => {
            println!(
                "cargo:warning=REPR_GUEST_BUILD contains invalid Unicode. Defaulting to false."
            );
            false
        }
    };

    println!("cargo:warning=Building for Bitcoin network: {}", network);

    // Use embed_methods_with_options with our custom options
    let guest_pkg_to_options = get_guest_options(network.clone(), bridge_circuit_mode.clone());
    embed_methods_with_options(guest_pkg_to_options);

    if is_repr_guest_build {
        copy_binary_to_elfs_folder(network, bridge_circuit_mode);
        println!("cargo:warning=Copying binary to elfs folder");
    } else {
        println!("cargo:warning=Not copying binary to elfs folder");
    }
}

fn get_guest_options(
    network: String,
    bridge_circuit_mode: String,
) -> HashMap<&'static str, risc0_build::GuestOptions> {
    let mut guest_pkg_to_options = HashMap::new();

    let opts = if env::var("REPR_GUEST_BUILD").is_ok() {
        let current_dir = env::current_dir().expect("Failed to get current dir");
        let current_dir = current_dir.to_str().expect("Failed to convert path to str");
        let root_dir = format!("{current_dir}/../..");

        let docker_opts = DockerOptionsBuilder::default()
            .root_dir(root_dir)
            .env(vec![
                ("BITCOIN_NETWORK".to_string(), network.clone()),
                (
                    "BRIDGE_CIRCUIT_MODE".to_string(),
                    bridge_circuit_mode.to_string(),
                ),
            ])
            .build()
            .unwrap();

        println!(
            "cargo:warning=Root dir: {}",
            docker_opts.root_dir().display()
        );

        GuestOptionsBuilder::default()
            .use_docker(docker_opts)
            .build()
            .unwrap()
    } else {
        println!("cargo:warning=Guest code is not built in docker");
        GuestOptionsBuilder::default()
            .build()
            .unwrap()
    };

    guest_pkg_to_options.insert("bridge-circuit-guest", opts);
    guest_pkg_to_options
}

fn copy_binary_to_elfs_folder(network: String, bridge_circuit_mode: String) {
    let current_dir = env::current_dir().expect("Failed to get current dir");
    let base_dir = current_dir.join("../..");

    let elfs_dir = base_dir.join("risc0-circuits/elfs");

    if !elfs_dir.exists() {
        fs::create_dir_all(&elfs_dir).expect("Failed to create elfs directory");
        println!("cargo:warning=Created elfs directory at {:?}", elfs_dir);
    }

    let src_path = base_dir.join("target/riscv-guest/bridge-circuit/bridge-circuit-guest/riscv32im-risc0-zkvm-elf/docker/bridge-circuit-guest.bin");
    if !src_path.exists() {
        println!(
            "cargo:warning=Source binary not found at {:?}, skipping copy",
            src_path
        );
        return;
    }
    
    let dest_filename = if bridge_circuit_mode == "test" {
        format!("test-{}-bridge-circuit-guest.bin", network.to_lowercase())
    } else {
        format!("{}-bridge-circuit-guest.bin", network.to_lowercase())
    };

    let dest_path = elfs_dir.join(&dest_filename);

    match fs::copy(&src_path, &dest_path) {
        Ok(_) => println!(
            "cargo:warning=Successfully copied binary to {:?}",
            dest_path
        ),
        Err(e) => println!("cargo:warning=Failed to copy binary: {}", e),
    }
}
