use risc0_binfmt::compute_image_id;
use risc0_build::{embed_methods, embed_methods_with_options, DockerOptionsBuilder, GuestOptionsBuilder};
use std::{collections::HashMap, env, fs, path::Path};

fn main() {
    // Build environment variables
    println!("cargo:rerun-if-env-changed=SKIP_GUEST_BUILD");
    println!("cargo:rerun-if-env-changed=REPR_GUEST_BUILD");
    println!("cargo:rerun-if-env-changed=OUT_DIR");

    // Compile time constant environment variables
    println!("cargo:rerun-if-env-changed=BITCOIN_NETWORK");
    println!("cargo:rerun-if-env-changed=TEST_SKIP_GUEST_BUILD");

    if std::env::var("CLIPPY_ARGS").is_ok() {
        println!("cargo:warning=Skipping guest build in Clippy");
        return;
    }

    // Check if we should skip the guest build for tests
    if let Ok("1" | "true") = env::var("TEST_SKIP_GUEST_BUILD").as_deref() {
        println!("cargo:warning=Skipping guest build in test. Exiting");
        return;
    }

    let network = env::var("BITCOIN_NETWORK").unwrap_or_else(|_| {
        println!("cargo:warning=BITCOIN_NETWORK not set, defaulting to 'mainnet'");
        "mainnet".to_string()
    });
    println!("cargo:warning=Building for Bitcoin network: {}", network);

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

    // Use embed_methods_with_options with our custom options
    let guest_pkg_to_options = get_guest_options(network.clone());
    embed_methods_with_options(guest_pkg_to_options);

    // After the build is complete, copy the generated file to the elfs folder
    if is_repr_guest_build {
        println!("cargo:warning=Copying binary to elfs folder");
        copy_binary_to_elfs_folder(network);
    } else {
        println!("cargo:warning=Not copying binary to elfs folder");
    }
}

fn get_guest_options(network: String) -> HashMap<&'static str, risc0_build::GuestOptions> {
    let mut guest_pkg_to_options = HashMap::new();

    let opts = if env::var("REPR_GUEST_BUILD").is_ok() {
        let current_dir = env::current_dir().expect("Failed to get current dir");
        let current_dir = current_dir.to_str().expect("Failed to convert path to str");
        let root_dir = format!("{current_dir}/../..");

        println!(
            "cargo:warning=Using Docker for guest build with root dir: {}",
            root_dir
        );

        let docker_opts = DockerOptionsBuilder::default()
            .root_dir(root_dir)
            .env(vec![("BITCOIN_NETWORK".to_string(), network.clone())])
            .build()
            .unwrap();

        GuestOptionsBuilder::default()
            // .features(features)
            .use_docker(docker_opts)
            .build()
            .unwrap()
    } else {
        println!("cargo:warning=Guest code is not built in docker");
        GuestOptionsBuilder::default()
            // .features(features)
            .build()
            .unwrap()
    };

    guest_pkg_to_options.insert("work-only-guest", opts);
    guest_pkg_to_options
}

fn copy_binary_to_elfs_folder(network: String) {
    let current_dir = env::current_dir().expect("Failed to get current dir");
    let base_dir = current_dir.join("../..");

    // Create elfs directory if it doesn't exist
    let elfs_dir = base_dir.join("risc0-circuits/elfs");
    if !elfs_dir.exists() {
        fs::create_dir_all(&elfs_dir).expect("Failed to create elfs directory");
        println!("cargo:warning=Created elfs directory at {:?}", elfs_dir);
    }

    // Build source path
    let src_path = base_dir.join("target/riscv-guest/work-only/work-only-guest/riscv32im-risc0-zkvm-elf/docker/work-only-guest.bin");
    if !src_path.exists() {
        println!(
            "cargo:warning=Source binary not found at {:?}, skipping copy",
            src_path
        );
        return;
    }

    // Build destination path with network prefix
    let dest_filename = format!("{}-work-only-guest.bin", network.to_lowercase());
    let dest_path = elfs_dir.join(&dest_filename);

    // Copy the file
    match fs::copy(&src_path, &dest_path) {
        Ok(_) => println!(
            "cargo:warning=Successfully copied binary to {:?}",
            dest_path
        ),
        Err(e) => println!("cargo:warning=Failed to copy binary: {}", e),
    }

    let elf_path = match network.as_str() {
        "mainnet" => "../elfs/mainnet-work-only-guest.bin",
        "testnet4" => "../elfs/testnet4-work-only-guest.bin",
        "signet" => "../elfs/signet-work-only-guest.bin",
        "regtest" => "../elfs/regtest-work-only-guest.bin",
        _ => {
            println!("cargo:warning=Invalid network specified, defaulting to mainnet");
            "../elfs/mainnet-work-only-guest.bin"
        }
    };

    let elf_bytes: Vec<u8> = fs::read(Path::new(elf_path)).expect("Failed to read ELF file");

    let method_id = compute_image_id(elf_bytes.as_slice()).unwrap();
    println!("cargo:warning=Computed method ID: {:x?}", method_id);
    println!(
        "cargo:warning=Computed method ID words: {:?}",
        method_id.as_words()
    );
}
