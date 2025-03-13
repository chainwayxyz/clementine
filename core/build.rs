use std::{env, path::Path, process::Command};

fn trim_ascii_end(s: &str) -> &str {
    let trimmed_len = s
        .as_bytes()
        .iter()
        .rposition(|&b| !b.is_ascii_whitespace())
        .map_or(0, |pos| pos + 1);
    &s[..trimmed_len]
}

fn compile_protobuf() {
    // Try to set PROTOC env var if on *nix.
    if let Ok(output) = Command::new("which").args(["protoc"]).output() {
        // Skip compilation, if command failed.
        if !output.status.success() {
            return;
        }

        // Set env var.
        let path = String::from_utf8_lossy(&output.stdout);
        env::set_var("PROTOC", trim_ascii_end(&path));
    }

    // Skip compilation if env var is not set.
    if env::var("PROTOC").is_err() {
        return;
    };

    let proto_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/rpc/");
    let protos = &["clementine.proto"];

    let proto_files: Vec<String> = protos
        .iter()
        .map(|proto| {
            proto_root
                .join(proto)
                .to_str()
                .expect("proto_root is not a valid path")
                .to_owned()
        })
        .collect();

    // Tell Cargo that if a proto file changes, rerun this build script.
    for pf in &proto_files {
        println!("cargo:rerun-if-changed={}", pf);
    }

    // Compile server and client code from proto files
    tonic_build::configure()
        .build_server(true)
        .build_client(true)
        .type_attribute(
            "clementine.KickoffId",
            "#[derive(Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize)]",
        )
        .out_dir("./src/rpc")
        .compile_protos(
            &proto_files,
            &[proto_root.to_str().expect("proto_root is not a valid path")],
        )
        .expect("Failed to compile protos");
}

fn main() {
    compile_protobuf();
}
