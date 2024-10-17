use std::{env, path::Path, process::Command};

fn compile_protobuf() {
    // Try to set PROTOC env var if on *nix.
    if let Ok(output) = Command::new("which").args(["protoc"]).output() {
        // Skip compilation, if command failed.
        if !output.status.success() {
            return;
        }

        // Set env var.
        let path = String::from_utf8_lossy(&output.stdout);
        env::set_var("PROTOC", path.into_owned().trim_ascii_end());
    }

    // Skip compilation if env var is not set.
    if env::var("PROTOC").is_err() {
        return;
    };

    let proto_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/rpc/");
    let protos = &["clementine.proto"];

    let proto_files: Vec<String> = protos
        .iter()
        .map(|proto| proto_root.join(proto).to_str().unwrap().to_owned())
        .collect();

    // Tell Cargo that if a proto file changes, rerun this build script.
    for pf in &proto_files {
        println!("cargo:rerun-if-changed={}", pf);
    }

    // Compile server and client code from proto files
    tonic_build::configure()
        .build_server(true)
        .build_client(true)
        .out_dir("./src/rpc")
        .compile_protos(&proto_files, &[proto_root.to_str().unwrap()])
        .unwrap();
}

fn main() {
    compile_protobuf();
}
