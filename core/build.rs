use std::{
    env,
    path::{Path, PathBuf},
    process::Command,
};

use vergen_git2::{BuildBuilder, CargoBuilder, Emitter, Git2Builder, RustcBuilder, SysinfoBuilder};

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
        .out_dir("./src/rpc")
        .compile_protos(
            &proto_files,
            &[proto_root.to_str().expect("proto_root is not a valid path")],
        )
        .expect("Failed to compile protos");
}

fn main() {
    compile_protobuf();
    let build = BuildBuilder::all_build().expect("Failed to build build instructions");
    let cargo = CargoBuilder::all_cargo().expect("Failed to build cargo instructions");
    let git2 = Git2Builder::default()
        .all()
        .repo_path(PathBuf::from("..").into()) // .git folder is in the workspace folder
        .build()
        .expect("Failed to build git2 instructions");
    let rustc = RustcBuilder::all_rustc().expect("Failed to build rustc instructions");
    let si = SysinfoBuilder::all_sysinfo().expect("Failed to build sysinfo instructions");

    Emitter::default()
        .add_instructions(&build)
        .expect("Failed to add build instructions")
        .add_instructions(&cargo)
        .expect("Failed to add cargo instructions")
        .add_instructions(&git2)
        .expect("Failed to add git instructions")
        .add_instructions(&rustc)
        .expect("Failed to add rustc instructions")
        .add_instructions(&si)
        .expect("Failed to add sysinfo instructions")
        .emit()
        .expect("Failed to emit vergen");
}
