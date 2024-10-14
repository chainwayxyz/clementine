use std::path::Path;

fn compile_protobuf() {
    let proto_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/rpc/");
    let protos = &["clementine.proto"];

    let proto_files: Vec<String> = protos
        .iter()
        .map(|proto| proto_root.join(proto).to_str().unwrap().to_owned())
        .collect();

    // Compile server and client code from proto files
    if let Err(e) = tonic_build::configure()
        .build_server(true)
        .build_client(true)
        .out_dir("./src/rpc")
        .compile_protos(&proto_files, &[proto_root.to_str().unwrap()]) 
    {
        panic!("Failed to compile protos: {}", e);
    }
}

fn main() {
    compile_protobuf();
}
