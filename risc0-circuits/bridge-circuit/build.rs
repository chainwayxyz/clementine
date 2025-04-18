use std::env;
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=bridge_circuit_build.dockerfile");
    std::env::remove_var("RUSTC_WORKSPACE_WRAPPER");

    if env::var("REPR_GUEST_BUILD").is_ok() {
        // Get the absolute path to the project root
        let current_dir = env::current_dir().expect("Failed to get current directory");
        let project_root = current_dir.parent().unwrap().parent().unwrap();
        let output_dir = project_root.join("target/riscv-guest/riscv32im-risc0-zkvm-elf/docker");

        eprintln!("Current directory: {:?}", current_dir);
        eprintln!("Project root: {:?}", project_root);
        eprintln!("Output directory: {:?}", output_dir);

        // Ensure the output directory exists
        std::fs::create_dir_all(&output_dir).expect("Failed to create output directory");

        let output = Command::new("docker")
            .args([
                "buildx",
                "build",
                "--platform",
                "linux/amd64",
                "-f",
                "build-files/bridge_circuit_build.dockerfile",
                "--no-cache",
                // "--target",
                // "test",
                "--output",
                "type=local,dest=.",
                ".", // Use current directory as context
                "--build-arg",
                &format!(
                    "BITCOIN_NETWORK={}",
                    std::env::var("BITCOIN_NETWORK").unwrap().as_str()
                ),
                "--build-arg",
                &format!(
                    "BRIDGE_CIRCUIT_MODE={}",
                    std::env::var("BRIDGE_CIRCUIT_MODE").unwrap().as_str()
                ),
            ])
            .current_dir(project_root) // Set working directory to project root
            .output()
            .expect("Failed to execute Docker command");

        // println!("stdout: {}", String::from_utf8_lossy(&output.stdout));

        if !output.status.success() {
            eprintln!("Docker build failed:");
            eprintln!("stdout: {}", String::from_utf8_lossy(&output.stdout));
            eprintln!("stderr: {}", String::from_utf8_lossy(&output.stderr));
            panic!("Docker build failed");
        }
    }

    risc0_build::embed_methods();
}
