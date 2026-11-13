//! Download the pinned SP1 Groth16 artifacts before timed proving tests.

#[tokio::main]
async fn main() -> eyre::Result<()> {
    sp1_sdk::utils::setup_logger();
    let path = sp1_sdk::install::try_install_circuit_artifacts("groth16")
        .await
        .map_err(|err| eyre::eyre!("{err:#}"))?;
    println!(
        "SP1 {} Groth16 proving artifacts ready at {}",
        sp1_sdk::SP1_CIRCUIT_VERSION,
        path.display()
    );
    Ok(())
}
