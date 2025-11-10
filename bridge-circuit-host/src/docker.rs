use hex::ToHex;
use num_bigint::BigUint;
use num_traits::Num;
use risc0_groth16::{ProofJson, Seal};
use risc0_zkvm::sha::Digestible;
use risc0_zkvm::{
    sha::Digest, ReceiptClaim, SuccinctReceipt, SuccinctReceiptVerifierParameters, SystemState,
};
use risc0_zkvm::{Groth16Receipt, Groth16ReceiptVerifierParameters, InnerReceipt, Receipt};
use serde_json::Value;
use std::{
    env::consts::ARCH,
    fs,
    path::Path,
    process::{Command, Stdio},
};

use eyre::{eyre, ContextCompat, Result, WrapErr};
use tempfile::tempdir;
use tracing;

use crate::utils::to_json;

/// Convert a STARK proof to a SNARK proof. Taken from risc0-groth16 and modified slightly.
pub fn stark_to_bitvm2_g16(
    succinct_receipt: SuccinctReceipt<ReceiptClaim>,
    journal: &[u8],
) -> Result<(Seal, [u8; 31])> {
    let ident_receipt = risc0_zkvm::recursion::identity_p254(&succinct_receipt)
        .map_err(|e| eyre!("Failed to create identity receipt: {:?}", e))?;
    let identity_p254_seal_bytes = ident_receipt.get_seal_bytes();
    let receipt_claim = succinct_receipt
        .claim
        .value()
        .wrap_err("Failed to get receipt claim value")?;
    tracing::debug!("Journal for stark_to_bitvm2_g16: {:?}", journal);

    // This part is from risc0-groth16
    if !is_x86_architecture() {
        return Err(eyre!(
            "stark_to_snark is only supported on x86 architecture"
        ));
    }
    if !is_docker_installed() {
        return Err(eyre!("Please install docker first")); // Maybe check this at startup...
    }

    let tmp_dir = tempdir().wrap_err("Failed to create temporary directory")?;
    let work_var = std::env::var("RISC0_WORK_DIR").ok();
    let work_dir = work_var.as_ref().map(Path::new).unwrap_or(tmp_dir.path());
    tracing::debug!("work_dir: {:?}", work_dir);

    std::fs::write(work_dir.join("seal.r0"), identity_p254_seal_bytes.clone())
        .wrap_err("Failed to write seal file")?;
    let seal_path = work_dir.join("input.json");
    let proof_path = work_dir.join("proof.json");
    let output_path = work_dir.join("public.json");
    let mut seal_json = Vec::new();
    to_json(&*identity_p254_seal_bytes, &mut seal_json)
        .map_err(|e| eyre!("Failed to convert seal to JSON: {:?}", e))?;
    std::fs::write(seal_path.clone(), seal_json).wrap_err("Failed to write seal JSON")?;

    let pre_state: risc0_zkvm::MaybePruned<SystemState> = receipt_claim.clone().pre;
    tracing::debug!("pre_state: {:?}", pre_state);
    let pre_state_digest: Digest = pre_state.clone().digest();
    tracing::debug!("pre_state_digest: {:?}", pre_state_digest);
    let pre_state_digest_bits: Vec<String> = pre_state_digest
        .as_bytes()
        .iter()
        .flat_map(|&byte| (0..8).rev().map(move |i| ((byte >> i) & 1).to_string()))
        .collect();
    tracing::debug!("pre_state_digest_bits: {:?}", pre_state_digest_bits);
    let post_state: risc0_zkvm::MaybePruned<SystemState> = receipt_claim.clone().post;
    tracing::debug!("post_state: {:?}", post_state);
    let post_state_digest: Digest = post_state.clone().digest();
    let post_state_digest_bits: Vec<String> = post_state_digest
        .as_bytes()
        .iter()
        .flat_map(|&byte| (0..8).rev().map(move |i| ((byte >> i) & 1).to_string()))
        .collect();
    tracing::debug!("post_state_digest_bits: {:?}", post_state_digest_bits);

    let mut journal_bits = Vec::new();
    for byte in journal {
        for i in 0..8 {
            journal_bits.push((byte >> (7 - i)) & 1);
        }
    }
    tracing::debug!("journal_bits len: {:?}", journal_bits.len());

    let succinct_verifier_params = SuccinctReceiptVerifierParameters::default();
    tracing::debug!("Succinct verifier params: {:?}", succinct_verifier_params);
    let succinct_control_root = succinct_verifier_params.control_root;
    tracing::debug!("Succinct control root: {:?}", succinct_control_root);
    let mut succinct_control_root_bytes: [u8; 32] = succinct_control_root
        .as_bytes()
        .try_into()
        .wrap_err("Failed to convert succinct control root to 32 bytes")?;
    succinct_control_root_bytes.reverse();
    let succinct_control_root_bytes: String = succinct_control_root_bytes.encode_hex();
    let a1_str = succinct_control_root_bytes[0..32].to_string();
    let a0_str = succinct_control_root_bytes[32..64].to_string();
    tracing::debug!("Succinct control root a0: {:?}", a0_str);
    tracing::debug!("Succinct control root a1: {:?}", a1_str);
    let a0_dec = to_decimal(&a0_str)
        .ok_or_else(|| eyre!("Failed to convert succinct control root a0 to decimal"))?;
    let a1_dec = to_decimal(&a1_str)
        .ok_or_else(|| eyre!("Failed to convert succinct control root a1 to decimal"))?;
    tracing::debug!("Succinct control root a0 dec: {:?}", a0_dec);
    tracing::debug!("Succinct control root a1 dec: {:?}", a1_dec);
    tracing::debug!("CONTROL_ID: {:?}", ident_receipt.control_id);
    let mut id_bn254_fr_bits: Vec<String> = ident_receipt
        .control_id
        .as_bytes()
        .iter()
        .flat_map(|&byte| (0..8).rev().map(move |i| ((byte >> i) & 1).to_string()))
        .collect();
    tracing::debug!("id_bn254_fr_bits: {:?}", id_bn254_fr_bits);

    // remove 248th and 249th bits
    id_bn254_fr_bits.remove(248);
    id_bn254_fr_bits.remove(248);

    tracing::debug!(
        "id_bn254_fr_bits after removing 2 extra bits: {:?}",
        id_bn254_fr_bits
    );

    let mut seal_json: Value = {
        let file_content = fs::read_to_string(&seal_path).wrap_err("Failed to read seal file")?;
        serde_json::from_str(&file_content).wrap_err("Failed to parse seal JSON")?
    };

    seal_json["journal_digest_bits"] = journal_bits.into();
    seal_json["pre_state_digest_bits"] = pre_state_digest_bits.into();
    seal_json["post_state_digest_bits"] = post_state_digest_bits.into();
    seal_json["id_bn254_fr_bits"] = id_bn254_fr_bits.into();
    seal_json["control_root"] = vec![a0_dec, a1_dec].into();
    std::fs::write(
        seal_path,
        serde_json::to_string_pretty(&seal_json).wrap_err("Failed to write updated seal JSON")?,
    )
    .wrap_err("Failed to write seal file")?;

    let output = Command::new("podman")
        .arg("run")
        .arg("--pull=always")
        .arg("--rm")
        .arg("--platform=linux/amd64") // Force linux/amd64 platform
        .arg("-v")
        .arg(format!("{}:/mnt", work_dir.to_string_lossy()))
        .arg("docker.io/chainwayxyz/mainnet-risc0-bitvm2-groth16-prover@sha256:84b810479a6e9482a1827ba6ba7ccbd81f0420a5a7a19c7d256078f144b7737d")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .wrap_err("Failed to execute docker command")?;

    if !output.status.success() {
        return Err(eyre!(
            "STARK to SNARK prover docker image returned failure: {:?}",
            output
        ));
    }

    tracing::debug!("proof_path: {:?}", proof_path);
    let proof_content =
        std::fs::read_to_string(proof_path).wrap_err("Failed to read proof file")?;
    let output_content_dec =
        std::fs::read_to_string(output_path).wrap_err("Failed to read output file")?;
    let proof_json: ProofJson =
        serde_json::from_str(&proof_content).wrap_err("Failed to parse proof JSON")?;

    let parsed_json: Value =
        serde_json::from_str(&output_content_dec).wrap_err("Failed to parse output JSON")?;
    let output_str = parsed_json[0]
        .as_str()
        .ok_or_else(|| eyre!("Failed to get output string from JSON"))?;

    // Step 2: Convert the decimal string to BigUint and then to hexadecimal
    let output_content_hex = BigUint::from_str_radix(output_str, 10)
        .wrap_err("Failed to parse decimal string")?
        .to_str_radix(16);

    // If the length of the hexadecimal string is odd, add a leading zero
    let output_content_hex = if output_content_hex.len() % 2 == 0 {
        output_content_hex
    } else {
        format!("0{output_content_hex}")
    };

    // Step 3: Decode the hexadecimal string to a byte vector
    let output_byte_vec =
        hex::decode(&output_content_hex).wrap_err("Failed to decode hex string")?;
    let output_bytes: [u8; 31] = output_byte_vec
        .as_slice()
        .try_into()
        .wrap_err("Failed to convert output bytes to array")?;

    Ok((
        proof_json
            .try_into()
            .map_err(|e| eyre!("Failed to convert proof JSON to Seal: {:?}", e))?,
        output_bytes,
    ))
}

const ID_BN254_FR_BITS: [&str; 254] = [
    "1", "1", "0", "0", "0", "0", "0", "0", "0", "1", "1", "1", "1", "0", "1", "0", "0", "1", "1",
    "0", "0", "1", "0", "1", "0", "0", "0", "1", "0", "1", "0", "0", "0", "1", "0", "1", "1", "1",
    "0", "0", "0", "0", "1", "1", "1", "1", "0", "0", "1", "0", "1", "1", "0", "1", "0", "0", "1",
    "0", "0", "0", "1", "0", "1", "1", "0", "1", "1", "0", "0", "0", "0", "1", "0", "0", "0", "0",
    "0", "0", "0", "1", "1", "0", "0", "1", "0", "1", "1", "0", "0", "0", "1", "0", "1", "1", "1",
    "0", "1", "0", "1", "0", "0", "1", "1", "0", "0", "0", "0", "0", "0", "1", "1", "1", "1", "0",
    "1", "0", "0", "1", "0", "0", "1", "1", "0", "1", "1", "1", "0", "1", "1", "0", "0", "1", "0",
    "0", "1", "1", "1", "1", "0", "0", "0", "1", "1", "1", "0", "1", "0", "1", "0", "0", "1", "1",
    "1", "0", "1", "1", "1", "0", "1", "1", "0", "0", "1", "0", "0", "1", "1", "0", "1", "0", "0",
    "1", "0", "1", "1", "1", "0", "1", "0", "1", "1", "1", "0", "0", "1", "0", "1", "1", "0", "1",
    "0", "0", "0", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "0", "1", "0", "1", "1", "0",
    "0", "0", "0", "0", "0", "0", "0", "1", "1", "0", "1", "0", "0", "1", "1", "0", "1", "1", "0",
    "0", "1", "1", "0", "0", "1", "1", "0", "1", "1", "1", "0", "0", "1", "0", "0", "0", "1", "0",
    "0", "0", "0", "0", "1", "0", "0",
];

pub fn dev_stark_to_risc0_g16(receipt: Receipt, journal: &[u8]) -> Result<Receipt> {
    let identity_p254_seal_bytes = vec![0u8; 222668];
    let receipt_claim = receipt
        .claim()
        .wrap_err("Failed to get receipt claim")?
        .value()
        .wrap_err("Failed to get receipt claim value")?;

    // This part is from risc0-groth16
    if !is_x86_architecture() {
        return Err(eyre!(
            "stark_to_snark is only supported on x86 architecture"
        ));
    }
    if !is_docker_installed() {
        return Err(eyre!("Please install docker first"));
    }

    let tmp_dir = tempdir().wrap_err("Failed to create temporary directory")?;
    let work_var = std::env::var("RISC0_WORK_DIR").ok();
    let work_dir = work_var.as_ref().map(Path::new).unwrap_or(tmp_dir.path());
    tracing::debug!("work_dir: {:?}", work_dir);
    std::fs::write(work_dir.join("seal.r0"), identity_p254_seal_bytes.clone())
        .wrap_err("Failed to write seal file")?;
    let seal_path = work_dir.join("input.json");
    let proof_path = work_dir.join("proof.json");
    let _output_path = work_dir.join("public.json");

    let pre_state: risc0_zkvm::MaybePruned<SystemState> = receipt_claim.clone().pre;
    tracing::debug!("pre_state: {:?}", pre_state);
    let pre_state_digest: Digest = pre_state.clone().digest();
    tracing::debug!("pre_state_digest: {:?}", pre_state_digest);
    let pre_state_digest_bits: Vec<String> = pre_state_digest
        .as_bytes()
        .iter()
        .flat_map(|&byte| (0..8).rev().map(move |i| ((byte >> i) & 1).to_string()))
        .collect();
    tracing::debug!("pre_state_digest_bits: {:?}", pre_state_digest_bits);
    let post_state: risc0_zkvm::MaybePruned<SystemState> = receipt_claim.clone().post;
    tracing::debug!("post_state: {:?}", post_state);
    let post_state_digest: Digest = post_state.clone().digest();
    let post_state_digest_bits: Vec<String> = post_state_digest
        .as_bytes()
        .iter()
        .flat_map(|&byte| (0..8).rev().map(move |i| ((byte >> i) & 1).to_string()))
        .collect();
    tracing::debug!("post_state_digest_bits: {:?}", post_state_digest_bits);

    let journal_digest: Digest = journal.digest();

    let mut journal_digest_bits = Vec::new();
    for byte in journal_digest.as_bytes() {
        for i in 0..8 {
            journal_digest_bits.push((byte >> (7 - i)) & 1);
        }
    }
    tracing::debug!("journal_bits len: {:?}", journal_digest_bits.len());

    let succinct_verifier_params = SuccinctReceiptVerifierParameters::default();
    tracing::debug!("Succinct verifier params: {:?}", succinct_verifier_params);
    let succinct_control_root = succinct_verifier_params.control_root;
    tracing::debug!("Succinct control root: {:?}", succinct_control_root);
    let mut succinct_control_root_bytes: [u8; 32] = succinct_control_root
        .as_bytes()
        .try_into()
        .wrap_err("Failed to convert succinct control root to 32 bytes")?;
    succinct_control_root_bytes.reverse();
    let succinct_control_root_bytes: String = succinct_control_root_bytes.encode_hex();
    let a1_str = succinct_control_root_bytes[0..32].to_string();
    let a0_str = succinct_control_root_bytes[32..64].to_string();
    tracing::debug!("Succinct control root a0: {:?}", a0_str);
    tracing::debug!("Succinct control root a1: {:?}", a1_str);
    let a0_dec = to_decimal(&a0_str)
        .ok_or_else(|| eyre!("Failed to convert succinct control root a0 to decimal"))?;
    let a1_dec = to_decimal(&a1_str)
        .ok_or_else(|| eyre!("Failed to convert succinct control root a1 to decimal"))?;
    tracing::debug!("Succinct control root a0 dec: {:?}", a0_dec);
    tracing::debug!("Succinct control root a1 dec: {:?}", a1_dec);

    let id_bn254_fr_bits: Vec<String> = ID_BN254_FR_BITS
        .iter()
        .map(|&bit| bit.to_string())
        .collect();

    let mut seal_json: Value = serde_json::json!({});

    seal_json["journal_digest_bits"] = journal_digest_bits.into();
    seal_json["pre_state_digest_bits"] = pre_state_digest_bits.into();
    seal_json["post_state_digest_bits"] = post_state_digest_bits.into();
    seal_json["id_bn254_fr_bits"] = id_bn254_fr_bits.into();
    seal_json["control_root"] = vec![a0_dec, a1_dec].into();
    std::fs::write(
        seal_path,
        serde_json::to_string_pretty(&seal_json)
            .wrap_err("Failed to convert seal JSON to string")?,
    )
    .wrap_err("Failed to write seal file")?;

    // let output = Command::new("udocker")
    //     .arg("run")
    //     .arg("--pull=always")
    //     .arg("--rm")
    //     .arg("--platform=linux/amd64") // Force linux/amd64 platform
    //     .arg("-v")
    //     .arg(format!("{}:/mnt", work_dir.to_string_lossy()))
    //     .arg("docker.io/ozancw/dev-risc0-groth16-prover-const-digest-len@sha256:4e5c409998085a0edf37ebe4405be45178e8a7e78ea859d12c3d453e90d409cb")
    //     .stdout(Stdio::piped())
    //     .stderr(Stdio::piped())
    //     .output()
    //     .wrap_err("Failed to execute docker command")?;

    let image_digest = "docker.io/ozancw/dev-risc0-groth16-prover-const-digest-len@sha256:4e5c409998085a0edf37ebe4405be45178e8a7e78ea859d12c3d453e90d409cb";
    let container_name = "risc0_prover";
    let udocker_path = "udocker";

    // 1. Pull image by digest with Docker
    let output = Command::new("docker")
        .arg("pull")
        .arg(image_digest)
        .output()
        .context("Failed to pull docker image by digest")?;
    if !output.status.success() {
        return Err(eyre!("docker pull failed {:?}", output));
    }

    // 3. Save the tagged image to tar
    let output = Command::new("docker")
        .arg("save")
        .arg("-o")
        .arg("image-digest.tar")
        .arg(image_digest)
        .output()
        .context("Failed to save docker image to tar")?;
    if !output.status.success() {
        return Err(eyre!("docker save failed {:?}", output));
    }

    // 4. Load tar into udocker
    let output = Command::new(udocker_path)
        .arg("load")
        .arg("-i")
        .arg("image-digest.tar")
        .output()
        .context("Failed to load image into udocker")?;
    if !output.status.success() {
        return Err(eyre!("udocker load failed {:?}", output));
    }

    let output_str = String::from_utf8(output.stdout)?;
    let image_id_line = output_str
        .lines()
        .last()
        .ok_or_else(|| eyre!("No output lines from udocker load"))?;
    let image_id = image_id_line
        .trim_matches(&['[', ']', '\'', ' '][..])
        .to_string();
    tracing::info!("Loaded udocker image id: {image_id}");

    // 5. Create the container with P2 exec mode
    let create_output = Command::new(udocker_path)
        .arg("--allow-root")
        .arg("create")
        .arg(format!("--name={container_name}"))
        .arg(image_id)
        .output()
        .context("Failed to create udocker container")?;
    if !create_output.status.success() {
        return Err(eyre!("udocker create failed {:?}", create_output));
    }

    // 6. Setup execmode
    let setup_output = Command::new(udocker_path)
        .arg("--allow-root")
        .arg("setup")
        .arg("--execmode=P2")
        .arg(container_name)
        .output()
        .context("Failed to setup udocker container")?;
    if !setup_output.status.success() {
        return Err(eyre!("udocker setup failed {:?}", setup_output));
    }

    // 7. Run container with volume mount
    let output = Command::new(udocker_path)
        .arg("--allow-root")
        .arg("run")
        .arg("--rm")
        .arg("-v")
        .arg(format!("{}:/mnt", work_dir.to_string_lossy()))
        .arg(container_name)
        .output()
        .context("Failed to run udocker container")?;
    if !output.status.success() {
        return Err(eyre!(
            "STARK to SNARK prover docker image returned failure: {:?}",
            output
        ));
    }

    tracing::debug!("proof_path: {:?}", proof_path);
    let contents = std::fs::read_to_string(proof_path).wrap_err("Failed to read proof file")?;
    let proof_json: ProofJson =
        serde_json::from_str(&contents).wrap_err("Failed to parse proof JSON")?;
    let seal: Seal = proof_json
        .try_into()
        .map_err(|e| eyre!("Failed to convert proof JSON to Seal: {:?}", e))?;
    let g16_verifier_params = Groth16ReceiptVerifierParameters::default(); // This is incorrect, but should not matter as it is not used.
    let g16_receipt = Groth16Receipt::new(
        seal.to_vec(),
        risc0_zkvm::MaybePruned::Value(receipt_claim),
        g16_verifier_params.digest(),
    );
    let inner_receipt = InnerReceipt::Groth16(g16_receipt);
    Ok(Receipt::new(inner_receipt, journal.to_vec()))
}

const ID_BN254_FR_BITS_DEV_BRIDGE: [&str; 254] = [
    "1", "1", "0", "0", "0", "0", "0", "0", "0", "1", "1", "1", "1", "0", "1", "0", "0", "1", "1",
    "0", "0", "1", "0", "1", "0", "0", "0", "1", "0", "1", "0", "0", "0", "1", "0", "1", "1", "1",
    "0", "0", "0", "0", "1", "1", "1", "1", "0", "0", "1", "0", "1", "1", "0", "1", "0", "0", "1",
    "0", "0", "0", "1", "0", "1", "1", "0", "1", "1", "0", "0", "0", "0", "1", "0", "0", "0", "0",
    "0", "0", "0", "1", "1", "0", "0", "1", "0", "1", "1", "0", "0", "0", "1", "0", "1", "1", "1",
    "0", "1", "0", "1", "0", "0", "1", "1", "0", "0", "0", "0", "0", "0", "1", "1", "1", "1", "0",
    "1", "0", "0", "1", "0", "0", "1", "1", "0", "1", "1", "1", "0", "1", "1", "0", "0", "1", "0",
    "0", "1", "1", "1", "1", "0", "0", "0", "1", "1", "1", "0", "1", "0", "1", "0", "0", "1", "1",
    "1", "0", "1", "1", "1", "0", "1", "1", "0", "0", "1", "0", "0", "1", "1", "0", "1", "0", "0",
    "1", "0", "1", "1", "1", "0", "1", "0", "1", "1", "1", "0", "0", "1", "0", "1", "1", "0", "1",
    "0", "0", "0", "1", "1", "1", "1", "1", "1", "1", "1", "1", "1", "0", "1", "0", "1", "1", "0",
    "0", "0", "0", "0", "0", "0", "0", "1", "1", "0", "1", "0", "0", "1", "1", "0", "1", "1", "0",
    "0", "1", "1", "0", "0", "1", "1", "0", "1", "1", "1", "0", "0", "1", "0", "0", "0", "1", "0",
    "0", "0", "0", "0", "1", "0", "0",
];

pub fn stark_to_bitvm2_g16_dev_mode(receipt: Receipt, journal: &[u8]) -> Result<(Seal, [u8; 31])> {
    let identity_p254_seal_bytes = vec![0u8; 222668];
    let receipt_claim = receipt
        .claim()
        .wrap_err("Failed to get receipt claim")?
        .value()
        .wrap_err("Failed to get receipt claim value")?;

    // This part is from risc0-groth16
    if !is_x86_architecture() {
        return Err(eyre!(
            "stark_to_snark is only supported on x86 architecture"
        ));
    }
    if !is_docker_installed() {
        return Err(eyre!("Please install docker first"));
    }

    let tmp_dir = tempdir().wrap_err("Failed to create temporary directory")?;
    let work_var = std::env::var("RISC0_WORK_DIR").ok();
    let work_dir = work_var.as_ref().map(Path::new).unwrap_or(tmp_dir.path());
    tracing::debug!("work_dir: {:?}", work_dir);
    std::fs::write(work_dir.join("seal.r0"), identity_p254_seal_bytes.clone())
        .wrap_err("Failed to write seal file")?;
    let seal_path = work_dir.join("input.json");
    let proof_path = work_dir.join("proof.json");
    let output_path = work_dir.join("public.json");

    let pre_state: risc0_zkvm::MaybePruned<SystemState> = receipt_claim.clone().pre;
    tracing::debug!("pre_state: {:?}", pre_state);
    let pre_state_digest: Digest = pre_state.clone().digest();
    tracing::debug!("pre_state_digest: {:?}", pre_state_digest);
    let pre_state_digest_bits: Vec<String> = pre_state_digest
        .as_bytes()
        .iter()
        .flat_map(|&byte| (0..8).rev().map(move |i| ((byte >> i) & 1).to_string()))
        .collect();
    tracing::debug!("pre_state_digest_bits: {:?}", pre_state_digest_bits);
    let post_state: risc0_zkvm::MaybePruned<SystemState> = receipt_claim.clone().post;
    tracing::debug!("post_state: {:?}", post_state);
    let post_state_digest: Digest = post_state.clone().digest();
    let post_state_digest_bits: Vec<String> = post_state_digest
        .as_bytes()
        .iter()
        .flat_map(|&byte| (0..8).rev().map(move |i| ((byte >> i) & 1).to_string()))
        .collect();
    tracing::debug!("post_state_digest_bits: {:?}", post_state_digest_bits);

    let mut journal_bits = Vec::new();
    for byte in journal {
        for i in 0..8 {
            journal_bits.push((byte >> (7 - i)) & 1);
        }
    }
    tracing::debug!("journal_bits len: {:?}", journal_bits.len());

    let succinct_verifier_params = SuccinctReceiptVerifierParameters::default();
    tracing::debug!("Succinct verifier params: {:?}", succinct_verifier_params);
    let succinct_control_root = succinct_verifier_params.control_root;
    tracing::debug!("Succinct control root: {:?}", succinct_control_root);
    let mut succinct_control_root_bytes: [u8; 32] = succinct_control_root
        .as_bytes()
        .try_into()
        .wrap_err("Failed to convert succinct control root to 32 bytes")?;
    succinct_control_root_bytes.reverse();
    let succinct_control_root_bytes: String = succinct_control_root_bytes.encode_hex();
    let a1_str = succinct_control_root_bytes[0..32].to_string();
    let a0_str = succinct_control_root_bytes[32..64].to_string();
    tracing::debug!("Succinct control root a0: {:?}", a0_str);
    tracing::debug!("Succinct control root a1: {:?}", a1_str);
    let a0_dec = to_decimal(&a0_str)
        .ok_or_else(|| eyre!("Failed to convert succinct control root a0 to decimal"))?;
    let a1_dec = to_decimal(&a1_str)
        .ok_or_else(|| eyre!("Failed to convert succinct control root a1 to decimal"))?;
    tracing::debug!("Succinct control root a0 dec: {:?}", a0_dec);
    tracing::debug!("Succinct control root a1 dec: {:?}", a1_dec);

    let id_bn254_fr_bits: Vec<String> = ID_BN254_FR_BITS_DEV_BRIDGE
        .iter()
        .map(|&bit| bit.to_string())
        .collect();

    let mut seal_json: Value = serde_json::json!({});

    seal_json["journal_digest_bits"] = journal_bits.into();
    seal_json["pre_state_digest_bits"] = pre_state_digest_bits.into();
    seal_json["post_state_digest_bits"] = post_state_digest_bits.into();
    seal_json["id_bn254_fr_bits"] = id_bn254_fr_bits.into();
    seal_json["control_root"] = vec![a0_dec, a1_dec].into();
    std::fs::write(
        seal_path,
        serde_json::to_string_pretty(&seal_json)
            .wrap_err("Failed to convert seal JSON to string")?,
    )
    .wrap_err("Failed to write seal file")?;

    let output = Command::new("podman")
        .arg("run")
        .arg("--pull=always")
        .arg("--rm")
        .arg("--platform=linux/amd64") // Force linux/amd64 platform
        .arg("-v")
        .arg(format!("{}:/mnt", work_dir.to_string_lossy()))
        .arg("docker.io/ozancw/dev-risc0-to-bitvm2-groth16-prover@sha256:9f1d8515b9c44a1280979bbcab327ec36041fae6dd0c4923997f084605f9f9e7")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .wrap_err("Failed to execute docker command")?;

    if !output.status.success() {
        return Err(eyre!(
            "STARK to SNARK prover docker image returned failure: {:?}",
            output
        ));
    }

    tracing::debug!("proof_path: {:?}", proof_path);
    let proof_content =
        std::fs::read_to_string(proof_path).wrap_err("Failed to read proof file")?;
    let output_content_dec =
        std::fs::read_to_string(output_path).wrap_err("Failed to read output file")?;
    tracing::debug!("output content: {:?}", output_content_dec);
    let proof_json: ProofJson =
        serde_json::from_str(&proof_content).wrap_err("Failed to parse proof JSON")?;

    // Convert output_content_dec from decimal to hex
    let parsed_json: Value =
        serde_json::from_str(&output_content_dec).wrap_err("Failed to parse output JSON")?;
    let output_str = parsed_json[0]
        .as_str()
        .wrap_err("Failed to get output string from JSON")?; // Extracts the string from the JSON array

    // Step 2: Convert the decimal string to BigUint and then to hexadecimal
    let output_content_hex = BigUint::from_str_radix(output_str, 10)
        .wrap_err("Failed to parse decimal string")?
        .to_str_radix(16);

    // If the length of the hexadecimal string is odd, add a leading zero
    let output_content_hex = if output_content_hex.len() % 2 == 0 {
        output_content_hex
    } else {
        format!("0{output_content_hex}")
    };

    // Step 3: Decode the hexadecimal string to a byte vector
    let output_byte_vec =
        hex::decode(&output_content_hex).wrap_err("Failed to decode hex string")?;
    // Create our target 31-byte array, initialized to all zeros.
    let mut output_bytes = [0u8; 31];

    // Calculate the starting position in the destination array.
    // This ensures the bytes are right-aligned, effectively padding with leading zeros.
    let start_index = 31 - output_byte_vec.len();

    // Copy the decoded bytes from the vector into the correct slice of the array.
    output_bytes[start_index..].copy_from_slice(&output_byte_vec);
    Ok((
        proof_json
            .try_into()
            .map_err(|e| eyre!("Failed to convert proof JSON to Seal: {:?}", e))?,
        output_bytes,
    ))
}

fn is_docker_installed() -> bool {
    Command::new("docker")
        .arg("--version")
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false)
}

fn is_x86_architecture() -> bool {
    ARCH == "x86_64" || ARCH == "x86"
}

pub fn to_decimal(s: &str) -> Option<String> {
    let int = BigUint::from_str_radix(s, 16).ok();
    int.map(|n| n.to_str_radix(10))
}
