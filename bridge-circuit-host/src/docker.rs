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
    path::{Path, PathBuf},
    process::Command,
    sync::Mutex,
};
use tar::{Archive, Builder};

use eyre::{eyre, ContextCompat, Result, WrapErr};
use tempfile::tempdir;
use tracing;

use crate::utils::{is_dev_mode, to_json};

/// Image .tar files are stored in the ~/.clementine/IMAGES_SUBDIR directory.
const IMAGES_SUBDIR: &str = "images";
const STARK_TO_BITVM2_IMAGE_DIGEST: &str =
    "docker.io/chainwayxyz/mainnet-risc0-bitvm2-groth16-prover@sha256:84b810479a6e9482a1827ba6ba7ccbd81f0420a5a7a19c7d256078f144b7737d";
const DEV_STARK_TO_BITVM2_IMAGE_DIGEST: &str =
    "docker.io/ozancw/dev-risc0-to-bitvm2-groth16-prover@sha256:9f1d8515b9c44a1280979bbcab327ec36041fae6dd0c4923997f084605f9f9e7";
const DEV_STARK_TO_RISC0_G16_IMAGE_DIGEST: &str =
    "docker.io/ozancw/dev-risc0-groth16-prover-const-digest-len@sha256:4e5c409998085a0edf37ebe4405be45178e8a7e78ea859d12c3d453e90d409cb";
/// The config digests of the images
const STARK_TO_BITVM2_IMAGE_CONFIG_DIGEST: &str =
    "sha256:d92388157eeffac9323a942d46e14c36da4cd60e963b38f322fd66a3f5bcec39";
const DEV_STARK_TO_BITVM2_IMAGE_CONFIG_DIGEST: &str =
    "sha256:b2530a96a882132e407f7b75327c264aa68858bf68a431911642c655bd623091";
const DEV_STARK_TO_RISC0_G16_IMAGE_CONFIG_DIGEST: &str =
    "sha256:b2cde230ad4c37c6f71b54ed3415bb7d20d99f9e9f71be0645a313a9a68dc40e";

// NOTE: Keep container names unique to prevent udocker collisions between images.
const STARK_TO_BITVM2_CONTAINER_NAME: &str = "clementine_bitvm2_prover";
const DEV_STARK_TO_BITVM2_CONTAINER_NAME: &str = "clementine_dev_bitvm2_prover";
const DEV_STARK_TO_RISC0_G16_CONTAINER_NAME: &str = "clementine_dev_risc0_prover";

/// Mutex to ensure only one docker operation runs at a time
/// This prevents conflicts when RISC0_WORK_DIR is set and multiple functions run concurrently
/// Also in tests where multiple verifiers/operators are running concurrently, this mutex protects the skopeo/udocker operations from conflicting.
static DOCKER_MUTEX: std::sync::OnceLock<Mutex<()>> = std::sync::OnceLock::new();

fn get_docker_mutex() -> &'static Mutex<()> {
    DOCKER_MUTEX.get_or_init(|| Mutex::new(()))
}

/// Convert a STARK proof to a SNARK proof. Taken from risc0-groth16 and modified slightly.
pub fn stark_to_bitvm2_g16(
    succinct_receipt: SuccinctReceipt<ReceiptClaim>,
    journal: &[u8],
) -> Result<(Seal, [u8; 31])> {
    // Acquire the mutex to ensure only one docker operation runs at a time
    // This prevents conflicts when RISC0_WORK_DIR is set and multiple functions run concurrently
    let _guard = get_docker_mutex()
        .lock()
        .map_err(|e| eyre!("Failed to acquire docker mutex: {e:?}"))?;

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

    run_prover_container(
        STARK_TO_BITVM2_IMAGE_DIGEST,
        STARK_TO_BITVM2_CONTAINER_NAME,
        STARK_TO_BITVM2_IMAGE_CONFIG_DIGEST,
        work_dir,
    )?;

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

/// Repackages a Docker/OCI image tarball by removing symlinks and copying the files directly to the locations where symlinks would be.  
///  
/// # Problem Solved  
/// This function addresses a known issue with udocker (`udocker load`), where Docker images containing identical layers represented as symlinks can cause failures or incorrect behavior.  
/// See: https://github.com/indigo-dc/udocker/issues/361  
///  
/// # Caching Strategy  
/// - The function creates a modified tar file (with symlinks removed) in the same directory as the original, appending `_no_symlinks.tar` to the filename.  
/// - If a cached version exists, its modification time is checked to ensure it is newer than the original.  
/// - If the modification time is valid, the cached tar's digest is verified against the expected config digest.  
/// - If digest verification fails, the cached file is deleted and recomputed.  
/// - The original tar file is never modified; only the cached file is updated or recreated as needed.  
///  
/// # Security Considerations  
/// - Symlink resolution is performed to ensure that files are copied directly, preventing potential symlink attacks or unintended file access.  
/// - Digest verification is used to detect tampering or corruption of the cached tar file.  
/// - If digest verification fails, the cache is deleted to prevent use of a potentially compromised file.  
///  
/// # Error Conditions  
/// - Returns an error if the tar file name or parent directory is invalid.  
/// - Returns an error if file metadata cannot be read or if file operations (copy, delete) fail.  
/// - Returns an error if digest verification fails or if the cache cannot be recreated.  
///  
/// # Returns  
/// Returns the path to the modified (no-symlinks) tar file.  
fn remove_symlinks_from_image_tar(path: &Path, expected_config_digest: &str) -> Result<PathBuf> {
    // Determine cache file path in the same directory as the original tar
    let cache_file_name = path
        .file_stem()
        .and_then(|s| s.to_str())
        .ok_or_else(|| eyre!("Invalid tar file name: {path:?}"))?
        .to_string()
        + "_no_symlinks.tar";
    let cached_tar_path = path
        .parent()
        .ok_or_else(|| eyre!("Tar file has no parent directory: {path:?}"))?
        .join(&cache_file_name);

    // Check if cached version exists, check modification time first (cheap), then verify digest if needed
    let use_cache = if cached_tar_path.exists() {
        // First check modification time (cheap operation)
        let cached_metadata = fs::metadata(&cached_tar_path).wrap_err(format!(
            "Failed to get cached tar metadata: {cached_tar_path:?}"
        ))?;
        let original_metadata = fs::metadata(path)
            .wrap_err(format!("Failed to get original tar metadata: {path:?}"))?;

        // Compare modification times - only proceed with digest verification if cache is newer
        let mtime_valid = match (cached_metadata.modified(), original_metadata.modified()) {
            (Ok(cached_mtime), Ok(original_mtime)) => cached_mtime >= original_mtime,
            _ => false,
        };

        if !mtime_valid {
            tracing::debug!(
                "Cached tar is older than original or modification time unavailable, will reprocess: {cached_tar_path:?}"
            );
            false
        } else {
            // Modification time is valid, now verify digest (expensive operation)
            match verify_tar_image_digest(&cached_tar_path, expected_config_digest) {
                Ok(()) => {
                    tracing::debug!("Cached tar digest verified: {cached_tar_path:?}");
                    tracing::debug!("Using cached no-symlinks tar file: {cached_tar_path:?}");
                    true
                }
                Err(e) => {
                    tracing::warn!(
                        "Cached tar digest verification failed (file may be corrupted or tampered), will delete and recompute: {cached_tar_path:?}, error: {}",
                        e
                    );
                    // Delete the invalid cached file
                    fs::remove_file(&cached_tar_path).wrap_err(format!(
                        "Failed to delete invalid cached tar: {cached_tar_path:?}"
                    ))?;
                    false
                }
            }
        }
    } else {
        tracing::debug!("No cached tar file found, will process: {cached_tar_path:?}");
        false
    };

    // If cache is valid, return it directly
    if use_cache {
        return Ok(cached_tar_path);
    }

    // Create a temporary directory for processing - everything happens here, then we move the final file out
    let tmp_dir = tempdir().wrap_err(format!(
        "Failed to create temporary directory for processing tar file: {path:?}"
    ))?;
    let tmp_path = tmp_dir.path();
    let extracted_path = tmp_path.join("extracted");
    let tmp_path_canonical = fs::canonicalize(tmp_path).wrap_err(format!(
        "Failed to canonicalize temporary directory path: {tmp_path:?}"
    ))?;

    // Extract tarball to a subfolder within temp directory
    fs::create_dir(&extracted_path).wrap_err(format!(
        "Failed to create extracted subdirectory: {extracted_path:?}"
    ))?;
    let file =
        fs::File::open(path).wrap_err(format!("Failed to open tar file for reading: {path:?}"))?;
    let mut archive = Archive::new(file);
    archive.unpack(&extracted_path).wrap_err(format!(
        "Failed to unpack tar archive to extracted subdirectory: {extracted_path:?}"
    ))?;

    // Resolve symlinks in layer.tar
    let read_dir = fs::read_dir(&extracted_path).wrap_err(format!(
        "Failed to read extracted directory after unpacking: {extracted_path:?}"
    ))?;
    for entry in read_dir {
        let entry = entry.wrap_err(format!(
            "Failed to read directory entry in: {extracted_path:?}"
        ))?;
        let dir_path = entry.path();

        if dir_path.is_dir() {
            let layer_tar = dir_path.join("layer.tar");
            if layer_tar.exists() {
                let symlink_metadata = fs::symlink_metadata(&layer_tar).wrap_err(format!(
                    "Failed to get metadata for potential symlink: {layer_tar:?}"
                ))?;
                if symlink_metadata.file_type().is_symlink() {
                    let target_canonical = fs::canonicalize(&layer_tar).wrap_err(format!(
                        "Failed to canonicalize symlink target for {layer_tar:?}"
                    ))?;
                    let is_allowed_target = target_canonical.starts_with(&tmp_path_canonical);
                    if !is_allowed_target {
                        return Err(eyre!(
                            "Symlink target {target_canonical:?} resolves outside the allowed directories"
                        ));
                    }
                    let target_metadata = fs::metadata(&target_canonical).wrap_err(format!(
                        "Failed to get metadata for symlink target {target_canonical:?}"
                    ))?;
                    if !target_metadata.is_file() {
                        return Err(eyre!(
                            "Symlink target {target_canonical:?} is not a regular file"
                        ));
                    }
                    fs::remove_file(&layer_tar)
                        .wrap_err(format!("Failed to remove symlink: {layer_tar:?}"))?;
                    fs::copy(&target_canonical, &layer_tar).wrap_err(format!(
                        "Failed to copy symlink target {target_canonical:?} to {layer_tar:?}"
                    ))?;
                }
            }
        }
    }

    // Create the final tar file in the temp directory root (outside extracted subfolder)
    let final_tar_in_temp = tmp_path.join("processed.tar");
    let output_file = fs::File::create(&final_tar_in_temp).wrap_err(format!(
        "Failed to create processed tar file in temp directory: {final_tar_in_temp:?}"
    ))?;
    let mut builder = Builder::new(output_file);

    // Repack from the extracted subfolder - no need to skip processed.tar since it's not in extracted_path
    let read_dir_repack = fs::read_dir(&extracted_path).wrap_err(format!(
        "Failed to read extracted directory for repacking: {extracted_path:?}"
    ))?;
    for entry in read_dir_repack {
        let entry = entry.wrap_err(format!(
            "Failed to read directory entry during repacking in: {extracted_path:?}"
        ))?;
        let file_name = entry.file_name();
        let entry_path = entry.path();
        let metadata = entry
            .metadata()
            .wrap_err(format!("Failed to get metadata for entry: {entry_path:?}"))?;

        if metadata.is_dir() {
            builder
                .append_dir_all(file_name, &entry_path)
                .wrap_err(format!(
                    "Failed to append directory {entry_path:?} to tar archive"
                ))?;
        } else if metadata.is_file() {
            let mut file = fs::File::open(&entry_path).wrap_err(format!(
                "Failed to open file for appending to tar: {entry_path:?}"
            ))?;
            builder.append_file(file_name, &mut file).wrap_err(format!(
                "Failed to append file {entry_path:?} to tar archive"
            ))?;
        }
        // Skip symlinks and other file types
    }

    builder.finish().wrap_err(format!(
        "Failed to finish writing tar archive: {final_tar_in_temp:?}"
    ))?;

    // Move the final tar file from temp directory to cache location
    // Try rename first, fall back to copy+remove if rename fails for any reason (it won't work if the files are on different mount points)
    if fs::rename(&final_tar_in_temp, &cached_tar_path).is_err() {
        fs::copy(&final_tar_in_temp, &cached_tar_path).wrap_err(format!(
            "Failed to copy processed tar file from temp directory {final_tar_in_temp:?} to cache location {cached_tar_path:?}"
        ))?;
        fs::remove_file(&final_tar_in_temp).wrap_err(format!(
            "Failed to remove temp tar file after copying: {final_tar_in_temp:?}"
        ))?;
    }

    tracing::debug!("Cached processed tar file: {cached_tar_path:?}");

    Ok(cached_tar_path)
}

/// Creates an error from a failed command output, extracting stderr for the error message.
fn command_output_error(output: &std::process::Output, error_prefix: &str) -> eyre::Error {
    tracing::error!("{} failed {:?}", error_prefix, output);
    let stderr = String::from_utf8_lossy(&output.stderr);
    eyre!("{} failed: {}", error_prefix, stderr)
}

/// Verifies that a docker-archive tar file has the correct config digest by recomputing it.
/// Uses skopeo copy to a temporary docker-archive to force digest recomputation, ensuring the tar file
/// hasn't been tampered with. This function can be used to verify both original and
/// symlink-removed tar files.
///
/// # Arguments
/// * `tar_path` - Path to the docker-archive tar file to verify
/// * `expected_config_digest` - The expected config digest (e.g., "sha256:...")
///
/// # Returns
/// * `Ok(())` if the computed digest matches the expected digest
/// * `Err` if verification fails or digests don't match
pub fn verify_tar_image_digest(tar_path: &Path, expected_config_digest: &str) -> Result<()> {
    // Create a temporary docker-archive to force skopeo to recompute all digests
    // by reconstructing the image. This ensures we're verifying the docker-archive format
    // directly, not converting to a different format where digests might differ.
    let tmp_dir = tempdir().wrap_err("Failed to create temporary directory for verification")?;
    let tmp_tar_path = tmp_dir.path().join("verified.tar");

    // Copy from docker-archive to docker-archive - this forces skopeo to recompute all digests
    // because it reconstructs the image structure. If the tar is tampered, this will fail
    // or produce different digests.
    tracing::debug!(
        "Verifying tar file digest by copying to temporary docker-archive: {:?}",
        tar_path
    );
    let copy_output = Command::new("skopeo")
        .arg("copy")
        .arg(format!("docker-archive:{}", tar_path.to_string_lossy()))
        .arg(format!("docker-archive:{}", tmp_tar_path.to_string_lossy()))
        .output()
        .wrap_err("skopeo copy could not be executed for verification")?;

    if !copy_output.status.success() {
        let stderr = String::from_utf8_lossy(&copy_output.stderr);
        return Err(eyre!(
            "skopeo copy failed during tar verification (tar may be corrupted or tampered): {}",
            stderr
        ));
    }

    // Now inspect the docker-archive format - digests are guaranteed to be recomputed
    let inspect_output = Command::new("skopeo")
        .arg("inspect")
        .arg("--raw")
        .arg("--no-creds")
        .arg(format!("docker-archive:{}", tmp_tar_path.to_string_lossy()))
        .output()
        .wrap_err("skopeo inspect could not be executed for verification")?;

    if !inspect_output.status.success() {
        let stderr = String::from_utf8_lossy(&inspect_output.stderr);
        return Err(eyre!(
            "Failed to inspect docker-archive image during verification: {}",
            stderr
        ));
    }

    let manifest_json =
        String::from_utf8(inspect_output.stdout).wrap_err("Failed to parse manifest as UTF-8")?;
    let manifest: serde_json::Value =
        serde_json::from_str(&manifest_json).wrap_err("Failed to parse manifest JSON")?;

    // For docker-archive format, the config digest is in manifest.config.digest
    let computed_config_digest = manifest
        .get("config")
        .and_then(|c| c.get("digest"))
        .and_then(|d| d.as_str())
        .ok_or_else(|| eyre!("Failed to get config digest from docker-archive manifest"))?;

    if computed_config_digest != expected_config_digest {
        return Err(eyre!(
            "Tar file config digest mismatch: computed={}, expected={}. The tar file may have been tampered with.",
            computed_config_digest,
            expected_config_digest
        ));
    }

    tracing::debug!("Tar file digest verification successful: {:?}", tar_path);
    Ok(())
}

/// Pulls the image or loads the image from the cache if it exists. It ensures the config digest matches the given digest, or repulls the image if it doesn't. Returns the path to the modified tar file which deleted the symlinks.
fn pull_or_load_image(
    image_digest: &str,
    container_name: &str,
    image_config_digest: &str,
) -> Result<PathBuf> {
    let home_dir = std::env::home_dir().ok_or_else(|| eyre!("Failed to get HOME directory"))?;
    let images_dir = home_dir.join(".clementine").join(IMAGES_SUBDIR);
    fs::create_dir_all(&images_dir).wrap_err(format!(
        "Failed to create images directory for container tarballs: {images_dir:?}"
    ))?;
    let tar_file_path = images_dir.join(format!("{container_name}.tar"));

    // 2. Verify local tar digest if it exists
    let mut need_pull = true;
    if tar_file_path.exists() {
        match verify_tar_image_digest(&tar_file_path, image_config_digest) {
            Ok(()) => {
                tracing::info!("Local tar config digest verified, skipping pull");
                need_pull = false;
            }
            Err(e) => {
                tracing::warn!(
                    "Local tar config digest verification failed for {container_name} in path {tar_file_path:?} (file may be corrupted or tampered), will delete and re-pull: {e}",
                );
                fs::remove_file(&tar_file_path).wrap_err("Failed to delete local tar")?;
            }
        }
    }

    // 3. Pull with skopeo if needed
    if need_pull {
        tracing::info!("Pulling image via skopeo...");
        let pull_output = Command::new("skopeo")
            .arg("copy")
            .arg(format!("docker://{image_digest}"))
            .arg("--src-no-creds")
            .arg(format!(
                "docker-archive:{}",
                tar_file_path.to_string_lossy()
            ))
            .output()
            .wrap_err("skopeo copy could not be executed")?;
        if !pull_output.status.success() {
            return Err(command_output_error(&pull_output, "skopeo copy"));
        }
        // Verify the pulled image by recomputing digests
        verify_tar_image_digest(&tar_file_path, image_config_digest)
            .wrap_err("Newly pulled image failed digest verification")?;
    }

    let modified_tar_path = remove_symlinks_from_image_tar(&tar_file_path, image_config_digest)?;

    // Note: Verification is already done inside remove_symlinks_from_image_tar for cached files,
    // and the newly created file should match since it's derived from the verified original.
    // However, we verify again here as a final safety check.
    verify_tar_image_digest(&modified_tar_path, image_config_digest)
        .wrap_err("Symlink-removed tar failed digest verification")?;

    Ok(modified_tar_path)
}

/// Pulls or loads all the images needed for the prover.
pub fn pull_or_load_all_images() -> Result<()> {
    let _guard = get_docker_mutex()
        .lock()
        .map_err(|e| eyre!("Failed to acquire docker mutex: {e:?}"))?;
    if is_dev_mode() {
        pull_or_load_image(
            DEV_STARK_TO_BITVM2_IMAGE_DIGEST,
            DEV_STARK_TO_BITVM2_CONTAINER_NAME,
            DEV_STARK_TO_BITVM2_IMAGE_CONFIG_DIGEST,
        )?;
        pull_or_load_image(
            DEV_STARK_TO_RISC0_G16_IMAGE_DIGEST,
            DEV_STARK_TO_RISC0_G16_CONTAINER_NAME,
            DEV_STARK_TO_RISC0_G16_IMAGE_CONFIG_DIGEST,
        )?;
    } else {
        pull_or_load_image(
            STARK_TO_BITVM2_IMAGE_DIGEST,
            STARK_TO_BITVM2_CONTAINER_NAME,
            STARK_TO_BITVM2_IMAGE_CONFIG_DIGEST,
        )?;
    }
    Ok(())
}

/// Runs the prover container.
/// skopeo is used to pull images instead of udocker pull because udocker pull doesn't support pulling from a sha digest.
/// udocker is used instead of docker itself because it requires docker-in-docker to be set up if entities are run with docker.
/// udocker commands are ran with --allow-root to avoid issues if the container is run as root. If it isn't run as root, --allow-root does nothing.
fn run_prover_container(
    image_digest: &str,
    container_name: &str,
    image_config_digest: &str,
    work_dir: &Path,
) -> Result<()> {
    let modified_tar_path = pull_or_load_image(image_digest, container_name, image_config_digest)?;
    // Load tar into udocker
    let load_output = Command::new("udocker")
        .arg("--allow-root")
        .arg("load")
        .arg("-i")
        .arg(&modified_tar_path)
        .output()
        .wrap_err("udocker load could not be executed")?;
    if !load_output.status.success() {
        return Err(command_output_error(
            &load_output,
            format!("udocker load -i {modified_tar_path:?}").as_str(),
        ));
    }

    // udocker load returns the image id of the loaded image on the last line of the stdout.
    // also this output is different every time udocker load is run (even if the same .tar is used), so we need to parse the output to get the image id.
    let output_str = String::from_utf8(load_output.stdout)
        .wrap_err("Failed to parse udocker load stdout as UTF-8")?;
    tracing::debug!("udocker load stdout: {:?}", output_str);
    let udocker_image_id = output_str
        .lines()
        .last()
        .ok_or_else(|| eyre!("No output lines from udocker load"))?
        .trim_matches(&['[', ']', '\'', ' '][..])
        .to_string();
    tracing::debug!("Loaded udocker image id for {container_name}: {udocker_image_id}");

    struct UdockerCleanupGuard {
        container_name: String,
        image_id: String,
    }
    impl Drop for UdockerCleanupGuard {
        fn drop(&mut self) {
            // Note: If udocker run --rm succeeds, the container may already be removed,
            // but udocker rm will fail harmlessly (errors are ignored here).
            // Also, container may not exist if udocker create fails for some reason, but this Drop impl also cleans up the image.
            let _ = Command::new("udocker")
                .arg("--allow-root")
                .arg("rm")
                .arg(&self.container_name)
                .output();

            // every udocker load creates a new container image (even if the same .tar is used), if we don't clean up the old container image, it will accumulate and consume disk space.
            let _ = Command::new("udocker")
                .arg("--allow-root")
                .arg("rmi")
                .arg(&self.image_id)
                .output();

            tracing::debug!(
                "Cleaned up udocker container {} and image {}",
                self.container_name,
                self.image_id
            );
        }
    }
    let _udocker_guard = UdockerCleanupGuard {
        container_name: container_name.to_string(),
        image_id: udocker_image_id.clone(),
    };

    // Remove any stale container with the same name before creating a new one.
    // This is to prevent stale containers being used by previous versions. There might be better ways so that we don't do this if it's not necessary.
    let rm_output = Command::new("udocker")
        .arg("--allow-root")
        .arg("rm")
        .arg(container_name)
        .output()
        .wrap_err("udocker rm could not be executed")?;

    if !rm_output.status.success() {
        let stderr = String::from_utf8_lossy(&rm_output.stderr);
        // Ignore error if container doesn't exist (we're just cleaning up stale containers)
        if !stderr.contains("invalid container id") && !stderr.contains("container not found") {
            return Err(eyre!("udocker rm {container_name} failed: {stderr}"));
        }
    }

    // Create the container using udocker create
    let create_output = Command::new("udocker")
        .arg("--allow-root")
        .arg("create")
        .arg(format!("--name={container_name}"))
        .arg(&udocker_image_id)
        .output()
        .wrap_err("udocker create could not be executed")?;
    if !create_output.status.success() {
        let stderr = String::from_utf8_lossy(&create_output.stderr);
        if stderr.contains("container name already exists") {
            tracing::warn!(
                "udocker create: container name '{}' already exists despite pre-cleanup. Error: {}",
                container_name,
                stderr
            );
        } else {
            return Err(eyre!(
                "udocker create failed for {container_name}: {stderr}"
            ));
        }
    }

    // Setup container with P2 exec mode (doesn't require user namespaces or root privileges)
    let setup_output = Command::new("udocker")
        .arg("--allow-root")
        .arg("setup")
        .arg("--execmode=P2")
        .arg(container_name)
        .output()
        .wrap_err("udocker setup could not be executed")?;
    if !setup_output.status.success() {
        return Err(command_output_error(
            &setup_output,
            format!("udocker setup {container_name}").as_str(),
        ));
    }

    // Run container with volume mount
    let run_output = Command::new("udocker")
        .arg("--allow-root")
        .arg("run")
        .arg("--rm")
        .arg("-v")
        .arg(format!("{}:/mnt", work_dir.to_string_lossy()))
        .arg(container_name)
        .output()
        .wrap_err("udocker run could not be executed")?;
    if !run_output.status.success() {
        return Err(command_output_error(
            &run_output,
            format!("udocker run {container_name}").as_str(),
        ));
    }

    Ok(())
}

pub fn dev_stark_to_risc0_g16(receipt: Receipt, journal: &[u8]) -> Result<Receipt> {
    // Acquire the mutex to ensure only one docker operation runs at a time
    // This prevents conflicts when RISC0_WORK_DIR is set and multiple functions run concurrently
    let _guard = get_docker_mutex()
        .lock()
        .map_err(|e| eyre!("Failed to acquire docker mutex: {e:?}"))?;

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

    run_prover_container(
        DEV_STARK_TO_RISC0_G16_IMAGE_DIGEST,
        DEV_STARK_TO_RISC0_G16_CONTAINER_NAME,
        DEV_STARK_TO_RISC0_G16_IMAGE_CONFIG_DIGEST,
        work_dir,
    )?;

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
    // Acquire the mutex to ensure only one docker operation runs at a time
    // This prevents conflicts when RISC0_WORK_DIR is set and multiple functions run concurrently
    let _guard = get_docker_mutex()
        .lock()
        .map_err(|e| eyre!("Failed to acquire docker mutex: {e:?}"))?;

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

    run_prover_container(
        DEV_STARK_TO_BITVM2_IMAGE_DIGEST,
        DEV_STARK_TO_BITVM2_CONTAINER_NAME,
        DEV_STARK_TO_BITVM2_IMAGE_CONFIG_DIGEST,
        work_dir,
    )?;

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

fn is_x86_architecture() -> bool {
    ARCH == "x86_64" || ARCH == "x86"
}

pub fn to_decimal(s: &str) -> Option<String> {
    let int = BigUint::from_str_radix(s, 16).ok();
    int.map(|n| n.to_str_radix(10))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tar::{EntryType, Header};

    /// Test that pull_or_load_image succeeds for the STARK_TO_BITVM2 image.
    /// This validates that STARK_TO_BITVM2_IMAGE_CONFIG_DIGEST is correct.
    #[test]
    fn test_pull_or_load_image_mainnet_bitvm2() {
        let _guard = get_docker_mutex().lock().unwrap_or_else(|e| e.into_inner());
        // Skip this test in debug mode, to not pull these images from remote on debug tests.
        if cfg!(debug_assertions) {
            return;
        }
        let result = pull_or_load_image(
            STARK_TO_BITVM2_IMAGE_DIGEST,
            STARK_TO_BITVM2_CONTAINER_NAME,
            STARK_TO_BITVM2_IMAGE_CONFIG_DIGEST,
        );
        assert!(
            result.is_ok(),
            "pull_or_load_image failed for mainnet bitvm2 image: {:?}",
            result.as_ref().err()
        );
        let path = result.unwrap();
        assert!(path.exists(), "Modified tar file should exist at {path:?}");
    }

    /// Test that pull_or_load_image succeeds for the DEV_STARK_TO_BITVM2 image.
    /// This validates that DEV_STARK_TO_BITVM2_IMAGE_CONFIG_DIGEST is correct.
    #[test]
    fn test_pull_or_load_image_dev_bitvm2() {
        let _guard = get_docker_mutex().lock().unwrap_or_else(|e| e.into_inner());
        // Skip this test in debug mode, to not pull these images from remote on debug tests.
        if cfg!(debug_assertions) {
            return;
        }
        let result = pull_or_load_image(
            DEV_STARK_TO_BITVM2_IMAGE_DIGEST,
            DEV_STARK_TO_BITVM2_CONTAINER_NAME,
            DEV_STARK_TO_BITVM2_IMAGE_CONFIG_DIGEST,
        );
        assert!(
            result.is_ok(),
            "pull_or_load_image failed for dev bitvm2 image: {:?}",
            result.as_ref().err()
        );
        let path = result.unwrap();
        assert!(path.exists(), "Modified tar file should exist at {path:?}");
    }

    /// Test that pull_or_load_image succeeds for the DEV_STARK_TO_RISC0_G16 image.
    /// This validates that DEV_STARK_TO_RISC0_G16_IMAGE_CONFIG_DIGEST is correct.
    #[test]
    fn test_pull_or_load_image_dev_risc0_g16() {
        let _guard = get_docker_mutex().lock().unwrap_or_else(|e| e.into_inner());
        // Skip this test in debug mode, to not pull these images from remote on debug tests.
        if cfg!(debug_assertions) {
            return;
        }
        let result = pull_or_load_image(
            DEV_STARK_TO_RISC0_G16_IMAGE_DIGEST,
            DEV_STARK_TO_RISC0_G16_CONTAINER_NAME,
            DEV_STARK_TO_RISC0_G16_IMAGE_CONFIG_DIGEST,
        );
        assert!(
            result.is_ok(),
            "pull_or_load_image failed for dev risc0 groth16 image: {:?}",
            result.as_ref().err()
        );
        let path = result.unwrap();
        assert!(path.exists(), "Modified tar file should exist at {path:?}");
    }

    /// Helper function to create a minimal Docker image tar structure for testing
    ///
    /// # How the tar is created:
    /// 1. Creates a tar archive using the `tar::Builder`
    /// 2. Adds a directory entry: `layer1/` (simulating a Docker layer directory)
    /// 3. Adds a target file: `layer1/target_file` with content "target file content"
    /// 4. Adds `layer1/layer.tar` either as:
    ///    - A symlink pointing to "target_file" (if `has_symlink` is true)
    ///    - A regular file with content "layer tar content" (if `has_symlink` is false)
    ///
    /// This simulates a Docker image tar where layer.tar files can be symlinks pointing
    /// to other layer.tar files (for deduplication). The `remove_symlinks_from_image_tar`
    /// function should replace these symlinks with actual file copies.
    fn create_test_tar_with_symlink(
        tar_path: &Path,
        has_symlink: bool,
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let file = fs::File::create(tar_path)?;
        let mut builder = Builder::new(file);

        // Create a layer directory structure
        let layer_dir_name = "layer1";
        let mut layer_header = Header::new_gnu();
        layer_header.set_entry_type(EntryType::Directory);
        layer_header.set_path(layer_dir_name)?;
        layer_header.set_size(0);
        layer_header.set_cksum();
        builder.append(&layer_header, &mut std::io::empty())?;

        // Create a target file that the symlink will point to
        let target_file_name = format!("{layer_dir_name}/target_file");
        let target_content = b"target file content";
        let mut target_header = Header::new_gnu();
        target_header.set_path(&target_file_name)?;
        target_header.set_size(target_content.len() as u64);
        target_header.set_cksum();
        builder.append(&target_header, target_content.as_slice())?;

        // Create layer.tar file - either as a symlink or regular file
        let layer_tar_name = format!("{layer_dir_name}/layer.tar");
        if has_symlink {
            // Create layer.tar as a symlink pointing to target_file
            let mut symlink_header = Header::new_gnu();
            symlink_header.set_entry_type(EntryType::Symlink);
            symlink_header.set_path(&layer_tar_name)?;
            symlink_header.set_link_name("target_file")?;
            symlink_header.set_size(0);
            symlink_header.set_cksum();
            builder.append(&symlink_header, &mut std::io::empty())?;
        } else {
            // Create layer.tar as a regular file
            let layer_tar_content = b"layer tar content";
            let mut layer_tar_header = Header::new_gnu();
            layer_tar_header.set_path(&layer_tar_name)?;
            layer_tar_header.set_size(layer_tar_content.len() as u64);
            layer_tar_header.set_cksum();
            builder.append(&layer_tar_header, layer_tar_content.as_slice())?;
        }

        builder.finish()?;
        Ok(())
    }

    /// Test remove_symlinks_from_image_tar with a tar file containing symlinks
    #[test]
    fn test_remove_symlinks_from_image_tar_with_symlink() {
        let tmp_dir = tempdir().unwrap();
        let tar_path = tmp_dir.path().join("test_image.tar");
        // Use a fake digest since our test tar isn't a real Docker image
        // In real usage, this would be a hardcoded constant like DEV_STARK_TO_RISC0_G16_IMAGE_CONFIG_DIGEST
        let expected_digest =
            "sha256:0000000000000000000000000000000000000000000000000000000000000000";

        // Create a tar file with a symlink
        create_test_tar_with_symlink(&tar_path, true).unwrap();

        // Note about digest verification for dummy tar:
        // - remove_symlinks_from_image_tar only verifies digests for EXISTING cached files (line 306)
        // - For newly created files, it processes without verification
        // - So our test tar (which is NOT a valid Docker image) never gets verified
        // - If verification WERE attempted, verify_tar_image_digest would:
        //   1. Try to use skopeo to inspect the tar
        //   2. Skopeo would fail because our test tar lacks Docker manifest/config files
        //   3. Or if skopeo processed it, the computed digest wouldn't match our fake "sha256:0000..."
        // - This is fine for testing - we're only testing the symlink removal logic, not digest verification
        let result = remove_symlinks_from_image_tar(&tar_path, expected_digest);

        // The function should succeed in processing the tar file and removing symlinks
        assert!(
            result.is_ok(),
            "Should succeed in processing tar file with symlinks. Result: {result:?}"
        );

        // Verify the cache file was created
        let cached_path = result.unwrap();
        assert!(
            cached_path.exists(),
            "Cache file should exist after processing"
        );

        // Verify the cache file name is correct
        let cache_file_name = tar_path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap()
            .to_string()
            + "_no_symlinks.tar";
        let expected_cached_path = tar_path.parent().unwrap().join(&cache_file_name);
        assert_eq!(
            cached_path, expected_cached_path,
            "Cache path should match expected path"
        );

        // Verify that symlinks are actually removed by extracting and checking the processed tar
        let extract_dir = tmp_dir.path().join("verify_extracted");
        fs::create_dir_all(&extract_dir).unwrap();

        let cached_file = fs::File::open(&cached_path).unwrap();
        let mut cached_archive = Archive::new(cached_file);
        cached_archive.unpack(&extract_dir).unwrap();

        // Check that layer.tar is now a regular file, not a symlink
        let layer_tar_path = extract_dir.join("layer1/layer.tar");
        assert!(
            layer_tar_path.exists(),
            "layer.tar should exist in processed tar"
        );

        let layer_tar_metadata = fs::symlink_metadata(&layer_tar_path).unwrap();
        assert!(
            !layer_tar_metadata.file_type().is_symlink(),
            "layer.tar should be a regular file, not a symlink, after processing"
        );
        assert!(
            layer_tar_metadata.is_file(),
            "layer.tar should be a regular file"
        );

        // Verify the content is correct (should be a copy of target_file content)
        let layer_tar_content = fs::read_to_string(&layer_tar_path).unwrap();
        let target_file_content =
            fs::read_to_string(extract_dir.join("layer1/target_file")).unwrap();
        assert_eq!(
            layer_tar_content, target_file_content,
            "layer.tar should contain the same content as target_file (symlink was replaced with copy)"
        );

        // Clean up temporary tar files created during test
        let _ = fs::remove_file(&tar_path);
        let _ = fs::remove_file(&cached_path);
    }

    /// Test remove_symlinks_from_image_tar with invalid path
    #[test]
    fn test_remove_symlinks_from_image_tar_invalid_path() {
        let invalid_path = Path::new("/nonexistent/path/image.tar");
        let expected_digest =
            "sha256:0000000000000000000000000000000000000000000000000000000000000000";

        let result = remove_symlinks_from_image_tar(invalid_path, expected_digest);
        assert!(result.is_err(), "Should fail with invalid path");
    }

    /// Test remove_symlinks_from_image_tar with tar file that has no parent directory
    #[test]
    fn test_remove_symlinks_from_image_tar_no_parent() {
        // This is a bit contrived, but we can test the error path
        // by using a path that doesn't have a proper parent in the expected way
        let tmp_dir = tempdir().unwrap();
        let tar_path = tmp_dir.path().join("test.tar");
        fs::File::create(&tar_path).unwrap();

        // Create a path that will fail when trying to get parent
        // Actually, any valid path will have a parent, so we'll test with a root path
        // which should fail in a different way
        let root_path = Path::new("/test.tar");
        let expected_digest =
            "sha256:0000000000000000000000000000000000000000000000000000000000000000";

        // This will fail when trying to open the file, not when getting parent
        let result = remove_symlinks_from_image_tar(root_path, expected_digest);
        assert!(result.is_err(), "Should fail with root path");
    }

    /// Test remove_symlinks_from_image_tar cache behavior - no cache exists
    #[test]
    fn test_remove_symlinks_from_image_tar_no_cache() {
        let tmp_dir = tempdir().unwrap();
        let tar_path = tmp_dir.path().join("test_image.tar");
        let expected_digest =
            "sha256:0000000000000000000000000000000000000000000000000000000000000000";

        // Create a tar file without symlinks
        create_test_tar_with_symlink(&tar_path, false).unwrap();

        // Verify cache file doesn't exist initially
        let cache_file_name = "test_image_no_symlinks.tar";
        let cached_tar_path = tmp_dir.path().join(cache_file_name);
        assert!(
            !cached_tar_path.exists(),
            "Cache should not exist initially"
        );

        // The function processes the tar file and creates a cache.
        // Note: remove_symlinks_from_image_tar doesn't verify digests for newly created files,
        // only for existing cache files. So it will succeed in processing our test tar file.
        // The digest verification happens in pull_or_load_image, not here.
        let result = remove_symlinks_from_image_tar(&tar_path, expected_digest);

        // The function should succeed in processing the tar file (it's a valid tar, just not a Docker image)
        assert!(
            result.is_ok(),
            "Should succeed in processing tar file. Result: {result:?}"
        );

        // Verify the cache file was created
        let cached_path = result.unwrap();
        assert!(
            cached_path.exists(),
            "Cache file should exist after processing"
        );
        assert_eq!(
            cached_path, cached_tar_path,
            "Cache path should match expected path"
        );

        // Clean up temporary tar files created during test
        let _ = fs::remove_file(&tar_path);
        let _ = fs::remove_file(&cached_path);
    }

    /// Test remove_symlinks_from_image_tar with tar containing directory structure
    #[test]
    fn test_remove_symlinks_from_image_tar_directory_structure() {
        let tmp_dir = tempdir().unwrap();
        let tar_path = tmp_dir.path().join("test_image.tar");
        let expected_digest =
            "sha256:0000000000000000000000000000000000000000000000000000000000000000";

        // Create a tar with proper Docker image structure (directory with layer.tar)
        let file = fs::File::create(&tar_path).unwrap();
        let mut builder = Builder::new(file);

        // Create a layer directory
        let layer_dir = "abc123";
        let mut dir_header = Header::new_gnu();
        dir_header.set_entry_type(EntryType::Directory);
        dir_header.set_path(layer_dir).unwrap();
        dir_header.set_size(0);
        dir_header.set_cksum();
        builder.append(&dir_header, &mut std::io::empty()).unwrap();

        // Create a regular layer.tar file (not a symlink)
        let layer_tar_path = format!("{layer_dir}/layer.tar");
        let layer_content = b"some layer content";
        let mut layer_header = Header::new_gnu();
        layer_header.set_path(&layer_tar_path).unwrap();
        layer_header.set_size(layer_content.len() as u64);
        layer_header.set_cksum();
        builder
            .append(&layer_header, layer_content.as_slice())
            .unwrap();

        builder.finish().unwrap();

        // The function should process this tar file successfully.
        // Note: remove_symlinks_from_image_tar doesn't verify digests for newly created files,
        // only for existing cache files. So it will succeed in processing our test tar file.
        let result = remove_symlinks_from_image_tar(&tar_path, expected_digest);

        // Should succeed in processing the tar file
        assert!(
            result.is_ok(),
            "Should succeed in processing tar file with directory structure. Result: {result:?}"
        );

        // Verify the cache file was created
        let cached_path = result.unwrap();
        assert!(
            cached_path.exists(),
            "Cache file should exist after processing"
        );

        // Clean up temporary tar files created during test
        let _ = fs::remove_file(&tar_path);
        let _ = fs::remove_file(&cached_path);
    }

    /// Test parsing of udocker load output (the logic that extracts image ID)
    /// Uses actual udocker load output from a real tar file
    /// Uses existing hardcoded image digests (DEV_STARK_TO_RISC0_G16_IMAGE_DIGEST)
    #[test]
    fn test_parse_udocker_load_output() {
        let _guard = get_docker_mutex().lock().unwrap_or_else(|e| e.into_inner());

        // Skip this test in debug mode, to not pull these images from remote on debug tests.
        if cfg!(debug_assertions) {
            return;
        }

        // Check if udocker is available - fail the test if it's not installed
        let udocker_check = Command::new("udocker").arg("--version").output();
        let udocker_available = udocker_check
            .as_ref()
            .map(|output| output.status.success())
            .unwrap_or(false);
        assert!(
            udocker_available,
            "udocker must be installed for this test to run"
        );

        // Pull or load the image tar file
        let modified_tar_path = pull_or_load_image(
            DEV_STARK_TO_RISC0_G16_IMAGE_DIGEST,
            DEV_STARK_TO_RISC0_G16_CONTAINER_NAME,
            DEV_STARK_TO_RISC0_G16_IMAGE_CONFIG_DIGEST,
        )
        .expect("Failed to pull or load image");

        // Run udocker load on the actual tar file
        let load_output = Command::new("udocker")
            .arg("--allow-root")
            .arg("load")
            .arg("-i")
            .arg(&modified_tar_path)
            .output()
            .expect("udocker load could not be executed");

        assert!(
            load_output.status.success(),
            "udocker load should succeed. stderr: {}",
            String::from_utf8_lossy(&load_output.stderr)
        );

        // Parse the output using the same logic as in run_prover_container
        let output_str = String::from_utf8(load_output.stdout)
            .expect("Failed to parse udocker load stdout as UTF-8");

        let udocker_image_id = output_str
            .lines()
            .last()
            .ok_or_else(|| eyre!("No output lines from udocker load"))
            .expect("Should have at least one line of output")
            .trim_matches(&['[', ']', '\'', ' '][..])
            .to_string();

        // Verify that we got a non-empty image ID
        assert!(!udocker_image_id.is_empty(), "Image ID should not be empty");

        // Verify that the parsed image ID is correct by checking if it exists in udocker
        let images_output = Command::new("udocker")
            .arg("--allow-root")
            .arg("images")
            .output()
            .expect("udocker images could not be executed");

        assert!(
            images_output.status.success(),
            "udocker images should succeed. stderr: {}",
            String::from_utf8_lossy(&images_output.stderr)
        );

        let images_str = String::from_utf8(images_output.stdout)
            .expect("Failed to parse udocker images stdout as UTF-8");

        // Validate that the parsed image ID exists in the images list
        assert!(
            images_str.contains(&udocker_image_id),
            "Parsed image ID {udocker_image_id} should exist in udocker images. Images output: {images_str}"
        );

        // Clean up the loaded image (only if it exists, which we just verified)
        let rmi_output = Command::new("udocker")
            .arg("--allow-root")
            .arg("rmi")
            .arg(&udocker_image_id)
            .output()
            .expect("udocker rmi could not be executed");

        assert!(
            rmi_output.status.success(),
            "udocker rmi should succeed for existing image {udocker_image_id}. stderr: {}",
            String::from_utf8_lossy(&rmi_output.stderr)
        );
    }

    /// Test error handling for empty udocker load output
    #[test]
    fn test_parse_udocker_load_output_empty() {
        let output_str = "".to_string();
        let result = output_str
            .lines()
            .last()
            .ok_or_else(|| eyre!("No output lines from udocker load"));
        assert!(result.is_err(), "Should fail with empty output");
    }
}
