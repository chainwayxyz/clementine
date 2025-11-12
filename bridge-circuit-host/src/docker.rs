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

use crate::utils::to_json;

/// Image .tar files are stored in the ~/.clementine/IMAGES_SUBDIR directory.
const IMAGES_SUBDIR: &str = "images";
const STARK_TO_BITVM2_IMAGE_DIGEST: &str =
    "docker.io/chainwayxyz/mainnet-risc0-bitvm2-groth16-prover@sha256:84b810479a6e9482a1827ba6ba7ccbd81f0420a5a7a19c7d256078f144b7737d";
const DEV_STARK_TO_BITVM2_IMAGE_DIGEST: &str =
    "docker.io/ozancw/dev-risc0-to-bitvm2-groth16-prover@sha256:9f1d8515b9c44a1280979bbcab327ec36041fae6dd0c4923997f084605f9f9e7";
const DEV_STARK_TO_RISC0_G16_IMAGE_DIGEST: &str =
    "docker.io/ozancw/dev-risc0-groth16-prover-const-digest-len@sha256:4e5c409998085a0edf37ebe4405be45178e8a7e78ea859d12c3d453e90d409cb";

// NOTE: Keep container names unique to prevent udocker collisions between images.
const STARK_TO_BITVM2_CONTAINER_NAME: &str = "clementine_mainnet_bitvm2_prover";
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
        .map_err(|e| eyre!("Failed to acquire docker mutex: {}", e))?;

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

/// Repackages a Docker/OCI image tarball, removing symlinks and copies the files directly where symlinks would be.
/// This is because udocker load has some issues if there are 2 identical layers in Docker image (symlinks are used if there are identical layers)  
/// Related issue: https://github.com/indigo-dc/udocker/issues/361
/// Creates a modified tar file in the images folder (cached) and returns its path.
/// The original tar file is never modified. The cached file persists in the images folder.
fn remove_symlinks_from_image_tar(path: &Path) -> Result<PathBuf> {
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

    // Check if cached version exists and is newer than original
    let use_cache = if cached_tar_path.exists() {
        let cached_metadata = fs::metadata(&cached_tar_path).wrap_err(format!(
            "Failed to get cached tar metadata: {cached_tar_path:?}"
        ))?;
        let original_metadata = fs::metadata(path)
            .wrap_err(format!("Failed to get original tar metadata: {path:?}"))?;

        // Compare modification times - use cache if it's newer than original
        match (cached_metadata.modified(), original_metadata.modified()) {
            (Ok(cached_mtime), Ok(original_mtime)) => {
                if cached_mtime >= original_mtime {
                    tracing::debug!("Using cached no-symlinks tar file: {cached_tar_path:?}");
                    true
                } else {
                    tracing::debug!(
                        "Cached tar is older than original, will reprocess: {cached_tar_path:?}"
                    );
                    false
                }
            }
            _ => {
                tracing::debug!(
                    "Could not compare modification times, will reprocess: {cached_tar_path:?}"
                );
                false
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

    // Create a temporary directory for processing
    let tmp_dir = tempdir().wrap_err(format!(
        "Failed to create temporary directory for processing tar file: {path:?}"
    ))?;
    let tmp_path = tmp_dir.path();

    // Extract tarball
    let file =
        fs::File::open(path).wrap_err(format!("Failed to open tar file for reading: {path:?}"))?;
    let mut archive = Archive::new(file);
    archive.unpack(tmp_path).wrap_err(format!(
        "Failed to unpack tar archive to temporary directory: {tmp_path:?}"
    ))?;

    // Resolve symlinks in layer.tar
    let read_dir = fs::read_dir(tmp_path).wrap_err(format!(
        "Failed to read temporary directory after unpacking: {tmp_path:?}"
    ))?;
    for entry in read_dir {
        let entry = entry.wrap_err(format!("Failed to read directory entry in: {tmp_path:?}"))?;
        let dir_path = entry.path();

        if dir_path.is_dir() {
            let layer_tar = dir_path.join("layer.tar");
            if layer_tar.exists() {
                let symlink_metadata = fs::symlink_metadata(&layer_tar).wrap_err(format!(
                    "Failed to get metadata for potential symlink: {layer_tar:?}"
                ))?;
                if symlink_metadata.file_type().is_symlink() {
                    let target = fs::read_link(&layer_tar)
                        .wrap_err(format!("Failed to read symlink target for: {layer_tar:?}"))?;
                    fs::remove_file(&layer_tar)
                        .wrap_err(format!("Failed to remove symlink: {layer_tar:?}"))?;
                    // Resolve the target path relative to the directory containing the symlink
                    let resolved_target = if target.is_absolute() {
                        target
                    } else {
                        dir_path.join(&target)
                    };
                    fs::copy(&resolved_target, &layer_tar).wrap_err(format!(
                        "Failed to copy symlink target {resolved_target:?} to {layer_tar:?}"
                    ))?;
                }
            }
        }
    }

    // Repack into a temporary file first (in the same directory as cache for atomic rename),
    // then atomically rename to cache location. This prevents leaving a corrupted cache file if writing fails.
    let cache_dir = cached_tar_path
        .parent()
        .ok_or_else(|| eyre!("Cached tar path has no parent directory: {cached_tar_path:?}"))?;
    let temp_tar_file = cache_dir.join(format!(
        ".{}.tmp",
        cached_tar_path
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| eyre!("Invalid cached tar file name: {cached_tar_path:?}"))?
    ));

    let output_file = fs::File::create(&temp_tar_file).wrap_err(format!(
        "Failed to create temporary tar file: {temp_tar_file:?}"
    ))?;
    let mut builder = Builder::new(output_file);

    let read_dir_repack = fs::read_dir(tmp_path).wrap_err(format!(
        "Failed to read temporary directory for repacking: {tmp_path:?}"
    ))?;
    for entry in read_dir_repack {
        let entry = entry.wrap_err(format!(
            "Failed to read directory entry during repacking in: {tmp_path:?}"
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
        "Failed to finish writing tar archive: {temp_tar_file:?}"
    ))?;

    // Atomically rename the temp file to the cache location
    // Since both files are in the same directory, this is guaranteed to be atomic
    // This ensures we don't leave a corrupted cache file if something fails
    if let Err(e) = fs::rename(&temp_tar_file, &cached_tar_path) {
        // Clean up temp file on error
        let _ = fs::remove_file(&temp_tar_file);
        return Err(e).wrap_err(format!(
            "Failed to atomically rename temp tar file {temp_tar_file:?} to cache location {cached_tar_path:?}"
        ));
    }

    tracing::debug!("Cached processed tar file: {cached_tar_path:?}");

    Ok(cached_tar_path)
}

fn run_prover_container(image_digest: &str, container_name: &str, work_dir: &Path) -> Result<()> {
    let home_dir = std::env::var("HOME").wrap_err("Failed to get HOME directory")?;
    let images_dir = PathBuf::from(home_dir)
        .join(".clementine")
        .join(IMAGES_SUBDIR);
    fs::create_dir_all(&images_dir).wrap_err(format!(
        "Failed to create images directory for container tarballs: {images_dir:?}"
    ))?;
    let tar_file_path = images_dir.join(format!("{container_name}.tar"));

    // 1. Get remote config digest
    let remote_config_digest_output = Command::new("skopeo")
        .arg("inspect")
        .arg("--raw")
        .arg(format!("docker://{image_digest}"))
        .output()
        .wrap_err("skopeo inspect could not be executed")?;
    if !remote_config_digest_output.status.success() {
        return Err(eyre!(
            "skopeo inspect remote failed: {:?}",
            remote_config_digest_output
        ));
    }
    let remote_config_digest_json = String::from_utf8(remote_config_digest_output.stdout)
        .wrap_err("Failed to parse remote image manifest as UTF-8")?;
    let remote_config_digest: String =
        serde_json::from_str::<serde_json::Value>(&remote_config_digest_json)?
            .get("config")
            .and_then(|c| c.get("digest"))
            .and_then(|d| d.as_str())
            .ok_or_else(|| eyre!("Failed to get remote config digest"))?
            .to_string();

    // 2. Inspect local tar digest if it exists
    let mut need_pull = true;
    if tar_file_path.exists() {
        let local_config_digest_output = Command::new("skopeo")
            .arg("inspect")
            .arg("--raw")
            .arg(format!(
                "docker-archive:{}",
                tar_file_path.to_string_lossy()
            ))
            .output()
            .wrap_err("skopeo inspect could not be executed")?;
        if local_config_digest_output.status.success() {
            let local_config_digest_json = String::from_utf8(local_config_digest_output.stdout)
                .wrap_err("Failed to parse local image manifest as UTF-8")?;
            let local_config_digest: String =
                serde_json::from_str::<serde_json::Value>(&local_config_digest_json)?
                    .get("config")
                    .and_then(|c| c.get("digest"))
                    .and_then(|d| d.as_str())
                    .ok_or_else(|| eyre!("Failed to get local config digest"))?
                    .to_string();

            if local_config_digest == remote_config_digest {
                tracing::info!("Local tar config digest matches remote, skipping pull");
                need_pull = false;
            } else {
                tracing::warn!(
                    "Local tar config digest mismatch, deleting and re-pulling: local={}, remote={}",
                    local_config_digest,
                    remote_config_digest
                );
                fs::remove_file(&tar_file_path).wrap_err("Failed to delete local tar")?;
            }
        } else {
            tracing::warn!("Failed to inspect local tar config digest, re-pulling");
            fs::remove_file(&tar_file_path).ok();
        }
    }

    // 3. Pull with skopeo if needed
    if need_pull {
        tracing::info!("Pulling image via skopeo...");
        let pull_output = Command::new("skopeo")
            .arg("copy")
            .arg(format!("docker://{image_digest}"))
            .arg(format!(
                "docker-archive:{}",
                tar_file_path.to_string_lossy()
            ))
            .output()
            .wrap_err("skopeo copy could not be executed")?;
        if !pull_output.status.success() {
            return Err(eyre!("skopeo copy failed: {:?}", pull_output));
        }
    }

    let modified_tar_path = remove_symlinks_from_image_tar(&tar_file_path)?;

    // 4. Load tar into udocker
    let load_output = Command::new("udocker")
        .arg("--allow-root")
        .arg("load")
        .arg("-i")
        .arg(&modified_tar_path)
        .output()
        .wrap_err("udocker load could not be executed")?;
    if !load_output.status.success() {
        return Err(eyre!("udocker load failed {:?}", load_output));
    }

    // udocker load returns the image id of the loaded image on the last line of the stdout.
    // also this output is different everytime udocker load is run (even if the same .tar is used), so we need to parse the output to get the image id.
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
            // every udocker load creates a new container image (even if the same .tar is used), if we don't clean up the old container image, it will accumulate and consume disk space.
            let _ = Command::new("udocker")
                .arg("--allow-root")
                .arg("rm")
                .arg(&self.container_name)
                .output();

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
            return Err(eyre!("udocker rm failed: {}", stderr));
        }
    }

    // 5. Create the container with P2 exec mode
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
            return Err(eyre!("udocker create failed: {}", stderr));
        }
    }

    // 6. Setup execmode
    let setup_output = Command::new("udocker")
        .arg("--allow-root")
        .arg("setup")
        .arg("--execmode=P2")
        .arg(container_name)
        .output()
        .wrap_err("udocker setup could not be executed")?;
    if !setup_output.status.success() {
        return Err(eyre!("udocker setup failed {:?}", setup_output));
    }

    // 7. Run container with volume mount
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
        return Err(eyre!(
            "STARK to SNARK prover docker image returned failure: {:?}",
            run_output
        ));
    }

    Ok(())
}

pub fn dev_stark_to_risc0_g16(receipt: Receipt, journal: &[u8]) -> Result<Receipt> {
    // Acquire the mutex to ensure only one docker operation runs at a time
    // This prevents conflicts when RISC0_WORK_DIR is set and multiple functions run concurrently
    let _guard = get_docker_mutex()
        .lock()
        .map_err(|e| eyre!("Failed to acquire docker mutex: {}", e))?;

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
        .map_err(|e| eyre!("Failed to acquire docker mutex: {}", e))?;

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
