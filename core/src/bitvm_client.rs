use crate::actor::WinternitzDerivationPath;
use crate::builder::address::taproot_builder_with_scripts;
use crate::builder::script::{SpendableScript, WinternitzCommit};

use crate::config::protocol::ProtocolParamset;
use crate::constants::MAX_SCRIPT_REPLACEMENT_OPERATIONS;
use crate::errors::BridgeError;
use bitcoin::{self};
use bitcoin::{ScriptBuf, XOnlyPublicKey};

use bitvm::chunk::api::{
    api_generate_full_tapscripts, api_generate_partial_script, Assertions, NUM_HASH, NUM_PUBS,
    NUM_U256,
};

use bitvm::signatures::{Wots, Wots20};
use borsh::{BorshDeserialize, BorshSerialize};
use bridge_circuit_host::utils::{get_verifying_key, is_dev_mode};
use sha2::{Digest, Sha256};
use std::fs;
use tokio::sync::Mutex;

use std::str::FromStr;
use std::sync::{Arc, LazyLock, OnceLock};
use std::time::Instant;

/// Replacing bitvm scripts require cloning the scripts, which can be ~4GB. And this operation is done every deposit.
/// So we ensure only 1 thread is doing this at a time to avoid OOM.
pub static REPLACE_SCRIPTS_LOCK: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));

lazy_static::lazy_static! {
    /// Global secp context.
    pub static ref SECP: bitcoin::secp256k1::Secp256k1<bitcoin::secp256k1::All> = bitcoin::secp256k1::Secp256k1::new();
}

lazy_static::lazy_static! {
    /// This is an unspendable pubkey.
    ///
    /// See https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki#constructing-and-spending-taproot-outputs
    ///
    /// It is used to create a taproot address where the internal key is not spendable.
    /// Here are the other protocols that use this key:
    /// - Babylon:https://github.com/babylonlabs-io/btc-staking-ts/blob/v0.4.0-rc.2/src/constants/internalPubkey.ts
    /// - Ark: https://github.com/ark-network/ark/blob/cba48925bcc836cc55f9bb482f2cd1b76d78953e/common/tree/validation.go#L47
    /// - BitVM: https://github.com/BitVM/BitVM/blob/2dd2e0e799d2b9236dd894da3fee8c4c4893dcf1/bridge/src/scripts.rs#L16
    /// - Best in Slot: https://github.com/bestinslot-xyz/brc20-programmable-module/blob/2113bdd73430a8c3757e537cb63124a6cb33dfab/src/evm/precompiles/get_locked_pkscript_precompile.rs#L53
    /// - https://github.com/BlockstreamResearch/options/blob/36a77175919101393b49f1211732db762cc7dfc1/src/options_lib/src/contract.rs#L132
    ///
    pub static ref UNSPENDABLE_XONLY_PUBKEY: bitcoin::secp256k1::XOnlyPublicKey =
        XOnlyPublicKey::from_str("50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0").expect("this key is valid");
}

/// Global BitVM cache wrapped in a OnceLock.
///
/// # Usage
/// Use with `BITVM_CACHE.get_or_init(load_or_generate_bitvm_cache)` to get the cache or optionally load it.
/// The cache will be initialized from a file, and if that fails, the fresh data will be generated.
pub static BITVM_CACHE: OnceLock<BitvmCacheWithMetadata> = OnceLock::new();

pub struct BitvmCacheWithMetadata {
    pub bitvm_cache: BitvmCache,
    pub sha256_bitvm_cache: [u8; 32],
}

pub fn load_or_generate_bitvm_cache() -> BitvmCacheWithMetadata {
    let start = Instant::now();

    let cache_path = std::env::var("BITVM_CACHE_PATH").unwrap_or_else(|_| {
        if is_dev_mode() {
            "bitvm_cache_dev.bin".to_string()
        } else {
            "bitvm_cache.bin".to_string()
        }
    });

    let bitvm_cache = {
        tracing::debug!("Attempting to load BitVM cache from file: {}", cache_path);

        match BitvmCache::load_from_file(&cache_path) {
            Ok(cache) => {
                tracing::debug!("Loaded BitVM cache from file");

                cache
            }
            Err(_) => {
                tracing::info!("No BitVM cache found, generating fresh data");

                let fresh_data = generate_fresh_data();

                if let Err(e) = fresh_data.save_to_file(&cache_path) {
                    tracing::error!(
                        "Failed to save freshly generated BitVM cache to file: {}",
                        e
                    );
                }
                fresh_data
            }
        }
    };

    tracing::debug!("BitVM initialization took: {:?}", start.elapsed());

    // calculate sha256 of disprove scripts, to be used in compatibility checks
    let mut hasher = Sha256::new();
    for script in bitvm_cache.disprove_scripts.iter() {
        hasher.update(script);
    }
    hasher.update(
        // expect is fine here because BitVM cache is generated on main() and shouldn't fail
        borsh::to_vec(&bitvm_cache.replacement_places)
            .expect("Failed to serialize replacement places while generating fresh data")
            .as_slice(),
    );
    let sha256_bitvm_cache: [u8; 32] = hasher.finalize().into();

    BitvmCacheWithMetadata {
        bitvm_cache,
        sha256_bitvm_cache,
    }
}

#[derive(BorshSerialize, BorshDeserialize, Debug)]
pub struct BitvmCache {
    pub disprove_scripts: Vec<Vec<u8>>,
    pub replacement_places: Box<ClementineBitVMReplacementData>,
}

impl BitvmCache {
    fn save_to_file(&self, path: &str) -> Result<(), BridgeError> {
        let serialized = borsh::to_vec(self).map_err(|e| {
            tracing::error!("Failed to serialize BitVM cache: {}", e);
            BridgeError::ConfigError("Failed to serialize BitVM cache".to_string())
        })?;

        fs::write(path, serialized).map_err(|e| {
            tracing::error!("Failed to save BitVM cache: {}", e);
            BridgeError::ConfigError("Failed to save BitVM cache".to_string())
        })
    }

    fn load_from_file(path: &str) -> Result<Self, BridgeError> {
        let bytes = fs::read(path).map_err(|e| {
            tracing::error!("Failed to read BitVM cache: {}", e);
            BridgeError::ConfigError("No BitVM cache found".to_string())
        })?;

        tracing::info!("Loaded BitVM cache from file, read {} bytes", bytes.len());

        Self::try_from_slice(&bytes).map_err(|e| {
            tracing::error!("Failed to deserialize BitVM cache: {}", e);
            BridgeError::ConfigError("Failed to deserialize BitVM cache".to_string())
        })
    }
}

fn generate_fresh_data() -> BitvmCache {
    let vk = get_verifying_key();

    let dummy_pks = ClementineBitVMPublicKeys::create_replacable();

    let partial_scripts = api_generate_partial_script(&vk);

    let scripts = partial_scripts
        .iter()
        .map(|s| s.clone().to_bytes())
        .collect::<Vec<_>>();

    for (script_idx, script) in scripts.iter().enumerate() {
        let mut pos = 0;
        while pos + 20 <= script.len() {
            // Check if this window matches our pattern (255u8 in the end)
            if script[pos + 4..pos + 20] == [255u8; 16] {
                panic!("Dummy value found in script {}", script_idx);
            }
            pos += 1;
        }
    }

    let disprove_scripts = api_generate_full_tapscripts(dummy_pks.bitvm_pks, &partial_scripts);

    let scripts: Vec<Vec<u8>> = disprove_scripts
        .iter()
        .map(|s| s.clone().to_bytes())
        .collect();

    // Build mapping of dummy keys to their positions
    let mut replacement_places: ClementineBitVMReplacementData = Default::default();
    // For each script
    for (script_idx, script) in scripts.iter().enumerate() {
        let mut pos = 0;
        while pos + 20 <= script.len() {
            // Check if this window matches our pattern (255u8 in the end)
            if script[pos + 4..pos + 20] == [255u8; 16] {
                let pk_type_idx = script[pos];
                let pk_idx = u16::from_be_bytes([script[pos + 1], script[pos + 2]]);
                let digit_idx = script[pos + 3];

                match pk_type_idx {
                    0 => {
                        replacement_places.payout_tx_blockhash_pk[digit_idx as usize]
                            .push((script_idx, pos));
                    }
                    1 => {
                        replacement_places.latest_blockhash_pk[digit_idx as usize]
                            .push((script_idx, pos));
                    }
                    2 => {
                        replacement_places.challenge_sending_watchtowers_pk[digit_idx as usize]
                            .push((script_idx, pos));
                    }
                    3 => {
                        replacement_places.bitvm_pks.0[pk_idx as usize][digit_idx as usize]
                            .push((script_idx, pos));
                    }
                    4 => {
                        replacement_places.bitvm_pks.1[pk_idx as usize][digit_idx as usize]
                            .push((script_idx, pos));
                    }
                    5 => {
                        replacement_places.bitvm_pks.2[pk_idx as usize][digit_idx as usize]
                            .push((script_idx, pos));
                    }
                    _ => {
                        panic!("Invalid pk type index: {}", pk_type_idx);
                    }
                }
                pos += 20;
            } else {
                pos += 1;
            }
        }
    }

    BitvmCache {
        disprove_scripts: scripts,
        replacement_places: Box::new(replacement_places),
    }
}

#[derive(Debug, Clone, BorshSerialize, BorshDeserialize, PartialEq, Eq)]
pub struct ClementineBitVMPublicKeys {
    pub combined_method_id_constant: [u8; 32],
    pub deposit_constant: [u8; 32],
    pub payout_tx_blockhash_pk: <Wots20 as Wots>::PublicKey,
    pub latest_blockhash_pk: <Wots20 as Wots>::PublicKey,
    pub challenge_sending_watchtowers_pk: <Wots20 as Wots>::PublicKey,
    pub bitvm_pks: bitvm::chunk::api::PublicKeys,
}

#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
#[allow(clippy::type_complexity)]
pub struct ClementineBitVMReplacementData {
    pub payout_tx_blockhash_pk: [Vec<(usize, usize)>; 44],
    pub latest_blockhash_pk: [Vec<(usize, usize)>; 44],
    pub challenge_sending_watchtowers_pk: [Vec<(usize, usize)>; 44],
    pub bitvm_pks: (
        [[Vec<(usize, usize)>; 68]; NUM_PUBS],
        [[Vec<(usize, usize)>; 68]; NUM_U256],
        [[Vec<(usize, usize)>; 36]; NUM_HASH],
    ),
}

impl Default for ClementineBitVMReplacementData {
    fn default() -> Self {
        Self {
            payout_tx_blockhash_pk: std::array::from_fn(|_| Vec::new()),
            latest_blockhash_pk: std::array::from_fn(|_| Vec::new()),
            challenge_sending_watchtowers_pk: std::array::from_fn(|_| Vec::new()),
            bitvm_pks: (
                std::array::from_fn(|_| std::array::from_fn(|_| Vec::new())),
                std::array::from_fn(|_| std::array::from_fn(|_| Vec::new())),
                std::array::from_fn(|_| std::array::from_fn(|_| Vec::new())),
            ),
        }
    }
}

impl ClementineBitVMPublicKeys {
    pub fn get_replacable_value(pk_type_idx: u8, pk_idx: u16, digit_idx: u8) -> [u8; 20] {
        let mut dummy_value = [255u8; 20];
        dummy_value[0] = pk_type_idx;
        dummy_value[1] = pk_idx.to_be_bytes()[0];
        dummy_value[2] = pk_idx.to_be_bytes()[1];
        dummy_value[3] = digit_idx;
        dummy_value
    }

    pub fn get_replacable_wpks<const DIGIT_LEN: usize>(
        pk_type_idx: u8,
        pk_idx: u16,
    ) -> [[u8; 20]; DIGIT_LEN] {
        (0..DIGIT_LEN as u8)
            .map(|digit_idx| Self::get_replacable_value(pk_type_idx, pk_idx, digit_idx))
            .collect::<Vec<_>>()
            .try_into()
            .expect("Should be able to convert to array")
    }

    pub fn get_multiple_replacable_wpks<const DIGIT_LEN: usize, const PK_LEN: usize>(
        pk_type_idx: u8,
    ) -> [[[u8; 20]; DIGIT_LEN]; PK_LEN] {
        (0..PK_LEN as u16)
            .map(|pk_idx| Self::get_replacable_wpks(pk_type_idx, pk_idx))
            .collect::<Vec<_>>()
            .try_into()
            .expect("Should be able to convert to array")
    }

    pub fn create_replacable() -> Self {
        let combined_method_id_constant = [255u8; 32];
        let deposit_constant = [255u8; 32];
        let payout_tx_blockhash_pk = Self::get_replacable_wpks(0, 0);
        let latest_blockhash_pk = Self::get_replacable_wpks(1, 0);
        let challenge_sending_watchtowers_pk = Self::get_replacable_wpks(2, 0);
        let bitvm_part_1 = Self::get_multiple_replacable_wpks(3);
        let bitvm_part_2 = Self::get_multiple_replacable_wpks(4);
        let bitvm_part_3 = Self::get_multiple_replacable_wpks(5);
        let bitvm_pks = (bitvm_part_1, bitvm_part_2, bitvm_part_3);
        Self {
            combined_method_id_constant,
            deposit_constant,
            payout_tx_blockhash_pk,
            latest_blockhash_pk,
            challenge_sending_watchtowers_pk,
            bitvm_pks,
        }
    }

    pub fn get_number_of_32_bytes_wpks() -> usize {
        NUM_PUBS + NUM_U256
    }

    pub fn get_number_of_160_bytes_wpks() -> usize {
        NUM_HASH + 2
    }

    pub fn from_flattened_vec(flattened_wpks: &[Vec<[u8; 20]>]) -> Self {
        // These are dummy since they are coming from another source
        let combined_method_id_constant = [255u8; 32];
        let deposit_constant = [255u8; 32];

        // Use the first element for payout_tx_blockhash_pk
        let payout_tx_blockhash_pk = Self::vec_to_array::<44>(&flattened_wpks[0]);

        // Use the second element for latest_blockhash_pk
        let latest_blockhash_pk = Self::vec_to_array::<44>(&flattened_wpks[1]);

        // Use the third element for challenge_sending_watchtowers_pk
        let challenge_sending_watchtowers_pk = Self::vec_to_array::<44>(&flattened_wpks[2]);

        // Create the nested arrays for bitvm_pks, starting from the fourth element
        let bitvm_pks_1 =
            Self::vec_slice_to_nested_array::<68, NUM_PUBS>(&flattened_wpks[3..3 + NUM_PUBS]);

        let bitvm_pks_2 = Self::vec_slice_to_nested_array::<68, NUM_U256>(
            &flattened_wpks[3 + NUM_PUBS..3 + NUM_PUBS + NUM_U256],
        );

        let bitvm_pks_3 = Self::vec_slice_to_nested_array::<36, NUM_HASH>(
            &flattened_wpks[3 + NUM_PUBS + NUM_U256..3 + NUM_PUBS + NUM_U256 + NUM_HASH],
        );

        Self {
            combined_method_id_constant,
            deposit_constant,
            payout_tx_blockhash_pk,
            latest_blockhash_pk,
            challenge_sending_watchtowers_pk,
            bitvm_pks: (bitvm_pks_1, bitvm_pks_2, bitvm_pks_3),
        }
    }

    pub fn to_flattened_vec(&self) -> Vec<Vec<[u8; 20]>> {
        let mut flattened_wpks = Vec::new();

        // Convert each array to Vec<[u8; 20]>
        flattened_wpks.push(self.payout_tx_blockhash_pk.to_vec());
        flattened_wpks.push(self.latest_blockhash_pk.to_vec());
        flattened_wpks.push(self.challenge_sending_watchtowers_pk.to_vec());

        // Convert and add each nested array from bitvm_pks
        for arr in &self.bitvm_pks.0 {
            flattened_wpks.push(arr.to_vec());
        }

        for arr in &self.bitvm_pks.1 {
            flattened_wpks.push(arr.to_vec());
        }

        for arr in &self.bitvm_pks.2 {
            flattened_wpks.push(arr.to_vec());
        }

        flattened_wpks
    }

    // Helper to convert Vec<[u8; 20]> to [[u8; 20]; N]
    pub fn vec_to_array<const N: usize>(vec: &[[u8; 20]]) -> [[u8; 20]; N] {
        let mut result = [[255u8; 20]; N];
        for (i, item) in vec.iter().enumerate() {
            if i < N {
                result[i] = *item;
            }
        }
        result
    }

    // Helper to convert &[Vec<[u8; 20]>] to [[[u8; 20]; INNER_LEN]; OUTER_LEN]
    pub fn vec_slice_to_nested_array<const INNER_LEN: usize, const OUTER_LEN: usize>(
        slice: &[Vec<[u8; 20]>],
    ) -> [[[u8; 20]; INNER_LEN]; OUTER_LEN] {
        let mut result = [[[255u8; 20]; INNER_LEN]; OUTER_LEN];
        for (i, vec) in slice.iter().enumerate() {
            if i < OUTER_LEN {
                result[i] = Self::vec_to_array::<INNER_LEN>(vec);
            }
        }
        result
    }

    pub const fn number_of_assert_txs() -> usize {
        33
    }

    pub const fn number_of_flattened_wpks() -> usize {
        381
    }

    pub fn get_assert_scripts(
        &self,
        xonly_public_key: XOnlyPublicKey,
    ) -> Vec<std::sync::Arc<dyn SpendableScript>> {
        let mut scripts = Vec::new();
        let first_script: Arc<dyn SpendableScript> = Arc::new(WinternitzCommit::new(
            vec![
                (self.challenge_sending_watchtowers_pk.to_vec(), 40),
                (self.bitvm_pks.0[0].to_vec(), 64),
                (self.bitvm_pks.1[NUM_U256 - 2].to_vec(), 64),
                (self.bitvm_pks.1[NUM_U256 - 1].to_vec(), 64),
                (self.bitvm_pks.2[NUM_HASH - 3].to_vec(), 32),
                (self.bitvm_pks.2[NUM_HASH - 2].to_vec(), 32),
                (self.bitvm_pks.2[NUM_HASH - 1].to_vec(), 32),
            ],
            xonly_public_key,
            4,
        ));
        scripts.push(first_script);
        // iterate NUM_U256 6 by 6
        for i in (0..NUM_U256 - 2).step_by(6) {
            let last_idx = std::cmp::min(i + 6, NUM_U256);
            let script: Arc<dyn SpendableScript> = Arc::new(WinternitzCommit::new(
                self.bitvm_pks.1[i..last_idx]
                    .iter()
                    .map(|x| (x.to_vec(), 64))
                    .collect::<Vec<_>>(),
                xonly_public_key,
                4,
            ));
            scripts.push(script);
        }
        // iterate NUM_HASH 12 by 12
        for i in (0..NUM_HASH - 3).step_by(12) {
            let last_idx = std::cmp::min(i + 12, NUM_HASH);
            let script: Arc<dyn SpendableScript> = Arc::new(WinternitzCommit::new(
                self.bitvm_pks.2[i..last_idx]
                    .iter()
                    .map(|x| (x.to_vec(), 32))
                    .collect::<Vec<_>>(),
                xonly_public_key,
                4,
            ));
            scripts.push(script);
        }
        scripts
    }

    pub fn get_assert_commit_data(
        asserts: Assertions,
        challenge_sending_watchtowers: &[u8; 20],
    ) -> Vec<Vec<Vec<u8>>> {
        let mut commit_data = Vec::new();
        tracing::info!(
            "Getting assert commit data, challenge_sending_watchtowers: {:?}",
            challenge_sending_watchtowers
        );
        commit_data.push(vec![
            challenge_sending_watchtowers.to_vec(),
            asserts.0[0].to_vec(),
            asserts.1[NUM_U256 - 2].to_vec(),
            asserts.1[NUM_U256 - 1].to_vec(),
            asserts.2[NUM_HASH - 3].to_vec(),
            asserts.2[NUM_HASH - 2].to_vec(),
            asserts.2[NUM_HASH - 1].to_vec(),
        ]);
        for i in (0..NUM_U256 - 2).step_by(6) {
            let last_idx = std::cmp::min(i + 6, NUM_U256);
            commit_data.push(
                asserts.1[i..last_idx]
                    .iter()
                    .map(|x| x.to_vec())
                    .collect::<Vec<_>>(),
            );
        }
        for i in (0..NUM_HASH - 3).step_by(12) {
            let last_idx = std::cmp::min(i + 12, NUM_HASH);
            commit_data.push(
                asserts.2[i..last_idx]
                    .iter()
                    .map(|x| x.to_vec())
                    .collect::<Vec<_>>(),
            );
        }
        commit_data
    }

    pub fn get_latest_blockhash_derivation(
        deposit_outpoint: bitcoin::OutPoint,
        paramset: &'static ProtocolParamset,
    ) -> WinternitzDerivationPath {
        WinternitzDerivationPath::BitvmAssert(20 * 2, 1, 0, deposit_outpoint, paramset)
    }

    pub fn get_payout_tx_blockhash_derivation(
        deposit_outpoint: bitcoin::OutPoint,
        paramset: &'static ProtocolParamset,
    ) -> WinternitzDerivationPath {
        WinternitzDerivationPath::BitvmAssert(20 * 2, 0, 0, deposit_outpoint, paramset)
    }

    pub fn get_challenge_sending_watchtowers_derivation(
        deposit_outpoint: bitcoin::OutPoint,
        paramset: &'static ProtocolParamset,
    ) -> WinternitzDerivationPath {
        WinternitzDerivationPath::BitvmAssert(20 * 2, 2, 0, deposit_outpoint, paramset)
    }

    pub fn mini_assert_derivations_0(
        deposit_outpoint: bitcoin::OutPoint,
        paramset: &'static ProtocolParamset,
    ) -> Vec<WinternitzDerivationPath> {
        vec![
            Self::get_challenge_sending_watchtowers_derivation(deposit_outpoint, paramset), // Will not go into BitVM disprove scripts
            WinternitzDerivationPath::BitvmAssert(32 * 2, 3, 0, deposit_outpoint, paramset), // This is the Groth16 public output
            WinternitzDerivationPath::BitvmAssert(32 * 2, 4, 12, deposit_outpoint, paramset), // This is the extra 13th NUM_U256, after chunking by 6 for the first 2 asserts
            WinternitzDerivationPath::BitvmAssert(32 * 2, 4, 13, deposit_outpoint, paramset), // This is the extra 14th NUM_U256, after chunking by 6 for the first 2 asserts
            WinternitzDerivationPath::BitvmAssert(16 * 2, 5, 360, deposit_outpoint, paramset),
            WinternitzDerivationPath::BitvmAssert(16 * 2, 5, 361, deposit_outpoint, paramset),
            WinternitzDerivationPath::BitvmAssert(16 * 2, 5, 362, deposit_outpoint, paramset),
        ]
    }

    pub fn get_assert_derivations(
        mini_assert_idx: usize,
        deposit_outpoint: bitcoin::OutPoint,
        paramset: &'static ProtocolParamset,
    ) -> Vec<WinternitzDerivationPath> {
        if mini_assert_idx == 0 {
            Self::mini_assert_derivations_0(deposit_outpoint, paramset)
        } else if (1..=2).contains(&mini_assert_idx) {
            // for 1, we will have 6 derivations index starting from 0 to 5
            // for 2, we will have 6 derivations index starting from 6 to 11
            let derivations: u32 = (mini_assert_idx as u32 - 1) * 6;

            let mut derivations_vec = vec![];
            for i in 0..6 {
                if derivations + i < NUM_U256 as u32 - 2 {
                    derivations_vec.push(WinternitzDerivationPath::BitvmAssert(
                        32 * 2,
                        4,
                        derivations + i,
                        deposit_outpoint,
                        paramset,
                    ));
                }
            }
            derivations_vec
        } else {
            let derivations: u32 = (mini_assert_idx as u32 - 3) * 12;
            let mut derivations_vec = vec![];
            for i in 0..12 {
                if derivations + i < NUM_HASH as u32 - 3 {
                    derivations_vec.push(WinternitzDerivationPath::BitvmAssert(
                        16 * 2,
                        5,
                        derivations + i,
                        deposit_outpoint,
                        paramset,
                    ));
                }
            }
            derivations_vec
        }
    }
    pub fn get_assert_taproot_leaf_hashes(
        &self,
        xonly_public_key: XOnlyPublicKey,
    ) -> Vec<bitcoin::TapNodeHash> {
        let assert_scripts = self.get_assert_scripts(xonly_public_key);
        assert_scripts
            .into_iter()
            .map(|script| {
                let taproot_builder = taproot_builder_with_scripts(&[script.to_script_buf()]);
                taproot_builder
                    .try_into_taptree()
                    .expect("taproot builder always builds a full taptree")
                    .root_hash()
            })
            .collect::<Vec<_>>()
    }

    pub fn get_g16_verifier_disprove_scripts(&self) -> Result<Vec<ScriptBuf>, BridgeError> {
        if cfg!(debug_assertions) {
            Ok(vec![ScriptBuf::from_bytes(vec![0x51])]) // OP_TRUE
        } else {
            Ok(replace_disprove_scripts(self)?)
        }
    }
}

pub fn replace_disprove_scripts(
    pks: &ClementineBitVMPublicKeys,
) -> Result<Vec<ScriptBuf>, BridgeError> {
    let start = Instant::now();
    tracing::info!("Starting script replacement");

    let cache = &BITVM_CACHE
        .get_or_init(load_or_generate_bitvm_cache)
        .bitvm_cache;
    let replacement_places = &cache.replacement_places;

    // Calculate estimated operations to prevent DoS attacks
    let estimated_operations = calculate_replacement_operations(replacement_places);
    tracing::info!(
        "Estimated operations for script replacement: {}",
        estimated_operations
    );
    if estimated_operations > MAX_SCRIPT_REPLACEMENT_OPERATIONS {
        tracing::warn!(
            "Rejecting script replacement: estimated {} operations exceeds limit of {}",
            estimated_operations,
            MAX_SCRIPT_REPLACEMENT_OPERATIONS
        );
        return Err(BridgeError::BitvmReplacementResourceExhaustion(
            estimated_operations,
        ));
    }

    tracing::info!("Estimated operations: {}", estimated_operations);

    let mut result: Vec<Vec<u8>> = cache.disprove_scripts.clone();

    for (digit, places) in replacement_places.payout_tx_blockhash_pk.iter().enumerate() {
        for (script_idx, pos) in places.iter() {
            result[*script_idx][*pos..*pos + 20]
                .copy_from_slice(&pks.payout_tx_blockhash_pk[digit]);
        }
    }

    for (digit, places) in replacement_places.latest_blockhash_pk.iter().enumerate() {
        for (script_idx, pos) in places.iter() {
            result[*script_idx][*pos..*pos + 20].copy_from_slice(&pks.latest_blockhash_pk[digit]);
        }
    }

    for (digit, places) in replacement_places
        .challenge_sending_watchtowers_pk
        .iter()
        .enumerate()
    {
        for (script_idx, pos) in places.iter() {
            result[*script_idx][*pos..*pos + 20]
                .copy_from_slice(&pks.challenge_sending_watchtowers_pk[digit]);
        }
    }

    for (digit, places) in replacement_places.bitvm_pks.0.iter().enumerate() {
        for (pk_idx, places) in places.iter().enumerate() {
            for (script_idx, pos) in places.iter() {
                result[*script_idx][*pos..*pos + 20]
                    .copy_from_slice(&pks.bitvm_pks.0[digit][pk_idx]);
            }
        }
    }

    for (digit, places) in replacement_places.bitvm_pks.1.iter().enumerate() {
        for (pk_idx, places) in places.iter().enumerate() {
            for (script_idx, pos) in places.iter() {
                result[*script_idx][*pos..*pos + 20]
                    .copy_from_slice(&pks.bitvm_pks.1[digit][pk_idx]);
            }
        }
    }

    for (digit, places) in replacement_places.bitvm_pks.2.iter().enumerate() {
        for (pk_idx, places) in places.iter().enumerate() {
            for (script_idx, pos) in places.iter() {
                result[*script_idx][*pos..*pos + 20]
                    .copy_from_slice(&pks.bitvm_pks.2[digit][pk_idx]);
            }
        }
    }

    let result: Vec<ScriptBuf> = result.into_iter().map(ScriptBuf::from_bytes).collect();

    let elapsed = start.elapsed();
    tracing::info!(
        "Script replacement completed in {:?} with {} operations",
        elapsed,
        estimated_operations
    );

    Ok(result)
}

/// Helper function to calculate the total number of replacement operations
fn calculate_replacement_operations(replacement_places: &ClementineBitVMReplacementData) -> usize {
    let mut total_operations = 0;

    // Count payout_tx_blockhash_pk operations
    for places in &replacement_places.payout_tx_blockhash_pk {
        total_operations += places.len();
    }

    // Count latest_blockhash_pk operations
    for places in &replacement_places.latest_blockhash_pk {
        total_operations += places.len();
    }

    // Count challenge_sending_watchtowers_pk operations
    for places in &replacement_places.challenge_sending_watchtowers_pk {
        total_operations += places.len();
    }

    // Count bitvm_pks operations (this is typically the largest contributor)
    for digit_places in &replacement_places.bitvm_pks.0 {
        for places in digit_places {
            total_operations += places.len();
        }
    }

    for digit_places in &replacement_places.bitvm_pks.1 {
        for places in digit_places {
            total_operations += places.len();
        }
    }

    for digit_places in &replacement_places.bitvm_pks.2 {
        for places in digit_places {
            total_operations += places.len();
        }
    }

    total_operations
}

#[cfg(test)]
mod tests {
    use bitcoin::secp256k1::rand::thread_rng;
    use bitcoin::{hashes::Hash, Txid};

    use super::*;
    use crate::{actor::Actor, test::common::create_test_config_with_thread_name};
    #[test]
    fn test_to_flattened_vec() {
        let bitvm_pks = ClementineBitVMPublicKeys::create_replacable();
        let flattened_vec = bitvm_pks.to_flattened_vec();
        let from_vec_to_array = ClementineBitVMPublicKeys::from_flattened_vec(&flattened_vec);
        assert_eq!(bitvm_pks, from_vec_to_array);
    }

    #[tokio::test]
    async fn test_vec_to_array_with_actor_values() {
        let config = create_test_config_with_thread_name().await;

        let sk = bitcoin::secp256k1::SecretKey::new(&mut thread_rng());
        let signer = Actor::new(sk, Some(sk), config.protocol_paramset().network);
        let deposit_outpoint = bitcoin::OutPoint {
            txid: Txid::all_zeros(),
            vout: 0,
        };
        let bitvm_pks = signer
            .generate_bitvm_pks_for_deposit(deposit_outpoint, config.protocol_paramset())
            .unwrap();

        let flattened_vec = bitvm_pks.to_flattened_vec();
        let from_vec_to_array = ClementineBitVMPublicKeys::from_flattened_vec(&flattened_vec);
        assert_eq!(bitvm_pks, from_vec_to_array);
    }

    #[tokio::test]
    #[ignore = "This test is too slow to run on every commit"]
    async fn test_generate_fresh_data() {
        let bitvm_cache = generate_fresh_data();
        bitvm_cache
            .save_to_file("bitvm_cache_new.bin")
            .expect("Failed to save BitVM cache");
    }
}
