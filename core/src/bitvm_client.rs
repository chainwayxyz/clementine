use crate::actor::WinternitzDerivationPath;
use crate::builder::address::taproot_builder_with_scripts;
use crate::builder::script::{SpendableScript, WinternitzCommit};

use crate::config::protocol::ProtocolParamset;
use crate::errors::BridgeError;
use ark_bn254::Bn254;
use bitcoin::key::Parity;
use bitcoin::{self};
use bitcoin::{ScriptBuf, XOnlyPublicKey};

use bitvm::chunk::api::{
    api_generate_full_tapscripts, api_generate_partial_script, NUM_PUBS, NUM_U160, NUM_U256,
};
use bitvm::signatures::wots_api::wots160;

//use bitvm::chunker::assigner::BridgeAssigner;
use ark_serialize::CanonicalDeserialize;

use borsh::{BorshDeserialize, BorshSerialize};
use std::fs;

use std::str::FromStr;
use std::sync::Arc;
use std::time::Instant;

lazy_static::lazy_static! {
    /// Global secp context.
    pub static ref SECP: bitcoin::secp256k1::Secp256k1<bitcoin::secp256k1::All> = bitcoin::secp256k1::Secp256k1::new();
}

lazy_static::lazy_static! {
    /// This is an unspendable pubkey.
    ///
    /// See https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki#constructing-and-spending-taproot-outputs
    pub static ref UNSPENDABLE_PUBKEY: bitcoin::secp256k1::PublicKey =
        "93c7378d96518a75448821c4f7c8f4bae7ce60f804d03d1f0628dd5dd0f5de51".parse::<bitcoin::secp256k1::XOnlyPublicKey>().expect("this key is valid").public_key(Parity::Even);
}

lazy_static::lazy_static! {
    /// This is an unspendable pubkey.
    ///
    /// See https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki#constructing-and-spending-taproot-outputs
    pub static ref UNSPENDABLE_XONLY_PUBKEY: bitcoin::secp256k1::XOnlyPublicKey =
        XOnlyPublicKey::from_str("93c7378d96518a75448821c4f7c8f4bae7ce60f804d03d1f0628dd5dd0f5de51").expect("this key is valid");
}

// lazy_static::lazy_static! {
//     pub static ref ALL_BITVM_INTERMEDIATE_VARIABLES: BTreeMap<String, usize> = BridgeAssigner::default().all_intermediate_variable();
// }
lazy_static::lazy_static! {
    pub static ref BITVM_CACHE: BitvmCache = {
        let start = Instant::now();

        let bitvm_cache = {
            let cache_path = "bitvm_cache.bin";
            match BitvmCache::load_from_file(cache_path) {
                Ok(cache) => {
                    tracing::info!("Loaded BitVM cache from file");
                    cache
                }
                Err(_) => {
                    tracing::info!("No BitVM cache found, generating fresh data");
                    let fresh_data = generate_fresh_data();
                    if let Err(e) = fresh_data.save_to_file(cache_path) {
                        tracing::error!("Failed to save BitVM cache to file: {}", e);
                    }
                    fresh_data
                }
            }
        };
        println!("BitVM initialization took: {:?}", start.elapsed());
        bitvm_cache
    };
}

#[derive(BorshSerialize, BorshDeserialize, Debug)]
pub struct BitvmCache {
    pub disprove_scripts: Vec<Vec<u8>>,
    pub replacement_places: ClementineBitVMReplacementData,
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

        Self::try_from_slice(&bytes).map_err(|e| {
            tracing::error!("Failed to deserialize BitVM cache: {}", e);
            BridgeError::ConfigError("Failed to deserialize BitVM cache".to_string())
        })
    }
}

fn generate_fresh_data() -> BitvmCache {
    let vk_bytes = [
        115, 158, 251, 51, 106, 255, 102, 248, 22, 171, 229, 158, 80, 192, 240, 217, 99, 162, 65,
        107, 31, 137, 197, 79, 11, 210, 74, 65, 65, 203, 243, 14, 123, 2, 229, 125, 198, 247, 76,
        241, 176, 116, 6, 3, 241, 1, 134, 195, 39, 5, 124, 47, 31, 43, 164, 48, 120, 207, 150, 125,
        108, 100, 48, 155, 137, 132, 16, 193, 139, 74, 179, 131, 42, 119, 25, 185, 98, 13, 235,
        118, 92, 11, 154, 142, 134, 220, 191, 220, 169, 250, 244, 104, 123, 7, 247, 33, 178, 155,
        121, 59, 75, 188, 206, 198, 182, 97, 0, 64, 231, 45, 55, 92, 100, 17, 56, 159, 79, 13, 219,
        221, 33, 39, 193, 24, 36, 58, 105, 8, 70, 206, 176, 209, 146, 45, 201, 157, 226, 84, 213,
        135, 143, 178, 156, 112, 137, 246, 123, 248, 215, 168, 51, 95, 177, 47, 57, 29, 199, 224,
        98, 48, 144, 253, 15, 201, 192, 142, 62, 143, 13, 228, 89, 51, 58, 6, 226, 139, 99, 207,
        22, 113, 215, 79, 91, 158, 166, 210, 28, 90, 218, 111, 151, 4, 55, 230, 76, 90, 209, 149,
        113, 248, 245, 50, 231, 137, 51, 157, 40, 29, 184, 198, 201, 108, 199, 89, 67, 136, 239,
        96, 216, 237, 172, 29, 84, 3, 128, 240, 2, 218, 169, 217, 118, 179, 34, 226, 19, 227, 59,
        193, 131, 108, 20, 113, 46, 170, 196, 156, 45, 39, 151, 218, 22, 132, 250, 209, 183, 46,
        249, 115, 239, 14, 176, 200, 134, 158, 148, 139, 212, 167, 152, 205, 183, 236, 242, 176,
        96, 177, 187, 184, 252, 14, 226, 127, 127, 173, 147, 224, 220, 8, 29, 63, 73, 215, 92, 161,
        110, 20, 154, 131, 23, 217, 116, 145, 196, 19, 167, 84, 185, 16, 89, 175, 180, 110, 116,
        57, 198, 237, 147, 183, 164, 169, 220, 172, 52, 68, 175, 113, 244, 62, 104, 134, 215, 99,
        132, 199, 139, 172, 108, 143, 25, 238, 201, 128, 85, 24, 73, 30, 186, 142, 186, 201, 79, 3,
        176, 185, 70, 66, 89, 127, 188, 158, 209, 83, 17, 22, 187, 153, 8, 63, 58, 174, 236, 132,
        226, 43, 145, 97, 242, 198, 117, 105, 161, 21, 241, 23, 84, 32, 62, 155, 245, 172, 30, 78,
        41, 199, 219, 180, 149, 193, 163, 131, 237, 240, 46, 183, 186, 42, 201, 49, 249, 142, 188,
        59, 212, 26, 253, 23, 27, 205, 231, 163, 76, 179, 135, 193, 152, 110, 91, 5, 218, 67, 204,
        164, 128, 183, 221, 82, 16, 72, 249, 111, 118, 182, 24, 249, 91, 215, 215, 155, 2, 0, 0, 0,
        0, 0, 0, 0, 212, 110, 6, 228, 73, 146, 46, 184, 158, 58, 94, 4, 141, 241, 158, 0, 175, 140,
        72, 75, 52, 6, 72, 49, 112, 215, 21, 243, 151, 67, 106, 22, 158, 237, 80, 204, 41, 128, 69,
        52, 154, 189, 124, 203, 35, 107, 132, 241, 234, 31, 3, 165, 87, 58, 10, 92, 252, 227, 214,
        99, 176, 66, 118, 22, 177, 20, 120, 198, 252, 236, 7, 148, 207, 78, 152, 132, 94, 207, 50,
        243, 4, 169, 146, 240, 79, 98, 0, 212, 106, 137, 36, 193, 21, 175, 180, 1, 26, 107, 39,
        198, 89, 152, 26, 220, 138, 105, 243, 45, 63, 106, 163, 80, 74, 253, 176, 207, 47, 52, 7,
        84, 59, 151, 47, 178, 165, 112, 251, 161,
    ]
    .to_vec();

    let vk: ark_groth16::VerifyingKey<Bn254> =
        ark_groth16::VerifyingKey::deserialize_uncompressed(&vk_bytes[..])
            .expect("Failed to deserialize verifying key");

    let dummy_pks = ClementineBitVMPublicKeys::create_replacable();

    let partial_scripts = api_generate_partial_script(&vk);

    let scripts = partial_scripts
        .iter()
        .map(|s| s.clone().compile().to_bytes())
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
        .map(|s| s.clone().compile().to_bytes())
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
        replacement_places,
    }
}

#[derive(Debug, Clone, BorshSerialize, BorshDeserialize, PartialEq, Eq)]
pub struct ClementineBitVMPublicKeys {
    pub combined_method_id_constant: [u8; 32],
    pub deposit_constant: [u8; 32],
    pub payout_tx_blockhash_pk: wots160::PublicKey,
    pub latest_blockhash_pk: wots160::PublicKey,
    pub challenge_sending_watchtowers_pk: wots160::PublicKey,
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
        [[Vec<(usize, usize)>; 44]; NUM_U160],
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
        NUM_U160 + 2
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

        let bitvm_pks_3 = Self::vec_slice_to_nested_array::<44, NUM_U160>(
            &flattened_wpks[3 + NUM_PUBS + NUM_U256..3 + NUM_PUBS + NUM_U256 + NUM_U160],
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
        42
    }

    pub const fn number_of_flattened_wpks() -> usize {
        396
    }

    pub fn get_assert_scripts(
        &self,
        xonly_public_key: XOnlyPublicKey,
    ) -> Vec<std::sync::Arc<dyn SpendableScript>> {
        let mut scripts = Vec::new();
        let first_script: Arc<dyn SpendableScript> = Arc::new(WinternitzCommit::new(
            vec![
                (self.latest_blockhash_pk.to_vec(), 40),
                (self.challenge_sending_watchtowers_pk.to_vec(), 40),
                (self.bitvm_pks.0[0].to_vec(), 64),
            ],
            xonly_public_key,
            4,
        ));
        scripts.push(first_script);
        // iterate NUM_U256 5 by 5
        for i in (0..NUM_U256).step_by(5) {
            let last_idx = std::cmp::min(i + 5, NUM_U256);
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
        // iterate NUM_U160 10 by 10
        for i in (0..NUM_U160).step_by(10) {
            let last_idx = std::cmp::min(i + 10, NUM_U160);
            let script: Arc<dyn SpendableScript> = Arc::new(WinternitzCommit::new(
                self.bitvm_pks.2[i..last_idx]
                    .iter()
                    .map(|x| (x.to_vec(), 40))
                    .collect::<Vec<_>>(),
                xonly_public_key,
                4,
            ));
            scripts.push(script);
        }
        scripts
    }

    pub fn get_assert_derivations(
        mini_assert_idx: usize,
        txid: bitcoin::Txid,
        paramset: &'static ProtocolParamset,
    ) -> Vec<WinternitzDerivationPath> {
        if mini_assert_idx == 0 {
            vec![
                WinternitzDerivationPath::BitvmAssert(20 * 2, 1, 0, txid, paramset),
                WinternitzDerivationPath::BitvmAssert(20 * 2, 2, 0, txid, paramset),
                WinternitzDerivationPath::BitvmAssert(20 * 2, 3, 0, txid, paramset),
            ]
        } else if (1..=3).contains(&mini_assert_idx) {
            // for 1, we will have 5 derivations index starting from 0 to 4
            // for 2, we will have 5 derivations index starting from 5 to 9
            // for 3, we will have 5 derivations index starting from 10 to 13
            let derivations: u32 = (mini_assert_idx as u32 - 1) * 5;

            let mut derivations_vec = vec![];
            for i in 0..5 {
                if derivations + i < NUM_U256 as u32 {
                    derivations_vec.push(WinternitzDerivationPath::BitvmAssert(
                        32 * 2,
                        derivations + i,
                        0,
                        txid,
                        paramset,
                    ));
                }
            }
            derivations_vec
        } else {
            let derivations: u32 = (mini_assert_idx as u32 - 3) * 10;
            let mut derivations_vec = vec![];
            for i in 0..10 {
                if derivations + i < NUM_U160 as u32 {
                    derivations_vec.push(WinternitzDerivationPath::BitvmAssert(
                        20 * 2,
                        derivations + i,
                        0,
                        txid,
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
            .iter()
            .map(|script| {
                let taproot_builder = taproot_builder_with_scripts(&[script.to_script_buf()]);
                taproot_builder
                    .try_into_taptree()
                    .expect("taproot builder always builds a full taptree")
                    .root_hash()
            })
            .collect::<Vec<_>>()
    }

    pub fn get_g16_verifier_disprove_scripts(&self) -> Vec<ScriptBuf> {
        if cfg!(debug_assertions) {
            vec![ScriptBuf::from_bytes(vec![0x51])] // OP_TRUE
        } else {
            replace_disprove_scripts(self)
        }
    }
}

pub fn replace_disprove_scripts(pks: &ClementineBitVMPublicKeys) -> Vec<ScriptBuf> {
    let start = Instant::now();
    tracing::info!("Starting script replacement");

    let cache = &*BITVM_CACHE;
    let mut result: Vec<Vec<u8>> = cache.disprove_scripts.clone();
    let replacement_places = &cache.replacement_places;

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
    tracing::info!("Script replacement completed in {:?}", elapsed);

    result
}

#[cfg(test)]
mod tests {
    use bitcoin::{hashes::Hash, Txid};
    use secp256k1::rand::thread_rng;

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
        let config = create_test_config_with_thread_name(None).await;

        let sk = bitcoin::secp256k1::SecretKey::new(&mut thread_rng());
        let signer = Actor::new(sk, Some(sk), config.protocol_paramset().network);
        let bitvm_pks = signer
            .generate_bitvm_pks_for_deposit(Txid::all_zeros(), config.protocol_paramset())
            .unwrap();

        let flattened_vec = bitvm_pks.to_flattened_vec();
        let from_vec_to_array = ClementineBitVMPublicKeys::from_flattened_vec(&flattened_vec);
        assert_eq!(bitvm_pks, from_vec_to_array);
    }

    #[tokio::test]
    #[ignore = "This test is too slow to run on every commit"]
    async fn test_generate_fresh_data() {
        let _bitvm_cache = generate_fresh_data();
    }
}
