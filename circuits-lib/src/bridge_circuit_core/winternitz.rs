use super::{structs, utils};
use borsh::{BorshDeserialize, BorshSerialize};
use final_spv::spv::SPV;
use header_chain::header_chain::BlockHeaderCircuitOutput;
use serde::{Deserialize, Serialize};
pub type HashOut = [u8; 20];
pub type PublicKey = Vec<HashOut>;
pub type SecretKey = Vec<u8>;
use utils::hash160;
use structs::{LightClientProof, StorageProof};
use bitcoin::hashes::{self, Hash};


#[derive(Eq, PartialEq, Clone, Debug, BorshDeserialize, BorshSerialize)]
pub struct WinternitzHandler {
    pub pub_key: PublicKey,
    pub params: Parameters,
    pub signature: Vec<Vec<u8>>,
    pub message: Vec<u8>,
}

#[derive(Eq, PartialEq, Clone, Debug, BorshDeserialize, BorshSerialize)]
pub struct WinternitzCircuitInput {
    pub winternitz_details: Vec<WinternitzHandler>,
    pub hcp: BlockHeaderCircuitOutput, // This will be removed once the LightClientProof includes the MMRGuest of the Bitcoin blockhashes
    pub payout_spv: SPV,
    pub lcp: LightClientProof,
    pub operator_id: u32,
    pub sp: StorageProof,
}

#[derive(Serialize, Deserialize, Eq, PartialEq, Clone, Debug, BorshDeserialize, BorshSerialize)]
pub struct WinternitzCircuitOutput {
    pub winternitz_pubkeys_digest: [u8; 20],
    pub correct_watchtowers: Vec<bool>,
    pub payout_tx_blockhash: [u8; 32],
    pub last_blockhash: [u8; 32],
    pub deposit_txid: [u8; 32],
    pub operator_id: Vec<u8>,
}

pub fn verify_winternitz_signature(input: &WinternitzHandler) -> bool {
    if input.pub_key.len() != input.params.n as usize
        || input.signature.len() != input.params.n as usize
        || input.message.len() != input.params.n0 as usize
    {
        return false;
    }

    let checksum = get_message_checksum(&input.params, &input.message);

    for (i, &digit) in input.message.iter().enumerate() {
        let signature_byte_arr: [u8; 20] = input.signature[i].as_slice().try_into().unwrap();

        let hash_bytes =
            (0..(input.params.d - digit as u32)).fold(signature_byte_arr, |hash, _| hash160(&hash));

        if hash_bytes != input.pub_key[i] {
            println!("{:?}, {:?}", hash_bytes, input.pub_key[i]);
            return false;
        }
    }

    for ((&checksum, sig), &pubkey) in checksum
        .iter()
        .zip(&input.signature[input.message.len()..])
        .zip(&input.pub_key[input.message.len()..])
    {
        let signature_byte_arr: [u8; 20] = sig.as_slice().try_into().unwrap();
        let hash_bytes = (0..(input.params.d - checksum as u32))
            .fold(signature_byte_arr, |hash, _| hash160(&hash));

        if hash_bytes != pubkey {
            println!("{:?}, {:?}", hash_bytes, pubkey);
            return false;
        }
    }

    true
}

pub fn get_message_checksum(ps: &Parameters, digits: &[u8]) -> Vec<u8> {
    to_digits(checksum(ps, digits), ps.d + 1, ps.n1 as i32)
}

pub fn sign_digits(ps: &Parameters, secret_key: &SecretKey, digits: &[u8]) -> Vec<Vec<u8>> {
    let cheksum1 = get_message_checksum(ps, digits);
    let mut result: Vec<Vec<u8>> = Vec::with_capacity(ps.n as usize);
    for i in 0..ps.n0 {
        let sig = digit_signature(secret_key, i, digits[i as usize]);
        result.push(sig.hash_bytes);
    }
    for i in 0..ps.n1 {
        let sig = digit_signature(secret_key, i + digits.len() as u32, cheksum1[i as usize]);
        result.push(sig.hash_bytes);
    }
    result
}

pub fn generate_public_key(ps: &Parameters, secret_key: &SecretKey) -> PublicKey {
    let mut public_key = PublicKey::with_capacity(ps.n as usize);
    for i in 0..ps.n {
        public_key.push(public_key_for_digit(ps, secret_key, i));
    }
    public_key
}

fn checksum(ps: &Parameters, digits: &[u8]) -> u32 {
    let mut sum: u32 = 0;
    for &digit in digits {
        sum += digit as u32;
    }
    ps.d * ps.n0 - sum
}

#[derive(
    Serialize, Deserialize, Eq, PartialEq, Hash, Clone, Debug, BorshDeserialize, BorshSerialize,
)]
pub struct Parameters {
    n0: u32,
    log_d: u32,
    n1: u32,
    d: u32,
    n: u32,
}

#[derive(Debug, Clone)]
pub struct DigitSignature {
    pub hash_bytes: Vec<u8>,
}

impl Parameters {
    pub fn new(n0: u32, log_d: u32) -> Self {
        assert!(
            (4..=8).contains(&log_d),
            "You can only choose block lengths in the range [4, 8]"
        );
        let d: u32 = (1 << log_d) - 1;
        let n1: u32 = log_base_ceil(d * n0, d + 1) + 1;
        let n: u32 = n0 + n1;
        Parameters {
            n0,
            log_d,
            n1,
            d,
            n,
        }
    }
}

fn public_key_for_digit(ps: &Parameters, secret_key: &SecretKey, digit_index: u32) -> HashOut {
    let mut secret_i = secret_key.clone();
    secret_i.push(digit_index as u8);
    let mut hash = hashes::hash160::Hash::hash(&secret_i);

    for _ in 0..ps.d {
        hash = hashes::hash160::Hash::hash(&hash[..]);
    }

    *hash.as_byte_array()
}

pub fn digit_signature(
    secret_key: &SecretKey,
    digit_index: u32,
    message_digit: u8,
) -> DigitSignature {
    let mut secret_i = secret_key.clone();
    secret_i.push(digit_index as u8);
    let mut hash = hashes::hash160::Hash::hash(&secret_i);
    for _ in 0..message_digit {
        hash = hashes::hash160::Hash::hash(&hash[..]);
    }
    let hash_bytes = hash.as_byte_array().to_vec();
    DigitSignature { hash_bytes }
}

pub fn to_digits(mut number: u32, base: u32, digit_count: i32) -> Vec<u8> {
    let mut digits = Vec::new();
    if digit_count == -1 {
        while number > 0 {
            let digit = number % base;
            number = (number - digit) / base;
            digits.push(digit);
        }
    } else {
        digits.reserve(digit_count as usize);
        for _ in 0..digit_count {
            let digit = number % base;
            number = (number - digit) / base;
            digits.push(digit);
        }
    }
    let mut digits_u8: Vec<u8> = vec![0; digits.len()];
    for (i, num) in digits.iter().enumerate() {
        let bytes = num.to_le_bytes(); // Convert u32 to 4 bytes (little-endian)
        digits_u8[i] = bytes[0];
    }
    digits_u8
}

pub fn log_base_ceil(n: u32, base: u32) -> u32 {
    let mut res: u32 = 0;
    let mut cur: u64 = 1;
    while cur < (n as u64) {
        cur *= base as u64;
        res += 1;
    }
    res
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_checksum() {
        let ps = Parameters::new(4, 4);
        let digits = vec![1, 2, 3, 4];
        let expected_checksum = ps.d * ps.n0 - digits.iter().map(|&x| x as u32).sum::<u32>();
        assert_eq!(checksum(&ps, &digits), expected_checksum);
    }

    #[test]
    fn test_to_digits() {
        assert_eq!(to_digits(10, 2, -1), vec![0, 1, 0, 1]);
        assert_eq!(to_digits(255, 16, 2), vec![15, 15]);
    }

    #[test]
    fn test_log_base_ceil() {
        assert_eq!(log_base_ceil(8, 2), 3);
        assert_eq!(log_base_ceil(10, 2), 4);
    }

    #[test]
    fn test_public_key_for_digit() {
        let ps = Parameters::new(4, 4);
        let secret_key = vec![1, 2, 3, 4];
        let pk = public_key_for_digit(&ps, &secret_key, 0);
        assert_eq!(pk.len(), 20);
    }

    #[test]
    fn test_digit_signature() {
        let secret_key = vec![1, 2, 3, 4];
        let sig = digit_signature(&secret_key, 1, 2);
        assert_eq!(sig.hash_bytes.len(), 20);
    }

    #[test]
    fn test_generate_public_key() {
        let ps = Parameters::new(4, 4);
        let secret_key = vec![1, 2, 3, 4];
        let public_key = generate_public_key(&ps, &secret_key);
        assert_eq!(public_key.len(), ps.n as usize);
    }

    // #[test]
    // fn test_sign_and_verify() {
    //     let ps = Parameters::new(4, 4);
    //     let secret_key = vec![1, 2, 3, 4];
    //     let message = vec![1, 2, 3, 4];

    //     let public_key = generate_public_key(&ps, &secret_key);
    //     let signature = sign_digits(&ps, &secret_key, &message);

    //     let input = WinternitzCircuitInput {
    //         pub_key: public_key,
    //         params: ps,
    //         signature: signature.clone(),
    //         message: message.clone(),
    //     };

    //     assert!(verify_signature(&input));
    // }

    // #[test]
    // fn test_invalid_signature() {
    //     let ps = Parameters::new(4, 4);
    //     let secret_key = vec![1, 2, 3, 4];
    //     let message = vec![1, 2, 3, 4];

    //     let public_key = generate_public_key(&ps, &secret_key);
    //     let mut signature = sign_digits(&ps, &secret_key, &message);

    //     signature[0][0] ^= 0xFF;

    //     let input = WinternitzCircuitInput {
    //         pub_key: public_key,
    //         params: ps,
    //         signature,
    //         message,
    //     };

    //     assert!(!verify_signature(&input));
    // }
}
