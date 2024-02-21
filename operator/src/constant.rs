/// This file is the duplicate of the constant.rs file in the helpers crate


use bitcoin::OutPoint;
use bitcoin::Txid;
use circuit_helpers::hashes::sha256_32bytes;
use circuit_helpers::hashes::sha256_64bytes;
use circuit_helpers::hashes::sha256_96bytes;

pub type ConnectorTreeUTXOs = Vec<Vec<OutPoint>>;
pub type Data = [u8; 32];
pub type PreimageType = [u8; 32];
pub type HashType = [u8; 32];
pub type InscriptionTxs = (OutPoint, Txid);
pub const HASH_FUNCTION_96: fn(Data, Data, Data) -> Data = sha256_96bytes;
pub const HASH_FUNCTION_64: fn(Data, Data) -> Data = sha256_64bytes;
pub const HASH_FUNCTION_32: fn(Data) -> Data = sha256_32bytes;
pub const EMPTYDATA: Data = [0; 32];
pub const DUST_VALUE: u64 = 1000;
// pub const MINIMUM_FEE: Amount = Amount::from_sat(300);
pub const MIN_RELAY_FEE: u64 = 500;
pub type EVMAddress = [u8; 20];
pub const TAPROOT_LEAF_TAPSCRIPT: u8 = 192;
pub const CONFIRMATION_BLOCK_COUNT: u32 = 6;
pub const PERIOD_BLOCK_COUNT: u32 = 25920; // 10 mins for 1 block, 6 months = 6*30*24*6 = 25920
pub const MAX_BITVM_CHALLENGE_RESPONSE_BLOCK_COUNT: u32 = 11520; // 10 mins for 1 block, 40 challenge response, every challenge response is 2 days, 40*2*24*6 = 11520
pub const MAX_BLOCK_HANDLE_OPS: u32 = 1008; // This is a period to handle remaining withdrawals, and inscribe connector tree preimages, 1 week = 7*24*6 = 1008
pub const K_DEEP: u32 = 500; // Approximately 3.5 days
// First lightclient cutoff = PERIOD_BLOCK_COUNT - MAX_BITVM_CHALLENGE_RESPONSE_BLOCK_COUNT - K_DEEP - MAX_BLOCK_HANDLE_OPS = 12892 = 12892*10/60/24/30 ~ 3 months
// Second lightclient cutoff = 2*PERIOD_BLOCK_COUNT - MAX_BITVM_CHALLENGE_RESPONSE_BLOCK_COUNT - K_DEEP - MAX_BLOCK_HANDLE_OPS
