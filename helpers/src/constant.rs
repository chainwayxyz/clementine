use bitcoin::Network;
use crate::hashes::sha256_64bytes;
use crate::hashes::sha256_32bytes;

pub type Data = [u8; 32];
pub const HASH_FUNCTION_64: fn(Data, Data) -> Data = sha256_64bytes;
pub const HASH_FUNCTION_32: fn(Data) -> Data = sha256_32bytes;
pub const EMPTYDATA: Data = [0; 32];
pub const DUST: u64 = 546;
pub const FEE: u64 = 154;
pub const REGTEST: Network = bitcoin::Network::Regtest;
pub const MIN_RELAY_FEE: u64 = 445;
pub type EVMAddress = [u8; 20];