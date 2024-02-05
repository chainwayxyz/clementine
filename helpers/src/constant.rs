use bitcoin::Amount;
use bitcoin::Network;
use crate::hashes::sha256_96bytes;
use crate::hashes::sha256_64bytes;
use crate::hashes::sha256_32bytes;

pub type Data = [u8; 32];
pub const HASH_FUNCTION_96: fn(Data, Data, Data) -> Data = sha256_96bytes;
pub const HASH_FUNCTION_64: fn(Data, Data) -> Data = sha256_64bytes;
pub const HASH_FUNCTION_32: fn(Data) -> Data = sha256_32bytes;
pub const EMPTYDATA: Data = [0; 32];
pub const DUST_VALUE: Amount = Amount::from_sat(1000);
// pub const MINIMUM_FEE: Amount = Amount::from_sat(300);
pub const REGTEST: Network = bitcoin::Network::Regtest;
pub const MIN_RELAY_FEE: Amount = Amount::from_sat(500);
pub type EVMAddress = [u8; 20];
pub const TAPROOT_LEAF_TAPSCRIPT: u8 = 192;