use circuits_lib::{common, bridge_circuit::bridge_circuit};
use hex_literal::hex;

static MAINNET: [u8; 32] = hex!("c2a6fe36da915c98d003766ed0c3b048485be8194483cfee0694a76ca598443f");
static TESTNET4: [u8; 32] = hex!("af9bddd502a4b7ea9600e02ec89e95f2b0f1637e0850662c0565e5af7947d081");
static REGTEST: [u8; 32] = hex!("6858e5b435438b8e97a6b227847b9b00b369b41195386a1580ae1096dfe36acd");
static SIGNET: [u8; 32] = hex!("a51794069e55d295c214f87f08d12f9b6a8548610b2e0fcf590c26b83918ea86");

pub static WORK_ONLY_IMAGE_ID: [u8; 32] = match option_env!("BITCOIN_NETWORK") {
    Some(network) if matches!(network.as_bytes(), b"mainnet") => MAINNET,
    Some(network) if matches!(network.as_bytes(), b"testnet4") => TESTNET4,
    Some(network) if matches!(network.as_bytes(), b"signet") => SIGNET,
    Some(network) if matches!(network.as_bytes(), b"regtest") => REGTEST,
    None => TESTNET4,
    _ => panic!("Invalid network type"),
};

fn main() {
    let zkvm_guest = common::zkvm::Risc0Guest::new();
    bridge_circuit(&zkvm_guest, WORK_ONLY_IMAGE_ID);
}
