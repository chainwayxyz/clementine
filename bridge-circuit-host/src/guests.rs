//! Guest ELFs embedded in the host, each paired with its program key from
//! [`circuits_lib::common::programs`].
use crate::sp1::ProofKind;
use circuits_lib::common::programs::{self, ProgramKey};
use std::fmt;

/// A trusted guest ELF, the program key generated from it, and the proof its consumer needs.
#[derive(Clone, Copy)]
pub struct Guest {
    pub elf: &'static [u8],
    pub key: ProgramKey,
    pub kind: ProofKind,
}

impl fmt::Debug for Guest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Guest")
            .field("key", &self.key)
            .field("kind", &self.kind)
            .field("elf_len", &self.elf.len())
            .finish()
    }
}

/// Guests that one Bitcoin network uses together, and Citrea's light client program.
#[derive(Debug)]
pub struct NetworkGuests {
    pub header_chain: Guest,
    pub work_only: Guest,
    pub bridge: Guest,
    pub light_client: ProgramKey,
}

macro_rules! elf {
    ($name:expr) => {
        include_bytes!(concat!("../../sp1-circuits/elfs/", $name, ".elf"))
    };
}

/// Guests of a test network. With `use-test-vk`, the bridge guest is the development build,
/// whose key the network's programs also select.
macro_rules! test_network_guests {
    ($network:literal, $programs:expr) => {
        NetworkGuests {
            header_chain: Guest {
                elf: elf!(concat!($network, "-header-chain")),
                key: $programs.header_chain,
                kind: ProofKind::Compressed,
            },
            work_only: Guest {
                elf: elf!(concat!($network, "-work-only")),
                key: $programs.work_only,
                kind: ProofKind::Groth16,
            },
            bridge: Guest {
                #[cfg(not(feature = "use-test-vk"))]
                elf: elf!(concat!($network, "-bridge-circuit")),
                #[cfg(feature = "use-test-vk")]
                elf: elf!(concat!("test-", $network, "-bridge-circuit")),
                key: $programs.bridge,
                kind: ProofKind::BridgeGroth16,
            },
            light_client: $programs.light_client,
        }
    };
}

pub static MAINNET: NetworkGuests = NetworkGuests {
    header_chain: Guest {
        elf: elf!("mainnet-header-chain"),
        key: programs::MAINNET.header_chain,
        kind: ProofKind::Compressed,
    },
    work_only: Guest {
        elf: elf!("mainnet-work-only"),
        key: programs::MAINNET.work_only,
        kind: ProofKind::Groth16,
    },
    bridge: Guest {
        elf: elf!("mainnet-bridge-circuit"),
        key: programs::MAINNET.bridge,
        kind: ProofKind::BridgeGroth16,
    },
    light_client: programs::MAINNET.light_client,
};
pub static TESTNET4: NetworkGuests = test_network_guests!("testnet4", programs::TESTNET4);
pub static SIGNET: NetworkGuests = test_network_guests!("signet", programs::SIGNET);
pub static REGTEST: NetworkGuests = test_network_guests!("regtest", programs::REGTEST);

impl NetworkGuests {
    /// Guests for a runtime network, or `None` if Clementine does not support it.
    pub fn for_network(network: bitcoin::Network) -> Option<&'static Self> {
        match network {
            bitcoin::Network::Bitcoin => Some(&MAINNET),
            bitcoin::Network::Testnet4 => Some(&TESTNET4),
            bitcoin::Network::Signet => Some(&SIGNET),
            bitcoin::Network::Regtest => Some(&REGTEST),
            _ => None,
        }
    }
}
