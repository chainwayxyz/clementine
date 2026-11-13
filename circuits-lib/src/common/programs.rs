//! SP1 program keys used together on each Bitcoin network.
//!
//! `scripts/build_sp1_guests.py` generates the keys in [`super::sp1_programs`]. With `use-test-vk`,
//! non-mainnet networks use the development bridge guest, which verifies watchtower proofs with
//! the development Groth16 key. The other guests are the same in both builds.
use super::{sp1_programs as generated, BuildNetwork, BUILD_NETWORK};

/// Identifier of an SP1 program: the digest of its verifying key, which is eight KoalaBear
/// field elements. SP1 has two encodings of this digest, because its two verifiers work over
/// different fields. `scripts/build_sp1_guests.py` generates both from the program ELFs, so no
/// code converts between them; `generated_key_encodings_match_sp1` checks that they agree.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProgramKey {
    /// `vk.hash_u32()`: the eight field elements as words, each below 2^31. SP1's native
    /// recursion (`verify_sp1_proof`) checks compressed proofs over KoalaBear and takes this
    /// form, so guests use it to verify header chain and light client proofs. Mock receipts,
    /// circuit outputs and Citrea's `light_client_proof_method_id` also use this form.
    pub recursion: [u32; 8],
    /// `vk.bytes32()`: the eight words packed into one big-endian BN254 scalar,
    /// `sum(recursion[i] << (31 * (7 - i)))`, which fits in 248 bits. SP1's Groth16 proofs are
    /// over BN254 and take the program as one public input, so Groth16 verification and the
    /// BitVM key use this form.
    pub groth16: [u8; 32],
}

/// SP1 program keys of the guests that one Bitcoin network uses together.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NetworkPrograms {
    pub header_chain: ProgramKey,
    pub work_only: ProgramKey,
    pub bridge: ProgramKey,
    /// Citrea's light client program. Signet uses Citrea devnet.
    pub light_client: ProgramKey,
}

/// Replaces the bridge program with its development build when compiled with `use-test-vk`.
const fn with_development_bridge(
    programs: NetworkPrograms,
    development_bridge: ProgramKey,
) -> NetworkPrograms {
    if cfg!(feature = "use-test-vk") {
        NetworkPrograms {
            bridge: development_bridge,
            ..programs
        }
    } else {
        programs
    }
}

pub const MAINNET: NetworkPrograms = generated::MAINNET;
pub const TESTNET4: NetworkPrograms =
    with_development_bridge(generated::TESTNET4, generated::TESTNET4_DEVELOPMENT_BRIDGE);
pub const SIGNET: NetworkPrograms =
    with_development_bridge(generated::SIGNET, generated::SIGNET_DEVELOPMENT_BRIDGE);
pub const REGTEST: NetworkPrograms =
    with_development_bridge(generated::REGTEST, generated::REGTEST_DEVELOPMENT_BRIDGE);

/// Programs for the network this crate is compiled for, [`BUILD_NETWORK`]. Guests must not
/// read this table directly: a reference into it can compile the whole table, with the guest's
/// own key, into the ELF, and that key then depends on itself. Each constant below holds one
/// program's key.
const CURRENT: NetworkPrograms = match BUILD_NETWORK {
    BuildNetwork::Mainnet => MAINNET,
    BuildNetwork::Testnet4 => TESTNET4,
    BuildNetwork::Signet => SIGNET,
    BuildNetwork::Regtest => REGTEST,
};
/// The header chain program of [`BUILD_NETWORK`].
pub const CURRENT_HEADER_CHAIN: ProgramKey = CURRENT.header_chain;
/// The work-only program of [`BUILD_NETWORK`].
pub const CURRENT_WORK_ONLY: ProgramKey = CURRENT.work_only;
/// Citrea's light client program of [`BUILD_NETWORK`].
pub const CURRENT_LIGHT_CLIENT: ProgramKey = CURRENT.light_client;

impl NetworkPrograms {
    /// Programs for a runtime network, or `None` if Clementine does not support it.
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Check the generated native words against SP1's field packing, including every
    /// network's Citrea key (whose ELF is supplied by Citrea rather than built here).
    #[test]
    fn generated_key_encodings_match_sp1() {
        use slop_algebra::{AbstractField, PrimeField};

        let networks = [MAINNET, TESTNET4, SIGNET, REGTEST];
        let development = [
            generated::TESTNET4_DEVELOPMENT_BRIDGE,
            generated::SIGNET_DEVELOPMENT_BRIDGE,
            generated::REGTEST_DEVELOPMENT_BRIDGE,
        ];
        for key in networks
            .into_iter()
            .flat_map(|network| {
                [
                    network.header_chain,
                    network.work_only,
                    network.bridge,
                    network.light_client,
                ]
            })
            .chain(development)
        {
            assert!(key.recursion.iter().all(|word| *word < 0x7f00_0001));
            let fields = key.recursion.map(AbstractField::from_canonical_u32);
            let expected = sp1_hypercube::koalabears_to_bn254(&fields)
                .as_canonical_biguint()
                .to_bytes_be();
            let mut padded = [0; 32];
            padded[32 - expected.len()..].copy_from_slice(&expected);
            assert_eq!(key.groth16, padded);
        }
    }
}
