//! Whether a guest verifies a proof of another circuit.
use super::{BuildNetwork, BUILD_NETWORK};
use borsh::{BorshDeserialize, BorshSerialize};

/// Whether a guest verifies a proof of another circuit. The host selects
/// [`Self::SkipForTesting`] only for a mock receipt, which has no proof to verify.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, BorshDeserialize, BorshSerialize)]
pub enum GuestVerificationMode {
    #[default]
    Verify,
    SkipForTesting,
}

impl GuestVerificationMode {
    /// Whether the guest verifies the proof. A mainnet guest never skips verification.
    pub fn should_verify(self) -> bool {
        self.should_verify_on(BUILD_NETWORK)
    }

    fn should_verify_on(self, network: BuildNetwork) -> bool {
        assert!(
            self == Self::Verify || network != BuildNetwork::Mainnet,
            "SkipForTesting is not allowed on mainnet"
        );
        self == Self::Verify
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mainnet_builds_never_skip_verification() {
        for network in [BuildNetwork::Mainnet, BuildNetwork::Testnet4] {
            assert!(GuestVerificationMode::Verify.should_verify_on(network));
        }
        assert!(!GuestVerificationMode::SkipForTesting.should_verify_on(BuildNetwork::Testnet4));
        let skip = std::panic::catch_unwind(|| {
            GuestVerificationMode::SkipForTesting.should_verify_on(BuildNetwork::Mainnet)
        });
        assert!(skip.is_err(), "a mainnet build skipped verification");
    }
}
