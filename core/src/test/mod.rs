//! Note to developer: Guard the new integration test files with the
//! `#[cfg(feature = "integration-tests")]` attribute (see #testing-clementine
//! in [`super`]).

pub mod common;
#[cfg(all(feature = "automation", feature = "integration-tests"))]
mod deposit_and_withdraw_e2e;
#[cfg(all(feature = "automation", feature = "integration-tests"))]
mod full_flow;
#[cfg(all(feature = "automation", feature = "integration-tests"))]
mod lcp_method_id_check;
#[cfg(all(feature = "automation", feature = "integration-tests"))]
mod reorg;

#[cfg(feature = "integration-tests")]
mod musig2;

#[cfg(not(feature = "automation"))]
mod manual_reimbursement;

#[cfg(feature = "integration-tests")]
mod rpc_auth;
#[cfg(all(feature = "automation", feature = "integration-tests"))]
mod state_manager;

#[cfg(feature = "integration-tests")]
mod taproot;

#[cfg(feature = "integration-tests")]
mod withdraw;

mod sign;

#[cfg(all(feature = "automation", feature = "integration-tests"))]
mod additional_disprove_scripts;

#[cfg(all(feature = "automation", feature = "integration-tests"))]
mod bitvm_disprove_scripts;

#[cfg(all(feature = "automation", feature = "integration-tests"))]
mod bridge_circuit_test_data;

#[cfg(feature = "integration-tests")]
mod bitvm_script;

/// Citrea image for e2e tests.
pub const CITREA_E2E_DOCKER_IMAGE: &str =
    "chainwayxyz/citrea-test:0c2e39c32cd91726f3ef30b7f79df66cb620dbf7";

/// Bitcoin Core image for e2e nodes; keep it in step with CI's `bitcoin-version`.
pub const E2E_BITCOIN_DOCKER_IMAGE: &str = "bitcoin/bitcoin:30.4";

/// Bitcoin node config for e2e tests: the index and RPC access Clementine needs, plus
/// `extra_args`.
pub fn e2e_bitcoin_config(extra_args: Vec<&'static str>) -> citrea_e2e::config::BitcoinConfig {
    let mut args = vec![
        "-txindex=1",
        "-fallbackfee=0.000001",
        "-rpcallowip=0.0.0.0/0",
    ];
    args.extend(extra_args);
    citrea_e2e::config::BitcoinConfig {
        extra_args: args,
        docker_image: Some(E2E_BITCOIN_DOCKER_IMAGE.to_string()),
        ..Default::default()
    }
}

/// Runs an e2e test case with Citrea and Bitcoin Core in Docker.
pub fn e2e_citrea_config(
    config: citrea_e2e::config::TestCaseConfig,
) -> citrea_e2e::config::TestCaseConfig {
    citrea_e2e::config::TestCaseConfig {
        docker: citrea_e2e::config::TestCaseDockerConfig {
            bitcoin: true,
            citrea: true,
        },
        ..config
    }
}

use ctor::ctor;

#[ctor]
// Increases stack to 32MB for tests, since tests fail with stack overflow otherwise,
// and defaults `CITREA_DOCKER_IMAGE` to the pinned Citrea test image.
// Note that this is unsafe as using stdlib before `main` has no guarantees.
// Read more: https://docs.rs/ctor/latest/ctor/attr.ctor.html
//
unsafe fn test_env() {
    std::env::set_var("RUST_MIN_STACK", "33554432");
    if !std::env::var("CITREA_DOCKER_IMAGE").is_ok_and(|value| !value.is_empty()) {
        std::env::set_var("CITREA_DOCKER_IMAGE", CITREA_E2E_DOCKER_IMAGE);
    }
}
