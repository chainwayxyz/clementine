//! Note to developer: Guard the new integration test files with the
//! `#[cfg(feature = "integration-tests")]` attribute (see #testing-clementine
//! in [`super`]).

pub mod common;
#[cfg(all(feature = "automation", feature = "integration-tests"))]
mod deposit_and_withdraw_e2e;
#[cfg(all(feature = "automation", feature = "integration-tests"))]
mod full_flow;

#[cfg(feature = "integration-tests")]
mod musig2;

#[cfg(feature = "integration-tests")]
mod rpc_auth;
#[cfg(all(feature = "automation", feature = "integration-tests"))]
mod state_manager;

#[cfg(feature = "integration-tests")]
mod taproot;

#[cfg(feature = "integration-tests")]
mod withdraw;

#[cfg(all(feature = "automation", feature = "integration-tests"))]
mod additional_disprove_scripts;

#[cfg(all(feature = "automation", feature = "integration-tests"))]
mod bitvm_disprove_scripts;

#[cfg(all(feature = "automation", feature = "integration-tests"))]
mod watchtower_challenge;

#[cfg(feature = "integration-tests")]
mod bitvm_script;

mod citrea_deposit_tests;

use ctor::ctor;

#[ctor]
// Increases stack to 32MB for tests, since tests fail with stack overflow otherwise.
// Note that this is unsafe as using stdlib before `main` has no guarantees.
// Read more: https://docs.rs/ctor/latest/ctor/attr.ctor.html
//
// After some investigation, the stack issue was narrowed down to `risc0-zkvm`s
// prover. The CPU-based prover runs out of stack space in a parallelized accumulate
// operation. FFI function is `risc0_circuit_rv32im_cpu_accum`, which is called
// indirectly by `risc0-circuit-rv32im` in `src/prove/hal/mod.rs:205`. The stack usage
// in the failing thread is ~384700 bytes.
unsafe fn rust_min_stack() {
    std::env::set_var("RUST_MIN_STACK", "33554432");
}
