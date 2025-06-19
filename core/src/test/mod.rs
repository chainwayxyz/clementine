pub mod common;
#[cfg(feature = "automation")]
mod deposit_and_withdraw_e2e;
#[cfg(feature = "automation")]
mod full_flow;
mod musig2;
mod rpc_auth;
#[cfg(feature = "automation")]
mod state_manager;
mod taproot;
mod withdraw;

#[cfg(feature = "automation")]
mod additional_disprove_scripts;

#[cfg(feature = "automation")]
mod bitvm_disprove_scripts;
mod bitvm_script;

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
