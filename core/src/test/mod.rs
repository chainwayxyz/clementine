pub mod common;
mod deposit_and_withdraw_e2e;
mod full_flow;
mod musig2;
mod rpc_auth;
mod state_manager;
mod taproot;
mod withdraw;

mod bitvm_script;

use ctor::ctor;

#[ctor]
// Increases stack to 32MB for tests, required due to bitvm
// Note that this is unsafe as using stdlib before `main` has no guarantees.
// Read more: https://docs.rs/ctor/latest/ctor/attr.ctor.html
unsafe fn rust_min_stack() {
    std::env::set_var("RUST_MIN_STACK", "33554432");
}
