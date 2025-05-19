pub mod common;
mod deposit_and_withdraw_e2e;
mod full_flow;
mod musig2;
mod rpc_auth;
#[cfg(feature = "state-machine")]
mod state_manager;
mod taproot;
mod withdraw;

mod bitvm_script;
