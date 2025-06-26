test_unit:
	cargo test --all-features

test_integration:
	cargo test --package clementine-core --lib --all-features -- test::deposit_and_withdraw_e2e --show-output
	cargo test --package clementine-core --lib --all-features -- test::full_flow --show-output
	cargo test --package clementine-core --lib --all-features -- test::musig2 --show-output
	cargo test --package clementine-core --lib --all-features -- test::rpc_auth --show-output
	cargo test --package clementine-core --lib --all-features -- test::state_manager --show-output
	cargo test --package clementine-core --lib --all-features -- test::taproot --show-output
	cargo test --package clementine-core --lib --all-features -- test::withdraw --show-output
	cargo test --package clementine-core --lib --all-features -- test::additional_disprove_scripts --show-output
	cargo test --package clementine-core --lib --all-features -- test::bitvm_disprove_scripts --show-output
	cargo test --package clementine-core --lib --all-features -- test::watchtower_challenge --show-output
