test_unit:
	cargo test --features automation

test_integration:
	cargo test --workspace --all-features -p core test:: -- --test-threads 6
