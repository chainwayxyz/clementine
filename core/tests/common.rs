//! # Common Test Utilities
//!
//! This file includes common functions/variables for tests.

/// Returns test path for the specified test configuration.
pub fn get_test_config(configuration_file: &str) -> String {
    format!(
        "{}/tests/data/{}",
        env!("CARGO_MANIFEST_DIR"),
        configuration_file
    )
}

/// Retrieves the list of configuration files in `tests/data` directory.
///
/// Currently WIP
pub fn _get_all_test_configs() -> Vec<String> {
    todo!()
}
