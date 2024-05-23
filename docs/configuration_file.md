# Configuration File

## Specification

Configuration file is in [toml](https://toml.io/en/) format.

For configuration options, there are no external specification for configuration
file. See `BridgeConfig` struct in [`core/src/config.rs`](../core/src/config.rs)
for what options are available.

## Test Files

For testing, static configuration files are used. This is problematic if user's
environment is not configured as specified by the test configuration file.

To solve this issue, user can specify a configuration file with `TEST_CONFIG`
environment variable which specified in
[`core/src/mock/common.rs`](../core/src/mock/common.rs). This configuration file
will overwrite test configuration file.
