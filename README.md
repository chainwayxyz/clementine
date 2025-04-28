# Clementine 🍊

Clementine is Citrea's BitVM based trust-minimized two-way peg program.

The repository includes:

- A library for bridge operator, verifiers, aggregator and watchtower
- Circuits that will be optimistically verified with BitVM

> [!WARNING]
>
> Clementine is still a work in progress. It has not been audited and should not
> be used in production under any circumstances. It also requires a full BitVM
> implementation to be run fully on-chain.

## Instructions

### Setup

Clementine requires a Bitcoin node up and running. Please install and configure
Bitcoin Core if you haven't already.

### Preparing a Configuration File or Using Environment Variables to Configure Clementine

Clementine supports two primary configuration methods:

1. **Configuration Files**: Specify main configuration and protocol parameters via TOML files
2. **Environment Variables**: Configure the application entirely through environment variables

#### Configuration Files

Running the binary as a verifier, aggregator, operator or watchtower requires a
configuration file. An example configuration file is located at
[`core/tests/data/test_config.toml`](core/tests/data/test_config.toml) and can
be taken as reference. Please copy that configuration file to another location
and modify fields to your local configuration.

Additionally, Clementine requires protocol parameters, that are either specified
by a file or from the environment. Uou can specify a separate protocol
parameters file using the `--protocol-params-file` option. This file contains
protocol-specific settings that affect transactions in the contract.

#### Environment Variables

It is also possible to use environment variables instead of configuration files.
The [`.env.example`] file can be taken as a reference for this matter.

#### Configuration Source Selection

Clementine uses the following logic to determine the configuration source:

1. **Main Configuration**:
   - If `READ_CONFIG_FROM_ENV=1` or `READ_CONFIG_FROM_ENV=on`, configuration is read from environment variables
   - If `READ_CONFIG_FROM_ENV=0` or `READ_CONFIG_FROM_ENV=off` or not set, configuration is read from the specified config file

2. **Protocol Parameters**:
   - If `READ_PARAMSET_FROM_ENV=1` or `READ_PARAMSET_FROM_ENV=on`, protocol parameters are read from environment variables
   - If `READ_PARAMSET_FROM_ENV=0` or `READ_PARAMSET_FROM_ENV=off` or not set, protocol parameters are read from the specified protocol parameters file

You can mix these approaches - for example, reading main configuration from a file but protocol parameters from environment variables.

### Starting a Server

Clementine is designed to be run multiple times for every actor that an entity
requires. An actor's server can be started using its corresponding argument:

```sh
# Build the binary
cargo build --release

# Run binary with configuration file
./target/release/clementine-core verifier --config-file /path/to/config.toml
./target/release/clementine-core operator --config-file /path/to/config.toml
./target/release/clementine-core aggregator --config-file /path/to/config.toml

# Run with both configuration and protocol parameter files
./target/release/clementine-core verifier --config-file /path/to/config.toml --protocol-params-file /path/to/params.toml

# Run with environment variables
READ_CONFIG_FROM_ENV=1 READ_PARAMSET_FROM_ENV=1 ./target/release/clementine-core verifier

# Mixing configuration sources
READ_CONFIG_FROM_ENV=0 READ_PARAMSET_FROM_ENV=1 ./target/release/clementine-core verifier --config-file /path/to/config.toml
```

A server's log level can be specified with `--verbose` flag:

```sh
./target/release/clementine-core operator --config-file /path/to/config.toml --verbose 5 # Logs everything
```

For more information, use `--help` flag:

```sh
./target/release/clementine-core --help
```

### Testing

#### Prerequisites

1. **PostgreSQL Database**

   Tests require a PostgreSQL database with a high max connection limit due to parallelism of tests.
   You can quickly set one up using Docker:

   ```bash
   docker run --name clementine-test-db \
   -e POSTGRES_USER=clementine \
   -e POSTGRES_PASSWORD=clementine \
   -e POSTGRES_DB=clementine \
   -p 5432:5432 \
   --restart always \
   -d postgres:15 \
   bash -c "exec docker-entrypoint.sh postgres -c 'max_connections=1000'"
   ```

2. **RISC Zero Toolchain**

   For prover tests, you'll need to install the RISC Zero toolchain:

   ```bash
   cargo install cargo-risczero
   ```

#### [Optional] Docker

A docker image is provided in
[Docker Hub](https://hub.docker.com/r/chainwayxyz/clementine). It can be locally
built with:

```bash
docker build -f scripts/docker/Dockerfile -t clementine:latest .
```

An example Docker compose file is located at
[`scripts/docker/docker-compose.yml`](scripts/docker/docker-compose.yml) and it
can be used to bring up a verifier server. It can also be modified for bringing
up other servers. To bring it up:

```bash
docker compose -f scripts/docker/docker-compose.yml up
```

#### Configuration

Enabling dev-mode for risc0-zkvm can help lower the proving times, in tests.
Please note that this should only be enabled when testing.

```sh
export RISC0_DEV_MODE=1
```

A custom configuration file can be specified for testing. This can be helpful
if developer's environment is not matching with the example test configuration
(e.g. database user name). Please note that only database fields are necessary
in this overwrite configuration file.

```sh
export TEST_CONFIG=/path/to/configuration.toml
```

#### Run Tests

To run all tests:

```sh
cargo test
```

## License

**(C) 2024 Chainway Limited** `clementine` was developed by Chainway Limited.
While we plan to adopt an open source license, we have not yet selected one. As
such, all rights are reserved for the time being. Please reach out to us if you
have thoughts on licensing.
