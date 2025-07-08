# Clementine 🍊

Clementine is Citrea's BitVM based trust-minimized two-way peg program. You can
check Clementine whitepaper at [citrea.xyz/clementine_whitepaper.pdf](https://citrea.xyz/clementine_whitepaper.pdf).

The repository includes:

- A library for bridge operator, verifiers, aggregator and watchtower
- Circuits that will be optimistically verified with BitVM

> [!WARNING]
>
> Clementine is still a work in progress. It has not been audited and should not
> be used in production under any circumstances. It also requires a full BitVM
> implementation to be run fully on-chain.

## Documentation

Code documentation can be viewed at
[chainwayxyz.github.io/clementine/clementine_core](https://chainwayxyz.github.io/clementine/clementine_core/).
It can also be generated locally:

```bash
cargo doc --no-deps
```

Documentation will be available at `target/doc/clementine_core/index.html` after
that.

## Instructions

### Setup

Before compiling Clementine:

1. Install Rust: [rustup.rs](https://rustup.rs/)
2. Install RiscZero (2.1.0): [dev.risczero.com/api/zkvm/install](https://dev.risczero.com/api/zkvm/install)

   ```bash
   curl -L https://risczero.com/install | bash
   rzup install cargo-risczero 2.1.0 # Or v2.1.0
   rzup install r0vm 2.1.0
   rzup install rust 1.85.0
   ```

3. If on Mac, install XCode and its app from AppStore (if `xcrun metal` gives an error):

   ```bash
   xcode-select --install
   ```

4. If on Ubuntu, install these packages:

   ```bash
   sudo apt install build-essential libssl-dev pkg-config
   ```

Before running Clementine:

1. Install and configure a Bitcoin node (at least v29.0)
2. Install and configure PostgreSQL
3. Set `RUST_MIN_STACK` to at least 33554432

   ```bash
   # In *nix systems:
   export RUST_MIN_STACK=33554432
   ```

### Configure Clementine

Clementine can be configured to enable automation at build-time via the `automation` feature. The automation feature enables the State Manager and Transaction Sender which automatically fulfills the duties of verifier/operator/aggregator entities. It also enables automatic sending and management of transactions to the Bitcoin network via Transaction Sender.

```bash
cargo build --release --features automation
```

Clementine supports two runtime primary configuration methods:

1. **Configuration Files**: Specify main configuration and protocol parameters via TOML files
2. **Environment Variables**: Configure the application entirely through environment variables

#### Configuration Files

Running the binary as a verifier, aggregator, operator or watchtower requires a
configuration file. An example configuration file is located at
[`core/src/test/data/bridge_config.toml`](core/src/test/data/bridge_config.toml) and can
be taken as reference. Please copy that configuration file to another location
and modify fields to your local configuration.

Additionally, Clementine requires protocol parameters, that are either specified
by a file or from the environment. You can specify a separate protocol
parameters file using the `--protocol-params` option. This file contains
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

### RPC Authentication

Clementine uses mutual TLS (mTLS) to secure gRPC communications between entities and to authenticate clients. Client certificates are verified and filtered by the verifier/operator to ensure that:

1. Verifier/Operator methods can only be called by the aggregator (using aggregator's client certificate `aggregator_cert_path`)
2. Internal methods can only be called by the entity's own client certificate (using the entity's client certificate `client_cert_path`)

The aggregator does not enforce client certificates but does use TLS for encryption.

#### Certificate Setup for Tests

Before running the servers, you need to generate certificates. A script is provided for this purpose:

```bash
# Run from the project root
./scripts/generate_certs.sh
```

This will create certificates in the following structure:

```text
certs/
├── ca/
│   ├── ca.key     # CA private key
│   └── ca.pem     # CA certificate
├── server/
│   ├── ca.pem     # Copy of CA certificate (for convenience)
│   ├── server.key # Server private key
│   └── server.pem # Server certificate
├── client/
│   ├── ca.pem     # Copy of CA certificate (for convenience)
│   ├── client.key # Client private key
│   └── client.pem # Client certificate
└── aggregator/
    ├── ca.pem     # Copy of CA certificate (for convenience)
    ├── aggregator.key # Aggregator private key
    └── aggregator.pem # Aggregator certificate
```

> [!NOTE]
> For production use, you should use certificates signed by a trusted CA rather than self-signed ones.

#### BitVM Cache

BitVM Cache will be generated, if not present. It can be downloaded with:

```sh
wget https://static.testnet.citrea.xyz/common/bitvm_cache_v3.bin -O bitvm_cache.bin
wget https://static.testnet.citrea.xyz/common/bitvm_cache_dev.bin -O bitvm_cache_dev.bin
```

### Starting a Server

Clementine is designed to be run multiple times for every actor that an entity
requires. An actor's server can be started using its corresponding argument.

#### Compiling Manually

```sh
# Build the binary (with optional automation)
cargo build --release [--features automation]

# Run binary with configuration file
./target/release/clementine-core verifier --config /path/to/config.toml
./target/release/clementine-core operator --config /path/to/config.toml
./target/release/clementine-core aggregator --config /path/to/config.toml

# Run with both configuration and protocol parameter files
./target/release/clementine-core verifier --config /path/to/config.toml --protocol-params /path/to/params.toml

# Run with environment variables
READ_CONFIG_FROM_ENV=1 READ_PARAMSET_FROM_ENV=1 ./target/release/clementine-core verifier

# Mixing configuration sources
READ_CONFIG_FROM_ENV=0 READ_PARAMSET_FROM_ENV=1 ./target/release/clementine-core verifier --config /path/to/config.toml
```

A server's log level can be specified with `--verbose` flag:

```sh
./target/release/clementine-core operator --config /path/to/config.toml --verbose 5 # Logs everything
```

For more information, use `--help` flag:

```sh
./target/release/clementine-core --help
```

#### Using Docker

1. Pull the image

   ```sh
   docker pull chainwayxyz/clementine
   ```

2. Run the image

   ```sh
   # Paths are from test configs and assuming BitVM cache is downloaded.
   docker run --rm -it \
      -v ./core/src/test/data/bridge_config.toml:/config.toml \
      -v ./core/src/test/data/protocol_paramset.toml:/protocol_paramset.toml \
      -v ./bitvm_cache.bin:/bitvm_cache.bin \
      -p 8080:8080 \
      chainwayxyz/clementine \
      verifier --config /config.toml --protocol-params /protocol_paramset.toml
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

3. **TLS Certificates**

   Tests that use gRPC connections require TLS certificates. These are automatically generated during test runs, but you can also generate them manually:

   ```bash
   ./scripts/generate_certs.sh
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
cargo test --all-features
```

Also, due to the test directory hierarchy, unit and integration tests can be
run separately:

```sh
cargo test_unit
cargo test_integration
```

#### Helper Scripts

There are handful amount of scripts in [scripts](scripts) directory. Most of
them are for testing but still can be used for setting up the environment. They
can change quite frequently. So, please check for useful ones.

Each script should have a name and comment inside that explain its purpose.

## Security Considerations

### TLS Certificates

- Keep private keys (\*.key) secure and don't commit them to version control
- In production, use properly signed certificates from a trusted CA
- Rotate certificates regularly
- Consider using distinct client certificates for different clients/services

## License

**(C) 2025 Chainway Limited** `clementine` was developed by Chainway Limited.
While we plan to adopt an open source license, we have not yet selected one. As
such, all rights are reserved for the time being. Please reach out to us if you
have thoughts on licensing.
