# Usage

Clementine provides a single binary, that can act as 3 different actors
services:

- Verifier (We sometimes call this as signer)
- Operator
- Aggregator

These services communicate via gRPC and use a Postgresql database. They can be
configured to share the same database.

An entity can choose to run these services on a single host to be a part of the
peg-in and peg-out process. All the services that are run by a single entity
should ideally share the same database. Typical entities are:

- Operator entity
- Runs both an operator and a verifier service
- Verifier entity
  - Runs a verifier service
- Aggregator entity
  - Runs both an aggregator and a verifier service

## Prerequisites

Before compiling Clementine:

1. Install Rust: [rustup.rs](https://rustup.rs/)
2. To rebuild the SP1 guests, install SP1 6.10.0 and Docker. See [SP1 proving](sp1.md#building).

   ```sh
   curl -fsSL https://sp1.succinct.xyz | bash
   sp1up --version v6.10.0
   ```

3. On macOS, install the Xcode command-line tools:

   ```sh
   xcode-select --install
   ```

4. If on Ubuntu, install these packages:

   ```sh
   sudo apt install build-essential libssl-dev pkg-config clang cmake protobuf-compiler
   ```

Before running Clementine:

1. Install and configure a Bitcoin node (at least v29.0)
2. Install and configure PostgreSQL. Using docker:

   ```sh
   docker run --name clementine-test-db \
   -e POSTGRES_USER=clementine \
   -e POSTGRES_PASSWORD=clementine \
   -e POSTGRES_DB=clementine \
   -p 5432:5432 \
   --restart always \
   -d postgres:15 \
   bash -c "exec docker-entrypoint.sh postgres -c 'max_connections=1000'"
   ```

3. [Optional] TLS certificates required to start and connect to a Clementine
   server. For tests, these are automatically generated, if not present. Please
   check [RPC Authentication](#rpc-authentication) and [Security Considerations](#security-considerations)
   sections when generating certificates for a deployment.

   ```sh
   ./scripts/generate_certs.sh
   ```

4. For development tests, compile with `--features testing` and set:

   ```sh
   export SP1_PROVER=mock
   ```

   Production builds use `SP1_PROVER=cpu` or `network`. `SP1_PROVER` defaults to
   `network`. Clementine does not start when it does not match the compiled
   programs. See [SP1 proving](sp1.md).

5. BitVM caches are generated automatically for the selected SP1 program and key.
   `BITVM_CACHE_PATH` can override the path; incompatible caches are regenerated.

6. Set `RUST_MIN_STACK` environment variable to at least `33554432`

   ```sh
   # On Unix-like systems:
   export RUST_MIN_STACK=33554432
   ```

## Configure Clementine

Clementine can be configured to enable automation at build-time via the
`automation` feature. The automation feature enables the State Manager and
Transaction Sender which automatically fulfills the duties of
verifier/operator/aggregator entities. It also enables automatic sending and
management of transactions to the Bitcoin network via Transaction Sender.

```bash
cargo build --release --features automation
```

Clementine supports two runtime primary configuration methods:

1. **Configuration Files**: Specify main configuration and protocol parameters via TOML files
2. **Environment Variables**: Configure the application entirely through environment variables

### Configuration Files

Running the binary as a verifier, aggregator, or operator requires a
configuration file. An example configuration file is located at
[`core/src/test/data/bridge_config.toml`](../core/src/test/data/bridge_config.toml) and can
be taken as reference. Please copy that configuration file to another location
and modify fields to your local configuration.

Additionally, Clementine requires protocol parameters, that are either specified
by a file or from the environment. You can specify a separate protocol
parameters file using the `--protocol-params` option. This file contains
protocol-specific settings that affect transactions in the contract.

### Environment Variables

It is also possible to use environment variables instead of configuration files.
The `.env.example` file can be taken as a reference for this matter.

### Configuration Source Selection

Clementine uses the following logic to determine the configuration source:

1. **Main Configuration**:

   - If `READ_CONFIG_FROM_ENV=1` or `READ_CONFIG_FROM_ENV=on`, configuration is read from environment variables
   - If `READ_CONFIG_FROM_ENV=0` or `READ_CONFIG_FROM_ENV=off` or not set, configuration is read from the specified config file

2. **Protocol Parameters**:
   - If `READ_PARAMSET_FROM_ENV=1` or `READ_PARAMSET_FROM_ENV=on`, protocol parameters are read from environment variables
   - If `READ_PARAMSET_FROM_ENV=0` or `READ_PARAMSET_FROM_ENV=off` or not set, protocol parameters are read from the specified protocol parameters file

You can mix these approaches - for example, reading main configuration from a file but protocol parameters from environment variables.

## RPC Authentication

Clementine uses mutual TLS (mTLS) to secure gRPC communications between entities
and to authenticate clients. Client certificates are verified and filtered by
the verifier/operator to ensure that:

1. Verifier/Operator methods can only be called by the aggregator (using
   aggregator's client certificate `aggregator_cert_path`)
2. Internal methods can only be called by the entity's own client certificate
   (using the entity's client certificate `client_cert_path`)

The aggregator does not enforce client certificates but does use TLS for encryption.

### Certificate Setup for Tests

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

## Starting a Server

Clementine is designed to be run multiple times for every actor that an entity
requires. An actor's server can be started using its corresponding argument.
Please follow instruction steps before trying to start a server.

### Compiling Manually

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

Setting `RUST_LIB_BACKTRACE` to `full` will enable full backtraces for errors

```sh
RUST_LIB_BACKTRACE=full ./target/release/clementine-core operator --config /path/to/config.toml
```

For more information, use `--help` flag:

```sh
./target/release/clementine-core --help
```

### Using Docker

A docker image is provided in
[Docker Hub](https://hub.docker.com/r/chainwayxyz/clementine). It can also be
locally built with:

```bash
docker build -f scripts/docker/Dockerfile -t clementine:latest .
```

## Running Tests

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

## Helper Scripts

There are handful amount of scripts in [scripts/](../scripts/) directory. Most of
them are for testing but still can be used for setting up the environment. They
can change quite frequently. So, please check for useful ones.

Each script should have a name and comment inside that explain its purpose.

## Debugging Tokio Tasks (`tokio-console`)

To debug tokio tasks, you can uncomment the `console-subscriber` dependency in `Cargo.toml` and the `console_subscriber::init();` line in `src/utils.rs`. Then, rebuild the project with `cargo build_console` which is an alias defined with the necessary flags.

```sh
cargo build_console
```

After running Clementine, you can access the console by running the following command:

```sh
tokio-console
```

## Security Considerations

### TLS Certificates

- Keep private keys (\*.key) secure and don't commit them to version control
- In production, use properly signed certificates from a trusted CA
- Rotate certificates regularly
- Consider using distinct client certificates for different clients/services
