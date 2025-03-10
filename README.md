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

### Preparing a Configuration File

Running the binary as a verifier, aggregator, operator or watchtower requires a
configuration file. An example configuration file is located at
[`core/tests/data/test_config.toml`](core/tests/data/test_config.toml) and can
be taken as reference. Please copy that configuration file to another location
and modify fields to your local configuration.

### Starting a Server

An actor's server can be started using its corresponding argument:

```sh
# Build the binary
cargo build --release

# Run binary with a target
./target/release/clementine-core verifier $CONFIGFILE # Start verifier server
./target/release/clementine-core operator $CONFIGFILE # Start operator server
./target/release/clementine-core aggregator $CONFIGFILE # Start aggregator server
./target/release/clementine-core watchtower $CONFIGFILE # Start watchtower server
```

A server's log level can be specified with `--verbose` flag:

```sh
./target/release/clementine-core operator $CONFIGFILE --verbose 5 # Logs everything
```

For more information, use `--help` flag:

```sh
./target/release/clementine-core --help
```

### Testing

#### Prerequisites

1. **PostgreSQL Database**

   Tests require a PostgreSQL database with a max connection limit of at least 200 due to parallelism. You can quickly set one up using Docker:

   ```bash
   docker run --name clementine-test-db \
     -e POSTGRES_USER=clementine \
     -e POSTGRES_PASSWORD=clementine \
     -e POSTGRES_DB=clementine \
     -p 5432:5432 \
     --restart always \
     -d postgres:15  -c 'max_connections=200'
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
