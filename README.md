# Clementine 🍊

Clementine is Citrea's BitVM based trust-minimized two-way peg program.

The repository includes:

- A library for bridge operator, verifiers and aggregator
- Circuits that will be optimistically verified with BitVM

> [!WARNING]
>
> Clementine is still a work in progress. It has not been audited and should not
> be used in production under any circumstances. It also requires a full BitVM
> implementation to be run fully on-chain.

## Instructions

Clementine requires a Bitcoin node up and running on the client. Please install
and configure Bitcoin Core if you haven't already.

### Preparing a Configuration File

Running a binary as a verifier, aggregator or operator requires a configuration
file. Example configuration file is located at
[`core/tests/data/test_config.toml`](core/tests/data/test_config.toml) and can
be taken as reference. Please copy that configuration file to another location
and modify fields to your local configuration.

### Starting a Server

A server can be started using its corresponding CLI flag:

```sh
# Build the binary
cargo build --release --bin server

# Run binary with a target
./target/release/server $CONFIGFILE --verifier-server # Start verifier server
./target/release/server $CONFIGFILE --aggregator-server # Start aggregator server
./target/release/server $CONFIGFILE --operator-server # Start operator server
```

A server's log level can be specified with `--verbose` flag:

```sh
./target/release/server $CONFIGFILE --operator-server --verbose 5 # Logs everything
```

More information, use `--help` flag:

```sh
./target/release/server --help
```

### Testing

#### Bitcoin Regtest Setup

To simulate deposits, withdrawals, proof generation on the Bitcoin Regtest
network, some configuration is needed.

Start the regtest server with the following command:

```sh
bitcoind -regtest -rpcuser=admin -rpcpassword=admin -rpcport=18443 -fallbackfee=0.00001 -wallet=admin -txindex=1
```

Create a wallet for the operator:

```sh
bitcoin-cli -regtest -rpcuser=admin -rpcpassword=admin -rpcport=18443 createwallet "admin"
```

Mine some blocks to the wallet:

```sh
bitcoin-cli -regtest -rpcuser=admin -rpcpassword=admin -rpcport=18443 generatetoaddress 101 $(bitcoin-cli -regtest -rpcuser=admin -rpcpassword=admin -rpcport=18443 getnewaddress)
```

Please note that this step is not necessary if
[bitcoin-mock-rpc](https://github.com/chainwayxyz/bitcoin-mock-rpc) will be used
for testing.

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

Enabling dev-mode for risc0-zkvm can help lower the compilation times.

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

Tests can also be run with
[bitcoin-mock-rpc](https://github.com/chainwayxyz/bitcoin-mock-rpc), which is an
alternative to Bitcoin Regtest:

```sh
cargo test --features mock_rpc
```

## License

**(C) 2024 Chainway Limited** `clementine` was developed by Chainway Limited.
While we plan to adopt an open source license, we have not yet selected one. As
such, all rights are reserved for the time being. Please reach out to us if you
have thoughts on licensing.
