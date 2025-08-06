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

High level documentations are in [docs/](docs). These documentations explains
the design, architecture and usage of Clementine.

Code documentation is also present and can be viewed at
[chainwayxyz.github.io/clementine/clementine_core](https://chainwayxyz.github.io/clementine/clementine_core/).

It can also be generated locally:

```bash
cargo doc --no-deps
```

Documentation will be available at `target/doc/clementine_core/index.html` after
that.

## Instructions

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

#### Debugging Tokio Tasks (`tokio-console`)

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

## License

**(C) 2025 Chainway Limited** `clementine` was developed by Chainway Limited.
While we plan to adopt an open source license, we have not yet selected one. As
such, all rights are reserved for the time being. Please reach out to us if you
have thoughts on licensing.
