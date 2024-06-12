# Clementine 🍊

Clementine is Citrea's BitVM based trust-minimized two-way peg program.
The repository includes:

- Smart contracts for deposit and withdrawal
- A library for bridge operator and verifiers
- Circuits that will be optimistically verified with BitVM

The flow is as follows:

- Creating the operator and verifiers
- Initial setup that includes calculating period block heights, connector tree hashes, and funding connector source UTXOs.
- User deposit flow that includes creating a deposit transaction, signing it, and submitting it to the operator.
- Operator processing the deposit, getting signatures from verifiers, and submitting the deposit to the Bitcoin network.
- Verifiers verifying the deposit and signing the deposit transaction and claim signatures.
- Operator withdrawal flow for front covering withdrawal requests.
- Verifier to start a challenge with Bitcoin Proof of Work
- Operator to respond to the challenge with a bridge proof.

> [!WARNING]
>
> Clementine is still work-in-progress. It has not been audited and should not be used in production under any circumstances. It also requires a full BitVM implementation to be run fully on-chain.

## Instructions

### Preparing Test Environment

To run the whole process of simulating deposits, withdrawals, proof generation
on the Bitcoin Regtest network, you need Bitcoin Core to be installed.

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

Enable dev-mode for risc0-zkvm. This can help lower compilation times.

```sh
export RISC0_DEV_MODE=1
```

A custom configuration file can be specified for testing. This can be helpful
if developer's environment is not matching with a test's configuration file
(e.g. database user name).

```sh
export TEST_CONFIG=/path/to/configuration.toml
```

### Testing

To run every test:

```sh
cargo test
```

User's environment configuration can be different than hard coded test
configuration file. In that case, user can specify an external configuration
file that overwrites test configurations some fields, like database user and
password. To do that, set `TEST_CONFIG` environment variable with the path of
configuration file:

```sh
TEST_CONFIG=/path/to/user.toml cargo test
```

## License

**(C) 2024 Chainway Limited** `clementine` was developed by Chainway Limited.
While we plan to adopt an open source license, we have not yet selected one. As
such, all rights are reserved for the time being. Please reach out to us if you
have thoughts on licensing.
