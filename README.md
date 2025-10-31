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

## Reproducible Builds

Clementine supports fully reproducible builds using Nix, ensuring that anyone can verify that published binaries match the source code exactly. This is crucial for bridge operators and verifiers who need to trust the software they're running.

### Quick Start with Nix

```bash
# Install Nix with flakes support
sh <(curl -L https://nixos.org/nix/install) --daemon

# Build Clementine (without automation)
nix build .#clementine-cli

# Build with automation feature
nix build .#clementine-cli-automation

# The binary will be in result/bin/
./result/bin/clementine-cli --version
```

For detailed instructions, verification procedures, and multi-platform builds, see [docs/reproducible-builds.md](docs/reproducible-builds.md).

## Documentation

High level documentations are in [docs/](docs). These documentations explains
the design, architecture and usage of Clementine.

To start using Clementine, jump [docs/usage.md](docs/usage.md) documentation.

Code documentation is also present and can be viewed at
[chainwayxyz.github.io/clementine/clementine_core](https://chainwayxyz.github.io/clementine/clementine_core/).

It can also be generated locally:

```bash
cargo doc --no-deps
```

Documentation will be available at `target/doc/clementine_core/index.html` after
that.
