# Clementine 🍊

Clementine is Citrea's BitVM based trust-minimized two-way peg program. You can
check Clementine whitepaper at [citrea.xyz/clementine_whitepaper.pdf](https://citrea.xyz/clementine_whitepaper.pdf).

The repository includes:

- A library for bridge operator, verifiers, aggregator and watchtower
- Circuits that will be optimistically verified with BitVM

Audit reports for Clementine are present in [audits](audits/) directory.

> [!WARNING]
>
> Clementine is still a work in progress. It has not been audited and should not
> be used in production under any circumstances. It also requires a full BitVM
> implementation to be run fully on-chain.

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

## License

**(C) 2025 Chainway Limited** `clementine` was developed by Chainway Limited.
While we plan to adopt an open source license, we have not yet selected one. As
such, all rights are reserved for the time being. Please reach out to us if you
have thoughts on licensing.
