# SP1 proving and BitVM verification

Clementine uses SP1 6.10.0. Each Bitcoin network has three guests in `sp1-circuits`: header
chain, work only and bridge. Their native recursion keys (`vk.hash_u32()`) and Groth16 identifiers (`vk.bytes32()`) are generated into
`circuits-lib/src/common/sp1_programs.rs`, together with Citrea's light client program key.

## Proofs

Header-chain proofs are compressed SP1 proofs. The header-chain, work-only and bridge guests
verify them with SP1's native recursion (`verify_sp1_proof`) through `ZkvmGuest::verify`, and
the host passes the proofs to the prover. The host verifies compressed proofs with the SP1
SDK's light prover (`Prover::verify`), and Groth16 proofs with `sp1_verifier::Groth16Verifier`;
see `bridge_circuit_host::sp1::verify`. Header-chain method IDs are SP1's `vk.hash_u32()`
words of the program key.

Work-only and bridge proofs are Groth16 proofs, because they are checked on Bitcoin. The
header-chain and work-only programs commit SHA-256 public-value digests; the bridge program
enables SP1's `blake3` feature so that Bitcoin scripts can check its digest.

Citrea's light client proof is a compressed SP1 proof, or a mock on networks other than
mainnet. The bridge guest verifies a compressed proof with native recursion, like a
header-chain proof. For a mock receipt, the host sets `GuestVerificationMode::SkipForTesting`
in the guest input and attaches no proof, so test networks can be proven for real with mock
Citrea proofs. A mainnet guest panics on `SkipForTesting`, and the host rejects mock receipts
on mainnet. The
operator saves Citrea's light client proof of the payout block when it handles the payout and
uses it for asserts.

Proof transport is Borsh. `circuits_lib::common::sp1::Receipt` matches Citrea's SP1 proof
envelope. Mock receipts and Citrea's `light_client_proof_method_id` identify programs by
`vk.hash_u32()`; only Groth16 verification uses the `vk.bytes32()` form.

## BitVM verifying key

SP1 v6 Groth16 has five public inputs: `[program_vkey_hash, public_values_digest, exit_code,
vk_root, proof_nonce]`. Clementine fixes the exit code to zero (success), the recursion-key
root to the pinned SP1 root, and the nonce to zero, and checks these fields before it extracts
the proof points. For the trusted bridge program, the key becomes:

```
IC0' = IC0 + program_vkey_hash * IC1 + pinned_vk_root * IC4
IC1' = IC2
```

The key has one public input: `BLAKE3(public_values)` with the high three bits cleared. The
BitVM scripts therefore depend on the bridge program. BitVM caches store the program key and a
checksum of the verifying key; caches of another program or key are regenerated.

## Bridge public values and additional disprove

The guest commits exactly 64 bytes, `deposit_constant || X`, where
`X = BLAKE3(payout_blockhash || latest_blockhash || challenge_sending_watchtowers)`.
SP1 hashes those bytes once for Groth16: `H = BLAKE3(deposit_constant || X)`, then
`H[0] &= 0x1f`. This clears the three most significant bits of the big-endian digest to
fit SP1's 253-bit scalar encoding; the last byte is retained. The additional-disprove
script independently computes the same scalar from the operator's signed values and
its embedded deposit constant. A mismatch makes the additional disprove spendable.

The guest does not pre-hash the 64-byte output. This removes the extra 32-byte BLAKE3
operation that was previously required in the Bitcoin script. The Groth16 scalar
remains 32 bytes, independently of the journal's 64-byte length.

## Proving backends

`SP1_PROVER` selects the backend. It defaults to `network`.

- `cpu` proves locally. Large proofs, such as header chain proofs from genesis, can run out of
  memory.
- `network` proves on Succinct's prover network with `NETWORK_PRIVATE_KEY`.
- `mock` only executes the guests and does not check native recursion proofs, so the guests
  need no mock-specific code. Mainnet configuration rejects it.

Development tests compile Clementine with `testing` (the host crates with `use-test-vk`). On
test networks, this selects the development bridge guest, which verifies watchtower proofs with
a deterministic development Groth16 key, and the development BitVM key. In mock mode,
work-only and bridge receipts carry development Groth16 proofs. They test the BitVM script and
transaction plumbing; they are not proofs of execution. Clementine does not start with mock
proving and production programs, or with a real prover and the development programs.

The reusable `sp1-host` crate owns SDK backend selection, cached setup and network requests;
`bridge-circuit-host` only supplies bridge inputs and verifies Clementine receipts. Setup is
shared by concurrent callers for the same guest/backend.

For BLAKE3 proofs on the prover network, the adapter executes the guest locally first,
including recursion verification, because SDK 6.10's automatic simulation sends a BLAKE3
public-values digest that the network compares as SHA-256. It omits that optional hint,
uses the measured cycles and gas as request limits (as SP1's own simulation does), and
checks the returned public values against local execution. There are no Clementine-specific
cycle/gas environment settings. Remove this compatibility path when the SDK and network
agree on BLAKE3 digests.

## Building

Install `cargo-prove` 6.10.0 and Docker, then run:

```
python3 scripts/build_sp1_guests.py [--citrea /path/to/citrea/artifacts]
```

The script builds every guest with `cargo prove build --docker` in the SP1 image pinned by
digest, in dependency order: header chain, work only, then bridge, because each guest embeds
the program keys of the guests it verifies. `cargo prove build --docker` does not forward
environment variables, so the script passes `BITCOIN_NETWORK` to rustc with `--env-set`. The
script records each ELF checksum and program key in `sp1-circuits/elfs/manifest.json` and
regenerates the key table. `--citrea` records the program keys of Citrea's light client ELFs
(`mainnet-light-client.elf`, `testnet4-light-client.elf`, `signet-light-client.elf` and
`regtest-light-client.elf`). Commit the manifest, the key table and the ELFs together. The
Circuit Check workflow rebuilds all guests and fails if they differ.

The guest workspaces patch crypto crates with SP1's precompile patches; for example, Groth16
verification uses the patched BN254 crate. `scripts/check-sp1-patches.py` fails if a supported
crypto dependency loses its patch.

## Deployment

This migration changes proof formats, program keys, stored receipts and BitVM scripts.
The 64-byte bridge output also changes the SP1 bridge program key and additional-disprove
script. Regenerate BitVM caches and transaction scripts together with the guest artifacts;
old 32-byte bridge journals do not prove execution of the new guest.

Deposits created with the RISC Zero programs cannot be disproved with the SP1 scripts. The
rollout depends on these conditions:

- Every live deposit is replaced after the upgrade. Replacement deposits are signed with the
  SP1 scripts and the new genesis.
- Before the switch, no kickoffs are in progress and no payouts wait for reimbursement on
  RISC Zero deposits. The SP1 programs cannot reimburse them: the bridge guest reads the
  deposit's move txid from Citrea storage at the payout block, so only payouts made after a
  deposit's replacement can be reimbursed through it.
- All actors set a new `genesis_height` and `genesis_chain_state_hash`. Both are part of the
  deposit constant, so actors with different values cannot sign deposits together. The new
  genesis must be finalized and at or below the upgrade height, so that every replacement
  comes after it.
- Citrea starts its SP1 light client proofs at a later L1 height and does not prove older
  heights. The new genesis must be at least that height plus one, because syncing a height
  also reads the light client proof of the previous height.

Migration `0001_clementine_v0.7` clears the stored RISC Zero header chain proofs. The
prover's first proof after that starts from the new genesis block. `genesis_height` can
be above `start_height`; `start_height` does not change, because operator collateral checks
and round state machines must see each operator's round transactions.

The light client proof syncer starts at the larger of `start_height` and `genesis_height`.
Nothing it skips is needed:

- Deposits and withdrawals are read by index from the bridge contract, so the first synced
  height reads all earlier ones. A fresh database gets replaced move txids from
  `depositTxIds`, which `replaceDeposit` overwrites.
- Payouts below genesis cannot be proven, because the payout block must be in the header
  chain proof.
- An existing database misses `DepositReplaced` events in the skipped range. These events
  update by deposit index, so the replacement of each deposit after the upgrade overwrites
  any missed value.

CI integration tests use the native SP1 Citrea binary pinned in `scripts/citrea-e2e.json`;
see [paired testing](usage.md#paired-citrea-integration-tests).
