# Real bridge proof fixture

`regtest-bridge-network.borsh` is a 397-byte Borsh production receipt (Groth16 seal
and public journal only) from the real regtest run on 2026-10-21. It contains no
private key or private witness. SDK: SP1 6.9.0.

- Program: `003d32bf7d76bad6f5d59998dee2727d2abab29017833136c5e6611cbf453642`
- Succinct request: `1b84b63cecd84d6e0ff3f46b2ab79fe4233ab1e035c793aef69e455e604b8ea7`
- Fulfilled: 2026-10-21 01:06:33 UTC
- SHA256: `5e6feb6c594d77b33c9ebe7c8cd2239ac7473fe616102d6a5c5f5de88ae0a9b4`

The network bridge regression verifies this receipt with the pinned production
Blake3 verifier, then rejects changed public values, a different program key,
a corrupted proof, and a mock receipt. No paid request is made by these tests.

This historical network proof commits a 32-byte journal. It exercises production SP1
verification independently of the current guest build. Current bridge guests commit
64 bytes (`deposit_constant || X`); the guest execution and additional-disprove tests
cover that encoding. This fixture is not a proof of the current bridge guest.
