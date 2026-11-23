# Clementine Threat Model

## Scope

Clementine is Citrea's BitVM-based Bitcoin two-way peg. It contains the aggregator, verifier and operator services (gRPC and PostgreSQL), the transaction sender, the Bitcoin syncer and state machines, the Bitcoin transaction graph, the BitVM integration and the SP1 circuits (header chain, work only and bridge) with their host crates. Verifiers are the N-of-N signers and also act as watchtowers. Everything in this repository is in scope. Citrea's `Bridge` contract is not in this repository, only its ABI (`scripts/Bridge.json`). How Clementine reads and depends on the contract is in scope. Whether the checked-in SP1 guest ELFs and the program keys in `sp1-circuits/elfs/manifest.json` and `circuits-lib/src/common/sp1_programs.rs` are reproducible from their sources is also in scope. Mainnet is the security target.

Assets are users' deposited BTC (before and after it moves to the vault), operators' funds and collateral, the funds that verifiers use for fees and challenges, and all keys and one-time secrets (MuSig2 nonces, Winternitz keys and challenge-ack preimages).

## Trust model

Deposited BTC cannot be stolen while at least one verifier is honest. Withdrawals keep being paid while the aggregator, the holder of the withdrawal verification key (`aggregator_verification_address`) and at least one operator are honest, because operators get withdrawal requests through the aggregator. A deposit needs the aggregator, every verifier and every operator with usable collateral; if it is not moved to the vault, the depositor can take it back after `user_takes_after` blocks. The aggregator is never assumed honest for safety, and it is accepted that the aggregator can DoS all actors. Every other actor can be malicious, and all malicious actors can collude. This includes operators, other verifiers and extra watchtowers. Depositors, withdrawers, challengers and anyone else on Bitcoin, Citrea or the network can also be malicious and can collude with them.

Trusted (honest, not bug-free):

- The Bitcoin Core RPC of every honest actor.
- The Citrea RPC of each honest verifier. An operator uses the Citrea deposits, withdrawals and payouts that the verifier sharing its database syncs.
- Each actor's own configuration (including the protocol paramset, security council, emergency-stop public key and certificates), secrets, database, filesystem (including BitVM caches and the initial header chain proof) and backups.
- The `Bridge` contract's owner and `operator` role, its proxy admin, and the security council.

Not trusted:

- Every other Citrea RPC.
- Provers: the Citrea light client prover and the Succinct SP1 prover network, if used.
- Fee and broadcast services, such as the mempool.space API and accelerator.
- Messages from other actors, RPC request contents, and Bitcoin transactions and witnesses created by others.

Assumptions:

- No reorg goes deeper than `finality_depth`.
- A transaction that pays the market feerate and reaches miners confirms within 72 blocks.
- At least one honest verifier runs the `automation` build, stays online and holds enough funds for fees and `operator_challenge_amount`.
- Honest operators stay online and hold enough funds for fees and collateral. Each one runs the `automation` build, or runs without it, gets reimbursed manually through `get_reimbursement_txs`, and restarts with `automation` early enough to answer a challenge before its timeouts.
- Each operator runs together with a verifier that shares its database.
- The aggregator's gRPC server is behind a firewall, so only the services and people that run it can reach it, even with `client_verification=false`.
- On mainnet and testnet4, verifiers only log the signed `Challenge` for a malicious kickoff. A person funds and sends it before the operator can send `ChallengeTimeout`, and before the operator can open its next round after `ReadyToReimburse`.
- An actor's database holds the signed graph and the state machines that it needs to respond. If it is lost, that actor is treated as offline for the deposits it signed.
- Each operator's remaining rounds (`num_round_txs`) are monitored, and the operator is replaced or new operators are added before they run out.
- After the N-of-N set changes, the security council replaces every current deposit, and the new verifier set signs the replacement deposits.

A finding that needs a trusted party to act maliciously or an assumption to break is out of scope.

## Attack paths

These are starting points, not a complete list. Look for other paths too and report what you find.

Theft that completes before anyone can react:

- Optimistic payout: verifiers sign an `OptimisticPayout` that a matching burned withdrawal of that deposit does not back.
- Early reimbursement: an operator reaches `Reimburse` before an honest verifier can confirm a challenge and a burn. For example, a deposit gets signed while a kickoff and reimburse for it is already on chain, or while the operator still has kickoffs left in rounds that it already passed.
- Verifier signatures: an N-of-N signature on `MoveToVault`, `EmergencyStop`, `Reimburse`, `OptimisticPayout` or a timeout or burn transaction is reused or combined into another spend, or verifiers sign a vault or graph that an attacker can spend.
- Citrea mapping: Clementine maps a Citrea deposit index, move txid, replacement deposit or withdrawal UTXO wrongly, so a vault pays a withdrawal of another deposit, or verifiers sign a deposit whose N-of-N key does not match the `Bridge` contract.

Theft through a dispute the operator should lose:

- Missed challenge: an honest verifier does not flag a malicious kickoff, for example because of payout detection, the payout's OP_RETURN or a replacement deposit. Or it flags a kickoff that the operator can answer, marks the round as challenged and then skips a malicious kickoff of the same round.
- Blind watchtower: no honest watchtower challenge confirms in time or counts in the bridge proof.
- False win: the operator survives the challenge without a valid payout, because the bridge, header chain or work-only circuit, the SP1 verifying key specialization, a BitVM or additional disprove script, a Winternitz commitment or the challenge-ack preimage check accepts what it should reject, or because the circuit ignores an honest watchtower's challenge.
- Round escape: a kickoff reaches `Reimburse` although another kickoff of the same round was disproved or timed out, or the round left kickoff connectors unspent, because a burn transaction (`Disprove`, `OperatorChallengeNack`, `AssertTimeout`, `LatestBlockhashTimeout`, `KickoffNotFinalized` or `UnspentKickoff`) cannot confirm.
- Missed deadline: an honest response confirms too late, because of timelock ordering, finality, pinning, replacement cycling, the fee cap, attacker-induced fees or tx-sender faults. For example, the operator sends `ReadyToReimburse` right after a malicious kickoff, so the challenge and `KickoffNotFinalized` must confirm within `operator_reimburse_timelock` instead of the longer challenge timeout.
- Lost watch: a restart, upgrade, N-of-N change or state-machine recovery leaves a kickoff or round that no honest verifier still tracks.

Other losses:

- Honest operator: it pays a withdrawal it cannot claim. Or it cannot answer a false challenge in time, it is disproved or burned with a valid proof, or challenges and watchtower challenges keep it from reaching its next round.
- One-time secrets: a MuSig2 secret nonce is reused after a retry, crash or concurrent session, a Winternitz key signs two different messages, or a challenge-ack preimage leaks through logs, RPC responses or the database before the operator reveals it.
- Authorization: an RPC caller other than the aggregator reaches a verifier or operator method, a caller other than the actor itself reaches an `Internal*` method, or a peer passes as another actor. Operator setup data and deposit keys carry the operator's own signature, and withdrawal requests carry the withdrawal verification signature.
- Relay: the aggregator changes, replays or reorders a message between actors, or gives actors different views of a deposit or setup, so that an honest actor signs or accepts something that causes a loss.
- Unconfirmable graph: a presigned transaction is invalid or nonstandard on a paramset without `bridge_nonstandard`, so the funds or responses that depend on it are stuck.

## Intended behavior

These are not bugs by themselves:

- The Prometheus telemetry endpoint has no authentication. It must run on a trusted network.
- Off-mainnet relaxations: `SP1_PROVER=mock`, the `testing` feature and its development programs (`use-test-vk`), debug builds (which commit an anyone-can-spend disprove leaf), mock Citrea light-client receipts, `client_verification=false` on verifiers and operators, collateral that is still in the mempool, `bridge_nonstandard` paramsets and their testnet4 accelerator path, example keys, development certificates and small regtest parameters.
- Denial of service by a service that an honest actor depends on, such as a stopped Citrea light client prover or SP1 prover network, if it shows clearly in the actor's task errors or RPC error responses. Such an issue is fixed within days, and the protocol's timelocks leave enough time for that.
- The aggregator and the holder of the emergency-stop decryption key can use a deposit's signed `EmergencyStop` transaction to move the deposit to the security council at any time, including after an operator paid a withdrawal and before it is reimbursed. The security council can also spend every vault directly. The council then settles users and operators, or creates replacement deposits. Theft that an emergency stop could prevent is still a vulnerability.
- On mainnet and testnet4, verifiers do not send `Challenge` automatically. They log the signed transaction for a person to send.
- Anyone who holds the operator's signed `Challenge`, such as a verifier or the aggregator, can challenge an honest kickoff by paying `operator_challenge_amount` to the operator. The operator then runs the full BitVM flow, and the reimbursements of its round wait for `DisproveTimeout`. A correct challenger gets back neither the challenge amount nor its fees.
- A challenged operator can get its collateral back before it is disproven. Without collateral it cannot open new rounds, so a malicious operator needs to be challenged only once.
- The aggregator chooses which operators it registers with verifiers and which extra watchtowers a deposit has. Verifiers check each operator's own setup signature and collateral (that guarantees all operators are in as they require live verifiers), and only the number and uniqueness of the watchtowers.
- Memory that the aggregator can make a verifier hold for MuSig2 nonce sessions, up to `MAX_ALL_SESSIONS_BYTES` (2 GB).

## Severity

Rate a finding by its demonstrated mainnet impact: funds lost or frozen, keys exposed, or an honest party slashed or not reimbursed. Denial of service and fee waste matter only when they cause such a loss or are unbounded. A non-mainnet finding is at most medium; rate it by the same impacts on that network. A tx sender failure that needs several independent unlikely events to coincide is informational, unless an attacker can cause it.
