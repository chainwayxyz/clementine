use bitcoin::amount::Amount;
use bitcoin::opcodes::all::OP_RETURN;
use bitcoin::script::Builder;
use bitcoin::secp256k1::XOnlyPublicKey;
use bitcoin::{ScriptBuf, TxOut};
use std::str::FromStr;

/// BIP-341 unspendable internal key (x-only pubkey).
///
/// Used to create taproot outputs where the internal key has no key-path spend.
/// See: <https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki#constructing-and-spending-taproot-outputs>
///
/// Other protocols using this key:
/// - [Babylon](https://github.com/babylonlabs-io/btc-staking-ts/blob/v0.4.0-rc.2/src/constants/internalPubkey.ts)
/// - [Ark](https://github.com/ark-network/ark/blob/cba48925bcc836cc55f9bb482f2cd1b76d78953e/common/tree/validation.go#L47)
/// - [BitVM](https://github.com/BitVM/BitVM/blob/2dd2e0e799d2b9236dd894da3fee8c4c4893dcf1/bridge/src/scripts.rs#L16)
/// - [Best in Slot](https://github.com/bestinslot-xyz/brc20-programmable-module/blob/2113bdd73430a8c3757e537cb63124a6cb33dfab/src/evm/precompiles/get_locked_pkscript_precompile.rs#L53)
/// - [BlockstreamResearch/options](https://github.com/BlockstreamResearch/options/blob/36a77175919101393b49f1211732db762cc7dfc1/src/options_lib/src/contract.rs#L132)
pub fn unspendable_internal_key() -> XOnlyPublicKey {
    XOnlyPublicKey::from_str("50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0")
        .expect("BIP-341 unspendable internal key is valid")
}

/// The standard unspendable internal key, lazily initialized.
pub static UNSPENDABLE_INTERNAL_KEY: std::sync::LazyLock<XOnlyPublicKey> =
    std::sync::LazyLock::new(unspendable_internal_key);

/// Protocol policy default for a relay-standard / dust-safe P2A anchor amount.
///
/// This is not a consensus constant; it's chosen to be robust under typical relay policy.
/// P2A itself is the script (`0x51024e73`); "standardness" depends on amount/policy.
const STANDARD_MIN_RELAYABLE_P2A_ANCHOR_AMOUNT: Amount = Amount::from_sat(240);

/// Creates a P2A (pay-to-anchor) output with the given amount.
///
/// P2A is a native segwit v1 output with a 2-byte witness program; the scriptPubKey is
/// `0x51024e73` (OP_1 OP_PUSHBYTES_2 4e73).
pub fn p2a_anchor_output(amount: Amount) -> TxOut {
    TxOut {
        value: amount,
        script_pubkey: ScriptBuf::new_p2a(),
    }
}

/// A relay-standard / dust-safe P2A anchor output (protocol default).
pub fn standard_p2a_anchor_output() -> TxOut {
    p2a_anchor_output(STANDARD_MIN_RELAYABLE_P2A_ANCHOR_AMOUNT)
}

/// An *ephemeral-dust style* P2A anchor output (0 sats).
///
/// Constructing this output does not guarantee relayability: it's typically used only when
/// relying on package relay / ephemeral-dust behavior.
pub fn ephemeral_dust_p2a_anchor_output() -> TxOut {
    p2a_anchor_output(Amount::from_sat(0))
}

/// Creates an OP_RETURN output with the given data slice.
///
/// This does not enforce node relay policy limits. Bitcoin Core v30 defaults allow multiple
/// OP_RETURN outputs and set `-datacarriersize=100000` (aggregate across such outputs).
pub fn op_return_txout<S: AsRef<bitcoin::script::PushBytes>>(slice: S) -> TxOut {
    let script = Builder::new()
        .push_opcode(OP_RETURN)
        .push_slice(slice)
        .into_script();

    TxOut {
        value: Amount::from_sat(0),
        script_pubkey: script,
    }
}
