use crate::builder;
use crate::{utils, EVMAddress};
use bitcoin::address::NetworkUnchecked;
use bitcoin::{
    taproot::{TaprootBuilder, TaprootSpendInfo},
    Address, ScriptBuf,
};
use secp256k1::XOnlyPublicKey;

/// Creates a taproot address with either key path spend or script spend path
/// addresses. This depends on given arguments.
///
/// # Arguments
///
/// - `scripts`: If empty, script will be key path spend
/// - `internal_key`: If not given, will be defaulted to an unspendable x-only public key
/// - `network`: Bitcoin network
///
/// # Returns
///
/// - [`Address`]: Generated taproot address
/// - [`TaprootSpendInfo`]: Taproot spending information
///
/// # Panics
///
/// Will panic if some of the operations have invalid paramaters.
pub fn create_taproot_address(
    scripts: &[ScriptBuf],
    internal_key: Option<XOnlyPublicKey>,
    network: bitcoin::Network,
) -> (Address, TaprootSpendInfo) {
    let n = scripts.len();

    let taproot_builder = if n == 0 {
        TaprootBuilder::new()
    } else if n > 1 {
        let m: u8 = ((n - 1).ilog2() + 1) as u8; // m = ceil(log(n))
        let k = 2_usize.pow(m.into()) - n;
        (0..n).fold(TaprootBuilder::new(), |acc, i| {
            acc.add_leaf(m - ((i >= n - k) as u8), scripts[i].clone())
                .unwrap()
        })
    } else {
        TaprootBuilder::new()
            .add_leaf(0, scripts[0].clone())
            .unwrap()
    };

    let tree_info = match internal_key {
        Some(xonly_pk) => taproot_builder.finalize(&utils::SECP, xonly_pk).unwrap(),
        None => taproot_builder
            .finalize(&utils::SECP, *utils::UNSPENDABLE_XONLY_PUBKEY)
            .unwrap(),
    };

    let taproot_address = match internal_key {
        Some(xonly_pk) => Address::p2tr(&utils::SECP, xonly_pk, tree_info.merkle_root(), network),
        None => Address::p2tr(
            &utils::SECP,
            *utils::UNSPENDABLE_XONLY_PUBKEY,
            tree_info.merkle_root(),
            network,
        ),
    };

    (taproot_address, tree_info)
}

/// Generates a deposit address for the user. Funds can be spend by N-of-N or
/// user can take after specified time.
///
/// # Parameters
///
/// - `nofn_xonly_pk`: N-of-N x-only public key of the depositor
/// - `recovery_taproot_address`: User's x-only public key that can be used to
///   take funds after some time
/// - `user_evm_address`: User's EVM address.
/// - `amount`: Amount to deposit (in sats)
/// - `network`: Bitcoin network to work on
/// - `user_takes_after`: User can take the funds back, after this amounts of
///   blocks have passed
///
/// # Returns
///
/// - [`Address`]: Deposit taproot Bitcoin address
/// - [`TaprootSpendInfo`]: Deposit address's taproot spending information
///
/// # Panics
///
/// Panics if given parameters are malformed.
pub fn generate_deposit_address(
    nofn_xonly_pk: XOnlyPublicKey,
    recovery_taproot_address: &Address<NetworkUnchecked>,
    user_evm_address: EVMAddress,
    amount: u64,
    network: bitcoin::Network,
    user_takes_after: u32,
) -> (Address, TaprootSpendInfo) {
    let deposit_script =
        builder::script::create_deposit_script(nofn_xonly_pk, user_evm_address, amount);

    let recovery_script_pubkey = recovery_taproot_address
        .clone()
        .assume_checked()
        .script_pubkey();
    let recovery_extracted_xonly_pk =
        XOnlyPublicKey::from_slice(&recovery_script_pubkey.as_bytes()[2..34]).unwrap();

    let script_timelock = builder::script::generate_relative_timelock_script(
        recovery_extracted_xonly_pk,
        user_takes_after,
    );

    create_taproot_address(&[deposit_script, script_timelock], None, network)
}

/// Shorthand function for creating a MuSig2 taproot address: No scripts and
/// `nofn_xonly_pk` as the internal key.
///
/// # Returns
///
/// See [`create_taproot_address`].
///
/// - [`Address`]: MuSig2 taproot Bitcoin address
/// - [`TaprootSpendInfo`]: MuSig2 address's taproot spending information
pub fn create_musig2_address(
    nofn_xonly_pk: XOnlyPublicKey,
    network: bitcoin::Network,
) -> (Address, TaprootSpendInfo) {
    create_taproot_address(&[], Some(nofn_xonly_pk), network)
}

/// Creates a kickoff taproot address with multisig script.
///
/// # Returns
///
/// See [`create_taproot_address`].
///
/// - [`Address`]: Kickoff taproot Bitcoin address
/// - [`TaprootSpendInfo`]: Kickoff address's taproot spending information
pub fn create_kickoff_address(
    nofn_xonly_pk: XOnlyPublicKey,
    operator_xonly_pk: XOnlyPublicKey,
    network: bitcoin::Network,
) -> (Address, TaprootSpendInfo) {
    let musig2_and_operator_script = builder::script::create_musig2_and_operator_multisig_script(
        nofn_xonly_pk,
        operator_xonly_pk,
    );

    create_taproot_address(&[musig2_and_operator_script], None, network)
}
