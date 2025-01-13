//! # Address Builder
//!
//! Address builder provides useful functions for building typical Bitcoin
//! addresses.

use crate::builder;
use crate::{utils, EVMAddress};
use bitcoin::address::NetworkUnchecked;
use bitcoin::Amount;
use bitcoin::{
    secp256k1::XOnlyPublicKey,
    taproot::{TaprootBuilder, TaprootSpendInfo},
    Address, ScriptBuf,
};

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
        Some(xonly_pk) => taproot_builder.finalize(SECP256K1, xonly_pk).unwrap(),
        None => taproot_builder
            .finalize(SECP256K1, *utils::UNSPENDABLE_XONLY_PUBKEY)
            .unwrap(),
    };

    let taproot_address = match internal_key {
        Some(xonly_pk) => Address::p2tr(SECP256K1, xonly_pk, tree_info.merkle_root(), network),
        None => Address::p2tr(
            SECP256K1,
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
/// - `amount`: Amount to deposit
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
    amount: Amount,
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
        user_takes_after as i64,
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

#[cfg(test)]
mod tests {
    use crate::{
        builder,
        musig2::AggregateFromPublicKeys,
        utils::{self},
    };
    use bitcoin::{
        key::{Keypair, TapTweak},
        secp256k1::{PublicKey, SecretKey},
        Address, AddressType, Amount, ScriptBuf, XOnlyPublicKey,
    };
    use secp256k1::rand;
    use std::str::FromStr;

    #[test]
    fn create_taproot_address() {
        let secret_key = SecretKey::new(&mut rand::thread_rng());
        let internal_key =
            XOnlyPublicKey::from_keypair(&Keypair::from_secret_key(SECP256K1, &secret_key)).0;

        // No internal key or scripts (key path spend).
        let (address, spend_info) =
            builder::address::create_taproot_address(&[], None, bitcoin::Network::Regtest);
        assert_eq!(address.address_type().unwrap(), AddressType::P2tr);
        assert!(address.is_related_to_xonly_pubkey(
            &utils::UNSPENDABLE_XONLY_PUBKEY
                .tap_tweak(SECP256K1, spend_info.merkle_root())
                .0
                .to_inner()
        ));
        assert_eq!(spend_info.internal_key(), *utils::UNSPENDABLE_XONLY_PUBKEY);
        assert!(spend_info.merkle_root().is_none());

        // Key path spend.
        let (address, spend_info) = builder::address::create_taproot_address(
            &[],
            Some(internal_key),
            bitcoin::Network::Regtest,
        );
        assert_eq!(address.address_type().unwrap(), AddressType::P2tr);
        assert!(address.is_related_to_xonly_pubkey(
            &internal_key
                .tap_tweak(SECP256K1, spend_info.merkle_root())
                .0
                .to_inner()
        ));
        assert_eq!(spend_info.internal_key(), internal_key);
        assert!(spend_info.merkle_root().is_none());

        let scripts = [ScriptBuf::new()];
        let (address, spend_info) = builder::address::create_taproot_address(
            &scripts,
            Some(internal_key),
            bitcoin::Network::Regtest,
        );
        assert_eq!(address.address_type().unwrap(), AddressType::P2tr);
        assert!(address.is_related_to_xonly_pubkey(
            &internal_key
                .tap_tweak(SECP256K1, spend_info.merkle_root())
                .0
                .to_inner()
        ));
        assert_eq!(spend_info.internal_key(), internal_key);
        assert!(spend_info.merkle_root().is_some());

        let scripts = [ScriptBuf::new(), ScriptBuf::new()];
        let (address, spend_info) = builder::address::create_taproot_address(
            &scripts,
            Some(internal_key),
            bitcoin::Network::Regtest,
        );
        assert_eq!(address.address_type().unwrap(), AddressType::P2tr);
        assert!(address.is_related_to_xonly_pubkey(
            &internal_key
                .tap_tweak(SECP256K1, spend_info.merkle_root())
                .0
                .to_inner()
        ));
        assert_eq!(spend_info.internal_key(), internal_key);
        assert!(spend_info.merkle_root().is_some());
    }

    #[test]
    #[ignore = "TODO: Investigate this"]
    fn generate_deposit_address_musig2_fixed_address() {
        let verifier_pks_hex: Vec<&str> = vec![
            "034f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa",
            "02466d7fcae563e5cb09a0d1870bb580344804617879a14949cf22285f1bae3f27",
            "023c72addb4fdf09af94f0c94d7fe92a386a7e70cf8a1d85916386bb2535c7b1b1",
            "032c0b7cf95324a07d05398b240174dc0c2be444d96b159aa6c7f7b1e668680991",
            "029ac20335eb38768d2052be1dbbc3c8f6178407458e51e6b4ad22f1d91758895b",
            "035ab4689e400a4a160cf01cd44730845a54768df8547dcdf073d964f109f18c30",
            "037962d45b38e8bcf82fa8efa8432a01f20c9a53e24c7d3f11df197cb8e70926da",
        ];
        let verifier_pks: Vec<PublicKey> = verifier_pks_hex
            .iter()
            .map(|pk| PublicKey::from_str(pk).unwrap())
            .collect();
        let nofn_xonly_pk = XOnlyPublicKey::from_musig2_pks(verifier_pks, None).unwrap();

        let evm_address: [u8; 20] = hex::decode("1234567890123456789012345678901234567890")
            .unwrap()
            .try_into()
            .unwrap();

        let recovery_taproot_address =
            Address::from_str("bcrt1p65yp9q9fxtf7dyvthyrx26xxm2czanvrnh9rtvphmlsjvhdt4k6qw4pkss")
                .unwrap();

        let deposit_address = builder::address::generate_deposit_address(
            nofn_xonly_pk,
            recovery_taproot_address.as_unchecked(),
            crate::EVMAddress(evm_address),
            Amount::from_sat(100_000_000),
            bitcoin::Network::Regtest,
            200,
        );

        // Comparing it to the taproot address generated in bridge backend.
        assert_eq!(
            deposit_address.0.to_string(),
            "bcrt1ptlz698wumzl7uyk6pgrvsx5ep29thtvngxftywnd4mwq24fuwkwsxasqf5" // TODO: check this later
        )
    }
}
