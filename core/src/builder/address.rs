//! # Address Builder
//!
//! Address builder provides useful functions for building typical Bitcoin
//! addresses.

use crate::builder;
use crate::utils::SECP;
use crate::{utils, EVMAddress};
use bitcoin::address::NetworkUnchecked;
use bitcoin::opcodes::all::OP_CHECKSIG;
use bitcoin::{
    secp256k1::XOnlyPublicKey,
    taproot::{TaprootBuilder, TaprootSpendInfo},
    Address, ScriptBuf,
};
use bitcoin::{Amount, Network};
use bitvm::signatures::winternitz;

pub fn taproot_builder_with_scripts(scripts: &[ScriptBuf]) -> TaprootBuilder {
    let builder = TaprootBuilder::new();
    let num_scripts = scripts.len();

    // Special return cases for n = 0 or n = 1
    match num_scripts {
        0 => return builder,
        1 => return builder.add_leaf(0, scripts[0].clone()).unwrap(),
        _ => {}
    }

    let deepest_layer_depth: u8 = ((num_scripts - 1).ilog2() + 1) as u8;

    let num_empty_nodes_in_final_depth = 2_usize.pow(deepest_layer_depth.into()) - num_scripts;
    let num_nodes_in_final_depth = num_scripts - num_empty_nodes_in_final_depth;

    (0..num_scripts).fold(builder, |acc, i| {
        let is_node_in_last_minus_one_depth = (i >= num_nodes_in_final_depth) as u8;

        acc.add_leaf(
            deepest_layer_depth - is_node_in_last_minus_one_depth,
            scripts[i].clone(),
        )
        .unwrap()
    })
}

/// Creates a taproot address with either key path spend or script spend path
/// addresses. This depends on given arguments.
///
/// # Arguments
///
/// - `scripts`: If empty, it is most likely a key path spend address
/// - `internal_key`: If not given, will be defaulted to an unspendable x-only public key
/// - `network`: Bitcoin network
/// - If both `scripts` and `internal_key` are given, it means one can spend using both script and key path.
/// - If none given, it is an unspendable address.
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
    // Build script tree
    let taproot_builder = taproot_builder_with_scripts(scripts);
    // Finalize the tree
    let tree_info = match internal_key {
        Some(xonly_pk) => taproot_builder.finalize(&SECP, xonly_pk).unwrap(),
        None => taproot_builder
            .finalize(&SECP, *utils::UNSPENDABLE_XONLY_PUBKEY)
            .unwrap(),
    };
    // Create the address
    let taproot_address = match internal_key {
        Some(xonly_pk) => Address::p2tr(&SECP, xonly_pk, tree_info.merkle_root(), network),
        None => Address::p2tr(
            &SECP,
            *utils::UNSPENDABLE_XONLY_PUBKEY,
            tree_info.merkle_root(),
            network,
        ),
    };

    (taproot_address, tree_info)
}

/// Generates a deposit address for the user. Funds can be spend by N-of-N or
/// user can take after specified time should the deposit fail.
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
    user_takes_after: u16,
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

pub fn derive_challenge_address_from_xonlypk_and_wpk(
    xonly_pk: &XOnlyPublicKey,
    winternitz_pk: &winternitz::PublicKey,
    network: Network,
) -> Address {
    let verifier =
        winternitz::Winternitz::<winternitz::ListpickVerifier, winternitz::TabledConverter>::new();
    let wots_params = winternitz::Parameters::new(240, 4);
    let mut script_builder = verifier.checksig_verify(&wots_params, winternitz_pk);
    script_builder = script_builder.push_x_only_key(xonly_pk);
    script_builder = script_builder.push_opcode(OP_CHECKSIG); // TODO: Add checksig in the beginning
    let script_builder = script_builder.compile();
    let (address, _) = create_taproot_address(&[script_builder.clone()], None, network);
    address
}

#[cfg(test)]
mod tests {
    use crate::{
        builder,
        musig2::AggregateFromPublicKeys,
        utils::{self, SECP},
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
            XOnlyPublicKey::from_keypair(&Keypair::from_secret_key(&SECP, &secret_key)).0;

        // No internal key or scripts (key path spend).
        let (address, spend_info) =
            builder::address::create_taproot_address(&[], None, bitcoin::Network::Regtest);
        assert_eq!(address.address_type().unwrap(), AddressType::P2tr);
        assert!(address.is_related_to_xonly_pubkey(
            &utils::UNSPENDABLE_XONLY_PUBKEY
                .tap_tweak(&SECP, spend_info.merkle_root())
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
                .tap_tweak(&SECP, spend_info.merkle_root())
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
                .tap_tweak(&SECP, spend_info.merkle_root())
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
                .tap_tweak(&SECP, spend_info.merkle_root())
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

    #[test]
    pub fn test_taproot_builder_with_scripts() {
        for i in [0, 1, 10, 50, 100, 1000].into_iter() {
            let scripts = (0..i)
                .map(|k| ScriptBuf::builder().push_int(k).into_script())
                .collect::<Vec<_>>();
            let builder = super::taproot_builder_with_scripts(&scripts);
            let tree_info = builder
                .finalize(&SECP, *utils::UNSPENDABLE_XONLY_PUBKEY)
                .unwrap();

            assert_eq!(tree_info.script_map().len(), i as usize);
        }
    }
}
