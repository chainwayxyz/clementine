//! # Bitcoin Address Construction
//!
//! Contains helper functions to create taproot addresses with given scripts and internal key.
//! Contains helper functions to create correct deposit addresses. Addresses need to be of a specific format to be
//! valid deposit addresses.

use super::script::{
    BaseDepositScript, CheckSig, Multisig, ReplacementDepositScript, SpendableScript,
    TimelockScript,
};
use crate::bitvm_client::SECP;
use crate::deposit::SecurityCouncil;
use crate::errors::BridgeError;
use crate::utils::ScriptBufExt;
use crate::{bitvm_client, EVMAddress};
use bitcoin::address::NetworkUnchecked;
use bitcoin::{
    secp256k1::XOnlyPublicKey,
    taproot::{TaprootBuilder, TaprootSpendInfo},
    Address, ScriptBuf,
};

use eyre::Context;

/// A helper to construct a `TaprootBuilder` from a slice of script buffers, forming the script tree.
/// Finds the needed depth the script tree needs to be to fit all the scripts and inserts the scripts.
pub fn taproot_builder_with_scripts(scripts: impl Into<Vec<ScriptBuf>>) -> TaprootBuilder {
    // doesn't clone if its already an owned Vec
    let mut scripts: Vec<ScriptBuf> = scripts.into();
    let builder = TaprootBuilder::new();
    let num_scripts = scripts.len();

    // Special return cases for n = 0 or n = 1
    match num_scripts {
        0 => return builder,
        1 => {
            return builder
                .add_leaf(0, scripts.remove(0))
                .expect("one root leaf added on empty builder")
        }
        _ => {}
    }

    let deepest_layer_depth: u8 = ((num_scripts - 1).ilog2() + 1) as u8;

    let num_empty_nodes_in_final_depth = 2_usize.pow(deepest_layer_depth.into()) - num_scripts;
    let num_nodes_in_final_depth = num_scripts - num_empty_nodes_in_final_depth;

    scripts
        .into_iter()
        .enumerate()
        .fold(builder, |acc, (i, script)| {
            let is_node_in_last_minus_one_depth = (i >= num_nodes_in_final_depth) as u8;

            acc.add_leaf(
                deepest_layer_depth - is_node_in_last_minus_one_depth,
                script,
            )
            .expect("algorithm tested to be correct")
        })
}

/// Calculates the depth of each leaf in a balanced Taproot tree structure.
/// The returned Vec contains the depth for each script at the corresponding index.
pub fn calculate_taproot_leaf_depths(num_scripts: usize) -> Vec<u8> {
    match num_scripts {
        0 => return vec![],
        1 => return vec![0],
        _ => {}
    }

    let deepest_layer_depth: u8 = ((num_scripts - 1).ilog2() + 1) as u8;

    let num_empty_nodes_in_final_depth = 2_usize.pow(deepest_layer_depth.into()) - num_scripts;
    let num_nodes_in_final_depth = num_scripts - num_empty_nodes_in_final_depth;

    (0..num_scripts)
        .map(|i| {
            let is_node_in_last_minus_one_depth = (i >= num_nodes_in_final_depth) as u8;
            deepest_layer_depth - is_node_in_last_minus_one_depth
        })
        .collect()
}

/// Creates a taproot address with given scripts and internal key.
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
/// Will panic if some of the operations have invalid parameters.
pub fn create_taproot_address(
    scripts: &[ScriptBuf],
    internal_key: Option<XOnlyPublicKey>,
    network: bitcoin::Network,
) -> (Address, TaprootSpendInfo) {
    // Build script tree
    let taproot_builder = taproot_builder_with_scripts(scripts);
    // Finalize the tree
    let tree_info = match internal_key {
        Some(xonly_pk) => taproot_builder
            .finalize(&SECP, xonly_pk)
            .expect("builder return is finalizable"),
        None => taproot_builder
            .finalize(&SECP, *bitvm_client::UNSPENDABLE_XONLY_PUBKEY)
            .expect("builder return is finalizable"),
    };

    // Create the address
    let taproot_address: Address = Address::p2tr_tweaked(tree_info.output_key(), network);

    (taproot_address, tree_info)
}

/// Generates a deposit address for the user. Funds can be spent by N-of-N or
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
    network: bitcoin::Network,
    user_takes_after: u16,
) -> Result<(Address, TaprootSpendInfo), BridgeError> {
    let deposit_script = BaseDepositScript::new(nofn_xonly_pk, user_evm_address).to_script_buf();

    let recovery_script_pubkey = recovery_taproot_address
        .clone()
        .assume_checked()
        .script_pubkey();

    let recovery_extracted_xonly_pk = recovery_script_pubkey
        .try_get_taproot_pk()
        .wrap_err("Recovery taproot address is not a valid taproot address")?;

    let script_timelock =
        TimelockScript::new(Some(recovery_extracted_xonly_pk), user_takes_after).to_script_buf();

    let (addr, spend) = create_taproot_address(&[deposit_script, script_timelock], None, network);
    Ok((addr, spend))
}

/// Builds a Taproot address specifically for replacement deposits.
/// Replacement deposits are to replace old move_to_vault transactions in case any issue is found on the bridge.
/// This address incorporates a script committing to an old move transaction ID
/// and a multisig script for the security council.
/// This replacement deposit address will be used to create a new deposit transaction, which will then be used to
/// sign the new related bridge deposit tx's.
///
/// # Parameters
///
/// - `old_move_txid`: The `Txid` of the old move_to_vault transaction that is being replaced.
/// - `nofn_xonly_pk`: The N-of-N XOnlyPublicKey for the deposit.
/// - `network`: The Bitcoin network on which the address will be used.
/// - `security_council`: The `SecurityCouncil` configuration for the multisig script.
///
/// # Returns
///
/// - `Ok((Address, TaprootSpendInfo))` containing the new replacement deposit address
///   and its associated `TaprootSpendInfo` if successful.
/// - `Err(BridgeError)` if any error occurs during address generation.
pub fn generate_replacement_deposit_address(
    old_move_txid: bitcoin::Txid,
    nofn_xonly_pk: XOnlyPublicKey,
    network: bitcoin::Network,
    security_council: SecurityCouncil,
) -> Result<(Address, TaprootSpendInfo), BridgeError> {
    let deposit_script =
        ReplacementDepositScript::new(nofn_xonly_pk, old_move_txid).to_script_buf();

    let security_council_script = Multisig::from_security_council(security_council).to_script_buf();

    let (addr, spend) =
        create_taproot_address(&[deposit_script, security_council_script], None, network);
    Ok((addr, spend))
}

/// Shorthand function for creating a checksig taproot address: A single checksig script with the given xonly PK and no internal key.
///
/// # Returns
///
/// See [`create_taproot_address`].
///
/// - [`Address`]: Checksig taproot Bitcoin address
/// - [`TaprootSpendInfo`]: Checksig address's taproot spending information
pub fn create_checksig_address(
    xonly_pk: XOnlyPublicKey,
    network: bitcoin::Network,
) -> (Address, TaprootSpendInfo) {
    let script = CheckSig::new(xonly_pk);
    create_taproot_address(&[script.to_script_buf()], None, network)
}

#[cfg(test)]
mod tests {
    use crate::{
        bitvm_client::{self, SECP},
        builder::{self, address::calculate_taproot_leaf_depths},
    };
    use bitcoin::secp256k1::rand;
    use bitcoin::{
        key::{Keypair, TapTweak},
        secp256k1::SecretKey,
        AddressType, ScriptBuf, XOnlyPublicKey,
    };

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
            &bitvm_client::UNSPENDABLE_XONLY_PUBKEY
                .tap_tweak(&SECP, spend_info.merkle_root())
                .0
                .to_x_only_public_key()
        ));
        assert_eq!(
            spend_info.internal_key(),
            *bitvm_client::UNSPENDABLE_XONLY_PUBKEY
        );
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
                .to_x_only_public_key()
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
                .to_x_only_public_key()
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
                .to_x_only_public_key()
        ));
        assert_eq!(spend_info.internal_key(), internal_key);
        assert!(spend_info.merkle_root().is_some());
    }

    #[test]
    pub fn test_taproot_builder_with_scripts() {
        for i in [0, 1, 10, 50, 100, 1000].into_iter() {
            let scripts = (0..i)
                .map(|k| ScriptBuf::builder().push_int(k).into_script())
                .collect::<Vec<_>>();
            let builder = super::taproot_builder_with_scripts(scripts);
            let tree_info = builder
                .finalize(&SECP, *bitvm_client::UNSPENDABLE_XONLY_PUBKEY)
                .unwrap();

            assert_eq!(tree_info.script_map().len(), i as usize);
        }
    }

    #[test]
    fn test_calculate_taproot_leaf_depths() {
        // Test case 1: 0 scripts
        let expected: Vec<u8> = vec![];
        assert_eq!(calculate_taproot_leaf_depths(0), expected);

        // Test case 2: 1 script
        assert_eq!(calculate_taproot_leaf_depths(1), vec![0]);

        // Test case 3: 2 scripts (balanced tree, depth 1 for both)
        assert_eq!(calculate_taproot_leaf_depths(2), vec![1, 1]);

        // Test case 4: 3 scripts (unbalanced)
        // The first two scripts are at depth 2, the last is promoted to depth 1.
        assert_eq!(calculate_taproot_leaf_depths(3), vec![2, 2, 1]);

        // Test case 5: 4 scripts (perfectly balanced tree, all at depth 2)
        assert_eq!(calculate_taproot_leaf_depths(4), vec![2, 2, 2, 2]);

        // Test case 6: 5 scripts (unbalanced)
        // num_nodes_in_final_depth is 2, so first two are at depth 3, rest are at depth 2.
        // deepest_layer_depth = ilog2(4) + 1 = 3
        // num_empty_nodes = 2^3 - 5 = 3
        // num_nodes_in_final_depth = 5 - 3 = 2
        // Depths: (3, 3, 2, 2, 2)
        assert_eq!(calculate_taproot_leaf_depths(5), vec![3, 3, 2, 2, 2]);

        // Test case 7: 8 scripts (perfectly balanced tree, all at depth 3)
        assert_eq!(
            calculate_taproot_leaf_depths(8),
            vec![3, 3, 3, 3, 3, 3, 3, 3]
        );
    }
}
