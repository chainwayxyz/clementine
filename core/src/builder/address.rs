//! # Bitcoin Address Construction
//!
//! Contains helper functions to create taproot addresses with given scripts and internal key.

pub use clementine_utils::address::{
    calculate_taproot_leaf_depths, create_taproot_address, taproot_builder_with_scripts,
};

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
