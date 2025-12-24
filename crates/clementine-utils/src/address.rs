use bitcoin::{
    script::PushBytesBuf,
    secp256k1::XOnlyPublicKey,
    taproot::{TaprootBuilder, TaprootSpendInfo},
    Address, Amount, ScriptBuf, TxOut,
};
use clementine_primitives::{SECP, UNSPENDABLE_XONLY_PUBKEY};

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
            .finalize(&SECP, *UNSPENDABLE_XONLY_PUBKEY)
            .expect("builder return is finalizable"),
    };

    // Create the address
    let taproot_address: Address = Address::p2tr_tweaked(tree_info.output_key(), network);

    (taproot_address, tree_info)
}


/// Creates an OP_RETURN output with the given data slice.
///
/// # Arguments
///
/// * `slice` - The data to embed in the OP_RETURN output.
///
/// # Returns
///
/// A [`TxOut`] with an OP_RETURN script containing the provided data.
pub fn op_return_txout<S: AsRef<[u8]>>(slice: S) -> TxOut {
    let buf = slice.as_ref().to_vec();
    let push_bytes = PushBytesBuf::try_from(buf).expect("data too large for op_return");
    TxOut {
        value: Amount::ZERO,
        script_pubkey: ScriptBuf::new_op_return(push_bytes),
    }
}

/// Helper function to check if a TxOut is a P2A anchor.
pub fn is_p2a_anchor(output: &TxOut) -> bool {
    output.script_pubkey
        == ScriptBuf::from_hex(
            "51024e73",
        )
        .expect("valid anchor script")
}
