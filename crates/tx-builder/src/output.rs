use bitcoin::amount::Amount;
use bitcoin::secp256k1::{Secp256k1, XOnlyPublicKey};
use bitcoin::taproot::{LeafVersion, NodeInfo, TapNodeHash, TaprootSpendInfo};
use bitcoin::{Network, ScriptBuf, TxOut};
use std::sync::Arc;

use crate::constants::unspendable_internal_key;
use crate::script::{ScriptLeaf, ScriptNode};

/// A transaction output descriptor with optional taproot spend info.
///
/// Created via [`from_scripts`](UnspentTxOut::from_scripts) for taproot
/// outputs, or [`from_partial`](UnspentTxOut::from_partial) for non-taproot
/// outputs (anchors, OP_RETURN).
#[derive(Debug, Clone)]
pub struct TaprootMeta<L> {
    scripts: Vec<ScriptNode>,
    named_leaves: Vec<(L, ScriptLeaf)>,
    spend_info: Option<Arc<TaprootSpendInfo>>,
}

impl<L> TaprootMeta<L> {
    pub fn new(
        scripts: Vec<ScriptNode>,
        named_leaves: Vec<(L, ScriptLeaf)>,
        spend_info: Option<Arc<TaprootSpendInfo>>,
    ) -> Self {
        Self {
            scripts,
            named_leaves,
            spend_info,
        }
    }

    pub fn scripts(&self) -> &Vec<ScriptNode> {
        &self.scripts
    }

    pub fn named_leaves(&self) -> &Vec<(L, ScriptLeaf)> {
        &self.named_leaves
    }

    pub fn spendinfo(&self) -> &Option<Arc<TaprootSpendInfo>> {
        &self.spend_info
    }
}

#[derive(Debug, Clone)]
pub struct UnspentTxOut<L> {
    /// The Bitcoin `TxOut` (value + script_pubkey).
    pub txout: TxOut,
    /// Taproot witness metadata used when the output is spent later.
    taproot: TaprootMeta<L>,
}

/// A fully resolved transaction output stored inside [`TxHandler`].
#[derive(Debug, Clone)]
pub struct ResolvedOutput<O, L> {
    id: O,
    unspent: UnspentTxOut<L>,
}

impl<O, L> ResolvedOutput<O, L> {
    pub fn new(id: O, unspent: UnspentTxOut<L>) -> Self {
        Self { id, unspent }
    }

    pub fn id(&self) -> &O {
        &self.id
    }

    pub fn unspent(&self) -> &UnspentTxOut<L> {
        &self.unspent
    }
}

/// Generic taproot output source represented as script leaves.
pub type TaprootOutputSource = Vec<ScriptNode>;

#[derive(Debug, Clone)]
pub enum TapNodeSpec<L> {
    Leaf { leaf: L, script: ScriptLeaf },
    Hidden(TapNodeHash),
    Branch(Vec<TapNodeSpec<L>>),
}

impl<L> TapNodeSpec<L> {
    pub fn leaf(leaf: L, script: impl Into<ScriptLeaf>) -> Self {
        Self::Leaf {
            leaf,
            script: script.into(),
        }
    }

    pub fn hidden(hash: TapNodeHash) -> Self {
        Self::Hidden(hash)
    }

    pub fn branch(children: Vec<TapNodeSpec<L>>) -> Self {
        Self::Branch(children)
    }
}

pub trait IntoDynamicOutput {
    fn into_unspent_txout(
        self,
        amount: Amount,
        internal_key: Option<XOnlyPublicKey>,
        network: Network,
    ) -> UnspentTxOut<String>;
}

impl IntoDynamicOutput for bitcoin::Address {
    fn into_unspent_txout(
        self,
        amount: Amount,
        _internal_key: Option<XOnlyPublicKey>,
        _network: Network,
    ) -> UnspentTxOut<String> {
        UnspentTxOut::from_partial(TxOut {
            value: amount,
            script_pubkey: self.script_pubkey(),
        })
    }
}

impl IntoDynamicOutput for Vec<ScriptNode> {
    fn into_unspent_txout(
        self,
        amount: Amount,
        internal_key: Option<XOnlyPublicKey>,
        network: Network,
    ) -> UnspentTxOut<String> {
        UnspentTxOut::from_scripts(amount, self, internal_key, network)
    }
}

pub fn unspent_txout_from_dynamic_output<T: IntoDynamicOutput>(
    output: T,
    amount: Amount,
    internal_key: Option<XOnlyPublicKey>,
    network: Network,
) -> UnspentTxOut<String> {
    output.into_unspent_txout(amount, internal_key, network)
}

impl<L: Clone> UnspentTxOut<L> {
    pub fn new(
        txout: TxOut,
        scripts: Vec<ScriptNode>,
        named_leaves: Vec<(L, ScriptLeaf)>,
        spend_info: Option<Arc<TaprootSpendInfo>>,
    ) -> Self {
        Self {
            txout,
            taproot: TaprootMeta::new(scripts, named_leaves, spend_info),
        }
    }

    pub fn key_path(amount: Amount, internal_key: Option<XOnlyPublicKey>) -> Self {
        let secp = Secp256k1::verification_only();
        let key = internal_key.unwrap_or_else(unspendable_internal_key);
        let spend_info = TaprootSpendInfo::new_key_spend(&secp, key, None);

        Self::new(
            TxOut {
                value: amount,
                script_pubkey: ScriptBuf::new_p2tr_tweaked(spend_info.output_key()),
            },
            Vec::new(),
            Vec::new(),
            Some(Arc::new(spend_info)),
        )
    }

    /// Build a taproot output from a set of script leaves.
    ///
    /// - `amount`: output value
    /// - `scripts`: the script leaves (order determines leaf indices)
    /// - `internal_key`: the taproot internal key (`None` = unspendable)
    /// - `network`: used for address derivation
    pub fn from_scripts(
        amount: Amount,
        scripts: Vec<ScriptNode>,
        internal_key: Option<XOnlyPublicKey>,
        _network: Network,
    ) -> Self {
        if scripts.is_empty() {
            return Self::key_path(amount, internal_key);
        }

        let secp = Secp256k1::verification_only();
        let key = internal_key.unwrap_or_else(unspendable_internal_key);
        let merkle_tree = build_balanced_taptree(&scripts);

        let spend_info = TaprootSpendInfo::from_node_info(&secp, key, merkle_tree);
        let output_key = spend_info.output_key();
        let script_pubkey = ScriptBuf::new_p2tr_tweaked(output_key);

        Self::new(
            TxOut {
                value: amount,
                script_pubkey,
            },
            scripts,
            Vec::new(),
            Some(Arc::new(spend_info)),
        )
    }

    pub fn from_taptree(
        amount: Amount,
        internal_key: Option<XOnlyPublicKey>,
        tree: Vec<TapNodeSpec<L>>,
    ) -> Self {
        if tree.is_empty() {
            return Self::key_path(amount, internal_key);
        }

        let mut scripts = Vec::new();
        collect_visible_scripts(&tree, &mut scripts);
        let mut named_leaves = Vec::new();
        collect_named_leaves(&tree, &mut named_leaves);

        let secp = Secp256k1::verification_only();
        let key = internal_key.unwrap_or_else(unspendable_internal_key);
        let spend_info = build_taptree(&tree)
            .map(|node| TaprootSpendInfo::from_node_info(&secp, key, node))
            .unwrap_or_else(|| TaprootSpendInfo::new_key_spend(&secp, key, None));

        Self::new(
            TxOut {
                value: amount,
                script_pubkey: ScriptBuf::new_p2tr_tweaked(spend_info.output_key()),
            },
            scripts,
            named_leaves,
            Some(Arc::new(spend_info)),
        )
    }

    pub fn with_named_leaves(mut self, named_leaves: Vec<(L, ScriptLeaf)>) -> Self {
        self.taproot.named_leaves = named_leaves;
        self
    }

    pub fn from_taproot_source(
        amount: Amount,
        source: TaprootOutputSource,
        internal_key: Option<XOnlyPublicKey>,
        network: Network,
    ) -> Self {
        Self::from_scripts(amount, source, internal_key, network)
    }

    /// Wrap a pre-built `TxOut` (e.g. an anchor or OP_RETURN output).
    ///
    /// No taproot spend info is stored.
    pub fn from_partial(txout: TxOut) -> Self {
        Self::new(txout, Vec::new(), Vec::new(), None)
    }

    pub fn txout(&self) -> &TxOut {
        &self.txout
    }

    pub fn txout_mut(&mut self) -> &mut TxOut {
        &mut self.txout
    }

    pub fn scripts(&self) -> &Vec<ScriptNode> {
        self.taproot.scripts()
    }

    pub fn named_leaves(&self) -> &Vec<(L, ScriptLeaf)> {
        self.taproot.named_leaves()
    }

    pub fn spendinfo(&self) -> &Option<Arc<TaprootSpendInfo>> {
        self.taproot.spendinfo()
    }
}

fn collect_visible_scripts<L: Clone>(specs: &[TapNodeSpec<L>], out: &mut Vec<ScriptNode>) {
    for spec in specs {
        match spec {
            TapNodeSpec::Leaf { script, .. } => out.push(script.clone().into()),
            TapNodeSpec::Hidden(_) => {}
            TapNodeSpec::Branch(children) => collect_visible_scripts(children, out),
        }
    }
}

fn collect_named_leaves<L: Clone>(specs: &[TapNodeSpec<L>], out: &mut Vec<(L, ScriptLeaf)>) {
    for spec in specs {
        match spec {
            TapNodeSpec::Leaf { leaf, script } => out.push((leaf.clone(), script.clone())),
            TapNodeSpec::Hidden(_) => {}
            TapNodeSpec::Branch(children) => collect_named_leaves(children, out),
        }
    }
}

fn node_for_spec<L: Clone>(spec: &TapNodeSpec<L>) -> Option<NodeInfo> {
    match spec {
        TapNodeSpec::Leaf { script, .. } => Some(NodeInfo::new_leaf_with_ver(
            script.to_script_buf(),
            LeafVersion::TapScript,
        )),
        TapNodeSpec::Hidden(hash) => Some(NodeInfo::new_hidden_node(*hash)),
        TapNodeSpec::Branch(children) => build_taptree(children),
    }
}

fn build_taptree<L: Clone>(specs: &[TapNodeSpec<L>]) -> Option<NodeInfo> {
    let mut nodes = specs.iter().filter_map(node_for_spec).collect::<Vec<_>>();
    while nodes.len() > 1 {
        let deepest_layer_depth = ((nodes.len() - 1).ilog2() + 1) as u8;
        let num_empty_nodes_in_final_depth = 2_usize.pow(deepest_layer_depth.into()) - nodes.len();
        let num_nodes_in_final_depth = nodes.len() - num_empty_nodes_in_final_depth;

        let mut parents =
            Vec::with_capacity((num_nodes_in_final_depth / 2) + num_empty_nodes_in_final_depth);

        for pair in nodes[..num_nodes_in_final_depth].chunks_exact(2) {
            parents.push(
                NodeInfo::combine(pair[0].clone(), pair[1].clone()).expect("valid taproot tree"),
            );
        }

        parents.extend_from_slice(&nodes[num_nodes_in_final_depth..]);
        nodes = parents;
    }

    nodes.pop()
}

/// Recursively build a balanced binary taproot tree from a slice of scripts.
///
/// Leaf order is preserved: script at index `i` gets leaf index `i`.
fn build_balanced_taptree(scripts: &[ScriptNode]) -> NodeInfo {
    assert!(!scripts.is_empty(), "cannot build an empty taproot tree");

    if scripts.len() == 1 {
        match &scripts[0] {
            ScriptNode::Leaf(leaf) => {
                return NodeInfo::new_leaf_with_ver(leaf.to_script_buf(), LeafVersion::TapScript);
            }
            ScriptNode::Scripts(scripts) => {
                return build_balanced_taptree(scripts.as_slice());
            }
            ScriptNode::TapNodeHash(hash) => {
                return NodeInfo::new_hidden_node(*hash);
            }
        }
    }

    // Split roughly in half: left gets the first ⌈n/2⌉ scripts.
    let mid = scripts.len().div_ceil(2);
    let left = build_balanced_taptree(&scripts[..mid]);
    let right = build_balanced_taptree(&scripts[mid..]);

    NodeInfo::combine(left, right).expect("valid taproot node combination")
}

#[cfg(test)]
mod tests {
    use super::{TapNodeSpec, UnspentTxOut};
    use crate::scripts::OtherSpendable;
    use bitcoin::amount::Amount;
    use bitcoin::script::Builder;
    use bitcoin::taproot::{LeafVersion, TapNodeHash};

    fn script(int: i64) -> bitcoin::ScriptBuf {
        Builder::new().push_int(int).into_script()
    }

    #[test]
    fn key_path_output_builds_spendinfo() {
        let output = UnspentTxOut::<u8>::key_path(Amount::from_sat(10_000), None);

        assert!(output.scripts().is_empty());
        assert!(output.named_leaves().is_empty());
        assert!(output.spendinfo().is_some());
    }

    #[test]
    fn from_taptree_preserves_named_leaves_and_hidden_nodes() {
        let leaf_a = script(1);
        let leaf_b = script(2);
        let hidden = TapNodeHash::assume_hidden([7; 32]);
        let output = UnspentTxOut::from_taptree(
            Amount::from_sat(50_000),
            None,
            vec![
                TapNodeSpec::leaf("a", OtherSpendable::new(leaf_a.clone())),
                TapNodeSpec::branch(vec![
                    TapNodeSpec::leaf("b", OtherSpendable::new(leaf_b.clone())),
                    TapNodeSpec::hidden(hidden),
                ]),
            ],
        );

        assert_eq!(output.scripts().len(), 2);
        assert_eq!(output.named_leaves().len(), 2);

        let spend_info = output.spendinfo().as_ref().expect("spend info present");
        assert!(spend_info
            .script_map()
            .contains_key(&(leaf_a, LeafVersion::TapScript)));
        assert!(spend_info
            .script_map()
            .contains_key(&(leaf_b, LeafVersion::TapScript)));
    }
}
