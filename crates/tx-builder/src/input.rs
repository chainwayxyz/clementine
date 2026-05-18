use bitcoin::taproot::TaprootSpendInfo;
use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, TxIn, TxOut, XOnlyPublicKey};
use std::sync::Arc;

use crate::output::{TaprootMeta, UnspentTxOut};
use crate::script::{flatten_script_bufs, ScriptLeaf, ScriptNode};
use crate::spec::SpendSpec;

/// A spendable transaction input — an outpoint plus the information needed to
/// construct its witness.
#[derive(Debug, Clone)]
pub struct SpendableTxIn<L> {
    /// The outpoint (txid + vout) of the output being spent.
    pub outpoint: OutPoint,
    /// The previous output being spent (value + script_pubkey).
    pub prevout: TxOut,
    /// Taproot witness metadata used when spending this input.
    taproot: TaprootMeta<L>,
}

impl<L: Clone> SpendableTxIn<L> {
    pub fn new_partial(previous_output: OutPoint, prevout: TxOut) -> Self {
        Self::new(previous_output, prevout, vec![], vec![], None)
    }

    pub fn from_output(previous_output: OutPoint, output: &UnspentTxOut<L>) -> Self {
        Self::new(
            previous_output,
            output.txout().clone(),
            output.scripts().clone(),
            output.named_leaves().clone(),
            output.spendinfo().clone(),
        )
    }

    pub fn from_scripts(
        previous_output: OutPoint,
        value: Amount,
        scripts: Vec<ScriptNode>,
        key_path: Option<XOnlyPublicKey>,
        network: bitcoin::Network,
    ) -> Self {
        let output = UnspentTxOut::from_scripts(value, scripts, key_path, network);
        Self::from_output(previous_output, &output)
    }

    pub fn new(
        previous_output: OutPoint,
        prevout: TxOut,
        scripts: Vec<ScriptNode>,
        named_leaves: Vec<(L, ScriptLeaf)>,
        spend_info: Option<Arc<TaprootSpendInfo>>,
    ) -> Self {
        let this = Self {
            outpoint: previous_output,
            prevout,
            taproot: TaprootMeta::new(scripts, named_leaves, spend_info),
        };
        if cfg!(debug_assertions) {
            this.check()
                .unwrap_or_else(|msg| panic!("invalid SpendableTxIn: {msg}"));
        }
        this
    }

    pub fn get_prevout(&self) -> &TxOut {
        &self.prevout
    }

    pub fn get_prevout_mut(&mut self) -> &mut TxOut {
        &mut self.prevout
    }

    pub fn get_prev_outpoint(&self) -> &OutPoint {
        &self.outpoint
    }

    pub fn get_scripts(&self) -> &Vec<ScriptNode> {
        self.taproot.scripts()
    }

    pub fn get_named_leaves(&self) -> &Vec<(L, ScriptLeaf)> {
        self.taproot.named_leaves()
    }

    pub fn get_named_leaf_script(&self, leaf: impl Into<L>) -> Option<&ScriptLeaf>
    where
        L: PartialEq,
    {
        let leaf = leaf.into();
        self.taproot
            .named_leaves()
            .iter()
            .find_map(|(candidate, script)| (candidate == &leaf).then_some(script))
    }

    pub fn get_spend_info(&self) -> &Option<Arc<TaprootSpendInfo>> {
        self.taproot.spendinfo()
    }

    fn check(&self) -> Result<(), String> {
        if self.taproot.spendinfo().is_none() {
            if !self.taproot.scripts().is_empty() || !self.taproot.named_leaves().is_empty() {
                return Err("taproot scripts or named leaves require spend info".to_string());
            }
            return Ok(());
        }

        let Some(spend_info) = self.taproot.spendinfo().as_ref() else {
            return Ok(());
        };
        let visible_scripts = flatten_script_bufs(self.taproot.scripts());

        if ScriptBuf::new_p2tr_tweaked(spend_info.output_key()) != self.prevout.script_pubkey {
            return Err("script_pubkey does not match taproot spend info".to_string());
        }

        for script in &visible_scripts {
            if spend_info
                .script_map()
                .get(&(script.clone(), bitcoin::taproot::LeafVersion::TapScript))
                .is_none()
            {
                return Err("spend info is missing a script leaf proof".to_string());
            }
        }

        for (_, named_leaf) in self.taproot.named_leaves() {
            let script = named_leaf.to_script_buf();
            if !visible_scripts.iter().any(|candidate| candidate == &script) {
                return Err("named leaf script is not present in script tree".to_string());
            }

            if spend_info
                .script_map()
                .get(&(script, bitcoin::taproot::LeafVersion::TapScript))
                .is_none()
            {
                return Err("named leaf is missing a script leaf proof".to_string());
            }
        }

        Ok(())
    }
}

pub(crate) fn debug_validate_spend_for_spendable<
    Leaf: Clone + std::fmt::Debug + PartialEq,
    Actor: Clone,
>(
    spend: &SpendSpec<Leaf, Actor>,
    spendable: &SpendableTxIn<Leaf>,
) -> Result<(), String> {
    match spend {
        SpendSpec::KeySpend { .. } => Ok(()),
        SpendSpec::NamedLeaf { leaf, .. } => {
            if spendable.get_named_leaf_script(leaf.clone()).is_none() {
                return Err(format!(
                    "named leaf {leaf:?} is not available on spendable input"
                ));
            }

            if spendable.get_spend_info().is_none() {
                return Err(format!(
                    "named leaf {leaf:?} requires taproot spend info on spendable input"
                ));
            }

            Ok(())
        }
        SpendSpec::RevealRequired { .. } => {
            if spendable.get_spend_info().is_none() {
                return Err(
                    "RevealRequired inputs require taproot spend info on spendable input"
                        .to_string(),
                );
            }

            Ok(())
        }
    }
}

#[derive(Debug, Clone)]
pub struct ResolvedInput<Input, Leaf, Actor> {
    id: Input,
    spendable: SpendableTxIn<Leaf>,
    sequence: Sequence,
    spend: SpendSpec<Leaf, Actor>,
}

impl<Input, Leaf: Clone, Actor: Clone> ResolvedInput<Input, Leaf, Actor> {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: Input,
        spendable: SpendableTxIn<Leaf>,
        sequence: Sequence,
        spend: SpendSpec<Leaf, Actor>,
    ) -> Self {
        Self {
            id,
            spendable,
            sequence,
            spend,
        }
    }

    pub fn id(&self) -> &Input {
        &self.id
    }

    pub fn spendable(&self) -> &SpendableTxIn<Leaf> {
        &self.spendable
    }

    pub fn owner(&self) -> Option<Actor> {
        self.spend.actor().cloned()
    }

    pub fn sighash_type(&self) -> Option<bitcoin::TapSighashType> {
        self.spend.sighash_type()
    }

    pub fn spend(&self) -> &SpendSpec<Leaf, Actor> {
        &self.spend
    }

    pub fn leaf(&self) -> Option<Leaf> {
        self.spend.leaf().cloned()
    }

    pub fn to_txin(&self) -> TxIn {
        TxIn {
            previous_output: *self.spendable.get_prev_outpoint(),
            sequence: self.sequence,
            script_sig: bitcoin::ScriptBuf::default(),
            witness: bitcoin::Witness::default(),
        }
    }
}

pub fn bound_to_usize<T>(value: T) -> usize
where
    T: TryInto<usize>,
    T::Error: std::fmt::Debug,
{
    value
        .try_into()
        .expect("dynamic family bound must be convertible to usize")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::output::TaprootMeta;
    use crate::scripts::CheckSig;
    use bitcoin::amount::Amount;
    use bitcoin::hashes::Hash;
    use bitcoin::secp256k1::{Keypair, Secp256k1, SecretKey, XOnlyPublicKey};
    use bitcoin::{Network, Txid};

    fn xonly(seed: u8) -> XOnlyPublicKey {
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&[seed; 32]).expect("valid secret key bytes");
        let keypair = Keypair::from_secret_key(&secp, &sk);
        XOnlyPublicKey::from_keypair(&keypair).0
    }

    #[test]
    fn spendable_check_rejects_named_leaf_outside_script_tree() {
        let output = UnspentTxOut::<u8>::from_scripts(
            Amount::from_sat(10_000),
            vec![CheckSig::new(xonly(1)).into()],
            None,
            Network::Regtest,
        );
        let spendable = SpendableTxIn {
            outpoint: OutPoint::new(Txid::from_slice(&[1; 32]).expect("valid txid"), 0),
            prevout: output.txout().clone(),
            taproot: TaprootMeta::new(
                output.scripts().clone(),
                vec![(0, CheckSig::new(xonly(2)).into())],
                output.spendinfo().clone(),
            ),
        };

        let err = spendable
            .check()
            .expect_err("named leaf outside the visible script tree should fail");
        assert!(err.contains("named leaf script is not present"));
    }

    #[test]
    fn spendable_check_rejects_taproot_metadata_without_spend_info() {
        let spendable = SpendableTxIn {
            outpoint: OutPoint::new(Txid::from_slice(&[2; 32]).expect("valid txid"), 0),
            prevout: TxOut {
                value: Amount::from_sat(10_000),
                script_pubkey: ScriptBuf::new(),
            },
            taproot: TaprootMeta::new(
                vec![CheckSig::new(xonly(3)).into()],
                vec![(0, CheckSig::new(xonly(3)).into())],
                None,
            ),
        };

        let err = spendable
            .check()
            .expect_err("taproot metadata without spend info should fail");
        assert!(err.contains("require spend info"));
    }
}
