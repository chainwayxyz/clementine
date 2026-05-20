use std::marker::PhantomData;

#[derive(Debug, Clone)]
pub struct TxSpec<Input, Output> {
    pub version: bitcoin::transaction::Version,
    pub lock_time: bitcoin::absolute::LockTime,
    pub inputs: Vec<Input>,
    pub outputs: Vec<Output>,
}

impl<Input, Output> TxSpec<Input, Output> {
    pub fn new(
        version: bitcoin::transaction::Version,
        lock_time: bitcoin::absolute::LockTime,
        inputs: Vec<Input>,
        outputs: Vec<Output>,
    ) -> Self {
        Self {
            version,
            lock_time,
            inputs,
            outputs,
        }
    }
}

impl<Input, Output> TxSpec<Input, Output>
where
    Output: PartialEq,
{
    pub fn output_index(&self, output: &Output) -> Option<usize> {
        self.outputs
            .iter()
            .position(|candidate| candidate == output)
    }
}

#[derive(Debug, Clone)]
pub enum InputSource<TxType, Vout, External> {
    ParentOutput { tx_type: TxType, vout: Vout },
    External(External),
}

#[derive(Debug, Clone)]
pub enum SpendSpec<Leaf, Actor = ()> {
    KeySpend {
        actor: Option<Actor>,
        sighash_type: Option<bitcoin::TapSighashType>,
    },
    NamedLeaf {
        leaf: Leaf,
        actor: Option<Actor>,
        sighash_type: Option<bitcoin::TapSighashType>,
    },
    RevealRequired {
        actor: Option<Actor>,
        sighash_type: Option<bitcoin::TapSighashType>,
    },
}

impl<Leaf, Actor> SpendSpec<Leaf, Actor> {
    pub fn key_spend() -> Self {
        Self::KeySpend {
            actor: None,
            sighash_type: None,
        }
    }

    pub fn named_leaf(leaf: Leaf) -> Self {
        Self::NamedLeaf {
            leaf,
            actor: None,
            sighash_type: None,
        }
    }

    pub fn reveal_required() -> Self {
        Self::RevealRequired {
            actor: None,
            sighash_type: None,
        }
    }

    pub fn key(actor: Actor, sighash_type: bitcoin::TapSighashType) -> Self {
        Self::key_spend().with_metadata(Some(actor), Some(sighash_type))
    }

    pub fn named_leaf_with(
        leaf: impl Into<Leaf>,
        actor: Actor,
        sighash_type: bitcoin::TapSighashType,
    ) -> Self {
        Self::named_leaf(leaf.into()).with_metadata(Some(actor), Some(sighash_type))
    }

    pub fn with_metadata(
        self,
        actor: Option<Actor>,
        sighash_type: Option<bitcoin::TapSighashType>,
    ) -> Self {
        match self {
            Self::KeySpend { .. } => Self::KeySpend {
                actor,
                sighash_type,
            },
            Self::NamedLeaf { leaf, .. } => Self::NamedLeaf {
                leaf,
                actor,
                sighash_type,
            },
            Self::RevealRequired { .. } => Self::RevealRequired {
                actor,
                sighash_type,
            },
        }
    }

    pub fn actor(&self) -> Option<&Actor> {
        match self {
            Self::KeySpend { actor, .. }
            | Self::NamedLeaf { actor, .. }
            | Self::RevealRequired { actor, .. } => actor.as_ref(),
        }
    }

    pub fn sighash_type(&self) -> Option<bitcoin::TapSighashType> {
        match self {
            Self::KeySpend { sighash_type, .. }
            | Self::NamedLeaf { sighash_type, .. }
            | Self::RevealRequired { sighash_type, .. } => *sighash_type,
        }
    }

    pub fn leaf(&self) -> Option<&Leaf> {
        match self {
            Self::NamedLeaf { leaf, .. } => Some(leaf),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct InputSpec<TxType, Vout, External, Leaf, Actor, Sequence> {
    pub source: InputSource<TxType, Vout, External>,
    pub spend: SpendSpec<Leaf, Actor>,
    pub sequence: Sequence,
}

#[derive(Debug, Clone)]
pub struct InputSpecBuilder<TxType, Vout, External, Leaf, Actor, Sequence> {
    source: InputSource<TxType, Vout, External>,
    sequence: Sequence,
    marker: PhantomData<fn() -> (Leaf, Actor)>,
}

impl<TxType, Vout, External, Leaf, Actor, Sequence>
    InputSpec<TxType, Vout, External, Leaf, Actor, Sequence>
{
    pub fn new(
        source: InputSource<TxType, Vout, External>,
        spend: SpendSpec<Leaf, Actor>,
        sequence: Sequence,
    ) -> Self {
        Self {
            source,
            spend,
            sequence,
        }
    }

    pub fn parent(
        tx_type: TxType,
        vout: impl Into<Vout>,
        sequence: Sequence,
    ) -> InputSpecBuilder<TxType, Vout, External, Leaf, Actor, Sequence> {
        InputSpecBuilder {
            source: InputSource::ParentOutput {
                tx_type,
                vout: vout.into(),
            },
            sequence,
            marker: PhantomData,
        }
    }

    pub fn external(
        external: impl Into<External>,
        sequence: Sequence,
    ) -> InputSpecBuilder<TxType, Vout, External, Leaf, Actor, Sequence> {
        InputSpecBuilder {
            source: InputSource::External(external.into()),
            sequence,
            marker: PhantomData,
        }
    }
}

impl<TxType, Vout, External, Leaf, Actor, Sequence>
    InputSpecBuilder<TxType, Vout, External, Leaf, Actor, Sequence>
{
    pub fn sequence(mut self, sequence: Sequence) -> Self {
        self.sequence = sequence;
        self
    }

    pub fn key_path(
        self,
        actor: Actor,
        sighash_type: bitcoin::TapSighashType,
    ) -> InputSpec<TxType, Vout, External, Leaf, Actor, Sequence> {
        self.key_path_with(Some(actor), sighash_type)
    }

    pub fn key_path_with(
        self,
        actor: Option<Actor>,
        sighash_type: bitcoin::TapSighashType,
    ) -> InputSpec<TxType, Vout, External, Leaf, Actor, Sequence> {
        InputSpec::new(
            self.source,
            SpendSpec::key_spend().with_metadata(actor, Some(sighash_type)),
            self.sequence,
        )
    }

    pub fn leaf(
        self,
        leaf: impl Into<Leaf>,
        actor: Actor,
        sighash_type: bitcoin::TapSighashType,
    ) -> InputSpec<TxType, Vout, External, Leaf, Actor, Sequence> {
        InputSpec::new(
            self.source,
            SpendSpec::named_leaf_with(leaf, actor, sighash_type),
            self.sequence,
        )
    }

    pub fn reveal(self) -> InputSpec<TxType, Vout, External, Leaf, Actor, Sequence> {
        InputSpec::new(
            self.source,
            SpendSpec::reveal_required().with_metadata(None, None),
            self.sequence,
        )
    }

    pub fn reveal_with(
        self,
        actor: Actor,
        sighash_type: bitcoin::TapSighashType,
    ) -> InputSpec<TxType, Vout, External, Leaf, Actor, Sequence> {
        InputSpec::new(
            self.source,
            SpendSpec::reveal_required().with_metadata(Some(actor), Some(sighash_type)),
            self.sequence,
        )
    }
}
