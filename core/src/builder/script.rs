//! # Script Builder
//!
//! Script builder provides useful functions for building typical Bitcoin
//! scripts.
// Currently generate_witness functions are not yet used.
#![allow(dead_code)]

use crate::EVMAddress;
use bitcoin::hashes::{hash160, Hash};
use bitcoin::opcodes::OP_TRUE;
use bitcoin::script::PushBytesBuf;
use bitcoin::{
    opcodes::{all::*, OP_FALSE},
    script::Builder,
    ScriptBuf, XOnlyPublicKey,
};
use bitcoin::{taproot, Amount, Txid, Witness};
use bitvm::signatures::winternitz::{Parameters, PublicKey, SecretKey};
use std::any::Any;
use std::fmt::Debug;

#[derive(Debug, Copy, Clone)]
pub enum SpendPath {
    ScriptSpend(usize),
    KeySpend,
    Unknown,
}

/// A trait that marks all script types. Each script has a `generate_script_inputs` (eg. [`WinternitzCommit::generate_script_inputs`]) function that
/// generates the witness for the script using various arguments. A `dyn SpendableScript` is cast into a concrete [`ScriptKind`] to
/// generate a witness, the trait object can be used to generate the script_buf.
///
/// We store [`Arc<dyn SpendableScript>`]s inside a [`super::transaction::TxHandler`] input, and we cast them into a [`ScriptKind`] when signing.
///
/// When creating a new Script, make sure you add it to the [`ScriptKind`] enum and add a test for it below.
/// Otherwise, it will not be spendable.
pub trait SpendableScript: Send + Sync + 'static + std::any::Any {
    fn as_any(&self) -> &dyn Any;

    fn kind(&self) -> ScriptKind;

    fn to_script_buf(&self) -> ScriptBuf;
}

impl Debug for dyn SpendableScript {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SpendableScript")
    }
}

/// Struct for scripts that do not conform to any other type of SpendableScripts
#[derive(Debug, Clone)]
pub struct OtherSpendable(ScriptBuf);

impl From<ScriptBuf> for OtherSpendable {
    fn from(script: ScriptBuf) -> Self {
        Self(script)
    }
}

impl SpendableScript for OtherSpendable {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn kind(&self) -> ScriptKind {
        ScriptKind::Other(self)
    }

    fn to_script_buf(&self) -> ScriptBuf {
        self.0.clone()
    }
}

impl OtherSpendable {
    fn as_script(&self) -> &ScriptBuf {
        &self.0
    }

    fn generate_script_inputs(&self, witness: Witness) -> Witness {
        witness
    }

    pub fn new(script: ScriptBuf) -> Self {
        Self(script)
    }
}

/// Struct for scripts that only includes a CHECKSIG
#[derive(Debug, Clone)]
pub struct CheckSig(pub(crate) XOnlyPublicKey);
impl SpendableScript for CheckSig {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn kind(&self) -> ScriptKind {
        ScriptKind::CheckSig(self)
    }

    fn to_script_buf(&self) -> ScriptBuf {
        Builder::new()
            .push_x_only_key(&self.0)
            .push_opcode(OP_CHECKSIG)
            .into_script()
    }
}

impl CheckSig {
    pub fn generate_script_inputs(&self, signature: &taproot::Signature) -> Witness {
        Witness::from_slice(&[signature.serialize()])
    }

    pub fn new(xonly_pk: XOnlyPublicKey) -> Self {
        Self(xonly_pk)
    }
}

/// Struct for scripts that commit to a message using Winternitz keys
/// Contains the Winternitz PK, CheckSig PK, message length respectively
/// can contain multiple different Winternitz public keys for different messages
#[derive(Clone)]
pub struct WinternitzCommit {
    commitments: Vec<(PublicKey, u32)>,
    pub(crate) checksig_pubkey: XOnlyPublicKey,
    log_d: u32,
}

impl SpendableScript for WinternitzCommit {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn kind(&self) -> ScriptKind {
        ScriptKind::WinternitzCommit(self)
    }

    fn to_script_buf(&self) -> ScriptBuf {
        let mut total_script = ScriptBuf::new();
        for (index, (pubkey, _size)) in self.commitments.iter().enumerate() {
            let params = self.get_params(index);
            let a = bitvm::signatures::winternitz_hash::WINTERNITZ_MESSAGE_VERIFIER
                .checksig_verify_and_clear_stack(&params, pubkey);
            total_script.extend(a.compile().instructions().map(|x| x.expect("just created")));
        }

        total_script.push_slice(self.checksig_pubkey.serialize());
        total_script.push_opcode(OP_CHECKSIG);
        total_script
    }
}

impl WinternitzCommit {
    pub fn get_params(&self, index: usize) -> Parameters {
        Parameters::new(self.commitments[index].1, self.log_d)
    }

    pub fn generate_script_inputs(
        &self,
        commit_data: &[(Vec<u8>, SecretKey)],
        signature: &taproot::Signature,
    ) -> Witness {
        let mut witness = Witness::new();
        witness.push(signature.serialize());
        for (index, (data, secret_key)) in commit_data.iter().enumerate().rev() {
            // #[cfg(debug_assertions)]
            // {
            //     let pk = winternitz::generate_public_key(&self.get_params(index), secret_key);
            //     if pk != self.commitments[index].0 {
            //         tracing::error!("Winternitz public key mismatch");
            //     }
            // }
            bitvm::signatures::winternitz_hash::WINTERNITZ_MESSAGE_VERIFIER
                .sign(&self.get_params(index), secret_key, data)
                .into_iter()
                .for_each(|x| witness.push(x));
        }
        witness
    }

    /// commitments is a Vec of winternitz public key and message length tuple
    pub fn new(
        commitments: Vec<(PublicKey, u32)>,
        checksig_pubkey: XOnlyPublicKey,
        log_d: u32,
    ) -> Self {
        Self {
            commitments,
            checksig_pubkey,
            log_d,
        }
    }
}

/// Struct for scripts that include a relative timelock (by block count) and optionally a CHECKSIG if a pubkey is provided.
/// Generates a relative timelock script with a given [`XOnlyPublicKey`] that CHECKSIG checks the signature against.
///
/// ATTENTION: If you want to spend a UTXO using timelock script, the
/// condition is that (`# in the script`) ≤ (`# in the sequence of the tx`)
/// ≤ (`# of blocks mined after UTXO appears on the chain`). However, this is not mandatory.
/// One can spend an output delayed for some number of blocks just by using the nSequence field
/// of the input inside the transaction. For more, see:
///
/// - [BIP-0068](https://github.com/bitcoin/bips/blob/master/bip-0068.mediawiki)
/// - [BIP-0112](https://github.com/bitcoin/bips/blob/master/bip-0112.mediawiki)
#[derive(Debug, Clone)]
pub struct TimelockScript(pub(crate) Option<XOnlyPublicKey>, u16);

impl SpendableScript for TimelockScript {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn kind(&self) -> ScriptKind {
        ScriptKind::TimelockScript(self)
    }

    fn to_script_buf(&self) -> ScriptBuf {
        let script_builder = Builder::new()
            .push_int(self.1 as i64)
            .push_opcode(OP_CSV)
            .push_opcode(OP_DROP);

        if let Some(xonly_pk) = self.0 {
            script_builder
                .push_x_only_key(&xonly_pk)
                .push_opcode(OP_CHECKSIG)
        } else {
            script_builder.push_opcode(OP_TRUE)
        }
        .into_script()
    }
}

impl TimelockScript {
    pub fn generate_script_inputs(&self, signature: Option<&taproot::Signature>) -> Witness {
        match signature {
            Some(sig) => Witness::from_slice(&[sig.serialize()]),
            None => Witness::default(),
        }
    }

    pub fn new(xonly_pk: Option<XOnlyPublicKey>, block_count: u16) -> Self {
        Self(xonly_pk, block_count)
    }
}

/// Struct for scripts that reveal a preimage and verify it against a hash.
pub struct PreimageRevealScript(pub(crate) XOnlyPublicKey, [u8; 20]);

impl SpendableScript for PreimageRevealScript {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn kind(&self) -> ScriptKind {
        ScriptKind::PreimageRevealScript(self)
    }

    fn to_script_buf(&self) -> ScriptBuf {
        Builder::new()
            .push_opcode(OP_HASH160)
            .push_slice(self.1)
            .push_opcode(OP_EQUALVERIFY)
            .push_x_only_key(&self.0)
            .push_opcode(OP_CHECKSIG)
            .into_script()
    }
}

impl PreimageRevealScript {
    pub fn generate_script_inputs(
        &self,
        preimage: impl AsRef<[u8]>,
        signature: &taproot::Signature,
    ) -> Witness {
        let mut witness = Witness::new();
        #[cfg(debug_assertions)]
        assert_eq!(
            hash160::Hash::hash(preimage.as_ref()),
            hash160::Hash::from_byte_array(self.1),
            "Preimage does not match"
        );

        witness.push(signature.serialize());
        witness.push(preimage.as_ref());
        witness
    }

    pub fn new(xonly_pk: XOnlyPublicKey, hash: [u8; 20]) -> Self {
        Self(xonly_pk, hash)
    }
}

/// Struct for deposit script that commits Citrea address to be deposited into onchain.
#[derive(Debug, Clone)]
pub struct BaseDepositScript(pub(crate) XOnlyPublicKey, EVMAddress, Amount);

impl SpendableScript for BaseDepositScript {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn kind(&self) -> ScriptKind {
        ScriptKind::BaseDepositScript(self)
    }

    fn to_script_buf(&self) -> ScriptBuf {
        let citrea: [u8; 6] = "citrea".as_bytes().try_into().expect("length == 6");

        Builder::new()
            .push_x_only_key(&self.0)
            .push_opcode(OP_CHECKSIG)
            .push_opcode(OP_FALSE)
            .push_opcode(OP_IF)
            .push_slice(citrea)
            .push_slice(self.1 .0)
            .push_slice(self.2.to_sat().to_be_bytes())
            .push_opcode(OP_ENDIF)
            .into_script()
    }
}

impl BaseDepositScript {
    pub fn generate_script_inputs(&self, signature: &taproot::Signature) -> Witness {
        Witness::from_slice(&[signature.serialize()])
    }

    pub fn new(nofn_xonly_pk: XOnlyPublicKey, evm_address: EVMAddress, amount: Amount) -> Self {
        Self(nofn_xonly_pk, evm_address, amount)
    }
}

/// Struct for deposit script that replaces an old move tx with a replacement deposit (to update bridge design on chain)
/// It commits to the old move txid inside the script.
#[derive(Debug, Clone)]
pub struct ReplacementDepositScript(pub(crate) XOnlyPublicKey, Txid, Amount);

impl SpendableScript for ReplacementDepositScript {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn kind(&self) -> ScriptKind {
        ScriptKind::ReplacementDepositScript(self)
    }

    fn to_script_buf(&self) -> ScriptBuf {
        let citrea_replace: [u8; 13] = "citreaReplace".as_bytes().try_into().expect("length == 13");

        Builder::new()
            .push_x_only_key(&self.0)
            .push_opcode(OP_CHECKSIG)
            .push_opcode(OP_FALSE)
            .push_opcode(OP_IF)
            .push_slice(citrea_replace)
            .push_slice(self.1.as_byte_array())
            .push_opcode(OP_ENDIF)
            .into_script()
    }
}

impl ReplacementDepositScript {
    pub fn generate_script_inputs(&self, signature: &taproot::Signature) -> Witness {
        Witness::from_slice(&[signature.serialize()])
    }

    pub fn new(nofn_xonly_pk: XOnlyPublicKey, old_move_txid: Txid, amount: Amount) -> Self {
        Self(nofn_xonly_pk, old_move_txid, amount)
    }
}

/// Struct for withdrawal script.
pub struct WithdrawalScript(usize);

impl SpendableScript for WithdrawalScript {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn kind(&self) -> ScriptKind {
        ScriptKind::WithdrawalScript(self)
    }

    fn to_script_buf(&self) -> ScriptBuf {
        let mut push_bytes = PushBytesBuf::new();
        push_bytes
            .extend_from_slice(&crate::utils::usize_to_var_len_bytes(self.0))
            .expect("Not possible to panic while adding a 4 to 8 bytes of slice");

        Builder::new()
            .push_opcode(OP_RETURN)
            .push_slice(push_bytes)
            .into_script()
    }
}

impl WithdrawalScript {
    pub fn new(index: usize) -> Self {
        Self(index)
    }
}

#[derive(Clone)]
pub enum ScriptKind<'a> {
    CheckSig(&'a CheckSig),
    WinternitzCommit(&'a WinternitzCommit),
    TimelockScript(&'a TimelockScript),
    PreimageRevealScript(&'a PreimageRevealScript),
    BaseDepositScript(&'a BaseDepositScript),
    ReplacementDepositScript(&'a ReplacementDepositScript),
    WithdrawalScript(&'a WithdrawalScript),
    Other(&'a OtherSpendable),
}

#[cfg(test)]
fn get_script_from_arr<T: SpendableScript>(
    arr: &Vec<Box<dyn SpendableScript>>,
) -> Option<(usize, &T)> {
    arr.iter()
        .enumerate()
        .find_map(|(i, x)| x.as_any().downcast_ref::<T>().map(|x| (i, x)))
}
#[cfg(test)]
mod tests {
    use crate::actor::{Actor, WinternitzDerivationPath};
    use crate::bitvm_client;
    use crate::config::protocol::ProtocolParamsetName;
    use crate::extended_rpc::ExtendedRpc;
    use std::sync::Arc;

    use super::*;

    use bitcoin::hashes::Hash;
    use bitcoin::secp256k1::PublicKey;
    use bitcoincore_rpc::RpcApi;
    use secp256k1::rand;
    // Create some dummy values for testing.
    // Note: These values are not cryptographically secure and are only used for tests.
    fn dummy_xonly() -> XOnlyPublicKey {
        // 32 bytes array filled with 0x03.
        *bitvm_client::UNSPENDABLE_XONLY_PUBKEY
    }

    fn dummy_scriptbuf() -> ScriptBuf {
        ScriptBuf::from_hex("51").expect("valid hex")
    }

    fn dummy_pubkey() -> PublicKey {
        *bitvm_client::UNSPENDABLE_PUBKEY
    }

    fn dummy_params() -> Parameters {
        Parameters::new(32, 4)
    }

    fn dummy_evm_address() -> EVMAddress {
        // For testing purposes, we use a dummy 20-byte array.
        EVMAddress([0u8; 20])
    }

    #[test]
    fn test_dynamic_casting_extended() {
        // Build a collection of SpendableScript implementations.
        let scripts: Vec<Box<dyn SpendableScript>> = vec![
            Box::new(OtherSpendable::new(dummy_scriptbuf())),
            Box::new(CheckSig::new(dummy_xonly())),
            Box::new(WinternitzCommit::new(
                vec![(vec![[0u8; 20]; 32], 32)],
                dummy_xonly(),
                4,
            )),
            Box::new(TimelockScript::new(Some(dummy_xonly()), 10)),
            Box::new(PreimageRevealScript::new(dummy_xonly(), [0; 20])),
            Box::new(BaseDepositScript::new(
                dummy_xonly(),
                dummy_evm_address(),
                Amount::from_sat(100),
            )),
        ];

        // helper closures that return Option<(usize, &T)> using get_script_from_arr.
        let checksig = get_script_from_arr::<CheckSig>(&scripts);
        let winternitz = get_script_from_arr::<WinternitzCommit>(&scripts);
        let timelock = get_script_from_arr::<TimelockScript>(&scripts);
        let preimage = get_script_from_arr::<PreimageRevealScript>(&scripts);
        let deposit = get_script_from_arr::<BaseDepositScript>(&scripts);
        let others = get_script_from_arr::<OtherSpendable>(&scripts);

        assert!(checksig.is_some(), "CheckSig not found");
        assert!(winternitz.is_some(), "WinternitzCommit not found");
        assert!(timelock.is_some(), "TimelockScript not found");
        assert!(preimage.is_some(), "PreimageRevealScript not found");
        assert!(deposit.is_some(), "DepositScript not found");
        assert!(others.is_some(), "OtherSpendable not found");

        // Print found items.
        println!("CheckSig: {:?}", checksig.unwrap().1);
        // println!("WinternitzCommit: {:?}", winternitz.unwrap().1);
        println!("TimelockScript: {:?}", timelock.unwrap().1);
        // println!("PreimageRevealScript: {:?}", preimage.unwrap().1);
        // println!("DepositScript: {:?}", deposit.unwrap().1);
        println!("OtherSpendable: {:?}", others.unwrap().1);
    }

    #[test]
    fn test_dynamic_casting() {
        use crate::bitvm_client;
        let scripts: Vec<Box<dyn SpendableScript>> = vec![
            Box::new(OtherSpendable(ScriptBuf::from_hex("51").expect(""))),
            Box::new(CheckSig(*bitvm_client::UNSPENDABLE_XONLY_PUBKEY)),
        ];

        let otherspendable = scripts
            .first()
            .expect("")
            .as_any()
            .downcast_ref::<OtherSpendable>()
            .expect("");

        let checksig = get_script_from_arr::<CheckSig>(&scripts).expect("");
        println!("{:?}", otherspendable);
        println!("{:?}", checksig);
    }

    #[test]
    fn test_scriptkind_completeness() {
        let script_variants: Vec<(&str, Arc<dyn SpendableScript>)> = vec![
            ("CheckSig", Arc::new(CheckSig::new(dummy_xonly()))),
            (
                "WinternitzCommit",
                Arc::new(WinternitzCommit::new(
                    vec![(vec![[0u8; 20]; 32], 32)],
                    dummy_xonly(),
                    4,
                )),
            ),
            (
                "TimelockScript",
                Arc::new(TimelockScript::new(Some(dummy_xonly()), 15)),
            ),
            (
                "PreimageRevealScript",
                Arc::new(PreimageRevealScript::new(dummy_xonly(), [1; 20])),
            ),
            (
                "BaseDepositScript",
                Arc::new(BaseDepositScript::new(
                    dummy_xonly(),
                    dummy_evm_address(),
                    Amount::from_sat(50),
                )),
            ),
            (
                "ReplacementDepositScript",
                Arc::new(ReplacementDepositScript::new(
                    dummy_xonly(),
                    Txid::all_zeros(),
                    Amount::from_sat(50),
                )),
            ),
            ("Other", Arc::new(OtherSpendable::new(dummy_scriptbuf()))),
        ];

        for (expected, script) in script_variants {
            let kind = script.kind();
            match (expected, kind) {
                ("CheckSig", ScriptKind::CheckSig(_)) => (),
                ("WinternitzCommit", ScriptKind::WinternitzCommit(_)) => (),
                ("TimelockScript", ScriptKind::TimelockScript(_)) => (),
                ("PreimageRevealScript", ScriptKind::PreimageRevealScript(_)) => (),
                ("BaseDepositScript", ScriptKind::BaseDepositScript(_)) => (),
                ("ReplacementDepositScript", ScriptKind::ReplacementDepositScript(_)) => (),
                ("Other", ScriptKind::Other(_)) => (),
                (s, _) => panic!("ScriptKind conversion not comprehensive for variant: {}", s),
            }
        }
    }
    // Tests for the spendability of all scripts
    use crate::bitvm_client::SECP;
    use crate::builder;
    use crate::builder::transaction::input::SpendableTxIn;
    use crate::builder::transaction::output::UnspentTxOut;
    use crate::builder::transaction::{TransactionType, TxHandlerBuilder, DEFAULT_SEQUENCE};
    use bitcoin::{Amount, Sequence, TxOut, Txid};

    async fn create_taproot_test_tx(
        rpc: &ExtendedRpc,
        scripts: Vec<Arc<dyn SpendableScript>>,
        spend_path: SpendPath,
        amount: Amount,
    ) -> (TxHandlerBuilder, bitcoin::Address) {
        let (address, taproot_spend_info) = builder::address::create_taproot_address(
            &scripts
                .iter()
                .map(|s| s.to_script_buf())
                .collect::<Vec<_>>(),
            None,
            bitcoin::Network::Regtest,
        );

        let outpoint = rpc.send_to_address(&address, amount).await.unwrap();
        let sequence = if let SpendPath::ScriptSpend(idx) = spend_path {
            if let Some(script) = scripts.get(idx) {
                match script.kind() {
                    ScriptKind::TimelockScript(&TimelockScript(_, seq)) => {
                        Sequence::from_height(seq)
                    }
                    _ => DEFAULT_SEQUENCE,
                }
            } else {
                DEFAULT_SEQUENCE
            }
        } else {
            DEFAULT_SEQUENCE
        };
        let mut builder = TxHandlerBuilder::new(TransactionType::Dummy);
        builder = builder.add_input(
            crate::rpc::clementine::NormalSignatureKind::OperatorSighashDefault,
            SpendableTxIn::new(
                outpoint,
                TxOut {
                    value: amount,
                    script_pubkey: address.script_pubkey(),
                },
                scripts.clone(),
                Some(taproot_spend_info.clone()),
            ),
            spend_path,
            sequence,
        );

        builder = builder.add_output(UnspentTxOut::new(
            TxOut {
                value: amount - Amount::from_sat(5000), // Subtract fee
                script_pubkey: address.script_pubkey(),
            },
            scripts,
            Some(taproot_spend_info),
        ));

        (builder, address)
    }

    use crate::test::common::*;

    #[tokio::test]

    async fn test_checksig_spendable() {
        let mut config = create_test_config_with_thread_name().await;
        let regtest = create_regtest_rpc(&mut config).await;
        let rpc = regtest.rpc().clone();

        let kp = bitcoin::secp256k1::Keypair::new(&SECP, &mut rand::thread_rng());
        let xonly_pk = kp.public_key().x_only_public_key().0;

        let scripts: Vec<Arc<dyn SpendableScript>> = vec![Arc::new(CheckSig::new(xonly_pk))];
        let (builder, _) = create_taproot_test_tx(
            &rpc,
            scripts,
            SpendPath::ScriptSpend(0),
            Amount::from_sat(10_000),
        )
        .await;
        let mut tx = builder.finalize();

        // Should be able to sign with the key
        let signer = Actor::new(
            kp.secret_key(),
            Some(bitcoin::secp256k1::SecretKey::new(&mut rand::thread_rng())),
            bitcoin::Network::Regtest,
        );

        signer
            .tx_sign_and_fill_sigs(&mut tx, &[], None)
            .expect("should be able to sign checksig");
        let tx = tx
            .promote()
            .expect("the transaction should be fully signed");

        rpc.client
            .send_raw_transaction(tx.get_cached_tx())
            .await
            .expect("bitcoin RPC did not accept transaction");
    }

    #[tokio::test]
    async fn test_winternitz_commit_spendable() {
        let mut config = create_test_config_with_thread_name().await;
        let regtest = create_regtest_rpc(&mut config).await;
        let rpc = regtest.rpc();

        let kp = bitcoin::secp256k1::Keypair::new(&SECP, &mut rand::thread_rng());
        let xonly_pk = kp.public_key().x_only_public_key().0;

        let derivation = WinternitzDerivationPath::BitvmAssert(
            64,
            3,
            0,
            Txid::all_zeros(),
            ProtocolParamsetName::Regtest.into(),
        );

        let derivation2 = WinternitzDerivationPath::BitvmAssert(
            64,
            2,
            0,
            Txid::all_zeros(),
            ProtocolParamsetName::Regtest.into(),
        );

        let signer = Actor::new(
            kp.secret_key(),
            Some(kp.secret_key()),
            bitcoin::Network::Regtest,
        );

        let script: Arc<dyn SpendableScript> = Arc::new(WinternitzCommit::new(
            vec![
                (
                    signer
                        .derive_winternitz_pk(derivation.clone())
                        .expect("failed to derive Winternitz public key"),
                    64,
                ),
                (
                    signer
                        .derive_winternitz_pk(derivation2.clone())
                        .expect("failed to derive Winternitz public key"),
                    64,
                ),
            ],
            xonly_pk,
            4,
        ));

        let scripts = vec![script];
        let (builder, _) = create_taproot_test_tx(
            rpc,
            scripts,
            SpendPath::ScriptSpend(0),
            Amount::from_sat(10_000),
        )
        .await;
        let mut tx = builder.finalize();

        signer
            .tx_sign_winternitz(
                &mut tx,
                &[
                    (vec![0; 32], derivation.clone()),
                    (vec![0; 32], derivation2.clone()),
                ],
            )
            .expect("failed to partially sign commitments");

        let tx = tx
            .promote()
            .expect("the transaction should be fully signed");

        rpc.client
            .send_raw_transaction(tx.get_cached_tx())
            .await
            .expect("bitcoin RPC did not accept transaction");
    }

    #[tokio::test]
    async fn test_timelock_script_spendable() {
        let mut config = create_test_config_with_thread_name().await;
        let regtest = create_regtest_rpc(&mut config).await;
        let rpc = regtest.rpc();

        let kp = bitcoin::secp256k1::Keypair::new(&SECP, &mut rand::thread_rng());
        let xonly_pk = kp.public_key().x_only_public_key().0;

        let scripts: Vec<Arc<dyn SpendableScript>> =
            vec![Arc::new(TimelockScript::new(Some(xonly_pk), 15))];
        let (builder, _) = create_taproot_test_tx(
            rpc,
            scripts,
            SpendPath::ScriptSpend(0),
            Amount::from_sat(10_000),
        )
        .await;

        let mut tx = builder.finalize();

        let signer = Actor::new(
            kp.secret_key(),
            Some(bitcoin::secp256k1::SecretKey::new(&mut rand::thread_rng())),
            bitcoin::Network::Regtest,
        );

        signer
            .tx_sign_and_fill_sigs(&mut tx, &[], None)
            .expect("should be able to sign timelock");

        rpc.client
            .send_raw_transaction(tx.get_cached_tx())
            .await
            .expect_err("should not pass without 15 blocks");

        rpc.mine_blocks(15).await.expect("failed to mine blocks");

        rpc.client
            .send_raw_transaction(tx.get_cached_tx())
            .await
            .expect("should pass after 15 blocks");
    }

    #[tokio::test]
    async fn test_preimage_reveal_script_spendable() {
        let mut config = create_test_config_with_thread_name().await;
        let regtest = create_regtest_rpc(&mut config).await;
        let rpc = regtest.rpc().clone();
        let kp = bitcoin::secp256k1::Keypair::new(&SECP, &mut rand::thread_rng());
        let xonly_pk = kp.public_key().x_only_public_key().0;

        let preimage = [1; 20];
        let hash = bitcoin::hashes::hash160::Hash::hash(&preimage);
        let script: Arc<dyn SpendableScript> =
            Arc::new(PreimageRevealScript::new(xonly_pk, hash.to_byte_array()));
        let scripts = vec![script];
        let (builder, _) = create_taproot_test_tx(
            &rpc,
            scripts,
            SpendPath::ScriptSpend(0),
            Amount::from_sat(10_000),
        )
        .await;
        let mut tx = builder.finalize();

        let signer = Actor::new(
            kp.secret_key(),
            Some(bitcoin::secp256k1::SecretKey::new(&mut rand::thread_rng())),
            bitcoin::Network::Regtest,
        );

        signer
            .tx_sign_preimage(&mut tx, preimage)
            .expect("failed to sign preimage reveal");

        let final_tx = tx
            .promote()
            .expect("the transaction should be fully signed");

        rpc.client
            .send_raw_transaction(final_tx.get_cached_tx())
            .await
            .expect("bitcoin RPC did not accept transaction");
    }

    #[tokio::test]
    async fn test_base_deposit_script_spendable() {
        let mut config = create_test_config_with_thread_name().await;
        let regtest = create_regtest_rpc(&mut config).await;
        let rpc = regtest.rpc().clone();

        let kp = bitcoin::secp256k1::Keypair::new(&SECP, &mut rand::thread_rng());
        let xonly_pk = kp.public_key().x_only_public_key().0;

        let script: Arc<dyn SpendableScript> = Arc::new(BaseDepositScript::new(
            xonly_pk,
            EVMAddress([2; 20]),
            Amount::from_sat(50),
        ));
        let scripts = vec![script];
        let (builder, _) = create_taproot_test_tx(
            &rpc,
            scripts,
            SpendPath::ScriptSpend(0),
            Amount::from_sat(10_000),
        )
        .await;
        let mut tx = builder.finalize();

        let signer = Actor::new(
            kp.secret_key(),
            Some(bitcoin::secp256k1::SecretKey::new(&mut rand::thread_rng())),
            bitcoin::Network::Regtest,
        );

        signer
            .tx_sign_and_fill_sigs(&mut tx, &[], None)
            .expect("should be able to sign base deposit");

        rpc.client
            .send_raw_transaction(tx.get_cached_tx())
            .await
            .expect("bitcoin RPC did not accept transaction");
    }

    #[tokio::test]
    async fn test_replacement_deposit_script_spendable() {
        let mut config = create_test_config_with_thread_name().await;
        let regtest = create_regtest_rpc(&mut config).await;
        let rpc = regtest.rpc().clone();

        let kp = bitcoin::secp256k1::Keypair::new(&SECP, &mut rand::thread_rng());
        let xonly_pk = kp.public_key().x_only_public_key().0;

        let script: Arc<dyn SpendableScript> = Arc::new(ReplacementDepositScript::new(
            xonly_pk,
            Txid::all_zeros(),
            Amount::from_sat(50),
        ));
        let scripts = vec![script];
        let (builder, _) = create_taproot_test_tx(
            &rpc,
            scripts,
            SpendPath::ScriptSpend(0),
            Amount::from_sat(10_000),
        )
        .await;
        let mut tx = builder.finalize();

        let signer = Actor::new(
            kp.secret_key(),
            Some(bitcoin::secp256k1::SecretKey::new(&mut rand::thread_rng())),
            bitcoin::Network::Regtest,
        );

        signer
            .tx_sign_and_fill_sigs(&mut tx, &[], None)
            .expect("should be able to sign replacement deposit");

        rpc.client
            .send_raw_transaction(tx.get_cached_tx())
            .await
            .expect("bitcoin RPC did not accept transaction");
    }
}
