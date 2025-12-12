//! This module defines the data structures related to Citrea deposits in the Clementine bridge.
//!
//! It includes structures for representing deposit data, actors involved (verifiers, watchtowers, operators),
//! and security council configurations. The module also provides functionality for managing different types
//! of deposits (base and replacement) and deriving the necessary scripts these deposits must have.

use std::collections::HashSet;
use std::sync::Arc;

use crate::builder::script::{
    BaseDepositScript, Multisig, ReplacementDepositScript, SpendableScript, TimelockScript,
};
use crate::builder::transaction::create_move_to_vault_txhandler;
use crate::config::protocol::ProtocolParamset;
use clementine_errors::BridgeError;
use crate::musig2::AggregateFromPublicKeys;
use crate::operator::RoundIndex;
use crate::utils::ScriptBufExt;
use crate::EVMAddress;
use bitcoin::address::NetworkUnchecked;
use bitcoin::secp256k1::PublicKey;
use bitcoin::{Address, OutPoint, Txid, XOnlyPublicKey};
use eyre::Context;

/// Data structure to represent a single kickoff utxo in an operators round tx.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize, Ord, PartialOrd,
)]
pub struct KickoffData {
    pub operator_xonly_pk: XOnlyPublicKey,
    pub round_idx: RoundIndex,
    pub kickoff_idx: u32,
}

/// Data structure to represent a deposit.
/// - nofn_xonly_pk is cached to avoid recomputing it each time.
/// - deposit includes the actual information about the deposit.
/// - actors includes the public keys of the actors that will participate in the deposit.
/// - security_council includes the public keys of the security council that can unlock the deposit to create a replacement deposit in case a bug is found in the bridge.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, Eq)]
pub struct DepositData {
    /// Cached nofn xonly public key used for deposit.
    pub nofn_xonly_pk: Option<XOnlyPublicKey>,
    pub deposit: DepositInfo,
    pub actors: Actors,
    pub security_council: SecurityCouncil,
}

impl PartialEq for DepositData {
    fn eq(&self, other: &Self) -> bool {
        // nofn_xonly_pk only depends on verifiers pk's so it can be ignored as verifiers are already compared
        // for security council, order of keys matter as it will change the m of n multisig script,
        // thus change the scriptpubkey of move to vault tx
        self.security_council == other.security_council
            && self.deposit.deposit_outpoint == other.deposit.deposit_outpoint
            // for watchtowers/verifiers/operators, order doesn't matter, we compare sorted lists
            // get() functions already return sorted lists
            && self.get_operators() == other.get_operators()
            && self.get_verifiers() == other.get_verifiers()
            && self.get_watchtowers() == other.get_watchtowers()
            && self.deposit.deposit_type == other.deposit.deposit_type
    }
}

impl DepositData {
    /// Returns the move to vault txid of the deposit.
    pub fn get_move_txid(
        &mut self,
        paramset: &'static ProtocolParamset,
    ) -> Result<Txid, BridgeError> {
        Ok(*create_move_to_vault_txhandler(self, paramset)?.get_txid())
    }
}

/// Data structure to represent the deposit outpoint and type.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct DepositInfo {
    pub deposit_outpoint: OutPoint,
    pub deposit_type: DepositType,
}

/// Type to represent the type of deposit, and related specific data for each type..
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub enum DepositType {
    BaseDeposit(BaseDepositData),
    ReplacementDeposit(ReplacementDepositData),
}

impl DepositData {
    /// Returns the outpoint of the deposit.
    pub fn get_deposit_outpoint(&self) -> OutPoint {
        self.deposit.deposit_outpoint
    }
    /// Returns the nofn xonly public key of the deposit. It is additionally cached to avoid recomputing it each time.
    pub fn get_nofn_xonly_pk(&mut self) -> Result<XOnlyPublicKey, BridgeError> {
        if let Some(pk) = self.nofn_xonly_pk {
            return Ok(pk);
        }
        let verifiers = self.get_verifiers();
        let nofn_xonly_pk = bitcoin::XOnlyPublicKey::from_musig2_pks(verifiers, None)?;
        self.nofn_xonly_pk = Some(nofn_xonly_pk);
        Ok(nofn_xonly_pk)
    }
    /// Returns the number of verifiers in the deposit.
    pub fn get_num_verifiers(&self) -> usize {
        self.actors.verifiers.len()
    }
    /// Returns the number of watchtowers in the deposit.
    pub fn get_num_watchtowers(&self) -> usize {
        self.get_num_verifiers() + self.actors.watchtowers.len()
    }
    /// Returns the index of a verifier in the deposit, in the sorted order of verifiers pk.
    pub fn get_verifier_index(&self, public_key: &PublicKey) -> Result<usize, eyre::Report> {
        self.get_verifiers()
            .iter()
            .position(|pk| pk == public_key)
            .ok_or_else(|| eyre::eyre!("Verifier with public key {} not found", public_key))
    }
    /// Returns the index of a watchtower in the deposit, in the sorted order of watchtowers pk.
    pub fn get_watchtower_index(&self, xonly_pk: &XOnlyPublicKey) -> Result<usize, eyre::Report> {
        self.get_watchtowers()
            .iter()
            .position(|pk| pk == xonly_pk)
            .ok_or_else(|| eyre::eyre!("Watchtower with xonly key {} not found", xonly_pk))
    }
    /// Returns the index of an operator in the deposit, in the sorted order of operators pk.
    pub fn get_operator_index(&self, xonly_pk: XOnlyPublicKey) -> Result<usize, eyre::Report> {
        self.get_operators()
            .iter()
            .position(|pk| pk == &xonly_pk)
            .ok_or_else(|| eyre::eyre!("Operator with xonly key {} not found", xonly_pk))
    }
    /// Returns sorted verifiers, they are sorted so that their order is deterministic.
    pub fn get_verifiers(&self) -> Vec<PublicKey> {
        let mut verifiers = self.actors.verifiers.clone();
        verifiers.sort();

        verifiers
    }
    /// Returns sorted watchtowers, they are sorted so that their order is deterministic.
    /// It is very important for watchtowers to be sorted, as this is the order the watchtower challenge utxo's will be
    /// in the kickoff tx. So any change in order will change the kickoff txid's.
    pub fn get_watchtowers(&self) -> Vec<XOnlyPublicKey> {
        let mut watchtowers = self
            .actors
            .verifiers
            .iter()
            .map(|pk| pk.x_only_public_key().0)
            .collect::<Vec<_>>();
        watchtowers.extend(self.actors.watchtowers.iter());
        watchtowers.sort();
        watchtowers
    }
    /// Returns sorted operators, they are sorted so that their order is deterministic.
    pub fn get_operators(&self) -> Vec<XOnlyPublicKey> {
        let mut operators = self.actors.operators.clone();
        operators.sort();
        operators
    }
    /// Returns the number of operators in the deposit.
    pub fn get_num_operators(&self) -> usize {
        self.actors.operators.len()
    }
    /// Returns the scripts a taproot address of a deposit_outpoint must have to spend the deposit.
    /// Deposits not having these scripts and corresponding taproot address should be rejected.
    pub fn get_deposit_scripts(
        &mut self,
        paramset: &'static ProtocolParamset,
    ) -> Result<Vec<Arc<dyn SpendableScript>>, BridgeError> {
        let nofn_xonly_pk = self.get_nofn_xonly_pk()?;

        match &mut self.deposit.deposit_type {
            DepositType::BaseDeposit(original_deposit_data) => {
                let deposit_script = Arc::new(BaseDepositScript::new(
                    nofn_xonly_pk,
                    original_deposit_data.evm_address,
                ));

                let recovery_script_pubkey = original_deposit_data
                    .recovery_taproot_address
                    .clone()
                    .assume_checked()
                    .script_pubkey();

                let recovery_extracted_xonly_pk = recovery_script_pubkey
                    .try_get_taproot_pk()
                    .wrap_err("Recovery taproot address is not a valid taproot address")?;

                let script_timelock = Arc::new(TimelockScript::new(
                    Some(recovery_extracted_xonly_pk),
                    paramset.user_takes_after,
                ));

                Ok(vec![deposit_script, script_timelock])
            }
            DepositType::ReplacementDeposit(replacement_deposit_data) => {
                let deposit_script: Arc<dyn SpendableScript> =
                    Arc::new(ReplacementDepositScript::new(
                        nofn_xonly_pk,
                        replacement_deposit_data.old_move_txid,
                    ));
                let security_council_script: Arc<dyn SpendableScript> = Arc::new(
                    Multisig::from_security_council(self.security_council.clone()),
                );

                Ok(vec![deposit_script, security_council_script])
            }
        }
    }

    /// Checks if all verifiers are unique.
    pub fn are_all_verifiers_unique(&self) -> bool {
        let set: HashSet<_> = self.actors.verifiers.iter().collect();
        set.len() == self.actors.verifiers.len()
    }

    /// Checks if all watchtowers are unique.
    pub fn are_all_watchtowers_unique(&self) -> bool {
        let set: HashSet<_> = self.get_watchtowers().into_iter().collect();
        set.len() == self.get_num_watchtowers()
    }

    /// Checks if all operators are unique.
    pub fn are_all_operators_unique(&self) -> bool {
        let set: HashSet<_> = self.actors.operators.iter().collect();
        set.len() == self.actors.operators.len()
    }
}

/// Data structure to represent the actors public keys that participate in the deposit.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct Actors {
    /// Public keys of verifiers that will participate in the deposit.
    pub verifiers: Vec<PublicKey>,
    /// X-only public keys of watchtowers that will participate in the deposit.
    /// NOTE: verifiers are automatically considered watchtowers. This field is only for additional watchtowers.
    pub watchtowers: Vec<XOnlyPublicKey>,
    /// X-only public keys of operators that will participate in the deposit.
    pub operators: Vec<XOnlyPublicKey>,
}

/// Data structure to represent the security council that can unlock the deposit using an m-of-n multisig to create a replacement deposit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecurityCouncil {
    pub pks: Vec<XOnlyPublicKey>,
    pub threshold: u32,
}

impl std::str::FromStr for SecurityCouncil {
    type Err = eyre::Report;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut parts = s.split(':');
        let threshold_str = parts
            .next()
            .ok_or_else(|| eyre::eyre!("Missing threshold"))?;
        let pks_str = parts
            .next()
            .ok_or_else(|| eyre::eyre!("Missing public keys"))?;

        if parts.next().is_some() {
            return Err(eyre::eyre!("Too many parts in security council string"));
        }

        let threshold = threshold_str
            .parse::<u32>()
            .map_err(|e| eyre::eyre!("Invalid threshold: {}", e))?;

        let pks: Result<Vec<XOnlyPublicKey>, _> = pks_str
            .split(',')
            .map(|pk_str| {
                let bytes = hex::decode(pk_str)
                    .map_err(|e| eyre::eyre!("Invalid hex in public key: {}", e))?;
                XOnlyPublicKey::from_slice(&bytes)
                    .map_err(|e| eyre::eyre!("Invalid public key: {}", e))
            })
            .collect();

        let pks = pks?;

        if pks.is_empty() {
            return Err(eyre::eyre!("No public keys provided"));
        }

        if threshold > pks.len() as u32 {
            return Err(eyre::eyre!(
                "Threshold cannot be greater than number of public keys"
            ));
        }

        Ok(SecurityCouncil { pks, threshold })
    }
}

impl serde::Serialize for SecurityCouncil {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> serde::Deserialize<'de> for SecurityCouncil {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

impl std::fmt::Display for SecurityCouncil {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:", self.threshold)?;
        let pks_str = self
            .pks
            .iter()
            .map(|pk| hex::encode(pk.serialize()))
            .collect::<Vec<_>>()
            .join(",");
        write!(f, "{pks_str}")
    }
}

/// Data structure to represent the data for a base deposit. These kinds of deposits are created by users.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct BaseDepositData {
    /// User's EVM address.
    pub evm_address: EVMAddress,
    /// User's recovery taproot address.
    pub recovery_taproot_address: bitcoin::Address<NetworkUnchecked>,
}

/// Data structure to represent the data for a replacement deposit. These kinds of deposits are created by the bridge, using
/// security council to unlock the previous deposit and move the funds to create a new deposit. Verifiers will sign the new deposit again.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ReplacementDepositData {
    /// old move_to_vault txid that was replaced
    pub old_move_txid: Txid,
}

/// Data structure to represent the data for an operator. These data is used in the tx creation so any deviation will change the tx's
/// created by the bridge.
#[derive(Debug, Clone, serde::Serialize, PartialEq, Eq)]
pub struct OperatorData {
    pub xonly_pk: XOnlyPublicKey,
    pub reimburse_addr: Address,
    pub collateral_funding_outpoint: OutPoint,
}

impl<'de> serde::Deserialize<'de> for OperatorData {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(serde::Deserialize)]
        struct OperatorDataHelper {
            xonly_pk: XOnlyPublicKey,
            reimburse_addr: Address<NetworkUnchecked>,
            collateral_funding_outpoint: OutPoint,
        }

        let helper = OperatorDataHelper::deserialize(deserializer)?;

        Ok(OperatorData {
            xonly_pk: helper.xonly_pk,
            reimburse_addr: helper.reimburse_addr.assume_checked(),
            collateral_funding_outpoint: helper.collateral_funding_outpoint,
        })
    }
}
