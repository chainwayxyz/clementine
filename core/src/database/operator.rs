//! # Operator Related Database Operations
//!
//! This module includes database functions which are mainly used by an operator.

use super::{
    wrapper::{
        AddressDB, DepositParamsDB, OutPointDB, ReceiptDB, SignaturesDB, TxidDB, XOnlyPublicKeyDB,
    },
    Database, DatabaseTransaction,
};
use crate::{
    builder::transaction::create_move_to_vault_txhandler,
    config::protocol::ProtocolParamset,
    deposit::{DepositData, KickoffData, OperatorData},
    operator::RoundIndex,
};
use crate::{
    errors::BridgeError,
    execute_query_with_tx,
    operator::PublicHash,
    rpc::clementine::{DepositSignatures, TaggedSignature},
};
use bitcoin::{OutPoint, Txid, XOnlyPublicKey};
use bitvm::signatures::winternitz;
use bitvm::signatures::winternitz::PublicKey as WinternitzPublicKey;
use eyre::{eyre, Context};
use risc0_zkvm::Receipt;
use std::str::FromStr;

pub type RootHash = [u8; 32];
//pub type PublicInputWots = Vec<[u8; 20]>;
pub type AssertTxHash = Vec<[u8; 32]>;

pub type BitvmSetup = (AssertTxHash, RootHash, RootHash);

impl Database {
    /// Sets the operator details to the db.
    /// This function additionally checks if the operator data already exists in the db.
    /// As we don't want to overwrite operator data on the db, as it can prevent us slash malicious operators that signed
    /// previous deposits. This function should give an error if an operator changed its data.
    pub async fn insert_operator_if_not_exists(
        &self,
        mut tx: Option<DatabaseTransaction<'_, '_>>,
        xonly_pubkey: XOnlyPublicKey,
        wallet_address: &bitcoin::Address,
        collateral_funding_outpoint: OutPoint,
    ) -> Result<(), BridgeError> {
        let query = sqlx::query(
            "INSERT INTO operators (xonly_pk, wallet_reimburse_address, collateral_funding_outpoint)
             VALUES ($1, $2, $3)
             ON CONFLICT (xonly_pk) DO NOTHING",
        )
        .bind(XOnlyPublicKeyDB(xonly_pubkey))
        .bind(AddressDB(wallet_address.as_unchecked().clone()))
        .bind(OutPointDB(collateral_funding_outpoint));

        let result = execute_query_with_tx!(self.connection, tx.as_deref_mut(), query, execute)?;

        // If no rows were affected, data already exists - check if it matches
        if result.rows_affected() == 0 {
            let existing = self.get_operator(tx, xonly_pubkey).await?;
            if let Some(op) = existing {
                if op.reimburse_addr != *wallet_address
                    || op.collateral_funding_outpoint != collateral_funding_outpoint
                {
                    return Err(BridgeError::OperatorDataMismatch(xonly_pubkey));
                }
            }
        }

        Ok(())
    }

    pub async fn get_operators(
        &self,
        tx: Option<DatabaseTransaction<'_, '_>>,
    ) -> Result<Vec<(XOnlyPublicKey, bitcoin::Address, OutPoint)>, BridgeError> {
        let query = sqlx::query_as(
            "SELECT xonly_pk, wallet_reimburse_address, collateral_funding_outpoint FROM operators;"
        );

        let operators: Vec<(XOnlyPublicKeyDB, AddressDB, OutPointDB)> =
            execute_query_with_tx!(self.connection, tx, query, fetch_all)?;

        // Convert the result to the desired format
        let data = operators
            .into_iter()
            .map(|(pk, addr, outpoint_db)| {
                let xonly_pk = pk.0;
                let addr = addr.0.assume_checked();
                let outpoint = outpoint_db.0; // Extract the Txid from TxidDB
                Ok((xonly_pk, addr, outpoint))
            })
            .collect::<Result<Vec<_>, BridgeError>>()?;
        Ok(data)
    }

    pub async fn get_operator(
        &self,
        tx: Option<DatabaseTransaction<'_, '_>>,
        operator_xonly_pk: XOnlyPublicKey,
    ) -> Result<Option<OperatorData>, BridgeError> {
        let query = sqlx::query_as(
            "SELECT xonly_pk, wallet_reimburse_address, collateral_funding_outpoint FROM operators WHERE xonly_pk = $1;"
        ).bind(XOnlyPublicKeyDB(operator_xonly_pk));

        let result: Option<(String, String, OutPointDB)> =
            execute_query_with_tx!(self.connection, tx, query, fetch_optional)?;

        match result {
            None => Ok(None),
            Some((_, addr, outpoint_db)) => {
                // Convert the result to the desired format
                let addr = bitcoin::Address::from_str(&addr)
                    .wrap_err("Invalid Address")?
                    .assume_checked();
                let outpoint = outpoint_db.0; // Extract the Txid from TxidDB
                Ok(Some(OperatorData {
                    xonly_pk: operator_xonly_pk,
                    reimburse_addr: addr,
                    collateral_funding_outpoint: outpoint,
                }))
            }
        }
    }

    /// Sets the unspent kickoff sigs received from operators during initial setup.
    /// Sigs of each round are stored together in the same row.
    /// On conflict, do not update the existing sigs. Although technically, as long as kickoff winternitz keys
    /// and operator data(collateral funding outpoint and reimburse address) are not changed, the sigs are still valid
    /// even if they are changed.
    pub async fn insert_unspent_kickoff_sigs_if_not_exist(
        &self,
        tx: Option<DatabaseTransaction<'_, '_>>,
        operator_xonly_pk: XOnlyPublicKey,
        round_idx: RoundIndex,
        signatures: Vec<TaggedSignature>,
    ) -> Result<(), BridgeError> {
        let query = sqlx::query(
            "INSERT INTO unspent_kickoff_signatures (xonly_pk, round_idx, signatures) VALUES ($1, $2, $3)
             ON CONFLICT (xonly_pk, round_idx) DO NOTHING;",
        ).bind(XOnlyPublicKeyDB(operator_xonly_pk)).bind(round_idx.to_index() as i32).bind(SignaturesDB(DepositSignatures{signatures}));

        execute_query_with_tx!(self.connection, tx, query, execute)?;
        Ok(())
    }

    /// Get unspent kickoff sigs for a specific operator and round.
    pub async fn get_unspent_kickoff_sigs(
        &self,
        tx: Option<DatabaseTransaction<'_, '_>>,
        operator_xonly_pk: XOnlyPublicKey,
        round_idx: RoundIndex,
    ) -> Result<Option<Vec<TaggedSignature>>, BridgeError> {
        let query = sqlx::query_as::<_, (SignaturesDB,)>("SELECT signatures FROM unspent_kickoff_signatures WHERE xonly_pk = $1 AND round_idx = $2")
            .bind(XOnlyPublicKeyDB(operator_xonly_pk))
            .bind(round_idx.to_index() as i32);

        let result: Result<(SignaturesDB,), sqlx::Error> =
            execute_query_with_tx!(self.connection, tx, query, fetch_one);

        match result {
            Ok((SignaturesDB(signatures),)) => Ok(Some(signatures.signatures)),
            Err(sqlx::Error::RowNotFound) => Ok(None),
            Err(e) => Err(BridgeError::DatabaseError(e)),
        }
    }

    /// Sets Winternitz public keys for bitvm related inputs of an operator.
    pub async fn insert_operator_bitvm_keys_if_not_exist(
        &self,
        mut tx: Option<DatabaseTransaction<'_, '_>>,
        operator_xonly_pk: XOnlyPublicKey,
        deposit_outpoint: OutPoint,
        winternitz_public_key: Vec<WinternitzPublicKey>,
    ) -> Result<(), BridgeError> {
        let wpk = borsh::to_vec(&winternitz_public_key).wrap_err(BridgeError::BorshError)?;
        let deposit_id = self
            .get_deposit_id(tx.as_deref_mut(), deposit_outpoint)
            .await?;
        let query = sqlx::query(
                "INSERT INTO operator_bitvm_winternitz_public_keys (xonly_pk, deposit_id, bitvm_winternitz_public_keys) VALUES ($1, $2, $3)
                ON CONFLICT DO NOTHING;",
            )
            .bind(XOnlyPublicKeyDB(operator_xonly_pk))
            .bind(i32::try_from(deposit_id).wrap_err("Failed to convert deposit id to i32")?)
            .bind(wpk);

        execute_query_with_tx!(self.connection, tx, query, execute)?;

        Ok(())
    }

    /// Gets Winternitz public keys for bitvm related inputs of an operator.
    pub async fn get_operator_bitvm_keys(
        &self,
        mut tx: Option<DatabaseTransaction<'_, '_>>,
        operator_xonly_pk: XOnlyPublicKey,
        deposit_outpoint: OutPoint,
    ) -> Result<Vec<winternitz::PublicKey>, BridgeError> {
        let deposit_id = self
            .get_deposit_id(tx.as_deref_mut(), deposit_outpoint)
            .await?;
        let query = sqlx::query_as(
                "SELECT bitvm_winternitz_public_keys FROM operator_bitvm_winternitz_public_keys WHERE xonly_pk = $1 AND deposit_id = $2;"
            )
            .bind(XOnlyPublicKeyDB(operator_xonly_pk))
            .bind(i32::try_from(deposit_id).wrap_err("Failed to convert deposit id to i32")?);

        let winternitz_pks: (Vec<u8>,) =
            execute_query_with_tx!(self.connection, tx, query, fetch_one)?;

        {
            let operator_winternitz_pks: Vec<winternitz::PublicKey> =
                borsh::from_slice(&winternitz_pks.0).wrap_err(BridgeError::BorshError)?;
            Ok(operator_winternitz_pks)
        }
    }

    /// Sets Winternitz public keys (only for kickoff blockhash commit) for an operator.
    /// On conflict, do not update the existing keys. This is very important, as otherwise the txids of
    /// operators round tx's will change.
    pub async fn insert_operator_kickoff_winternitz_public_keys_if_not_exist(
        &self,
        mut tx: Option<DatabaseTransaction<'_, '_>>,
        operator_xonly_pk: XOnlyPublicKey,
        winternitz_public_key: Vec<WinternitzPublicKey>,
    ) -> Result<(), BridgeError> {
        let wpk = borsh::to_vec(&winternitz_public_key).wrap_err(BridgeError::BorshError)?;

        let query = sqlx::query(
            "INSERT INTO operator_winternitz_public_keys (xonly_pk, winternitz_public_keys)
             VALUES ($1, $2)
             ON CONFLICT (xonly_pk) DO NOTHING",
        )
        .bind(XOnlyPublicKeyDB(operator_xonly_pk))
        .bind(wpk);

        let result = execute_query_with_tx!(self.connection, tx.as_deref_mut(), query, execute)?;

        // If no rows were affected, data already exists - check if it matches
        if result.rows_affected() == 0 {
            let existing = self
                .get_operator_kickoff_winternitz_public_keys(tx, operator_xonly_pk)
                .await?;
            if existing != winternitz_public_key {
                return Err(BridgeError::OperatorWinternitzPublicKeysMismatch(
                    operator_xonly_pk,
                ));
            }
        }

        Ok(())
    }

    /// Gets Winternitz public keys for every sequential collateral tx of an
    /// operator and a watchtower.
    pub async fn get_operator_kickoff_winternitz_public_keys(
        &self,
        tx: Option<DatabaseTransaction<'_, '_>>,
        op_xonly_pk: XOnlyPublicKey,
    ) -> Result<Vec<winternitz::PublicKey>, BridgeError> {
        let query = sqlx::query_as(
                "SELECT winternitz_public_keys FROM operator_winternitz_public_keys WHERE xonly_pk = $1;",
            )
            .bind(XOnlyPublicKeyDB(op_xonly_pk));

        let wpks: (Vec<u8>,) = execute_query_with_tx!(self.connection, tx, query, fetch_one)?;

        let operator_winternitz_pks: Vec<winternitz::PublicKey> =
            borsh::from_slice(&wpks.0).wrap_err(BridgeError::BorshError)?;

        Ok(operator_winternitz_pks)
    }

    /// Sets public hashes for a specific operator, sequential collateral tx and
    /// kickoff index combination. If there is hashes for given indexes, they
    /// will be overwritten by the new hashes.
    pub async fn insert_operator_challenge_ack_hashes_if_not_exist(
        &self,
        mut tx: Option<DatabaseTransaction<'_, '_>>,
        operator_xonly_pk: XOnlyPublicKey,
        deposit_outpoint: OutPoint,
        public_hashes: &Vec<[u8; 20]>,
    ) -> Result<(), BridgeError> {
        let deposit_id = self
            .get_deposit_id(tx.as_deref_mut(), deposit_outpoint)
            .await?;
        let query = sqlx::query(
            "INSERT INTO operators_challenge_ack_hashes (xonly_pk, deposit_id, public_hashes)
             VALUES ($1, $2, $3)
             ON CONFLICT (xonly_pk, deposit_id) DO NOTHING;",
        )
        .bind(XOnlyPublicKeyDB(operator_xonly_pk))
        .bind(i32::try_from(deposit_id).wrap_err("Failed to convert deposit id to i32")?)
        .bind(public_hashes);

        let result = execute_query_with_tx!(self.connection, tx.as_deref_mut(), query, execute)?;

        // If no rows were affected, data already exists - check if it matches
        if result.rows_affected() == 0 {
            let existing = self
                .get_operators_challenge_ack_hashes(tx, operator_xonly_pk, deposit_outpoint)
                .await?;
            if let Some(existing_hashes) = existing {
                if existing_hashes != *public_hashes {
                    return Err(BridgeError::OperatorChallengeAckHashesMismatch(
                        operator_xonly_pk,
                        deposit_outpoint,
                    ));
                }
            }
        }

        Ok(())
    }

    /// Retrieves public hashes for a specific operator, sequential collateral
    /// tx and kickoff index combination.
    pub async fn get_operators_challenge_ack_hashes(
        &self,
        mut tx: Option<DatabaseTransaction<'_, '_>>,
        operator_xonly_pk: XOnlyPublicKey,
        deposit_outpoint: OutPoint,
    ) -> Result<Option<Vec<PublicHash>>, BridgeError> {
        let deposit_id = self
            .get_deposit_id(tx.as_deref_mut(), deposit_outpoint)
            .await?;
        let query = sqlx::query_as::<_, (Vec<Vec<u8>>,)>(
            "SELECT public_hashes
            FROM operators_challenge_ack_hashes
            WHERE xonly_pk = $1 AND deposit_id = $2;",
        )
        .bind(XOnlyPublicKeyDB(operator_xonly_pk))
        .bind(i32::try_from(deposit_id).wrap_err("Failed to convert deposit id to i32")?);

        let result = execute_query_with_tx!(self.connection, tx, query, fetch_optional)?;

        match result {
            Some((public_hashes,)) => {
                let mut converted_hashes = Vec::new();
                for hash in public_hashes {
                    match hash.try_into() {
                        Ok(public_hash) => converted_hashes.push(public_hash),
                        Err(err) => {
                            tracing::error!("Failed to convert hash: {:?}", err);
                            return Err(eyre::eyre!("Failed to convert public hash").into());
                        }
                    }
                }
                Ok(Some(converted_hashes))
            }
            None => Ok(None), // If no result is found, return Ok(None)
        }
    }

    /// Saves deposit infos, and returns the deposit_id
    /// This function additionally checks if the deposit data already exists in the db.
    /// As we don't want to overwrite deposit data on the db, this function should give an error if deposit data is changed.
    pub async fn insert_deposit_data_if_not_exists(
        &self,
        mut tx: Option<DatabaseTransaction<'_, '_>>,
        deposit_data: &mut DepositData,
        paramset: &'static ProtocolParamset,
    ) -> Result<u32, BridgeError> {
        // compute move to vault txid
        let move_to_vault_txid = create_move_to_vault_txhandler(deposit_data, paramset)?
            .get_cached_tx()
            .compute_txid();

        let query = sqlx::query_as::<_, (i32,)>(
            "INSERT INTO deposits (deposit_outpoint, deposit_params, move_to_vault_txid)
                VALUES ($1, $2, $3)
                ON CONFLICT (deposit_outpoint) DO NOTHING
                RETURNING deposit_id",
        )
        .bind(OutPointDB(deposit_data.get_deposit_outpoint()))
        .bind(DepositParamsDB(deposit_data.clone().into()))
        .bind(TxidDB(move_to_vault_txid));

        let result =
            execute_query_with_tx!(self.connection, tx.as_deref_mut(), query, fetch_optional)?;

        // If we got a deposit_id back, that means we successfully inserted new data
        if let Some((deposit_id,)) = result {
            return Ok(u32::try_from(deposit_id).wrap_err("Failed to convert deposit id to u32")?);
        }

        // If no rows were returned, data already exists - check if it matches
        let existing_query = sqlx::query_as::<_, (i32, DepositParamsDB, TxidDB)>(
            "SELECT deposit_id, deposit_params, move_to_vault_txid FROM deposits WHERE deposit_outpoint = $1"
        )
        .bind(OutPointDB(deposit_data.get_deposit_outpoint()));

        let (existing_deposit_id, existing_deposit_params, existing_move_txid): (
            i32,
            DepositParamsDB,
            TxidDB,
        ) = execute_query_with_tx!(self.connection, tx, existing_query, fetch_one)?;

        let existing_deposit_data: DepositData = existing_deposit_params
            .0
            .try_into()
            .map_err(|e| eyre::eyre!("Invalid deposit params {e}"))?;

        if existing_deposit_data != *deposit_data {
            tracing::error!(
                "Deposit data mismatch: Existing {:?}, New {:?}",
                existing_deposit_data,
                deposit_data
            );
            return Err(BridgeError::DepositDataMismatch(
                deposit_data.get_deposit_outpoint(),
            ));
        }

        if existing_move_txid.0 != move_to_vault_txid {
            // This should never happen, only a sanity check
            tracing::error!(
                "Move to vault txid mismatch in set_deposit_data: Existing {:?}, New {:?}",
                existing_move_txid.0,
                move_to_vault_txid
            );
            return Err(BridgeError::DepositDataMismatch(
                deposit_data.get_deposit_outpoint(),
            ));
        }

        // If data matches, return the existing deposit_id
        Ok(u32::try_from(existing_deposit_id).wrap_err("Failed to convert deposit id to u32")?)
    }

    pub async fn get_deposit_data_with_move_tx(
        &self,
        tx: Option<DatabaseTransaction<'_, '_>>,
        move_to_vault_txid: Txid,
    ) -> Result<Option<DepositData>, BridgeError> {
        let query = sqlx::query_as::<_, (DepositParamsDB,)>(
            "SELECT deposit_params FROM deposits WHERE move_to_vault_txid = $1;",
        )
        .bind(TxidDB(move_to_vault_txid));

        let result: Option<(DepositParamsDB,)> =
            execute_query_with_tx!(self.connection, tx, query, fetch_optional)?;

        match result {
            Some((deposit_params,)) => Ok(Some(
                deposit_params
                    .0
                    .try_into()
                    .map_err(|e| eyre::eyre!("Invalid deposit params {e}"))?,
            )),
            None => Ok(None),
        }
    }

    pub async fn get_deposit_data(
        &self,
        tx: Option<DatabaseTransaction<'_, '_>>,
        deposit_outpoint: OutPoint,
    ) -> Result<Option<(u32, DepositData)>, BridgeError> {
        let query = sqlx::query_as(
            "SELECT deposit_id, deposit_params FROM deposits WHERE deposit_outpoint = $1;",
        )
        .bind(OutPointDB(deposit_outpoint));

        let result: Option<(i32, DepositParamsDB)> =
            execute_query_with_tx!(self.connection, tx, query, fetch_optional)?;

        match result {
            Some((deposit_id, deposit_params)) => Ok(Some((
                u32::try_from(deposit_id).wrap_err("Failed to convert deposit id to u32")?,
                deposit_params
                    .0
                    .try_into()
                    .map_err(|e| eyre::eyre!("Invalid deposit params {e}"))?,
            ))),
            None => Ok(None),
        }
    }

    /// Saves the deposit signatures to the database for a single operator.
    /// The signatures array is identified by the deposit_outpoint and operator_idx.
    /// For the order of signatures, please check [`crate::builder::sighash::create_nofn_sighash_stream`]
    /// which determines the order of the sighashes that are signed.
    #[allow(clippy::too_many_arguments)]
    pub async fn insert_deposit_signatures_if_not_exist(
        &self,
        mut tx: Option<DatabaseTransaction<'_, '_>>,
        deposit_outpoint: OutPoint,
        operator_xonly_pk: XOnlyPublicKey,
        round_idx: RoundIndex,
        kickoff_idx: usize,
        kickoff_txid: Txid,
        signatures: Vec<TaggedSignature>,
    ) -> Result<(), BridgeError> {
        let deposit_id = self
            .get_deposit_id(tx.as_deref_mut(), deposit_outpoint)
            .await?;

        // First check if the entry already exists.
        let query = sqlx::query_as(
            "SELECT kickoff_txid FROM deposit_signatures
        WHERE deposit_id = $1 AND operator_xonly_pk = $2 AND round_idx = $3 AND kickoff_idx = $4;",
        )
        .bind(i32::try_from(deposit_id).wrap_err("Failed to convert deposit id to i32")?)
        .bind(XOnlyPublicKeyDB(operator_xonly_pk))
        .bind(round_idx.to_index() as i32)
        .bind(kickoff_idx as i32);
        let txid_and_signatures: Option<(TxidDB,)> =
            execute_query_with_tx!(self.connection, tx.as_deref_mut(), query, fetch_optional)?;

        if let Some((existing_kickoff_txid,)) = txid_and_signatures {
            if existing_kickoff_txid.0 == kickoff_txid {
                return Ok(());
            } else {
                return Err(eyre!("Kickoff txid or signatures already set!").into());
            }
        }
        // On conflict, the previous signatures are already valid. Signatures only depend on deposit_outpoint (which depends on nofn pk) and
        // operator_xonly_pk (also depends on nofn_pk, as each operator is also a verifier and nofn_pk depends on verifiers pk)
        // Additionally operator collateral outpoint and reimbursement addr should be unchanged which we ensure in relevant db fns.
        // We add on conflict clause so it doesn't fail if the signatures are already set.
        // Why do we need to do this? If deposit fails somehow just at the end because movetx
        // signature fails to be collected, we might need to do a deposit again. Technically we can only collect movetx signature, not
        // do the full deposit.

        let query = sqlx::query(
            "INSERT INTO deposit_signatures (deposit_id, operator_xonly_pk, round_idx, kickoff_idx, kickoff_txid, signatures)
            VALUES ($1, $2, $3, $4, $5, $6)
            ON CONFLICT DO NOTHING;"
        )
        .bind(i32::try_from(deposit_id).wrap_err("Failed to convert deposit id to i32")?)
        .bind(XOnlyPublicKeyDB(operator_xonly_pk))
        .bind(round_idx.to_index() as i32)
        .bind(kickoff_idx as i32)
        .bind(TxidDB(kickoff_txid))
        .bind(SignaturesDB(DepositSignatures{signatures: signatures.clone()}));

        execute_query_with_tx!(self.connection, tx, query, execute)?;

        Ok(())
    }

    /// Gets a unique int for a deposit outpoint
    pub async fn get_deposit_id(
        &self,
        tx: Option<DatabaseTransaction<'_, '_>>,
        deposit_outpoint: OutPoint,
    ) -> Result<u32, BridgeError> {
        let query = sqlx::query_as(
            r#"
            WITH existing AS (
                SELECT deposit_id
                FROM deposits
                WHERE deposit_outpoint = $1
            ),
            inserted AS (
                INSERT INTO deposits (deposit_outpoint)
                SELECT $1
                WHERE NOT EXISTS (SELECT 1 FROM existing)
                RETURNING deposit_id
            )
            SELECT deposit_id FROM inserted
            UNION
            SELECT deposit_id FROM existing
            LIMIT 1;
            "#,
        )
        .bind(OutPointDB(deposit_outpoint));

        let deposit_id: Result<(i32,), sqlx::Error> =
            execute_query_with_tx!(self.connection, tx, query, fetch_one);
        Ok(u32::try_from(deposit_id?.0).wrap_err("Failed to convert deposit id to u32")?)
    }

    /// For a given kickoff txid, get the deposit outpoint that corresponds to it
    pub async fn get_deposit_outpoint_for_kickoff_txid(
        &self,
        tx: Option<DatabaseTransaction<'_, '_>>,
        kickoff_txid: Txid,
    ) -> Result<OutPoint, BridgeError> {
        let query = sqlx::query_as::<_, (OutPointDB,)>(
            "SELECT d.deposit_outpoint FROM deposit_signatures ds
             INNER JOIN deposits d ON d.deposit_id = ds.deposit_id
             WHERE ds.kickoff_txid = $1;",
        )
        .bind(TxidDB(kickoff_txid));
        let result: (OutPointDB,) = execute_query_with_tx!(self.connection, tx, query, fetch_one)?;
        Ok(result.0 .0)
    }

    /// Retrieves the deposit signatures for a single operator for a single reimburse
    /// process (single kickoff utxo).
    /// The signatures are tagged so that each signature can be matched with the correct
    /// txin it belongs to easily.
    pub async fn get_deposit_signatures(
        &self,
        tx: Option<DatabaseTransaction<'_, '_>>,
        deposit_outpoint: OutPoint,
        operator_xonly_pk: XOnlyPublicKey,
        round_idx: RoundIndex,
        kickoff_idx: usize,
    ) -> Result<Option<Vec<TaggedSignature>>, BridgeError> {
        let query = sqlx::query_as::<_, (SignaturesDB,)>(
            "SELECT ds.signatures FROM deposit_signatures ds
                    INNER JOIN deposits d ON d.deposit_id = ds.deposit_id
                 WHERE d.deposit_outpoint = $1
                 AND ds.operator_xonly_pk = $2
                 AND ds.round_idx = $3
                 AND ds.kickoff_idx = $4;",
        )
        .bind(OutPointDB(deposit_outpoint))
        .bind(XOnlyPublicKeyDB(operator_xonly_pk))
        .bind(round_idx.to_index() as i32)
        .bind(kickoff_idx as i32);

        let result: Result<(SignaturesDB,), sqlx::Error> =
            execute_query_with_tx!(self.connection, tx, query, fetch_one);

        match result {
            Ok((SignaturesDB(signatures),)) => Ok(Some(signatures.signatures)),
            Err(sqlx::Error::RowNotFound) => Ok(None),
            Err(e) => Err(BridgeError::DatabaseError(e)),
        }
    }

    /// Retrieves the light client proof for a deposit to be used while sending an assert.
    pub async fn get_lcp_for_assert(
        &self,
        tx: Option<DatabaseTransaction<'_, '_>>,
        deposit_id: u32,
    ) -> Result<Option<Receipt>, BridgeError> {
        let query = sqlx::query_as::<_, (ReceiptDB,)>(
            "SELECT lcp_receipt FROM lcp_for_asserts WHERE deposit_id = $1;",
        )
        .bind(i32::try_from(deposit_id).wrap_err("Failed to convert deposit id to i32")?);

        let result = execute_query_with_tx!(self.connection, tx, query, fetch_optional)?;

        Ok(result.map(|(lcp,)| lcp.0))
    }

    /// Saves the light client proof for a deposit to be used while sending an assert.
    /// We save first before sending kickoff to be sure we have the LCP available if we need to assert.
    pub async fn insert_lcp_for_assert(
        &self,
        tx: Option<DatabaseTransaction<'_, '_>>,
        deposit_id: u32,
        lcp: Receipt,
    ) -> Result<(), BridgeError> {
        let query = sqlx::query(
            "INSERT INTO lcp_for_asserts (deposit_id, lcp_receipt)
             VALUES ($1, $2)
             ON CONFLICT (deposit_id) DO NOTHING;",
        )
        .bind(i32::try_from(deposit_id).wrap_err("Failed to convert deposit id to i32")?)
        .bind(ReceiptDB(lcp));

        execute_query_with_tx!(self.connection, tx, query, execute)?;

        Ok(())
    }

    pub async fn get_deposit_data_with_kickoff_txid(
        &self,
        tx: Option<DatabaseTransaction<'_, '_>>,
        kickoff_txid: Txid,
    ) -> Result<Option<(DepositData, KickoffData)>, BridgeError> {
        let query = sqlx::query_as::<_, (DepositParamsDB, XOnlyPublicKeyDB, i32, i32)>(
            "SELECT d.deposit_params, ds.operator_xonly_pk, ds.round_idx, ds.kickoff_idx
             FROM deposit_signatures ds
             INNER JOIN deposits d ON d.deposit_id = ds.deposit_id
             WHERE ds.kickoff_txid = $1;",
        )
        .bind(TxidDB(kickoff_txid));

        let result = execute_query_with_tx!(self.connection, tx, query, fetch_optional)?;

        match result {
            Some((deposit_params, operator_xonly_pk, round_idx, kickoff_idx)) => Ok(Some((
                deposit_params
                    .0
                    .try_into()
                    .wrap_err("Can't convert deposit params")?,
                KickoffData {
                    operator_xonly_pk: operator_xonly_pk.0,
                    round_idx: RoundIndex::from_index(
                        usize::try_from(round_idx)
                            .wrap_err("Failed to convert round idx to usize")?,
                    ),
                    kickoff_idx: u32::try_from(kickoff_idx)
                        .wrap_err("Failed to convert kickoff idx to u32")?,
                },
            ))),
            None => Ok(None),
        }
    }

    /// Sets BitVM setup data for a specific operator and deposit combination.
    /// This function additionally checks if the BitVM setup data already exists in the db.
    /// As we don't want to overwrite BitVM setup data on the db, as maliciously overwriting
    /// can prevent us to regenerate previously signed kickoff tx's.
    pub async fn insert_bitvm_setup_if_not_exists(
        &self,
        mut tx: Option<DatabaseTransaction<'_, '_>>,
        operator_xonly_pk: XOnlyPublicKey,
        deposit_outpoint: OutPoint,
        assert_tx_addrs: impl AsRef<[[u8; 32]]>,
        root_hash: &[u8; 32],
        latest_blockhash_root_hash: &[u8; 32],
    ) -> Result<(), BridgeError> {
        let deposit_id = self
            .get_deposit_id(tx.as_deref_mut(), deposit_outpoint)
            .await?;

        let query = sqlx::query(
            "INSERT INTO bitvm_setups (xonly_pk, deposit_id, assert_tx_addrs, root_hash, latest_blockhash_root_hash)
             VALUES ($1, $2, $3, $4, $5)
             ON CONFLICT (xonly_pk, deposit_id) DO NOTHING;",
        )
        .bind(XOnlyPublicKeyDB(operator_xonly_pk))
        .bind(i32::try_from(deposit_id).wrap_err("Failed to convert deposit id to i32")?)
        .bind(
            assert_tx_addrs
                .as_ref()
                .iter()
                .map(|addr| addr.as_ref())
                .collect::<Vec<&[u8]>>(),
        )
        .bind(root_hash.to_vec())
        .bind(latest_blockhash_root_hash.to_vec());

        let result = execute_query_with_tx!(self.connection, tx.as_deref_mut(), query, execute)?;

        // If no rows were affected, data already exists - check if it matches
        if result.rows_affected() == 0 {
            let existing = self
                .get_bitvm_setup(tx, operator_xonly_pk, deposit_outpoint)
                .await?;
            if let Some((existing_addrs, existing_root, existing_blockhash)) = existing {
                let new_addrs = assert_tx_addrs.as_ref();
                if existing_addrs != new_addrs
                    || existing_root != *root_hash
                    || existing_blockhash != *latest_blockhash_root_hash
                {
                    return Err(BridgeError::BitvmSetupDataMismatch(
                        operator_xonly_pk,
                        deposit_outpoint,
                    ));
                }
            }
        }

        Ok(())
    }

    /// Retrieves BitVM setup data for a specific operator, sequential collateral tx and kickoff index combination
    pub async fn get_bitvm_setup(
        &self,
        mut tx: Option<DatabaseTransaction<'_, '_>>,
        operator_xonly_pk: XOnlyPublicKey,
        deposit_outpoint: OutPoint,
    ) -> Result<Option<BitvmSetup>, BridgeError> {
        let deposit_id = self
            .get_deposit_id(tx.as_deref_mut(), deposit_outpoint)
            .await?;
        let query = sqlx::query_as::<_, (Vec<Vec<u8>>, Vec<u8>, Vec<u8>)>(
            "SELECT assert_tx_addrs, root_hash, latest_blockhash_root_hash
             FROM bitvm_setups
             WHERE xonly_pk = $1 AND deposit_id = $2;",
        )
        .bind(XOnlyPublicKeyDB(operator_xonly_pk))
        .bind(i32::try_from(deposit_id).wrap_err("Failed to convert deposit id to i32")?);

        let result = execute_query_with_tx!(self.connection, tx, query, fetch_optional)?;

        match result {
            Some((assert_tx_addrs, root_hash, latest_blockhash_root_hash)) => {
                // Convert root_hash Vec<u8> back to [u8; 32]
                let root_hash_array: [u8; 32] = root_hash
                    .try_into()
                    .map_err(|_| eyre::eyre!("root_hash must be 32 bytes"))?;
                let latest_blockhash_root_hash_array: [u8; 32] = latest_blockhash_root_hash
                    .try_into()
                    .map_err(|_| eyre::eyre!("latest_blockhash_root_hash must be 32 bytes"))?;

                let assert_tx_addrs: Vec<[u8; 32]> = assert_tx_addrs
                    .into_iter()
                    .map(|addr| {
                        let mut addr_array = [0u8; 32];
                        addr_array.copy_from_slice(&addr);
                        addr_array
                    })
                    .collect();

                Ok(Some((
                    assert_tx_addrs,
                    root_hash_array,
                    latest_blockhash_root_hash_array,
                )))
            }
            None => Ok(None),
        }
    }

    pub async fn mark_kickoff_connector_as_used(
        &self,
        tx: Option<DatabaseTransaction<'_, '_>>,
        round_idx: RoundIndex,
        kickoff_connector_idx: u32,
        kickoff_txid: Option<Txid>,
    ) -> Result<(), BridgeError> {
        let query = sqlx::query(
            "INSERT INTO used_kickoff_connectors (round_idx, kickoff_connector_idx, kickoff_txid)
             VALUES ($1, $2, $3)
             ON CONFLICT (round_idx, kickoff_connector_idx) DO NOTHING;",
        )
        .bind(round_idx.to_index() as i32)
        .bind(
            i32::try_from(kickoff_connector_idx)
                .wrap_err("Failed to convert kickoff connector idx to i32")?,
        )
        .bind(kickoff_txid.map(TxidDB));

        execute_query_with_tx!(self.connection, tx, query, execute)?;

        Ok(())
    }

    pub async fn get_kickoff_connector_for_kickoff_txid(
        &self,
        tx: Option<DatabaseTransaction<'_, '_>>,
        kickoff_txid: Txid,
    ) -> Result<(RoundIndex, u32), BridgeError> {
        let query = sqlx::query_as::<_, (i32, i32)>(
            "SELECT round_idx, kickoff_connector_idx FROM used_kickoff_connectors WHERE kickoff_txid = $1;",
        )
        .bind(TxidDB(kickoff_txid));

        let result: (i32, i32) = execute_query_with_tx!(self.connection, tx, query, fetch_one)?;
        Ok((
            RoundIndex::from_index(
                result
                    .0
                    .try_into()
                    .wrap_err(BridgeError::IntConversionError)?,
            ),
            result
                .1
                .try_into()
                .wrap_err(BridgeError::IntConversionError)?,
        ))
    }

    pub async fn get_kickoff_txid_for_used_kickoff_connector(
        &self,
        tx: Option<DatabaseTransaction<'_, '_>>,
        round_idx: RoundIndex,
        kickoff_connector_idx: u32,
    ) -> Result<Option<Txid>, BridgeError> {
        let query = sqlx::query_as::<_, (Option<TxidDB>,)>(
            "SELECT kickoff_txid FROM used_kickoff_connectors WHERE round_idx = $1 AND kickoff_connector_idx = $2;",
        )
        .bind(round_idx.to_index() as i32)
        .bind(i32::try_from(kickoff_connector_idx).wrap_err("Failed to convert kickoff connector idx to i32")?);

        let result = execute_query_with_tx!(self.connection, tx, query, fetch_optional)?;

        match result {
            Some((txid,)) => Ok(txid.map(|txid| txid.0)),
            None => Ok(None),
        }
    }

    pub async fn get_unused_and_signed_kickoff_connector(
        &self,
        tx: Option<DatabaseTransaction<'_, '_>>,
        deposit_id: u32,
        operator_xonly_pk: XOnlyPublicKey,
    ) -> Result<Option<(RoundIndex, u32)>, BridgeError> {
        let query = sqlx::query_as::<_, (i32, i32)>(
            "WITH current_round AS (
                    SELECT round_idx
                    FROM current_round_index
                    WHERE id = 1
                )
                SELECT
                    ds.round_idx as round_idx,
                    ds.kickoff_idx as kickoff_connector_idx
                FROM deposit_signatures ds
                CROSS JOIN current_round cr
                WHERE ds.deposit_id = $1  -- Parameter for deposit_id
                    AND ds.operator_xonly_pk = $2
                    AND ds.round_idx >= cr.round_idx
                    AND NOT EXISTS (
                        SELECT 1
                        FROM used_kickoff_connectors ukc
                        WHERE ukc.round_idx = ds.round_idx
                        AND ukc.kickoff_connector_idx = ds.kickoff_idx
                    )
                ORDER BY ds.round_idx ASC
                LIMIT 1;",
        )
        .bind(i32::try_from(deposit_id).wrap_err("Failed to convert deposit id to i32")?)
        .bind(XOnlyPublicKeyDB(operator_xonly_pk));

        let result = execute_query_with_tx!(self.connection, tx, query, fetch_optional)?;

        match result {
            Some((round_idx, kickoff_connector_idx)) => Ok(Some((
                RoundIndex::from_index(
                    usize::try_from(round_idx).wrap_err("Failed to convert round idx to u32")?,
                ),
                u32::try_from(kickoff_connector_idx)
                    .wrap_err("Failed to convert kickoff connector idx to u32")?,
            ))),
            None => Ok(None),
        }
    }

    pub async fn get_current_round_index(
        &self,
        tx: Option<DatabaseTransaction<'_, '_>>,
    ) -> Result<RoundIndex, BridgeError> {
        let query =
            sqlx::query_as::<_, (i32,)>("SELECT round_idx FROM current_round_index WHERE id = 1");
        let result = execute_query_with_tx!(self.connection, tx, query, fetch_one)?;
        Ok(RoundIndex::from_index(
            usize::try_from(result.0).wrap_err(BridgeError::IntConversionError)?,
        ))
    }

    pub async fn update_current_round_index(
        &self,
        tx: Option<DatabaseTransaction<'_, '_>>,
        round_idx: RoundIndex,
    ) -> Result<(), BridgeError> {
        let query = sqlx::query("UPDATE current_round_index SET round_idx = $1 WHERE id = 1")
            .bind(round_idx.to_index() as i32);

        execute_query_with_tx!(self.connection, tx, query, execute)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::bitvm_client::{SECP, UNSPENDABLE_XONLY_PUBKEY};
    use crate::operator::{Operator, RoundIndex};
    use crate::rpc::clementine::{
        DepositSignatures, NormalSignatureKind, NumberedSignatureKind, TaggedSignature,
    };
    use crate::test::common::citrea::MockCitreaClient;
    use crate::{database::Database, test::common::*};
    use bitcoin::hashes::Hash;
    use bitcoin::key::constants::SCHNORR_SIGNATURE_SIZE;
    use bitcoin::key::Keypair;
    use bitcoin::{Address, OutPoint, Txid, XOnlyPublicKey};
    use std::str::FromStr;

    #[tokio::test]
    async fn test_set_get_operator() {
        let config = create_test_config_with_thread_name().await;
        let database = Database::new(&config).await.unwrap();
        let mut ops = Vec::new();
        let operator_xonly_pks = [generate_random_xonly_pk(), generate_random_xonly_pk()];
        let reimburse_addrs = [
            Address::from_str("bc1q6d6cztycxjpm7p882emln0r04fjqt0kqylvku2")
                .unwrap()
                .assume_checked(),
            Address::from_str("bc1qj2mw4uh24qf67kn4nyqfsnta0mmxcutvhkyfp9")
                .unwrap()
                .assume_checked(),
        ];
        for i in 0..2 {
            let txid_str =
                format!("16b3a5951cb816afeb9dab8a30d0ece7acd3a7b34437436734edd1b72b6bf0{i:02x}");
            let txid = Txid::from_str(&txid_str).unwrap();
            ops.push((
                operator_xonly_pks[i],
                reimburse_addrs[i].clone(),
                OutPoint {
                    txid,
                    vout: i as u32,
                },
            ));
        }

        // Test inserting multiple operators
        for x in ops.iter() {
            database
                .insert_operator_if_not_exists(None, x.0, &x.1, x.2)
                .await
                .unwrap();
        }

        // Test getting all operators
        let res = database.get_operators(None).await.unwrap();
        assert_eq!(res.len(), ops.len());
        for i in 0..2 {
            assert_eq!(res[i].0, ops[i].0);
            assert_eq!(res[i].1, ops[i].1);
            assert_eq!(res[i].2, ops[i].2);
        }

        // Test getting single operator
        let res_single = database
            .get_operator(None, operator_xonly_pks[1])
            .await
            .unwrap()
            .unwrap();
        assert_eq!(res_single.xonly_pk, ops[1].0);
        assert_eq!(res_single.reimburse_addr, ops[1].1);
        assert_eq!(res_single.collateral_funding_outpoint, ops[1].2);

        // Test that we can insert the same data without errors
        database
            .insert_operator_if_not_exists(None, ops[0].0, &ops[0].1, ops[0].2)
            .await
            .unwrap();

        // Test updating operator data
        let new_reimburse_addr = Address::from_str("bc1qj2mw4uh24qf67kn4nyqfsnta0mmxcutvhkyfp9")
            .unwrap()
            .assume_checked();
        let new_collateral_funding_outpoint = OutPoint {
            txid: Txid::from_byte_array([2u8; 32]),
            vout: 1,
        };

        // test that we can't update the reimburse address
        assert!(database
            .insert_operator_if_not_exists(
                None,
                operator_xonly_pks[0],
                &reimburse_addrs[0],
                new_collateral_funding_outpoint
            )
            .await
            .is_err());

        // test that we can't update the collateral funding outpoint
        assert!(database
            .insert_operator_if_not_exists(
                None,
                operator_xonly_pks[0],
                &new_reimburse_addr,
                ops[0].2
            )
            .await
            .is_err());

        // test that we can't update both
        assert!(database
            .insert_operator_if_not_exists(
                None,
                operator_xonly_pks[0],
                &new_reimburse_addr,
                new_collateral_funding_outpoint
            )
            .await
            .is_err());

        // Verify data remains unchanged after failed updates
        let res_unchanged = database
            .get_operator(None, operator_xonly_pks[0])
            .await
            .unwrap()
            .unwrap();
        assert_eq!(res_unchanged.xonly_pk, ops[0].0);
        assert_eq!(res_unchanged.reimburse_addr, ops[0].1);
        assert_eq!(res_unchanged.collateral_funding_outpoint, ops[0].2);
    }

    #[tokio::test]
    async fn test_set_get_operator_challenge_ack_hashes() {
        let config = create_test_config_with_thread_name().await;
        let database = Database::new(&config).await.unwrap();

        let public_hashes = vec![[1u8; 20], [2u8; 20]];
        let new_public_hashes = vec![[3u8; 20], [4u8; 20]];

        let deposit_outpoint = OutPoint {
            txid: Txid::from_byte_array([1u8; 32]),
            vout: 0,
        };

        let operator_xonly_pk = generate_random_xonly_pk();
        let non_existent_xonly_pk = generate_random_xonly_pk();

        // Test inserting new data
        database
            .insert_operator_challenge_ack_hashes_if_not_exist(
                None,
                operator_xonly_pk,
                deposit_outpoint,
                &public_hashes,
            )
            .await
            .unwrap();

        // Retrieve and verify
        let result = database
            .get_operators_challenge_ack_hashes(None, operator_xonly_pk, deposit_outpoint)
            .await
            .unwrap();
        assert_eq!(result, Some(public_hashes.clone()));

        // Test that we can insert the same data without errors
        database
            .insert_operator_challenge_ack_hashes_if_not_exist(
                None,
                operator_xonly_pk,
                deposit_outpoint,
                &public_hashes,
            )
            .await
            .unwrap();

        // Test non-existent entry
        let non_existent = database
            .get_operators_challenge_ack_hashes(None, non_existent_xonly_pk, deposit_outpoint)
            .await
            .unwrap();
        assert!(non_existent.is_none());

        // Test that we can't update with different data
        assert!(database
            .insert_operator_challenge_ack_hashes_if_not_exist(
                None,
                operator_xonly_pk,
                deposit_outpoint,
                &new_public_hashes,
            )
            .await
            .is_err());

        // Verify data remains unchanged after failed update
        let result = database
            .get_operators_challenge_ack_hashes(None, operator_xonly_pk, deposit_outpoint)
            .await
            .unwrap();
        assert_eq!(result, Some(public_hashes));
    }

    #[tokio::test]
    async fn test_save_get_unspent_kickoff_sigs() {
        let config = create_test_config_with_thread_name().await;
        let database = Database::new(&config).await.unwrap();

        let round_idx = 1;
        let signatures = DepositSignatures {
            signatures: vec![
                TaggedSignature {
                    signature_id: Some((NumberedSignatureKind::UnspentKickoff1, 1).into()),
                    signature: vec![0x1F; SCHNORR_SIGNATURE_SIZE],
                },
                TaggedSignature {
                    signature_id: Some((NumberedSignatureKind::UnspentKickoff2, 1).into()),
                    signature: (vec![0x2F; SCHNORR_SIGNATURE_SIZE]),
                },
                TaggedSignature {
                    signature_id: Some((NumberedSignatureKind::UnspentKickoff1, 2).into()),
                    signature: vec![0x1F; SCHNORR_SIGNATURE_SIZE],
                },
                TaggedSignature {
                    signature_id: Some((NumberedSignatureKind::UnspentKickoff2, 2).into()),
                    signature: (vec![0x2F; SCHNORR_SIGNATURE_SIZE]),
                },
            ],
        };

        let operator_xonly_pk = generate_random_xonly_pk();
        let non_existent_xonly_pk = generate_random_xonly_pk();

        database
            .insert_unspent_kickoff_sigs_if_not_exist(
                None,
                operator_xonly_pk,
                RoundIndex::Round(round_idx),
                signatures.signatures.clone(),
            )
            .await
            .unwrap();

        let result = database
            .get_unspent_kickoff_sigs(None, operator_xonly_pk, RoundIndex::Round(round_idx))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(result, signatures.signatures);

        let non_existent = database
            .get_unspent_kickoff_sigs(None, non_existent_xonly_pk, RoundIndex::Round(round_idx))
            .await
            .unwrap();
        assert!(non_existent.is_none());

        let non_existent = database
            .get_unspent_kickoff_sigs(
                None,
                non_existent_xonly_pk,
                RoundIndex::Round(round_idx + 1),
            )
            .await
            .unwrap();
        assert!(non_existent.is_none());
    }

    #[tokio::test]
    async fn test_bitvm_setup() {
        let config = create_test_config_with_thread_name().await;
        let database = Database::new(&config).await.unwrap();

        let assert_tx_hashes: Vec<[u8; 32]> = vec![[1u8; 32], [4u8; 32]];
        let root_hash = [42u8; 32];
        let latest_blockhash_root_hash = [43u8; 32];

        let deposit_outpoint = OutPoint {
            txid: Txid::from_byte_array([1u8; 32]),
            vout: 0,
        };
        let operator_xonly_pk = generate_random_xonly_pk();
        let non_existent_xonly_pk = generate_random_xonly_pk();

        // Test inserting new BitVM setup
        database
            .insert_bitvm_setup_if_not_exists(
                None,
                operator_xonly_pk,
                deposit_outpoint,
                &assert_tx_hashes,
                &root_hash,
                &latest_blockhash_root_hash,
            )
            .await
            .unwrap();

        // Retrieve and verify
        let result = database
            .get_bitvm_setup(None, operator_xonly_pk, deposit_outpoint)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(result.0, assert_tx_hashes);
        assert_eq!(result.1, root_hash);
        assert_eq!(result.2, latest_blockhash_root_hash);

        // Test that we can insert the same data without errors
        database
            .insert_bitvm_setup_if_not_exists(
                None,
                operator_xonly_pk,
                deposit_outpoint,
                &assert_tx_hashes,
                &root_hash,
                &latest_blockhash_root_hash,
            )
            .await
            .unwrap();

        // Test non-existent entry
        let non_existent = database
            .get_bitvm_setup(None, non_existent_xonly_pk, deposit_outpoint)
            .await
            .unwrap();
        assert!(non_existent.is_none());

        // Test updating BitVM setup data
        let new_assert_tx_hashes: Vec<[u8; 32]> = vec![[2u8; 32], [5u8; 32]];
        let new_root_hash = [44u8; 32];
        let new_latest_blockhash_root_hash = [45u8; 32];

        // test that we can't update the assert_tx_hashes
        assert!(database
            .insert_bitvm_setup_if_not_exists(
                None,
                operator_xonly_pk,
                deposit_outpoint,
                &new_assert_tx_hashes,
                &root_hash,
                &latest_blockhash_root_hash,
            )
            .await
            .is_err());

        // test that we can't update the root_hash
        assert!(database
            .insert_bitvm_setup_if_not_exists(
                None,
                operator_xonly_pk,
                deposit_outpoint,
                &assert_tx_hashes,
                &new_root_hash,
                &latest_blockhash_root_hash,
            )
            .await
            .is_err());

        // test that we can't update the latest_blockhash_root_hash
        assert!(database
            .insert_bitvm_setup_if_not_exists(
                None,
                operator_xonly_pk,
                deposit_outpoint,
                &assert_tx_hashes,
                &root_hash,
                &new_latest_blockhash_root_hash,
            )
            .await
            .is_err());

        // test that we can't update all of them
        assert!(database
            .insert_bitvm_setup_if_not_exists(
                None,
                operator_xonly_pk,
                deposit_outpoint,
                &new_assert_tx_hashes,
                &new_root_hash,
                &new_latest_blockhash_root_hash,
            )
            .await
            .is_err());

        // Verify data remains unchanged after failed updates
        let result = database
            .get_bitvm_setup(None, operator_xonly_pk, deposit_outpoint)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(result.0, assert_tx_hashes);
        assert_eq!(result.1, root_hash);
        assert_eq!(result.2, latest_blockhash_root_hash);
    }

    #[tokio::test]
    async fn upsert_get_operator_winternitz_public_keys() {
        let mut config = create_test_config_with_thread_name().await;
        let database = Database::new(&config).await.unwrap();
        let _regtest = create_regtest_rpc(&mut config).await;

        let operator = Operator::<MockCitreaClient>::new(config.clone())
            .await
            .unwrap();
        let op_xonly_pk =
            XOnlyPublicKey::from_keypair(&Keypair::from_secret_key(&SECP, &config.secret_key)).0;
        let deposit_outpoint = OutPoint {
            txid: Txid::from_slice(&[0x45; 32]).unwrap(),
            vout: 0x1F,
        };
        let wpks = operator
            .generate_assert_winternitz_pubkeys(deposit_outpoint)
            .unwrap();

        // Test inserting new data
        database
            .insert_operator_kickoff_winternitz_public_keys_if_not_exist(
                None,
                op_xonly_pk,
                wpks.clone(),
            )
            .await
            .unwrap();

        let result = database
            .get_operator_kickoff_winternitz_public_keys(None, op_xonly_pk)
            .await
            .unwrap();
        assert_eq!(result, wpks);

        // Test that we can insert the same data without errors
        database
            .insert_operator_kickoff_winternitz_public_keys_if_not_exist(
                None,
                op_xonly_pk,
                wpks.clone(),
            )
            .await
            .unwrap();

        // Test that we can't update with different data
        let different_wpks = operator
            .generate_assert_winternitz_pubkeys(OutPoint {
                txid: Txid::from_slice(&[0x46; 32]).unwrap(),
                vout: 0x1F,
            })
            .unwrap();
        assert!(database
            .insert_operator_kickoff_winternitz_public_keys_if_not_exist(
                None,
                op_xonly_pk,
                different_wpks
            )
            .await
            .is_err());

        let non_existent = database
            .get_operator_kickoff_winternitz_public_keys(None, *UNSPENDABLE_XONLY_PUBKEY)
            .await;
        assert!(non_existent.is_err());
    }

    #[tokio::test]
    async fn upsert_get_operator_bitvm_wpks() {
        let mut config = create_test_config_with_thread_name().await;
        let database = Database::new(&config).await.unwrap();
        let _regtest = create_regtest_rpc(&mut config).await;

        let operator = Operator::<MockCitreaClient>::new(config.clone())
            .await
            .unwrap();
        let op_xonly_pk =
            XOnlyPublicKey::from_keypair(&Keypair::from_secret_key(&SECP, &config.secret_key)).0;
        let deposit_outpoint = OutPoint {
            txid: Txid::from_slice(&[0x45; 32]).unwrap(),
            vout: 0x1F,
        };
        let wpks = operator
            .generate_assert_winternitz_pubkeys(deposit_outpoint)
            .unwrap();

        database
            .insert_operator_bitvm_keys_if_not_exist(
                None,
                op_xonly_pk,
                deposit_outpoint,
                wpks.clone(),
            )
            .await
            .unwrap();

        let result = database
            .get_operator_bitvm_keys(None, op_xonly_pk, deposit_outpoint)
            .await
            .unwrap();
        assert_eq!(result, wpks);

        let non_existent = database
            .get_operator_kickoff_winternitz_public_keys(None, *UNSPENDABLE_XONLY_PUBKEY)
            .await;
        assert!(non_existent.is_err());
    }

    #[tokio::test]
    async fn upsert_get_deposit_signatures() {
        let config = create_test_config_with_thread_name().await;
        let database = Database::new(&config).await.unwrap();

        let operator_xonly_pk = generate_random_xonly_pk();
        let unset_operator_xonly_pk = generate_random_xonly_pk();
        let deposit_outpoint = OutPoint {
            txid: Txid::from_slice(&[0x45; 32]).unwrap(),
            vout: 0x1F,
        };
        let round_idx = 1;
        let kickoff_idx = 1;
        let signatures = DepositSignatures {
            signatures: vec![
                TaggedSignature {
                    signature_id: Some(NormalSignatureKind::Reimburse1.into()),
                    signature: vec![0x1F; SCHNORR_SIGNATURE_SIZE],
                },
                TaggedSignature {
                    signature_id: Some((NumberedSignatureKind::OperatorChallengeNack1, 1).into()),
                    signature: (vec![0x2F; SCHNORR_SIGNATURE_SIZE]),
                },
            ],
        };

        database
            .insert_deposit_signatures_if_not_exist(
                None,
                deposit_outpoint,
                operator_xonly_pk,
                RoundIndex::Round(round_idx),
                kickoff_idx,
                Txid::all_zeros(),
                signatures.signatures.clone(),
            )
            .await
            .unwrap();
        // Setting this twice should not cause any issues
        database
            .insert_deposit_signatures_if_not_exist(
                None,
                deposit_outpoint,
                operator_xonly_pk,
                RoundIndex::Round(round_idx),
                kickoff_idx,
                Txid::all_zeros(),
                signatures.signatures.clone(),
            )
            .await
            .unwrap();
        // But with different kickoff txid and signatures should.
        assert!(database
            .insert_deposit_signatures_if_not_exist(
                None,
                deposit_outpoint,
                operator_xonly_pk,
                RoundIndex::Round(round_idx),
                kickoff_idx,
                Txid::from_slice(&[0x1F; 32]).unwrap(),
                signatures.signatures.clone(),
            )
            .await
            .is_err());

        let result = database
            .get_deposit_signatures(
                None,
                deposit_outpoint,
                operator_xonly_pk,
                RoundIndex::Round(round_idx),
                kickoff_idx,
            )
            .await
            .unwrap()
            .unwrap();
        assert_eq!(result, signatures.signatures);

        let non_existent = database
            .get_deposit_signatures(
                None,
                deposit_outpoint,
                operator_xonly_pk,
                RoundIndex::Round(round_idx + 1),
                kickoff_idx + 1,
            )
            .await
            .unwrap();
        assert!(non_existent.is_none());

        let non_existent = database
            .get_deposit_signatures(
                None,
                OutPoint::null(),
                unset_operator_xonly_pk,
                RoundIndex::Round(round_idx),
                kickoff_idx,
            )
            .await
            .unwrap();
        assert!(non_existent.is_none());
    }

    #[tokio::test]
    async fn concurrent_get_deposit_id_same_outpoint() {
        // this test was added to ensure get_deposit_id will not block if two different transactions only read the deposit_id
        use tokio::time::{timeout, Duration};

        let config = create_test_config_with_thread_name().await;
        let database = Database::new(&config).await.unwrap();

        let deposit_outpoint = OutPoint {
            txid: Txid::from_byte_array([7u8; 32]),
            vout: 0,
        };
        let mut first_insert = database.begin_transaction().await.unwrap();
        // insert the deposit outpoint into the database
        let original_id = database
            .get_deposit_id(Some(&mut first_insert), deposit_outpoint)
            .await
            .unwrap();
        first_insert.commit().await.unwrap();

        let mut tx1 = database.begin_transaction().await.unwrap();
        let mut tx2 = database.begin_transaction().await.unwrap();

        let id = database
            .get_deposit_id(Some(&mut tx1), deposit_outpoint)
            .await
            .unwrap();

        let id2 = timeout(
            Duration::from_secs(30),
            database.get_deposit_id(Some(&mut tx2), deposit_outpoint),
        )
        .await
        .unwrap()
        .unwrap();

        tx1.commit().await.unwrap();
        tx2.commit().await.unwrap();

        assert_eq!(id, id2, "both transactions should see the same deposit id");
        assert_eq!(
            id, original_id,
            "new transaction should see the same deposit id as the original"
        );
    }
}
