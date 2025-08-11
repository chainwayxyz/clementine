//! # Type Wrappers for Parsing
//!
//! This module includes wrappers for easy parsing of the foreign types.

use crate::EVMAddress;
use bitcoin::{
    address::NetworkUnchecked,
    block,
    consensus::{deserialize, serialize, Decodable, Encodable},
    hashes::Hash,
    hex::DisplayHex,
    secp256k1::{schnorr, Message, PublicKey},
    Address, OutPoint, ScriptBuf, TxOut, Txid, XOnlyPublicKey,
};
use eyre::eyre;
use prost::Message as _;
use risc0_zkvm::Receipt;
use secp256k1::musig;
use serde::{Deserialize, Serialize};
use sqlx::{
    error::BoxDynError,
    postgres::{PgArgumentBuffer, PgValueRef},
    Decode, Encode, Postgres,
};
use std::str::FromStr;

/// Macro to reduce boilerplate for [`impl_text_wrapper_custom`].
///
/// Implements the Type, Encode and Decode traits for a wrapper type.
/// Assumes the type is declared.
macro_rules! impl_text_wrapper_base {
    ($wrapper:ident, $inner:ty, $encode:expr, $decode:expr) => {
        impl sqlx::Type<sqlx::Postgres> for $wrapper {
            fn type_info() -> sqlx::postgres::PgTypeInfo {
                sqlx::postgres::PgTypeInfo::with_name("TEXT")
            }
        }

        impl Encode<'_, Postgres> for $wrapper {
            fn encode_by_ref(
                &self,
                buf: &mut PgArgumentBuffer,
            ) -> Result<sqlx::encode::IsNull, sqlx::error::BoxDynError> {
                let s = $encode(&self.0);
                <&str as Encode<Postgres>>::encode_by_ref(&s.as_str(), buf)
            }
        }

        impl<'r> Decode<'r, Postgres> for $wrapper {
            fn decode(value: PgValueRef<'r>) -> Result<Self, sqlx::error::BoxDynError> {
                let s = <&str as Decode<Postgres>>::decode(value)?;
                Ok(Self($decode(s)?))
            }
        }
    };
}

/// Macro for implementing text-based SQL wrapper types with custom encoding/decoding
///
/// # Parameters
/// - `$wrapper`: The name of the wrapper type to create
/// - `$inner`: The inner type being wrapped
/// - `$encode`: Expression for converting inner type to string
/// - `$decode`: Expression for converting string back to inner type
///
/// The macro creates a new type that wraps the inner type and implements:
/// - SQLx Type trait to indicate TEXT column type
/// - SQLx Encode trait for converting to database format
/// - SQLx Decode trait for converting from database format
macro_rules! impl_text_wrapper_custom {
    // Default case (include serde)
    ($wrapper:ident, $inner:ty, $encode:expr, $decode:expr) => {
        impl_text_wrapper_custom!($wrapper, $inner, $encode, $decode, true);
    };

    // true case - with serde
    ($wrapper:ident, $inner:ty, $encode:expr, $decode:expr, true) => {
        #[derive(sqlx::FromRow, Debug, Clone, Serialize, Deserialize, PartialEq)]
        pub struct $wrapper(pub $inner);

        impl_text_wrapper_base!($wrapper, $inner, $encode, $decode);
    };

    // false case - without serde
    ($wrapper:ident, $inner:ty, $encode:expr, $decode:expr, false) => {
        #[derive(sqlx::FromRow, Debug, Clone, PartialEq)]
        pub struct $wrapper(pub $inner);

        impl_text_wrapper_base!($wrapper, $inner, $encode, $decode);
    };
}

/// Macro for implementing BYTEA-based SQL wrapper types with custom encoding/decoding
///
/// # Parameters
/// - `$wrapper`: The name of the wrapper type to create
/// - `$inner`: The inner type being wrapped
/// - `$encode`: Expression for converting inner type to bytes
/// - `$decode`: Expression for converting bytes back to inner type
///
/// The macro creates a new type that wraps the inner type and implements:
/// - SQLx Type trait to indicate BYTEA column type
/// - SQLx Encode trait for converting to database format
/// - SQLx Decode trait for converting from database format
macro_rules! impl_bytea_wrapper_custom {
    ($wrapper:ident, $inner:ty, $encode:expr, $decode:expr) => {
        #[derive(sqlx::FromRow, Debug, Clone, PartialEq)]
        pub struct $wrapper(pub $inner);

        impl sqlx::Type<sqlx::Postgres> for $wrapper {
            fn type_info() -> sqlx::postgres::PgTypeInfo {
                sqlx::postgres::PgTypeInfo::with_name("BYTEA")
            }
        }

        impl Encode<'_, Postgres> for $wrapper {
            fn encode_by_ref(
                &self,
                buf: &mut PgArgumentBuffer,
            ) -> Result<sqlx::encode::IsNull, sqlx::error::BoxDynError> {
                let bytes = $encode(&self.0);
                <&[u8] as Encode<Postgres>>::encode(bytes.as_ref(), buf)
            }
        }

        impl<'r> Decode<'r, Postgres> for $wrapper {
            fn decode(value: PgValueRef<'r>) -> Result<Self, sqlx::error::BoxDynError> {
                let bytes = <Vec<u8> as Decode<Postgres>>::decode(value)?;
                Ok(Self($decode(&bytes)?))
            }
        }
    };
}

/// Same as `impl_bytea_wrapper_custom` but with an encode function that returns a Result
macro_rules! impl_bytea_wrapper_custom_with_error {
    ($wrapper:ident, $inner:ty, $encode:expr, $decode:expr) => {
        #[derive(sqlx::FromRow, Debug, Clone)]
        pub struct $wrapper(pub $inner);

        impl sqlx::Type<sqlx::Postgres> for $wrapper {
            fn type_info() -> sqlx::postgres::PgTypeInfo {
                sqlx::postgres::PgTypeInfo::with_name("BYTEA")
            }
        }

        impl Encode<'_, Postgres> for $wrapper {
            fn encode_by_ref(
                &self,
                buf: &mut PgArgumentBuffer,
            ) -> Result<sqlx::encode::IsNull, sqlx::error::BoxDynError> {
                let bytes = $encode(&self.0)?;
                <&[u8] as Encode<Postgres>>::encode(bytes.as_ref(), buf)
            }
        }

        impl<'r> Decode<'r, Postgres> for $wrapper {
            fn decode(value: PgValueRef<'r>) -> Result<Self, sqlx::error::BoxDynError> {
                let bytes = <Vec<u8> as Decode<Postgres>>::decode(value)?;
                Ok(Self($decode(&bytes)?))
            }
        }
    };
}

/// Macro for implementing BYTEA-based SQL wrapper types using standard serialization
///
/// This macro creates a wrapper type that uses the inner type's default serialization
/// methods (`serialize()` and `from_slice()`) for encoding/decoding to/from BYTEA columns.
///
/// # Parameters
/// - `$wrapper`: The name of the wrapper type to create
/// - `$inner`: The inner type being wrapped
///
/// The macro creates a new type that wraps the inner type and implements:
/// - SQLx Type trait to indicate BYTEA column type
/// - SQLx Encode trait for converting to database format
/// - SQLx Decode trait for converting from database format
macro_rules! impl_bytea_wrapper_default {
    ($wrapper:ident, $inner:ty) => {
        impl_bytea_wrapper_custom!(
            $wrapper,
            $inner,
            |x: &$inner| x.serialize(),
            |x: &[u8]| -> Result<$inner, BoxDynError> {
                <$inner>::from_slice(x).map_err(|e| Box::new(e) as sqlx::error::BoxDynError)
            }
        );
    };
}

/// Macro for implementing text-based SQL wrapper types using standard string conversion
///
/// This macro creates a wrapper type that uses the inner type's default string conversion
/// methods (`to_string()` and `from_str()`) for encoding/decoding to/from TEXT columns.
///
/// # Parameters
/// - `$wrapper`: The name of the wrapper type to create
/// - `$inner`: The inner type being wrapped
///
/// The macro creates a new type that wraps the inner type and implements:
/// - SQLx Type trait to indicate TEXT column type
/// - SQLx Encode trait for converting to database format
/// - SQLx Decode trait for converting from database format
macro_rules! impl_text_wrapper_default {
    ($wrapper:ident, $inner:ty) => {
        impl_text_wrapper_custom!(
            $wrapper,
            $inner,
            <$inner as ToString>::to_string,
            <$inner as FromStr>::from_str
        );
    };
}

impl_text_wrapper_default!(OutPointDB, OutPoint);
impl_text_wrapper_default!(BlockHashDB, block::BlockHash);
impl_text_wrapper_default!(PublicKeyDB, PublicKey);
impl_text_wrapper_default!(XOnlyPublicKeyDB, XOnlyPublicKey);

impl_bytea_wrapper_default!(SignatureDB, schnorr::Signature);

impl_bytea_wrapper_custom!(
    MusigPubNonceDB,
    musig::PublicNonce,
    |pub_nonce: &musig::PublicNonce| pub_nonce.serialize(),
    |x: &[u8]| -> Result<musig::PublicNonce, BoxDynError> {
        let arr: &[u8; 66] = x
            .try_into()
            .map_err(|_| eyre!("Expected 66 bytes for PublicNonce"))?;
        Ok(musig::PublicNonce::from_byte_array(arr)?)
    }
);

impl_bytea_wrapper_custom!(
    MusigAggNonceDB,
    musig::AggregatedNonce,
    |pub_nonce: &musig::AggregatedNonce| pub_nonce.serialize(),
    |x: &[u8]| -> Result<musig::AggregatedNonce, BoxDynError> {
        let arr: &[u8; 66] = x
            .try_into()
            .map_err(|_| eyre!("Expected 66 bytes for AggregatedNonce"))?;
        Ok(musig::AggregatedNonce::from_byte_array(arr)?)
    }
);

impl_bytea_wrapper_custom_with_error!(
    ReceiptDB,
    Receipt,
    |lcp: &Receipt| -> Result<Vec<u8>, BoxDynError> { borsh::to_vec(lcp).map_err(Into::into) },
    |x: &[u8]| -> Result<Receipt, BoxDynError> { borsh::from_slice(x).map_err(Into::into) }
);

impl_text_wrapper_custom!(
    AddressDB,
    Address<NetworkUnchecked>,
    |addr: &Address<NetworkUnchecked>| addr.clone().assume_checked().to_string(),
    |s: &str| Address::from_str(s)
);

impl_text_wrapper_custom!(
    EVMAddressDB,
    EVMAddress,
    |addr: &EVMAddress| hex::encode(addr.0),
    |s: &str| -> Result<EVMAddress, BoxDynError> {
        let bytes = hex::decode(s).map_err(Box::new)?;

        Ok(EVMAddress(bytes.try_into().map_err(|arr: Vec<u8>| {
            eyre!("Failed to deserialize EVMAddress from {:?}", arr)
        })?))
    }
);

impl_bytea_wrapper_custom!(
    TxidDB,
    Txid,
    |txid: &Txid| *txid, // Txid is Copy, which requires this hack
    |x: &[u8]| -> Result<Txid, BoxDynError> { Ok(Txid::from_slice(x)?) }
);

impl_bytea_wrapper_custom!(
    MessageDB,
    Message,
    |msg: &Message| *msg, // Message is Copy, which requires this hack
    |x: &[u8]| -> Result<Message, BoxDynError> { Ok(Message::from_digest(x.try_into()?)) }
);

use crate::rpc::clementine::DepositSignatures;
impl_bytea_wrapper_custom!(
    SignaturesDB,
    DepositSignatures,
    |signatures: &DepositSignatures| { signatures.encode_to_vec() },
    |x: &[u8]| -> Result<DepositSignatures, BoxDynError> {
        DepositSignatures::decode(x).map_err(Into::into)
    }
);

use crate::rpc::clementine::DepositParams;
impl_bytea_wrapper_custom!(
    DepositParamsDB,
    DepositParams,
    |deposit_params: &DepositParams| { deposit_params.encode_to_vec() },
    |x: &[u8]| -> Result<DepositParams, BoxDynError> {
        DepositParams::decode(x).map_err(Into::into)
    }
);

impl_bytea_wrapper_custom!(
    ScriptBufDB,
    ScriptBuf,
    |script: &ScriptBuf| serialize(script),
    |x: &[u8]| -> Result<ScriptBuf, BoxDynError> { deserialize(x).map_err(Into::into) }
);

impl_text_wrapper_custom!(
    BlockHeaderDB,
    block::Header,
    |header: &block::Header| {
        let mut bytes = Vec::new();
        header
            .consensus_encode(&mut bytes)
            .expect("exceeded max Vec size or ran out of memory");
        bytes.to_hex_string(bitcoin::hex::Case::Lower)
    },
    |s: &str| -> Result<block::Header, BoxDynError> {
        let bytes = hex::decode(s)?;
        block::Header::consensus_decode(&mut bytes.as_slice()).map_err(Into::into)
    }
);

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, sqlx::FromRow)]
pub struct UtxoDB {
    pub outpoint_db: OutPointDB,
    pub txout_db: TxOutDB,
}

impl_text_wrapper_custom!(
    TxOutDB,
    TxOut,
    |txout: &TxOut| bitcoin::consensus::encode::serialize_hex(&txout),
    |s: &str| -> Result<TxOut, BoxDynError> {
        bitcoin::consensus::encode::deserialize_hex(s)
            .map_err(|e| Box::new(e) as sqlx::error::BoxDynError)
    }
);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        bitvm_client::{self, SECP},
        database::Database,
        musig2,
        rpc::clementine::TaggedSignature,
        test::common::*,
        EVMAddress,
    };
    use bitcoin::{
        block::{self, Version},
        hashes::Hash,
        key::Keypair,
        secp256k1::{schnorr::Signature, SecretKey},
        Amount, BlockHash, CompactTarget, OutPoint, ScriptBuf, TxMerkleNode, TxOut, Txid,
    };
    use secp256k1::{musig::AggregatedNonce, SECP256K1};
    use sqlx::{Executor, Type};

    macro_rules! test_encode_decode_invariant {
        ($db_type:ty, $inner:ty, $db_wrapper:expr, $table_name:expr, $column_type:expr) => {
            let db_wrapper = $db_wrapper;

            let config = create_test_config_with_thread_name().await;
            let database = Database::new(&config).await.unwrap();

            // Create table if it doesn't exist
            database
                .connection
                .execute(sqlx::query(&format!(
                    "CREATE TABLE IF NOT EXISTS {} ({} {} PRIMARY KEY)",
                    $table_name, $table_name, $column_type
                )))
                .await
                .unwrap();

            // Insert the value
            database
                .connection
                .execute(
                    sqlx::query(&format!(
                        "INSERT INTO {} ({}) VALUES ($1)",
                        $table_name, $table_name
                    ))
                    .bind(db_wrapper.clone()),
                )
                .await
                .unwrap();

            // Retrieve the value
            let retrieved: $db_type = sqlx::query_scalar(&format!(
                "SELECT {} FROM {} WHERE {} = $1",
                $table_name, $table_name, $table_name
            ))
            .bind(db_wrapper.clone())
            .fetch_one(&database.connection)
            .await
            .unwrap();

            // Verify the retrieved value matches the original
            assert_eq!(retrieved, db_wrapper);

            // Clean up
            database
                .connection
                .execute(sqlx::query(&format!("DROP TABLE {}", $table_name)))
                .await
                .unwrap();
        };
    }
    #[tokio::test]
    async fn outpoint_encode_decode_invariant() {
        assert_eq!(
            OutPointDB::type_info(),
            sqlx::postgres::PgTypeInfo::with_name("TEXT")
        );

        test_encode_decode_invariant!(
            OutPointDB,
            OutPoint,
            OutPointDB(OutPoint {
                txid: Txid::all_zeros(),
                vout: 0x45
            }),
            "outpoint",
            "TEXT"
        );
    }

    #[tokio::test]
    async fn txoutdb_encode_decode_invariant() {
        assert_eq!(
            TxOutDB::type_info(),
            sqlx::postgres::PgTypeInfo::with_name("TEXT")
        );

        test_encode_decode_invariant!(
            TxOutDB,
            TxOut,
            TxOutDB(TxOut {
                value: Amount::from_sat(0x45),
                script_pubkey: ScriptBuf::new(),
            }),
            "txout",
            "TEXT"
        );
    }

    #[tokio::test]
    async fn addressdb_encode_decode_invariant() {
        assert_eq!(
            AddressDB::type_info(),
            sqlx::postgres::PgTypeInfo::with_name("TEXT")
        );

        let address = bitcoin::Address::p2tr(
            &SECP,
            *bitvm_client::UNSPENDABLE_XONLY_PUBKEY,
            None,
            bitcoin::Network::Regtest,
        );
        let address = AddressDB(address.as_unchecked().clone());

        test_encode_decode_invariant!(
            AddressDB,
            Address<NetworkUnchecked>,
            address,
            "address",
            "TEXT"
        );
    }

    #[tokio::test]
    async fn evmaddressdb_encode_decode_invariant() {
        assert_eq!(
            EVMAddressDB::type_info(),
            sqlx::postgres::PgTypeInfo::with_name("TEXT")
        );

        let evmaddress = EVMAddressDB(EVMAddress([0x45u8; 20]));
        test_encode_decode_invariant!(EVMAddressDB, EVMAddress, evmaddress, "evmaddress", "TEXT");
    }

    #[tokio::test]
    async fn txiddb_encode_decode_invariant() {
        assert_eq!(
            TxidDB::type_info(),
            sqlx::postgres::PgTypeInfo::with_name("BYTEA")
        );

        let txid = TxidDB(Txid::all_zeros());
        test_encode_decode_invariant!(TxidDB, Txid, txid, "txid", "BYTEA");
    }

    #[tokio::test]
    async fn signaturedb_encode_decode_invariant() {
        assert_eq!(
            SignatureDB::type_info(),
            sqlx::postgres::PgTypeInfo::with_name("BYTEA")
        );

        let signature = SignatureDB(Signature::from_slice(&[0u8; 64]).unwrap());
        test_encode_decode_invariant!(SignatureDB, Signature, signature, "signature", "BYTEA");
    }

    #[tokio::test]
    async fn signaturesdb_encode_decode_invariant() {
        assert_eq!(
            SignaturesDB::type_info(),
            sqlx::postgres::PgTypeInfo::with_name("BYTEA")
        );

        use crate::rpc::clementine::{
            DepositSignatures, NormalSignatureKind, NumberedSignatureKind,
        };
        let signatures = DepositSignatures {
            signatures: vec![
                TaggedSignature {
                    signature: vec![0x1Fu8; 64],
                    signature_id: Some(NormalSignatureKind::NormalSignatureUnknown.into()),
                },
                TaggedSignature {
                    signature: vec![0x45u8; 64],
                    signature_id: Some((NumberedSignatureKind::NumberedSignatureUnknown, 1).into()),
                },
            ],
        };
        test_encode_decode_invariant!(
            SignaturesDB,
            DepositSignatures,
            SignaturesDB(signatures),
            "signatures",
            "BYTEA"
        );
    }

    #[tokio::test]
    async fn utxodb_json_encode_decode_invariant() {
        use sqlx::types::Json;

        assert_eq!(
            Json::<UtxoDB>::type_info(),
            sqlx::postgres::PgTypeInfo::with_name("JSONB")
        );

        let utxodb = UtxoDB {
            outpoint_db: OutPointDB(OutPoint {
                txid: Txid::all_zeros(),
                vout: 0x45,
            }),
            txout_db: TxOutDB(TxOut {
                value: Amount::from_sat(0x45),
                script_pubkey: ScriptBuf::new(),
            }),
        };

        test_encode_decode_invariant!(Json<UtxoDB>, Utxodb, Json(utxodb), "utxodb", "JSONB");
    }

    #[tokio::test]
    async fn blockhashdb_encode_decode_invariant() {
        assert_eq!(
            OutPointDB::type_info(),
            sqlx::postgres::PgTypeInfo::with_name("TEXT")
        );

        let blockhash = BlockHashDB(BlockHash::all_zeros());
        test_encode_decode_invariant!(BlockHashDB, BlockHash, blockhash, "blockhash", "TEXT");
    }

    #[tokio::test]
    async fn blockheaderdb_encode_decode_invariant() {
        assert_eq!(
            OutPointDB::type_info(),
            sqlx::postgres::PgTypeInfo::with_name("TEXT")
        );

        let blockheader = BlockHeaderDB(block::Header {
            version: Version::TWO,
            prev_blockhash: BlockHash::all_zeros(),
            merkle_root: TxMerkleNode::all_zeros(),
            time: 0,
            bits: CompactTarget::default(),
            nonce: 0,
        });
        test_encode_decode_invariant!(
            BlockHeaderDB,
            block::Header,
            blockheader,
            "blockheader",
            "TEXT"
        );
    }

    #[tokio::test]
    async fn musigpubnoncedb_encode_decode_invariant() {
        assert_eq!(
            MusigPubNonceDB::type_info(),
            sqlx::postgres::PgTypeInfo::with_name("BYTEA")
        );

        let kp = Keypair::from_secret_key(&SECP, &SecretKey::from_slice(&[1u8; 32]).unwrap());
        let (_sec_nonce, pub_nonce) = musig2::nonce_pair(&kp).unwrap();
        let public_nonce = MusigPubNonceDB(pub_nonce);
        test_encode_decode_invariant!(
            MusigPubNonceDB,
            PublicNonce,
            public_nonce,
            "public_nonce",
            "BYTEA"
        );
    }

    #[tokio::test]
    async fn musigaggnoncedb_encode_decode_invariant() {
        assert_eq!(
            MusigAggNonceDB::type_info(),
            sqlx::postgres::PgTypeInfo::with_name("BYTEA")
        );

        let kp = Keypair::from_secret_key(&SECP, &SecretKey::from_slice(&[1u8; 32]).unwrap());
        let (_sec_nonce, pub_nonce) = musig2::nonce_pair(&kp).unwrap();
        let aggregated_nonce = MusigAggNonceDB(AggregatedNonce::new(SECP256K1, &[&pub_nonce]));
        test_encode_decode_invariant!(
            MusigAggNonceDB,
            AggregatedNonce,
            aggregated_nonce,
            "aggregated_nonce",
            "BYTEA"
        );
    }
}
