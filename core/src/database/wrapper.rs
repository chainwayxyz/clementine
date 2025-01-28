use crate::{errors::BridgeError, EVMAddress};
use bitcoin::{
    address::NetworkUnchecked,
    block,
    consensus::{Decodable, Encodable},
    hex::DisplayHex,
    secp256k1::{schnorr, Message, PublicKey},
    Address, OutPoint, TxOut, Txid, XOnlyPublicKey,
};
use secp256k1::musig;
use serde::{Deserialize, Serialize};
use sqlx::{
    error::BoxDynError,
    postgres::{PgArgumentBuffer, PgValueRef},
    Decode, Encode, Postgres,
};
use std::str::FromStr;

macro_rules! impl_text_wrapper_base {
    ($wrapper:ident, $inner:ty, $encode:expr, $decode:expr) => {
        impl sqlx::Type<sqlx::Postgres> for $wrapper {
            fn type_info() -> sqlx::postgres::PgTypeInfo {
                sqlx::postgres::PgTypeInfo::with_name("TEXT")
            }
        }

        impl Encode<'_, Postgres> for $wrapper {
            fn encode_by_ref(&self, buf: &mut PgArgumentBuffer) -> sqlx::encode::IsNull {
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
macro_rules! impl_text_wrapper_custom {
    // Default case (include serde)
    ($wrapper:ident, $inner:ty, $encode:expr, $decode:expr) => {
        impl_text_wrapper_custom!($wrapper, $inner, $encode, $decode, true);
    };

    // true case - with serde
    ($wrapper:ident, $inner:ty, $encode:expr, $decode:expr, true) => {
        #[derive(sqlx::FromRow, Debug, Clone, Serialize, Deserialize)]
        pub struct $wrapper(pub $inner);

        impl_text_wrapper_base!($wrapper, $inner, $encode, $decode);
    };

    // false case - without serde
    ($wrapper:ident, $inner:ty, $encode:expr, $decode:expr, false) => {
        #[derive(sqlx::FromRow, Debug, Clone)]
        pub struct $wrapper(pub $inner);

        impl_text_wrapper_base!($wrapper, $inner, $encode, $decode);
    };
}

// For types that need custom byte serialization
macro_rules! impl_bytea_wrapper_custom {
    ($wrapper:ident, $inner:ty, $encode:expr, $decode:expr) => {
        #[derive(sqlx::FromRow, Debug, Clone)]
        pub struct $wrapper(pub $inner);

        impl sqlx::Type<sqlx::Postgres> for $wrapper {
            fn type_info() -> sqlx::postgres::PgTypeInfo {
                sqlx::postgres::PgTypeInfo::with_name("BYTEA")
            }
        }

        impl Encode<'_, Postgres> for $wrapper {
            fn encode_by_ref(&self, buf: &mut PgArgumentBuffer) -> sqlx::encode::IsNull {
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

// For types that use standard serialization
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
impl_text_wrapper_default!(TxidDB, Txid);
impl_text_wrapper_default!(BlockHashDB, block::BlockHash);
impl_text_wrapper_default!(PublicKeyDB, PublicKey);
impl_text_wrapper_default!(XOnlyPublicKeyDB, XOnlyPublicKey);

impl_bytea_wrapper_default!(SignatureDB, schnorr::Signature);
impl_bytea_wrapper_default!(MusigPubNonceDB, musig::MusigPubNonce);
impl_bytea_wrapper_default!(MusigAggNonceDB, musig::MusigAggNonce);

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

        Ok(EVMAddress(
            bytes
                .try_into()
                .map_err(|_| Box::new(BridgeError::TryFromSliceError))?,
        ))
    }
);

impl_bytea_wrapper_custom!(
    MessageDB,
    Message,
    |msg: &Message| *msg, // Message is Copy, which requires this hack
    |x: &[u8]| -> Result<Message, BoxDynError> { Ok(Message::from_digest(x.try_into().unwrap())) }
);

impl_bytea_wrapper_custom!(
    SignaturesDB,
    Vec<schnorr::Signature>,
    |signatures: &Vec<schnorr::Signature>| -> Vec<u8> {
        borsh::to_vec(
            &signatures
                .iter()
                .map(|signature| signature.serialize().to_vec())
                .collect::<Vec<_>>(),
        )
        .unwrap()
    },
    |x: &[u8]| -> Result<Vec<schnorr::Signature>, BoxDynError> {
        Ok(borsh::from_slice::<Vec<Vec<u8>>>(x)?
            .iter()
            .map(|signature| schnorr::Signature::from_slice(signature).unwrap())
            .collect())
    }
);

impl_text_wrapper_custom!(
    BlockHeaderDB,
    block::Header,
    |header: &block::Header| {
        let mut bytes = Vec::new();
        header.consensus_encode(&mut bytes).unwrap();
        bytes.to_hex_string(bitcoin::hex::Case::Lower)
    },
    |s: &str| -> Result<block::Header, BoxDynError> {
        let bytes = hex::decode(s)?;
        block::Header::consensus_decode(&mut bytes.as_slice())
            .map_err(|e| Box::new(e) as sqlx::error::BoxDynError)
    }
);

#[derive(Serialize, Deserialize, sqlx::FromRow)]
pub struct Utxodb {
    pub outpoint_db: OutPointDB,
    pub txout_db: TxOutDB,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TxOutDB(pub TxOut);

impl sqlx::Type<sqlx::Postgres> for TxOutDB {
    fn type_info() -> sqlx::postgres::PgTypeInfo {
        sqlx::postgres::PgTypeInfo::with_name("TEXT")
    }
}

impl Encode<'_, Postgres> for TxOutDB {
    fn encode_by_ref(&self, buf: &mut PgArgumentBuffer) -> sqlx::encode::IsNull {
        let s = bitcoin::consensus::encode::serialize_hex(&self.0);
        <&str as Encode<Postgres>>::encode_by_ref(&s.as_str(), buf)
    }
}

impl<'r> Decode<'r, Postgres> for TxOutDB {
    fn decode(value: PgValueRef<'r>) -> Result<Self, sqlx::error::BoxDynError> {
        let s = <&str as Decode<Postgres>>::decode(value)?;
        let x: TxOut = bitcoin::consensus::encode::deserialize_hex(s)?;
        Ok(TxOutDB(x))
    }
}
// TODO: Improve these tests by checking conversions both ways. Note: I couldn't
// find any ways to do this but it needs to be done.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        config::BridgeConfig,
        create_test_config_with_thread_name,
        database::Database,
        initialize_database,
        utils::initialize_logger,
        utils::{self, SECP},
        EVMAddress,
    };
    use bitcoin::{
        block::{self, Version},
        hashes::Hash,
        secp256k1::schnorr::Signature,
        Amount, BlockHash, CompactTarget, OutPoint, ScriptBuf, TxMerkleNode, TxOut, Txid,
    };
    use sqlx::{Executor, Type};
    use std::{env, thread};

    macro_rules! test_encode_decode_invariant {
        ($db_type:ident, $inner:ty, $test_value:expr, $table_name:expr, $column_type:expr) => {
            let config = create_test_config_with_thread_name!(None);
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

            let value: $inner = $test_value;
            let db_wrapper = $db_type(value);

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
            assert_eq!(retrieved.0, db_wrapper.0);

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
            OutPoint {
                txid: Txid::all_zeros(),
                vout: 0x45
            },
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
            TxOut {
                value: Amount::from_sat(0x45),
                script_pubkey: ScriptBuf::new(),
            },
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
            *utils::UNSPENDABLE_XONLY_PUBKEY,
            None,
            bitcoin::Network::Regtest,
        );
        let address = address.as_unchecked().clone();

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

        let evmaddress = EVMAddress([0x45u8; 20]);
        test_encode_decode_invariant!(EVMAddressDB, EVMAddress, evmaddress, "evmaddress", "TEXT");
    }

    #[tokio::test]
    async fn txiddb_encode_decode_invariant() {
        assert_eq!(
            TxidDB::type_info(),
            sqlx::postgres::PgTypeInfo::with_name("TEXT")
        );

        let txid = Txid::all_zeros();
        test_encode_decode_invariant!(TxidDB, Txid, txid, "txid", "TEXT");
    }

    #[tokio::test]
    async fn signaturedb_encode_decode_invariant() {
        assert_eq!(
            SignatureDB::type_info(),
            sqlx::postgres::PgTypeInfo::with_name("BYTEA")
        );

        let signature = Signature::from_slice(&[0u8; 64]).unwrap();
        test_encode_decode_invariant!(SignatureDB, Signature, signature, "signature", "BYTEA");
    }

    #[tokio::test]
    async fn signaturesdb_encode_decode_invariant() {
        assert_eq!(
            SignaturesDB::type_info(),
            sqlx::postgres::PgTypeInfo::with_name("BYTEA")
        );

        let signatures = vec![
            Signature::from_slice(&[0x1Fu8; 64]).unwrap(),
            Signature::from_slice(&[0x45u8; 64]).unwrap(),
        ];
        test_encode_decode_invariant!(
            SignaturesDB,
            Vec<Signature>,
            signatures,
            "signatures",
            "BYTEA"
        );
    }

    #[tokio::test]
    async fn blockhashdb_encode_decode_invariant() {
        assert_eq!(
            OutPointDB::type_info(),
            sqlx::postgres::PgTypeInfo::with_name("TEXT")
        );

        let blockhash = BlockHash::all_zeros();
        test_encode_decode_invariant!(BlockHashDB, BlockHash, blockhash, "blockhash", "TEXT");
    }

    #[tokio::test]
    async fn blockheaderdb_encode_decode_invariant() {
        assert_eq!(
            OutPointDB::type_info(),
            sqlx::postgres::PgTypeInfo::with_name("TEXT")
        );

        let blockheader = block::Header {
            version: Version::TWO,
            prev_blockhash: BlockHash::all_zeros(),
            merkle_root: TxMerkleNode::all_zeros(),
            time: 0,
            bits: CompactTarget::default(),
            nonce: 0,
        };
        test_encode_decode_invariant!(
            BlockHeaderDB,
            block::Header,
            blockheader,
            "blockheader",
            "TEXT"
        );
    }
}
