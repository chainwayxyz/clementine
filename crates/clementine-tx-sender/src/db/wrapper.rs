//! Minimal SQLx wrapper types for tx-sender.

use bitcoin::hashes::Hash as _;
use bitcoin::Txid;
use sqlx::error::BoxDynError;
use sqlx::postgres::{PgArgumentBuffer, PgTypeInfo, PgValueRef};
use sqlx::{Decode, Encode, Postgres, Type};

/// Store `bitcoin::Txid` as `BYTEA` in Postgres.
#[derive(sqlx::FromRow, Debug, Clone)]
pub struct TxidDB(pub Txid);

impl Type<Postgres> for TxidDB {
    fn type_info() -> PgTypeInfo {
        PgTypeInfo::with_name("BYTEA")
    }
}

impl Encode<'_, Postgres> for TxidDB {
    fn encode_by_ref(
        &self,
        buf: &mut PgArgumentBuffer,
    ) -> Result<sqlx::encode::IsNull, BoxDynError> {
        let bytes = self.0.to_byte_array();
        <&[u8] as Encode<Postgres>>::encode_by_ref(&bytes.as_ref(), buf)
    }
}

impl<'r> Decode<'r, Postgres> for TxidDB {
    fn decode(value: PgValueRef<'r>) -> Result<Self, BoxDynError> {
        let bytes = <Vec<u8> as Decode<Postgres>>::decode(value)?;
        Ok(Self(Txid::from_slice(&bytes)?))
    }
}

// Enable binding Vec<TxidDB> as bytea[] in queries (e.g., WHERE txid = ANY($1)).
impl sqlx::postgres::PgHasArrayType for TxidDB {
    fn array_type_info() -> PgTypeInfo {
        PgTypeInfo::with_name("_bytea")
    }
}
