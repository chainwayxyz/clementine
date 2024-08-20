use std::str::FromStr;

use bitcoin::{address::NetworkUnchecked, Address, OutPoint, TxOut, Txid};
use serde::{Deserialize, Serialize};
use sqlx::{
    postgres::{PgArgumentBuffer, PgRow, PgValueRef},
    Decode, Encode, Postgres, Row,
};

use crate::{ByteArray66, EVMAddress, UTXO};

#[derive(Serialize, Deserialize)]
pub struct OutPointDB(pub OutPoint);

#[derive(Serialize, Deserialize)]
pub struct TxOutDB(pub TxOut);

#[derive(Serialize)]
pub struct AddressDB(pub Address<NetworkUnchecked>);

#[derive(Serialize, Deserialize)]
pub struct EVMAddressDB(pub EVMAddress);

#[derive(Serialize, Deserialize)]
pub struct TxidDB(pub Txid);

#[derive(Serialize, Deserialize)]
pub struct SignatureDB(pub secp256k1::schnorr::Signature);

#[derive(Serialize, Deserialize, sqlx::Type, sqlx::FromRow)]
#[sqlx(type_name = "utxodb")]
pub struct UTXODB {
    pub outpoint_db: OutPointDB,
    pub txout_db: TxOutDB,
}

impl sqlx::Type<sqlx::Postgres> for OutPointDB {
    fn type_info() -> sqlx::postgres::PgTypeInfo {
        sqlx::postgres::PgTypeInfo::with_name("TEXT")
    }
}

impl<'q> Encode<'q, Postgres> for OutPointDB {
    fn encode_by_ref(&self, buf: &mut PgArgumentBuffer) -> sqlx::encode::IsNull {
        // Encode as &str
        let s = self.0.to_string();
        <&str as Encode<Postgres>>::encode_by_ref(&s.as_str(), buf)
    }
}

impl<'r> Decode<'r, Postgres> for OutPointDB {
    fn decode(value: PgValueRef<'r>) -> Result<Self, sqlx::error::BoxDynError> {
        let s = <&str as Decode<Postgres>>::decode(value)?;
        Ok(OutPointDB(OutPoint::from_str(s)?))
    }
}

impl sqlx::Type<sqlx::Postgres> for AddressDB {
    fn type_info() -> sqlx::postgres::PgTypeInfo {
        sqlx::postgres::PgTypeInfo::with_name("TEXT")
    }
}

impl<'q> Encode<'q, Postgres> for AddressDB {
    fn encode_by_ref(&self, buf: &mut PgArgumentBuffer) -> sqlx::encode::IsNull {
        let s = self.0.clone().assume_checked().to_string();
        <&str as Encode<Postgres>>::encode_by_ref(&s.as_str(), buf)
    }
}

impl<'r> Decode<'r, Postgres> for AddressDB {
    fn decode(value: PgValueRef<'r>) -> Result<Self, sqlx::error::BoxDynError> {
        let s = <&str as Decode<Postgres>>::decode(value)?;
        Ok(AddressDB(Address::from_str(s)?))
    }
}

impl sqlx::Type<sqlx::Postgres> for EVMAddressDB {
    fn type_info() -> sqlx::postgres::PgTypeInfo {
        sqlx::postgres::PgTypeInfo::with_name("TEXT")
    }
}

impl<'q> Encode<'q, Postgres> for EVMAddressDB {
    fn encode_by_ref(&self, buf: &mut PgArgumentBuffer) -> sqlx::encode::IsNull {
        let s = hex::encode(self.0 .0);
        <&str as Encode<Postgres>>::encode_by_ref(&s.as_str(), buf)
    }
}

impl<'r> Decode<'r, Postgres> for EVMAddressDB {
    fn decode(value: PgValueRef<'r>) -> Result<Self, sqlx::error::BoxDynError> {
        let s = <&str as Decode<Postgres>>::decode(value)?;
        Ok(EVMAddressDB(EVMAddress(
            hex::decode(s).unwrap().try_into().unwrap(),
        )))
    }
}

impl sqlx::Type<sqlx::Postgres> for TxidDB {
    fn type_info() -> sqlx::postgres::PgTypeInfo {
        sqlx::postgres::PgTypeInfo::with_name("TEXT")
    }
}

impl<'q> Encode<'q, Postgres> for TxidDB {
    fn encode_by_ref(&self, buf: &mut PgArgumentBuffer) -> sqlx::encode::IsNull {
        let s = bitcoin::consensus::encode::serialize_hex(&self.0);
        <&str as Encode<Postgres>>::encode_by_ref(&s.as_str(), buf)
    }
}

impl<'r> Decode<'r, Postgres> for TxidDB {
    fn decode(value: PgValueRef<'r>) -> Result<Self, sqlx::error::BoxDynError> {
        let s = <&str as Decode<Postgres>>::decode(value)?;
        let x: Txid = bitcoin::consensus::encode::deserialize_hex(s)?;
        Ok(TxidDB(x))
    }
}

impl sqlx::Type<sqlx::Postgres> for TxOutDB {
    fn type_info() -> sqlx::postgres::PgTypeInfo {
        sqlx::postgres::PgTypeInfo::with_name("TEXT")
    }
}

impl<'q> Encode<'q, Postgres> for TxOutDB {
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

impl sqlx::Type<sqlx::Postgres> for SignatureDB {
    fn type_info() -> sqlx::postgres::PgTypeInfo {
        sqlx::postgres::PgTypeInfo::with_name("TEXT")
    }
}

impl<'q> Encode<'q, Postgres> for SignatureDB {
    fn encode_by_ref(&self, buf: &mut PgArgumentBuffer) -> sqlx::encode::IsNull {
        let s: String = secp256k1::schnorr::Signature::to_string(&self.0);
        <&str as Encode<Postgres>>::encode_by_ref(&s.as_str(), buf)
    }
}

impl<'r> Decode<'r, Postgres> for SignatureDB {
    fn decode(value: PgValueRef<'r>) -> Result<Self, sqlx::error::BoxDynError> {
        let s = <&str as Decode<Postgres>>::decode(value)?;
        let x: secp256k1::schnorr::Signature = secp256k1::schnorr::Signature::from_str(s)?;
        Ok(SignatureDB(x))
    }
}

/// Byte array of length 66

// impl sqlx::Type<sqlx::Postgres> for ByteArray66 {
//     fn type_info() -> sqlx::postgres::PgTypeInfo {
//         sqlx::postgres::PgTypeInfo::with_name("text")
//     }
// }

// impl<'q> Encode<'q, Postgres> for ByteArray66 {
//     fn encode_by_ref(&self, buf: &mut PgArgumentBuffer) -> sqlx::encode::IsNull {
//         // Encode as &str
//         let s = hex::encode(self.0);
//         <&str as Encode<Postgres>>::encode_by_ref(&s.as_str(), buf)
//     }
// }

// impl<'r> Decode<'r, Postgres> for ByteArray66 {
//     fn decode(value: PgValueRef<'r>) -> Result<Self, sqlx::error::BoxDynError> {
//         let s = <&str as Decode<Postgres>>::decode(value)?;
//         let x: [u8; 66] = hex::decode(s).unwrap().try_into().unwrap();
//         Ok(ByteArray66(x))
//     }
// }

impl sqlx::Type<sqlx::Postgres> for UTXO {
    fn type_info() -> sqlx::postgres::PgTypeInfo {
        sqlx::postgres::PgTypeInfo::with_name("TEXT")
    }
}

impl<'q> Encode<'q, Postgres> for UTXO {
    fn encode_by_ref(&self, buf: &mut PgArgumentBuffer) -> sqlx::encode::IsNull {
        let s = serde_json::to_string(self).unwrap();
        <&str as Encode<Postgres>>::encode_by_ref(&s.as_str(), buf)
    }
}

impl<'r> Decode<'r, Postgres> for UTXO {
    fn decode(value: PgValueRef<'r>) -> Result<Self, sqlx::error::BoxDynError> {
        let s = <&str as Decode<Postgres>>::decode(value)?;
        let x: UTXO = serde_json::from_str(s).unwrap();
        Ok(x)
    }
}

impl UTXO {
    fn decode_utxo_from_row(row: &PgRow, column_name: &str) -> Result<UTXO, sqlx::Error> {
        let s = row
            .try_get_raw(column_name)
            .map_err(|_| sqlx::Error::ColumnNotFound(column_name.into()))?;
        let str: &str = Decode::decode(s).map_err(|_| sqlx::Error::ColumnDecode {
            index: column_name.into(),
            source: Box::new(sqlx::Error::Decode("ColumnDecode Failed for UTXO".into())),
        })?;
        let res: UTXO = serde_json::from_str(str).unwrap();
        Ok(res)
    }
}
