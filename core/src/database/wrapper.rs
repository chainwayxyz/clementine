use crate::EVMAddress;
use bitcoin::{address::NetworkUnchecked, Address, OutPoint, TxOut, Txid};
use serde::{Deserialize, Serialize};
use sqlx::{
    postgres::{PgArgumentBuffer, PgValueRef},
    Decode, Encode, Postgres,
};
use std::str::FromStr;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct OutPointDB(pub OutPoint);

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TxOutDB(pub TxOut);

#[derive(Serialize, Debug, Clone)]
pub struct AddressDB(pub Address<NetworkUnchecked>);

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct EVMAddressDB(pub EVMAddress);

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TxidDB(pub Txid);

#[derive(Serialize, Deserialize, sqlx::FromRow, Debug, Clone)]
pub struct SignatureDB(pub secp256k1::schnorr::Signature);

#[derive(Serialize, Deserialize, sqlx::FromRow)]
pub struct Utxodb {
    pub outpoint_db: OutPointDB,
    pub txout_db: TxOutDB,
}

impl sqlx::Type<sqlx::Postgres> for OutPointDB {
    fn type_info() -> sqlx::postgres::PgTypeInfo {
        sqlx::postgres::PgTypeInfo::with_name("TEXT")
    }
}

impl Encode<'_, Postgres> for OutPointDB {
    fn encode_by_ref(&self, buf: &mut PgArgumentBuffer) -> sqlx::encode::IsNull {
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

impl Encode<'_, Postgres> for AddressDB {
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

impl Encode<'_, Postgres> for EVMAddressDB {
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

impl Encode<'_, Postgres> for TxidDB {
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

impl sqlx::Type<sqlx::Postgres> for SignatureDB {
    fn type_info() -> sqlx::postgres::PgTypeInfo {
        sqlx::postgres::PgTypeInfo::with_name("TEXT")
    }
}

impl Encode<'_, Postgres> for SignatureDB {
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

#[cfg(test)]
mod tests {
    use super::OutPointDB;
    use crate::{
        database::wrapper::{AddressDB, EVMAddressDB, SignatureDB, TxOutDB, TxidDB},
        utils, EVMAddress,
    };
    use bitcoin::{hashes::Hash, Amount, OutPoint, ScriptBuf, TxOut, Txid};
    use secp256k1::schnorr::Signature;
    use sqlx::{encode::IsNull, postgres::PgArgumentBuffer, Encode, Type};

    #[test]
    fn outpointdb() {
        assert_eq!(
            OutPointDB::type_info(),
            sqlx::postgres::PgTypeInfo::with_name("TEXT")
        );

        let outpoint = OutPoint {
            txid: Txid::all_zeros(),
            vout: 0x45,
        };
        let outpointdb = OutPointDB(outpoint);

        let mut hex: PgArgumentBuffer = PgArgumentBuffer::default();
        if let IsNull::Yes = outpointdb.clone().encode(&mut hex) {
            panic!("Couldn't write {:?} to the buffer!", outpointdb);
        }
    }

    #[test]
    fn txoutdb() {
        assert_eq!(
            TxOutDB::type_info(),
            sqlx::postgres::PgTypeInfo::with_name("TEXT")
        );

        let txout = TxOut {
            value: Amount::from_sat(0x45),
            script_pubkey: ScriptBuf::new(),
        };
        let txoutdb = TxOutDB(txout);

        let mut hex: PgArgumentBuffer = PgArgumentBuffer::default();
        if let IsNull::Yes = txoutdb.clone().encode(&mut hex) {
            panic!("Couldn't write {:?} to the buffer!", txoutdb);
        }
    }

    #[test]
    fn addressdb() {
        assert_eq!(
            AddressDB::type_info(),
            sqlx::postgres::PgTypeInfo::with_name("TEXT")
        );

        let address = bitcoin::Address::p2tr(
            &utils::SECP,
            *utils::UNSPENDABLE_XONLY_PUBKEY,
            None,
            bitcoin::Network::Regtest,
        );
        let address = address.as_unchecked();
        let addressdb = AddressDB(address.clone());

        let mut hex: PgArgumentBuffer = PgArgumentBuffer::default();
        if let IsNull::Yes = addressdb.clone().encode(&mut hex) {
            panic!("Couldn't write {:?} to the buffer!", addressdb);
        }
    }

    #[test]
    fn evmaddressdb() {
        assert_eq!(
            EVMAddressDB::type_info(),
            sqlx::postgres::PgTypeInfo::with_name("TEXT")
        );

        let evmaddress = EVMAddress([0x45u8; 20]);
        let evmaddressdb = EVMAddressDB(evmaddress);

        let mut hex: PgArgumentBuffer = PgArgumentBuffer::default();
        if let IsNull::Yes = evmaddressdb.clone().encode(&mut hex) {
            panic!("Couldn't write {:?} to the buffer!", evmaddressdb);
        }
    }

    #[test]
    fn txiddb() {
        assert_eq!(
            TxidDB::type_info(),
            sqlx::postgres::PgTypeInfo::with_name("TEXT")
        );

        let txid = Txid::all_zeros();
        let txiddb = TxidDB(txid);

        let mut hex: PgArgumentBuffer = PgArgumentBuffer::default();
        if let IsNull::Yes = txiddb.clone().encode(&mut hex) {
            panic!("Couldn't write {:?} to the buffer!", txiddb);
        }
    }

    #[test]
    fn signaturedb() {
        assert_eq!(
            SignatureDB::type_info(),
            sqlx::postgres::PgTypeInfo::with_name("TEXT")
        );

        let signature = Signature::from_slice(&[0u8; 64]).unwrap();
        let signaturedb = SignatureDB(signature);

        let mut hex: PgArgumentBuffer = PgArgumentBuffer::default();
        if let IsNull::Yes = signaturedb.clone().encode(&mut hex) {
            panic!("Couldn't write {:?} to the buffer!", signaturedb);
        }
    }
}
