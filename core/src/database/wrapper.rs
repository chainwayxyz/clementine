use crate::EVMAddress;
use bitcoin::{
    address::NetworkUnchecked,
    block,
    consensus::{Decodable, Encodable},
    hex::DisplayHex,
    Address, OutPoint, TxOut, Txid,
};
use serde::{Deserialize, Serialize};
use sqlx::{
    postgres::{PgArgumentBuffer, PgValueRef},
    Decode, Encode, Postgres,
};
use std::str::FromStr;

#[derive(Serialize, Deserialize, sqlx::FromRow)]
pub struct Utxodb {
    pub outpoint_db: OutPointDB,
    pub txout_db: TxOutDB,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct OutPointDB(pub OutPoint);

impl sqlx::Type<sqlx::Postgres> for OutPointDB {
    fn type_info() -> sqlx::postgres::PgTypeInfo {
        sqlx::postgres::PgTypeInfo::with_name("TEXT")
    }
}
impl<'q> Encode<'q, Postgres> for OutPointDB {
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

#[derive(Serialize, Debug, Clone)]
pub struct AddressDB(pub Address<NetworkUnchecked>);

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

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct EVMAddressDB(pub EVMAddress);

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

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TxidDB(pub Txid);

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

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TxOutDB(pub TxOut);

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

#[derive(Serialize, Deserialize, sqlx::FromRow, Debug, Clone)]
pub struct SignatureDB(pub secp256k1::schnorr::Signature);

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

#[derive(Serialize, Deserialize, sqlx::FromRow, Debug, Clone)]
pub struct BlockHashDB(pub block::BlockHash);

impl sqlx::Type<sqlx::Postgres> for BlockHashDB {
    fn type_info() -> sqlx::postgres::PgTypeInfo {
        sqlx::postgres::PgTypeInfo::with_name("TEXT")
    }
}
impl<'q> Encode<'q, Postgres> for BlockHashDB {
    fn encode_by_ref(&self, buf: &mut PgArgumentBuffer) -> sqlx::encode::IsNull {
        let s = self.0.to_string();
        <&str as Encode<Postgres>>::encode_by_ref(&s.as_str(), buf)
    }
}
impl<'r> Decode<'r, Postgres> for BlockHashDB {
    fn decode(value: PgValueRef<'r>) -> Result<Self, sqlx::error::BoxDynError> {
        let s = <&str as Decode<Postgres>>::decode(value)?;
        Ok(BlockHashDB(block::BlockHash::from_str(s)?))
    }
}

#[derive(Serialize, Deserialize, sqlx::FromRow, Debug, Clone)]
pub struct BlockHeaderDB(pub block::Header);

impl sqlx::Type<sqlx::Postgres> for BlockHeaderDB {
    fn type_info() -> sqlx::postgres::PgTypeInfo {
        sqlx::postgres::PgTypeInfo::with_name("TEXT")
    }
}
impl<'q> Encode<'q, Postgres> for BlockHeaderDB {
    fn encode_by_ref(&self, buf: &mut PgArgumentBuffer) -> sqlx::encode::IsNull {
        let mut hex: Vec<u8> = Vec::new();
        self.0.consensus_encode(&mut hex).unwrap();
        let s = hex.to_hex_string(bitcoin::hex::Case::Lower);
        <&str as Encode<Postgres>>::encode_by_ref(&s.as_str(), buf)
    }
}
impl<'r> Decode<'r, Postgres> for BlockHeaderDB {
    fn decode(value: PgValueRef<'r>) -> Result<Self, sqlx::error::BoxDynError> {
        let mut s = value.as_bytes()?;
        let x: block::Header = block::Header::consensus_decode(&mut s)?;
        Ok(BlockHeaderDB(x))
    }
}

#[cfg(test)]
mod tests {
    use super::OutPointDB;
    use crate::{
        database::wrapper::{
            AddressDB, BlockHashDB, BlockHeaderDB, EVMAddressDB, SignatureDB, TxOutDB, TxidDB,
        },
        utils, EVMAddress,
    };
    use bitcoin::{
        block::{self, Version},
        hashes::Hash,
        Amount, BlockHash, CompactTarget, OutPoint, ScriptBuf, TxMerkleNode, TxOut, Txid,
    };
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

    #[test]
    fn blockhashdb() {
        assert_eq!(
            OutPointDB::type_info(),
            sqlx::postgres::PgTypeInfo::with_name("TEXT")
        );

        let blockhash = BlockHash::all_zeros();
        let blockhashdb = BlockHashDB(blockhash);

        let mut hex: PgArgumentBuffer = PgArgumentBuffer::default();
        if let IsNull::Yes = blockhashdb.clone().encode(&mut hex) {
            panic!("Couldn't write {:?} to the buffer!", blockhashdb);
        }
    }

    #[test]
    fn blockheaderdb() {
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
        let blockheaderdb = BlockHeaderDB(blockheader);

        let mut hex: PgArgumentBuffer = PgArgumentBuffer::default();
        if let IsNull::Yes = blockheaderdb.clone().encode_by_ref(&mut hex) {
            panic!("Couldn't write {:?} to the buffer!", blockheaderdb);
        }
    }
}
