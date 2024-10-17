//! # Wrapper For Converting Proto Structures

use super::clementine::Outpoint;
use crate::errors::BridgeError;
use bitcoin::{hashes::Hash, OutPoint, Txid};

impl TryFrom<Outpoint> for OutPoint {
    type Error = BridgeError;

    fn try_from(value: Outpoint) -> Result<Self, Self::Error> {
        let hash = match Hash::from_slice(&value.txid) {
            Ok(h) => h,
            Err(e) => return Err(BridgeError::FromSliceError(e)),
        };

        Ok(OutPoint {
            txid: Txid::from_raw_hash(hash),
            vout: value.vout,
        })
    }
}
impl From<OutPoint> for Outpoint {
    fn from(value: OutPoint) -> Self {
        Outpoint {
            txid: value.txid.to_byte_array().to_vec(),
            vout: value.vout,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::rpc::clementine::Outpoint;
    use bitcoin::{hashes::Hash, OutPoint, Txid};

    #[test]
    fn from_bitcoin_outpoint_to_proto_outpoint() {
        let og_outpoint = OutPoint {
            txid: Txid::from_raw_hash(Hash::from_slice(&[0x1F; 32]).unwrap()),
            vout: 0x45,
        };

        let proto_outpoint: Outpoint = og_outpoint.into();
        let bitcoin_outpoint: OutPoint = proto_outpoint.try_into().unwrap();
        assert_eq!(og_outpoint, bitcoin_outpoint);

        let proto_outpoint = Outpoint {
            txid: vec![0x1F; 32],
            vout: 0x45,
        };
        let bitcoin_outpoint: OutPoint = proto_outpoint.try_into().unwrap();
        assert_eq!(og_outpoint, bitcoin_outpoint);
    }

    #[test]
    fn from_proto_outpoint_to_bitcoin_outpoint() {
        let og_outpoint = Outpoint {
            txid: vec![0x1F; 32],
            vout: 0x45,
        };

        let bitcoin_outpoint: OutPoint = og_outpoint.clone().try_into().unwrap();
        let proto_outpoint: Outpoint = bitcoin_outpoint.into();
        assert_eq!(og_outpoint, proto_outpoint);

        let bitcoin_outpoint = OutPoint {
            txid: Txid::from_raw_hash(Hash::from_slice(&[0x1F; 32]).unwrap()),
            vout: 0x45,
        };
        let proto_outpoint: Outpoint = bitcoin_outpoint.into();
        assert_eq!(og_outpoint, proto_outpoint);
    }
}
