//! # Wrapper For Converting Proto Structures

use super::clementine::{Outpoint, WinternitzPubkey};
use crate::errors::BridgeError;
use bitcoin::{hashes::Hash, OutPoint, Txid};
use bitvm::signatures::winternitz;

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

impl TryFrom<WinternitzPubkey> for winternitz::PublicKey {
    type Error = BridgeError;

    fn try_from(value: WinternitzPubkey) -> Result<Self, Self::Error> {
        let inner = value.digit_pubkey;

        inner
            .into_iter()
            .enumerate()
            .map(|(i, inner_vec)| {
                inner_vec.try_into().map_err(|e: Vec<u8>| {
                    BridgeError::RPCParamMalformed(
                        format!("digit_pubkey.[{}]", i),
                        format!("Incorrect length {:?}, expected 20", e.len()),
                    )
                })
            })
            .collect::<Result<Vec<[u8; 20]>, BridgeError>>()
    }
}
impl From<winternitz::PublicKey> for WinternitzPubkey {
    fn from(value: winternitz::PublicKey) -> Self {
        {
            let digit_pubkey = value.into_iter().map(|inner| inner.to_vec()).collect();

            WinternitzPubkey { digit_pubkey }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::rpc::clementine::{Outpoint, WinternitzPubkey};
    use bitcoin::{hashes::Hash, OutPoint, Txid};
    use bitvm::signatures::winternitz;

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

    #[test]
    fn from_proto_winternitz_public_key_to_bitvm() {
        let og_wpk = vec![[0x45u8; 20]];

        let rpc_wpk: WinternitzPubkey = og_wpk.clone().into();
        let rpc_converted_wpk: winternitz::PublicKey =
            rpc_wpk.try_into().expect("encoded wpk has to be valid");
        assert_eq!(og_wpk, rpc_converted_wpk);
    }
}
