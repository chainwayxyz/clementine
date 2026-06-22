use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, BorshDeserialize, BorshSerialize, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LightClientCircuitInputRpcResponse {
    #[serde(with = "u64_hex")]
    pub(crate) l1_height: u64,
    #[serde(with = "hex_array_32")]
    pub(crate) l1_hash: [u8; 32],
    #[serde(with = "hex_vec")]
    pub(crate) input: Vec<u8>,
}

mod u64_hex {
    use serde::{
        de::{self, Visitor},
        Deserializer, Serializer,
    };
    use std::fmt;

    pub fn serialize<S>(height: &u64, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&format!("0x{height:x}"))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<u64, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct U64Visitor;

        impl<'de> Visitor<'de> for U64Visitor {
            type Value = u64;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a u64 or hex string")
            }

            fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
                Ok(value)
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                if let Some(hex) = value.strip_prefix("0x") {
                    u64::from_str_radix(hex, 16).map_err(E::custom)
                } else {
                    value.parse::<u64>().map_err(E::custom)
                }
            }
        }

        deserializer.deserialize_any(U64Visitor)
    }
}

mod hex_vec {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&format!("0x{}", hex::encode(bytes)))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let encoded = String::deserialize(deserializer)?;
        hex::decode(encoded.strip_prefix("0x").unwrap_or(&encoded))
            .map_err(serde::de::Error::custom)
    }
}

mod hex_array_32 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&format!("0x{}", hex::encode(bytes)))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 32], D::Error>
    where
        D: Deserializer<'de>,
    {
        let encoded = String::deserialize(deserializer)?;
        let bytes = hex::decode(encoded.strip_prefix("0x").unwrap_or(&encoded))
            .map_err(serde::de::Error::custom)?;
        bytes
            .try_into()
            .map_err(|_| serde::de::Error::custom("expected 32-byte hex value"))
    }
}
