use serde::{Deserialize, Serialize};

/// Only the proof envelope is consumed; its authenticated journal is decoded after verification.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LightClientProofResponse {
    #[serde(with = "hex_vec")]
    pub proof: Vec<u8>,
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
