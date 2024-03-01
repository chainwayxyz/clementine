use serde::{de::DeserializeOwned, Serialize};

use crate::errors::BridgeError;

pub trait BridgeDatabase<K, V>
where
    K: KeyTrait,
    V: ValueTrait,
{
    fn get(&self, key: &K) -> Option<V>;

    fn set(&mut self, key: K, value: V) -> Result<(), BridgeError>;
}

pub trait KeyTrait: Clone + Serialize {
    fn serialized_key(&self) -> Result<Vec<u8>, BridgeError> {
        let serialized = serde_json::to_vec(self)?;
        Ok(serialized)
    }
}

pub trait ValueTrait: Clone + Serialize + DeserializeOwned {
    fn deserialized_value(value_stored: &Vec<u8>) -> Result<Self, BridgeError> {
        let deserialized = serde_json::from_slice(value_stored)?;
        Ok(deserialized)
    }
    fn serialized_value(&self) -> Result<Vec<u8>, BridgeError> {
        let serialized = serde_json::to_vec(self)?;
        Ok(serialized)
    }
}
