use std::collections::HashMap;

use crate::errors::BridgeError;

pub trait Database {
    fn get<K, V>(&self, key: K) -> Option<V>
    where
        K: Into<String>,
        V: Clone + std::convert::From<std::string::String>;

    fn set<K, V>(&self, key: K, value: V) -> Result<(), BridgeError>
    where
        K: Into<String>,
        V: Clone + std::convert::From<std::string::String>;
}

#[derive(Debug, Clone)]
pub struct GeneralDatabase {
    data: HashMap<String, String>,
}

impl Database for GeneralDatabase {
    fn get<K, V>(&self, key: K) -> Option<V>
    where
        K: Into<String>,
        V: Clone + std::convert::From<std::string::String>,
    {
        self.data.get(&key.into()).map(|v| v.clone().into())
    }

    fn set<K, V>(&self, key: K, value: V) -> Result<(), BridgeError>
    where
        K: Into<String>,
        V: Clone + std::convert::From<std::string::String>,
    {
        let key_str = key.into();
        // Assuming value also implements Into<String>
        self.data.insert(key_str, value.into());
        Ok(())
    }
}
