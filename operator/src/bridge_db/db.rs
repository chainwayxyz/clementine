use crate::traits::db::KeyTrait;
use crate::traits::db::ValueTrait;
use std::collections::HashMap;

use crate::{errors::BridgeError, traits::db::BridgeDatabase};

#[derive(Debug, Clone)]
pub struct OperatorDB {
    pub inner: HashMap<Vec<u8>, Vec<u8>>,
}

impl OperatorDB {
    pub fn new() -> Self {
        let inner = HashMap::new();
        OperatorDB { inner }
    }
}

impl<K, V> BridgeDatabase<K, V> for OperatorDB
where
    K: KeyTrait,
    V: ValueTrait,
{
    fn get(&self, key: &K) -> Option<V> {
        let serialized_key = K::serialized_key(key).unwrap();
        match self.inner.get(&serialized_key).cloned() {
            Some(value) => Some(V::deserialized_value(&value).unwrap()),
            None => None,
        }
    }

    fn set(&mut self, key: K, value: V) -> Result<(), BridgeError> {
        let serialized_key = K::serialized_key(&key).unwrap();
        let serialized_value = V::serialized_value(&value).unwrap();
        let res = self.inner.insert(serialized_key, serialized_value);
        match res {
            Some(_) => Ok(()),
            None => Err(BridgeError::DBError),
        }
    }
}
