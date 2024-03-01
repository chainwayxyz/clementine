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

    fn set(&mut self, key: &K, value: &V) -> Result<(), BridgeError> {
        println!("set");
        println!("key: {:?}", key);
        println!("value: {:?}", value);
        let serialized_key = K::serialized_key(key).unwrap();
        println!("serialized_key: {:?}", serialized_key);
        let serialized_value = V::serialized_value(value).unwrap();
        println!("serialized_value: {:?}", serialized_value);
        let res = self.inner.insert(serialized_key, serialized_value);
        
        match res {
            None => Ok(()),
            Some(_) =>  Err(BridgeError::DBError),
        }
    }
}

impl KeyTrait for String {
    fn serialized_key(&self) -> Result<Vec<u8>, BridgeError> {
        Ok(self.as_bytes().to_vec())
    }
}

impl ValueTrait for String {
    fn deserialized_value(value_stored: &Vec<u8>) -> Result<Self, BridgeError> {
        let deserialized = String::from_utf8(value_stored.to_vec())?;
        Ok(deserialized)
    }
    fn serialized_value(&self) -> Result<Vec<u8>, BridgeError> {
        Ok(self.as_bytes().to_vec())
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::traits::db::BridgeDatabase;

    #[test]
    fn test_operator_db() {
        let mut db = OperatorDB::new();
        let key = "key".to_string();
        let value = "value".to_string();
        db.set(&key, &value).unwrap();
        let res: String = db.get(&key).unwrap();
        assert_eq!(res, value);
    }
}