use std::collections::HashMap;
use std::hash::Hash;

use crate::{errors::BridgeError, traits::db::BridgeDatabase};

#[derive(Debug, Clone)]
pub struct OperatorDB<K1, K2, V1, V2>
where
    K1: Eq + Hash,
    K2: Eq + Hash,
    V1: Clone,
    V2: Clone,
{
    pub signature_db: SignatureDB<K1, V1>,
    pub utxo_db: UtxoDB<K2, V2>,
}

impl<K1, K2, V1, V2> OperatorDB<K1, K2, V1, V2>
where
    K1: Eq + Hash,
    K2: Eq + Hash,
    V1: Clone,
    V2: Clone,
{
    pub fn new(signature_db: SignatureDB<K1, V1>, utxo_db: UtxoDB<K2, V2>) -> Self {
        OperatorDB {
            signature_db,
            utxo_db,
        }
    }
}

#[derive(Debug, Clone)]
pub struct SignatureDB<K, V>
where
    K: Eq + Hash,
    V: Clone,
{
    pub inner: HashMap<K, V>,
}

impl<K1, V1> SignatureDB<K1, V1>
where
    K1: Eq + Hash,
    V1: Clone,
{
    pub fn new(inner: HashMap<K1, V1>) -> Self {
        SignatureDB { inner }
    }
}

impl<K1, V1> BridgeDatabase<K1, V1> for SignatureDB<K1, V1>
where
    K1: Eq + Hash,
    V1: Clone,
{
    fn get(&self, key: K1) -> Option<V1> {
        self.inner.get(&key).cloned()
    }

    fn set(&mut self, key: K1, value: V1) -> Result<(), BridgeError> {
        let res = self.inner.insert(key, value);
        match res {
            Some(_) => Ok(()),
            None => Err(BridgeError::DBError),
        }
    }
}

#[derive(Debug, Clone)]
pub struct UtxoDB<K2, V2>
where
    K2: Eq + Hash,
    V2: Clone,
{
    pub inner: HashMap<K2, V2>,
}

impl<K, V> UtxoDB<K, V>
where
    K: Eq + Hash,
    V: Clone,
{
    pub fn new(inner: HashMap<K, V>) -> Self {
        UtxoDB { inner }
    }
}

impl<K2, V2> BridgeDatabase<K2, V2> for UtxoDB<K2, V2>
where
    K2: Eq + Hash,
    V2: Clone,
{
    fn get(&self, key: K2) -> Option<V2> {
        self.inner.get(&key).cloned()
    }

    fn set(&mut self, key: K2, value: V2) -> Result<(), BridgeError> {
        let res = self.inner.insert(key, value);
        match res {
            Some(_) => Ok(()),
            None => Err(BridgeError::DBError),
        }
    }
}
