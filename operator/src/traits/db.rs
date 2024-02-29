use crate::errors::BridgeError;
use std::hash::Hash;

pub trait BridgeDatabase<K, V>
where
    K: Eq + Hash,
    V: Clone,
{
    fn get(&self, key: K) -> Option<V>;

    fn set(&mut self, key: K, value: V) -> Result<(), BridgeError>;
}
