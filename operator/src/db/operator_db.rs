use crate::{errors::BridgeError, traits::db::Database};

#[derive(Debug, Clone)]
pub struct OperatorDB<T>
where
    T: Database,
{
    pub inner: T,
}

impl<T: Database> OperatorDB<T> {
    pub fn new(inner: T) -> Self {
        OperatorDB { inner }
    }
}

impl<T: Database> Database for OperatorDB<T> {
    fn get<K, V>(&self, key: K) -> Option<V> {
        self.inner.get(key)
    }

    fn set<K, V>(&self, key: K, value: V) -> Result<(), BridgeError> {
        self.inner.set(key, value)
    }
}
