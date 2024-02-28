use crate::traits::db::Database;

#[derive(Debug, Clone)]
pub struct VerifierDB<T>
where
    T: Database,
{
    pub inner: T,
}

impl<T: Database> VerifierDB<T> {
    pub fn new(inner: T) -> Self {
        VerifierDB { inner }
    }
}
