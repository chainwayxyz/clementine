use std::ops::{Deref, DerefMut};

use super::common_db::CommonMockDB;

#[derive(Debug, Clone)]
pub struct VerifierMockDB {
    common_db: CommonMockDB,
}

impl VerifierMockDB {
    pub fn new() -> Self {
        Self {
            common_db: CommonMockDB::new(),
        }
    }
}

impl Deref for VerifierMockDB {
    type Target = CommonMockDB;

    fn deref(&self) -> &Self::Target {
        &self.common_db
    }
}

impl DerefMut for VerifierMockDB {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.common_db
    }
}
