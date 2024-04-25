use std::ops::{Deref, DerefMut};

use super::common::Database;

#[derive(Debug, Clone)]
pub struct VerifierMockDB {
    common_db: Database,
}

impl VerifierMockDB {
    pub fn new() -> Self {
        Self {
            common_db: Database::new(),
        }
    }
}

impl Deref for VerifierMockDB {
    type Target = Database;

    fn deref(&self) -> &Self::Target {
        &self.common_db
    }
}

impl DerefMut for VerifierMockDB {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.common_db
    }
}
