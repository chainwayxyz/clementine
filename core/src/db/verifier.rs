use std::ops::{Deref, DerefMut};

use super::common::Database;

#[derive(Debug, Clone)]
pub struct VerifierDB {
    common_db: Database,
}

impl VerifierDB {
    pub fn new() -> Self {
        Self {
            common_db: Database::new(),
        }
    }
}

impl Deref for VerifierDB {
    type Target = Database;

    fn deref(&self) -> &Self::Target {
        &self.common_db
    }
}

impl DerefMut for VerifierDB {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.common_db
    }
}
