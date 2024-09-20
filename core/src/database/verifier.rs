use super::common::Database;
use crate::config::BridgeConfig;
use std::ops::Deref;

/// TODO: Remove this wrapper and use Database directly.
#[derive(Debug, Clone)]
pub struct VerifierDB {
    database: Database,
}

impl VerifierDB {
    pub async fn new(config: BridgeConfig) -> Self {
        Self {
            database: Database::new(config).await.unwrap(),
        }
    }
}

impl Deref for VerifierDB {
    type Target = Database;

    fn deref(&self) -> &Self::Target {
        &self.database
    }
}
