use super::common::Database;
use crate::config::BridgeConfig;
use std::ops::{Deref, DerefMut};

#[derive(Debug, Clone)]
pub struct OperatorDB {
    common_db: Database,
}

impl OperatorDB {
    pub async fn new(config: BridgeConfig) -> Self {
        Self {
            common_db: Database::new(config).await.unwrap(),
        }
    }
}

impl Deref for OperatorDB {
    type Target = Database;

    fn deref(&self) -> &Self::Target {
        &self.common_db
    }
}

impl DerefMut for OperatorDB {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.common_db
    }
}
