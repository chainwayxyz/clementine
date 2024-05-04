//! # PostgreSQL Database Operations
//!
//! This module includes a wrapper for PostgreSQL. It uses sqlx for interacting
//! with PostgreSQL server.
//!
//! ## Expected Database Structure
//!
//! This module expects that host computer has PostgreSQL is installed and
//! configured properly. Expected configuration follows:
//!
//! * A user and it's password
//! * A database that the user can access
//! * Database should be configured with the SQL script that can be found in ...
//!
//! ## Module Capabilities

use crate::{config::BridgeConfig, errors::BridgeError};
use sqlx::{Pool, Postgres};

pub struct PostgreSQLDB {
    host: String,
    user: String,
    password: String,
    port: usize,
}

impl PostgreSQLDB {
    pub fn new(config: BridgeConfig) -> Self {
        Self {
            host: config.db_host,
            user: config.db_user,
            password: config.db_password,
            port: config.db_port,
            ..Default::default()
        }
    }

    pub async fn connect(&self) -> Result<Pool<Postgres>, BridgeError> {
        match sqlx::PgPool::connect(self.host.as_str()).await {
            Ok(c) => Ok(c),
            Err(e) => Err(BridgeError::DatabaseError(e)),
        }
    }
}

impl Default for PostgreSQLDB {
    fn default() -> Self {
        Self {
            host: "postgres".to_string(),
            user: "postgres".to_string(),
            password: "postgres".to_string(),
            port: 5432,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::PostgreSQLDB;
    use crate::config::BridgeConfig;

    /// An error should be returned if database connection is invalid.
    #[tokio::test]
    async fn invalid_connection() {
        let mut config = BridgeConfig::new();
        config.db_host = "nonexistinghost".to_string();
        config.db_user = "nonexistinguser".to_string();
        config.db_password = "nonexistingpassword".to_string();
        config.db_port = 123;

        let db: PostgreSQLDB = PostgreSQLDB::new(config);

        match db.connect().await {
            Ok(_connection) => {
                assert!(false);
            }
            Err(e) => {
                println!("{}", e);
                assert!(true);
            }
        };
    }
}
