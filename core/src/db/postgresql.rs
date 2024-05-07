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
use sqlx::{postgres::PgRow, Pool, Postgres};
use std::io::Error;

#[derive(Debug, Clone)]
pub struct PostgreSQLDB {
    host: String,
    database: String,
    user: String,
    password: String,
    port: usize,
    connection: Option<Pool<Postgres>>,
}

impl PostgreSQLDB {
    /// Creates a new `PostgreSQLDB` and copies configuration from given
    /// `BridgeConfig`.
    pub fn new(config: BridgeConfig) -> Self {
        Self {
            host: config.db_host,
            database: config.db_name,
            user: config.db_user,
            password: config.db_password,
            port: config.db_port,
            ..Default::default()
        }
    }

    /// Private function that runs given query through database and returns
    /// result.
    async fn run_query(&self, query: &str) -> Result<Vec<PgRow>, sqlx::Error> {
        tracing::debug!("Running query: {}", query);

        let conn = match self.connection.clone() {
            Some(c) => c,
            None => return Err(sqlx::Error::Io(Error::last_os_error())),
        };

        let res = sqlx::query(query).fetch_all(&conn).await;

        res
    }

    /// Start a pool connection to PostgreSQL database.
    pub async fn connect(&mut self) -> Result<(), BridgeError> {
        let url = "postgresql://".to_owned()
            + self.host.as_str()
            + ":"
            + self.port.to_string().as_str()
            + "?dbname="
            + self.database.as_str()
            + "&user="
            + self.user.as_str()
            + "&password="
            + self.password.as_str();
        tracing::debug!("Connecting database: {}", url);

        self.connection = match sqlx::PgPool::connect(url.as_str()).await {
            Ok(c) => Some(c),
            Err(e) => return Err(BridgeError::DatabaseError(e)),
        };

        Ok(())
    }

    /// Reads specified table's contents.
    pub async fn read(&self, table: &str) -> Result<Vec<PgRow>, sqlx::Error> {
        let query = format!("SELECT * FROM {};", table);
        let res = self.run_query(query.as_str()).await?;

        Ok(res)
    }

    /// Inserts given data to the specified table.
    pub async fn write(&self, table: &str, value: &str) -> Result<(), sqlx::Error> {
        let query = format!("INSERT INTO {} VALUES ({});", table, value);
        self.run_query(query.as_str()).await?;

        Ok(())
    }
}

impl Default for PostgreSQLDB {
    fn default() -> Self {
        Self {
            host: "postgres".to_string(),
            database: "postgres".to_string(),
            user: "postgres".to_string(),
            password: "postgres".to_string(),
            port: 5432,
            connection: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::PostgreSQLDB;
    use crate::{config::BridgeConfig, test_common};
    use sqlx::Row;

    #[test]
    fn new_from_config() {
        let mut config = BridgeConfig::new();
        config.db_host = "new_from_config".to_string();
        config.db_name = "new_from_config".to_string();
        config.db_user = "new_from_config".to_string();
        config.db_password = "new_from_config".to_string();
        config.db_port = 123;

        let db: PostgreSQLDB = PostgreSQLDB::new(config.clone());

        assert_eq!(db.host, config.db_host);
        assert_eq!(db.user, config.db_user);
        assert_eq!(db.password, config.db_password);
        assert_eq!(db.port, config.db_port);
    }

    /// An error should be returned if database configuration is invalid.
    #[tokio::test]
    async fn invalid_connection() {
        let mut config = BridgeConfig::new();
        config.db_host = "nonexistinghost".to_string();
        config.db_name = "nonexistingpassword".to_string();
        config.db_user = "nonexistinguser".to_string();
        config.db_password = "nonexistingpassword".to_string();
        config.db_port = 123;

        let mut db: PostgreSQLDB = PostgreSQLDB::new(config);

        match db.connect().await {
            Ok(()) => {
                assert!(false);
            }
            Err(e) => {
                println!("{}", e);
                assert!(true);
            }
        };
    }

    /// A connection object should be returned if database configuration is
    /// valid.
    ///
    /// This test is ignored because of host environment might not have a
    /// PostgreSQL installed. If it is intalled and configured correctly,
    /// `test_common::ENV_CONF_FILE` can be set as environment variable and
    /// test can be run with `--include-ignored` flag.
    #[tokio::test]
    #[ignore]
    async fn valid_connection() {
        let config =
            test_common::get_test_config_from_environment("test_config.toml".to_string()).unwrap();

        let mut db: PostgreSQLDB = PostgreSQLDB::new(config);

        match db.connect().await {
            Ok(()) => {
                assert!(true);
            }
            Err(e) => {
                eprintln!("{}", e);
                assert!(false);
            }
        };
    }

    #[tokio::test]
    async fn write_read_string() {
        let config =
            test_common::get_test_config_from_environment("test_config.toml".to_string()).unwrap();

        let mut db: PostgreSQLDB = PostgreSQLDB::new(config);

        db.connect().await.unwrap();

        db.write("test_table", "'test_data'").await.unwrap();

        let ret = db.read("test_table").await.unwrap();
        let mut is_found: bool = false;

        for i in ret {
            if i.get::<String, _>(0) == "test_data" {
                is_found = true;
                break;
            }
        }

        assert!(is_found);
    }

    #[tokio::test]
    async fn write_read_int() {
        let config =
            test_common::get_test_config_from_environment("test_config.toml".to_string()).unwrap();

        let mut db: PostgreSQLDB = PostgreSQLDB::new(config);

        db.connect().await.unwrap();

        db.write(
            "test_table",
            ("'temp',".to_string() + 0x45.to_string().as_str()).as_str(),
        )
        .await
        .unwrap();

        let ret = db.read("test_table").await.unwrap();
        let mut is_found: bool = false;

        for i in ret {
            if let Ok(0x45) = i.try_get::<i32, _>(1) {
                is_found = true;
                break;
            }
        }

        assert!(is_found);
    }
}
