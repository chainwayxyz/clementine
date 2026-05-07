//! Postgres database layer for tx-sender.

use crate::config::TxSenderPostgresConfig;
use clementine_errors::BridgeError;
use secrecy::ExposeSecret;
use sqlx::postgres::PgConnectOptions;
use sqlx::ConnectOptions;
use sqlx::{Pool, Postgres};
use std::time::Duration;

pub const DEFAULT_MAX_CONNECTIONS: u32 = 10;

/// A thin Postgres wrapper dedicated to tx-sender tables.
#[derive(Clone, Debug)]
pub struct TxSenderDb {
    pool: Pool<Postgres>,
}

pub type TxSenderTransaction = sqlx::Transaction<'static, Postgres>;
pub type TxSenderDbTx<'a> = &'a mut TxSenderTransaction;

#[cfg(feature = "citrea")]
pub mod citrea;
pub mod tx_sender;
pub mod wrapper;

/// Executes a query with a transaction if it is provided.
#[macro_export]
macro_rules! txsender_execute_query_with_tx {
    ($pool:expr, $tx:expr, $query:expr, $method:ident) => {
        match $tx {
            Some(tx) => $query.$method(&mut **tx).await,
            None => $query.$method($pool).await,
        }
    };
}

impl TxSenderDb {
    pub fn from_pool(pool: Pool<Postgres>) -> Self {
        Self { pool }
    }

    pub fn pool(&self) -> &Pool<Postgres> {
        &self.pool
    }

    pub async fn connect(cfg: &TxSenderPostgresConfig) -> Result<Self, BridgeError> {
        let mut opt = PgConnectOptions::default();
        opt = opt.host(cfg.host.as_str());
        opt = opt.port(cfg.port);
        opt = opt.username(cfg.user.expose_secret());
        opt = opt.password(cfg.password.expose_secret());
        opt = opt.database(cfg.dbname.as_str());
        opt = opt.log_slow_statements(log::LevelFilter::Debug, Duration::from_secs(3));

        let pool = sqlx::postgres::PgPoolOptions::new()
            .acquire_slow_level(log::LevelFilter::Debug)
            .max_connections(DEFAULT_MAX_CONNECTIONS)
            .connect_with(opt)
            .await
            .map_err(BridgeError::DatabaseError)?;

        Ok(Self { pool })
    }

    pub async fn begin_transaction(&self) -> Result<TxSenderTransaction, BridgeError> {
        Ok(self.pool.begin().await?)
    }

    pub async fn commit_transaction(&self, tx: TxSenderTransaction) -> Result<(), BridgeError> {
        tx.commit().await.map_err(Into::into)
    }

    /// Runs tx-sender schema initialization/migrations.
    pub async fn run_migrations(&self) -> Result<(), BridgeError> {
        static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!();
        MIGRATOR
            .run(&self.pool)
            .await
            .map_err(|e| BridgeError::Eyre(e.into()))?;
        Ok(())
    }
}
