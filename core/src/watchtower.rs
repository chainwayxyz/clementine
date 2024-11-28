use crate::{database::Database, extended_rpc::ExtendedRpc};

#[derive(Debug, Clone)]
pub struct Watchtower {
    _rpc: ExtendedRpc,
    _db: Database,
}
