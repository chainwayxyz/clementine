use crate::{database::Database, extended_rpc::ExtendedRpc};
use bitcoin_mock_rpc::RpcApiWrapper;

#[derive(Debug, Clone)]
pub struct Watchtower<R>
where
    R: RpcApiWrapper,
{
    _rpc: ExtendedRpc<R>,
    _db: Database,
}
