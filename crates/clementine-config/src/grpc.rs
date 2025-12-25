//! gRPC configuration.

use serde::Deserialize;

/// gRPC client/server limits configuration.
#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct GrpcLimits {
    /// Maximum message size in bytes.
    pub max_message_size: usize,
    /// Request timeout in seconds.
    pub timeout_secs: u64,
    /// TCP keepalive interval in seconds.
    pub tcp_keepalive_secs: u64,
    /// Request concurrency limit.
    pub req_concurrency_limit: usize,
    /// Rate limit request count.
    pub ratelimit_req_count: usize,
    /// Rate limit request interval in seconds.
    pub ratelimit_req_interval_secs: u64,
}

impl Default for GrpcLimits {
    fn default() -> Self {
        Self {
            max_message_size: 4 * 1024 * 1024,
            timeout_secs: 12 * 60 * 60, // 12 hours
            tcp_keepalive_secs: 60,
            req_concurrency_limit: 300, // 100 deposits at the same time
            ratelimit_req_count: 1000,
            ratelimit_req_interval_secs: 60,
        }
    }
}
