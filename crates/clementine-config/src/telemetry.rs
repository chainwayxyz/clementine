//! Telemetry configuration.

use serde::Deserialize;

/// Configuration for telemetry/metrics endpoints.
#[derive(Debug, Clone, Deserialize)]
pub struct TelemetryConfig {
    /// Host address for the telemetry server.
    pub host: String,
    /// Port number for the telemetry server.
    pub port: u16,
}

impl Default for TelemetryConfig {
    fn default() -> Self {
        Self {
            host: "0.0.0.0".to_string(),
            port: 8081,
        }
    }
}
