use secrecy::SecretString;
use serde::Deserialize;

// This is the endpoint that provides `discounted_multiplier` and `submit_fee_rate`.
pub const DEFAULT_FEE_RATE_ENDPOINT: &str = "/rest-api/getrate";
pub const DEFAULT_SUBMIT_PACKAGE_ENDPOINT: &str = "/rest-api/submit-package";
pub const DEFAULT_SUBMIT_TX_ENDPOINT: &str = "/rest-api/submit-tx";

#[derive(Clone, Debug, Deserialize)]
#[allow(clippy::struct_field_names)]
pub struct MaraSlipstreamConfig {
    pub host: String,
    #[serde(default = "default_fee_rate_endpoint")]
    pub fee_rate_endpoint: String,
    #[serde(default = "default_submit_package_endpoint")]
    pub submit_package_endpoint: String,
    #[serde(default = "default_submit_tx_endpoint")]
    pub submit_tx_endpoint: String,
    #[serde(default, alias = "client_key")]
    pub client_code: Option<SecretString>,
}

fn default_fee_rate_endpoint() -> String {
    DEFAULT_FEE_RATE_ENDPOINT.to_string()
}

fn default_submit_package_endpoint() -> String {
    DEFAULT_SUBMIT_PACKAGE_ENDPOINT.to_string()
}

fn default_submit_tx_endpoint() -> String {
    DEFAULT_SUBMIT_TX_ENDPOINT.to_string()
}
