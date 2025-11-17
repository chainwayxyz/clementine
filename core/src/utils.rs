use crate::builder::transaction::TransactionType;
use crate::config::TelemetryConfig;
use crate::errors::BridgeError;
use crate::operator::RoundIndex;
use crate::rpc::clementine::VergenResponse;
use bitcoin::{OutPoint, ScriptBuf, TapNodeHash, XOnlyPublicKey};
use eyre::Context as _;
use futures::future::join_all;
use http::HeaderValue;
use metrics_exporter_prometheus::PrometheusBuilder;
use serde::{Deserialize, Serialize};
use std::fmt::{Debug, Display};
use std::fs::File;
use std::future::Future;
use std::net::{Ipv4Addr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::time::error::Elapsed;
use tokio::time::timeout;
use tonic::Status;
use tower::{Layer, Service};
use tracing::level_filters::LevelFilter;
use tracing::{debug_span, Instrument, Subscriber};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::{fmt, EnvFilter, Layer as TracingLayer, Registry};

/// Initializes a [`tracing`] subscriber depending on the environment.
/// [`EnvFilter`] is used with an optional default level. Sets up the
/// [`color_eyre`] handler.
///
/// # Log Formats
///
/// - `json` **JSON** is used when `LOG_FORMAT=json`
/// - `human` **Human-readable** direct logs are used when `LOG_FORMAT` is not
///   set to `json`.
///
/// ## CI
///
/// In CI, logging is always in the human-readable format with output to the
/// console. The `INFO_LOG_FILE` env var can be used to set an optional log file
/// output. If not set, only console logging is used.
///
/// # Backtraces
///
/// Backtraces are enabled by default for tests. Error backtraces otherwise
/// depend on the `RUST_LIB_BACKTRACE` env var. Please read [`color_eyre`]
/// documentation for more details.
///
/// # Parameters
///
/// - `default_level`: Default level ranges from 0 to 5. This is overwritten through the
///   `RUST_LOG` env var.
///
/// # Returns
///
/// Returns `Err` in CI if the file logging cannot be initialized.  Already
/// initialized errors are ignored, so this function can be called multiple
/// times safely.
pub fn initialize_logger(default_level: Option<LevelFilter>) -> Result<(), BridgeError> {
    let is_ci = std::env::var("CI")
        .map(|v| v == "true" || v == "1")
        .unwrap_or(false);

    // UNCOMMENT TO DEBUG TOKIO TASKS
    // console_subscriber::init();

    if cfg!(test) {
        // Enable full backtraces for tests
        std::env::set_var("RUST_LIB_BACKTRACE", "full");
        std::env::set_var("RUST_BACKTRACE", "full");
    }

    // Initialize color-eyre for better error handling and backtraces
    let _ = color_eyre::config::HookBuilder::default()
        .add_frame_filter(Box::new(|frames| {
            // Frames with names starting with any of the str's below will be filtered out
            let filters = &[
                "std::",
                "test::",
                "tokio::",
                "core::",
                "<core::",
                "<alloc::",
                "start_thread",
                "<tonic::",
                "<futures::",
                "<tower::",
                "<hyper",
                "hyper",
                "__rust_try",
                "<axum::",
                "<F as ",
                "clone",
            ];

            frames.retain(|frame| {
                !filters.iter().any(|f| {
                    let name = if let Some(name) = frame.name.as_ref() {
                        name.as_str()
                    } else {
                        return true;
                    };

                    name.starts_with(f)
                })
            });
        }))
        .install();

    if is_ci {
        let info_log_file = std::env::var("INFO_LOG_FILE").ok();
        if let Some(file_path) = info_log_file {
            try_set_global_subscriber(env_subscriber_with_file(&file_path)?);
            tracing::trace!("Using file logging in CI, outputting to {}", file_path);
        } else {
            try_set_global_subscriber(env_subscriber_to_human(default_level));
            tracing::trace!("Using console logging in CI");
            tracing::warn!(
                "CI is set but INFO_LOG_FILE is missing, only console logs will be used."
            );
        }
    } else if is_json_logs() {
        try_set_global_subscriber(env_subscriber_to_json(default_level));
        tracing::trace!("Using JSON logging");
    } else {
        try_set_global_subscriber(env_subscriber_to_human(default_level));
        tracing::trace!("Using human-readable logging");
    }

    tracing::info!("Tracing initialized successfully.");
    Ok(())
}

pub fn initialize_telemetry(config: &TelemetryConfig) -> Result<(), BridgeError> {
    let telemetry_addr: SocketAddr = format!("{}:{}", config.host, config.port)
        .parse()
        .unwrap_or_else(|_| {
            tracing::warn!(
                "Invalid telemetry address: {}:{}, using default address: 127.0.0.1:8081",
                config.host,
                config.port
            );
            SocketAddr::from((Ipv4Addr::new(127, 0, 0, 1), 8081))
        });

    tracing::debug!("Initializing telemetry at {}", telemetry_addr);

    let builder = PrometheusBuilder::new().with_http_listener(telemetry_addr);

    builder
        .install()
        .map_err(|e| eyre::eyre!("Failed to initialize telemetry: {}", e))?;

    Ok(())
}

fn try_set_global_subscriber<S>(subscriber: S)
where
    S: Subscriber + Send + Sync + 'static,
{
    match tracing::subscriber::set_global_default(subscriber) {
        Ok(_) => {}
        // Statically, the only error possible is "already initialized"
        Err(_) => {
            #[cfg(test)]
            tracing::trace!("Tracing is already initialized, skipping without errors...");
            #[cfg(not(test))]
            tracing::info!(
                "Unexpected double initialization of tracing, skipping without errors..."
            );
        }
    }
}

fn env_subscriber_with_file(path: &str) -> Result<Box<dyn Subscriber + Send + Sync>, BridgeError> {
    if let Some(parent_dir) = std::path::Path::new(path).parent() {
        std::fs::create_dir_all(parent_dir).map_err(|e| {
            BridgeError::ConfigError(format!(
                "Failed to create log directory '{}': {}",
                parent_dir.display(),
                e
            ))
        })?;
    }

    let file = File::create(path).map_err(|e| BridgeError::ConfigError(e.to_string()))?;

    let file_filter = EnvFilter::from_default_env()
        .add_directive("info".parse().expect("It should parse info level"))
        .add_directive("ci=debug".parse().expect("It should parse ci debug level"));

    let console_filter = EnvFilter::builder()
        .with_default_directive(LevelFilter::WARN.into())
        .from_env_lossy();

    let file_layer = fmt::layer()
        .with_writer(file)
        .with_ansi(false)
        .with_file(true)
        .with_line_number(true)
        .with_target(true)
        .with_thread_ids(true)
        .with_thread_names(true)
        .with_filter(file_filter)
        .boxed();

    let console_layer = fmt::layer()
        .with_test_writer()
        .with_file(true)
        .with_line_number(true)
        .with_target(true)
        .with_filter(console_filter)
        .boxed();

    Ok(Box::new(
        Registry::default().with(file_layer).with(console_layer),
    ))
}

fn env_subscriber_to_json(level: Option<LevelFilter>) -> Box<dyn Subscriber + Send + Sync> {
    let filter = match level {
        Some(lvl) => EnvFilter::builder()
            .with_default_directive(lvl.into())
            .from_env_lossy(),
        None => EnvFilter::from_default_env(),
    };

    let json_layer = fmt::layer::<Registry>()
        .with_test_writer()
        // .with_timer(time::UtcTime::rfc_3339())
        .with_file(true)
        .with_line_number(true)
        .with_thread_ids(true)
        .with_thread_names(true)
        .with_target(true)
        .json();
    // .with_current_span(true)z
    // .with_span_list(true)
    // To see how long each span takes, uncomment this.
    // .with_span_events(FmtSpan::CLOSE)

    Box::new(tracing_subscriber::registry().with(json_layer).with(filter))
}

fn env_subscriber_to_human(level: Option<LevelFilter>) -> Box<dyn Subscriber + Send + Sync> {
    let filter = match level {
        Some(lvl) => EnvFilter::builder()
            .with_default_directive(lvl.into())
            .from_env_lossy(),
        None => EnvFilter::from_default_env(),
    };

    let standard_layer = fmt::layer()
        .with_test_writer()
        // .with_timer(time::UtcTime::rfc_3339())
        .with_file(true)
        .with_line_number(true)
        // To see how long each span takes, uncomment this.
        // .with_span_events(FmtSpan::CLOSE)
        .with_target(true);

    Box::new(
        tracing_subscriber::registry()
            .with(standard_layer)
            .with(filter),
    )
}

fn is_json_logs() -> bool {
    std::env::var("LOG_FORMAT")
        .map(|v| v.eq_ignore_ascii_case("json"))
        .unwrap_or(false)
}

pub fn get_vergen_response() -> VergenResponse {
    let mut vergen_response = String::new();

    // build info
    if let Some(date) = option_env!("VERGEN_BUILD_DATE") {
        vergen_response.push_str(&format!("Build Date: {date}\n"));
    }
    if let Some(timestamp) = option_env!("VERGEN_BUILD_TIMESTAMP") {
        vergen_response.push_str(&format!("Build Timestamp: {timestamp}\n"));
    }

    // git info
    if let Some(branch) = option_env!("VERGEN_GIT_BRANCH") {
        vergen_response.push_str(&format!("git branch: {branch}\n"));
    }
    if let Some(commit) = option_env!("VERGEN_GIT_SHA") {
        vergen_response.push_str(&format!("git commit: {commit}\n"));
    }
    if let Some(commit_date) = option_env!("VERGEN_GIT_COMMIT_DATE") {
        vergen_response.push_str(&format!("git commit date: {commit_date}\n"));
    }
    if let Some(commit_timestamp) = option_env!("VERGEN_GIT_COMMIT_TIMESTAMP") {
        vergen_response.push_str(&format!("git commit timestamp: {commit_timestamp}\n"));
    }
    if let Some(commit_author_name) = option_env!("VERGEN_GIT_COMMIT_AUTHOR_NAME") {
        vergen_response.push_str(&format!("git commit author name: {commit_author_name}\n"));
    }
    if let Some(commit_author_email) = option_env!("VERGEN_GIT_COMMIT_AUTHOR_EMAIL") {
        vergen_response.push_str(&format!("git commit author email: {commit_author_email}\n"));
    }
    if let Some(commit_count) = option_env!("VERGEN_GIT_COMMIT_COUNT") {
        vergen_response.push_str(&format!("git commit count: {commit_count}\n"));
    }
    if let Some(commit_message) = option_env!("VERGEN_GIT_COMMIT_MESSAGE") {
        vergen_response.push_str(&format!("git commit message: {commit_message}\n"));
    }
    if let Some(describe) = option_env!("VERGEN_GIT_DESCRIBE") {
        vergen_response.push_str(&format!("git describe: {describe}\n"));
    }
    if let Some(dirty) = option_env!("VERGEN_GIT_DIRTY") {
        vergen_response.push_str(&format!("git dirty: {dirty}\n"));
    }

    // cargo info
    if let Some(debug) = option_env!("VERGEN_CARGO_DEBUG") {
        vergen_response.push_str(&format!("cargo debug: {debug}\n"));
    }
    if let Some(opt_level) = option_env!("VERGEN_CARGO_OPT_LEVEL") {
        vergen_response.push_str(&format!("cargo opt level: {opt_level}\n"));
    }
    if let Some(target_triple) = option_env!("VERGEN_CARGO_TARGET_TRIPLE") {
        vergen_response.push_str(&format!("cargo target triple: {target_triple}\n"));
    }
    if let Some(features) = option_env!("VERGEN_CARGO_FEATURES") {
        vergen_response.push_str(&format!("cargo features: {features}\n"));
    }
    if let Some(dependencies) = option_env!("VERGEN_CARGO_DEPENDENCIES") {
        vergen_response.push_str(&format!("cargo dependencies: {dependencies}\n"));
    }

    // rustc info
    if let Some(channel) = option_env!("VERGEN_RUSTC_CHANNEL") {
        vergen_response.push_str(&format!("rustc channel: {channel}\n"));
    }
    if let Some(version) = option_env!("VERGEN_RUSTC_SEMVER") {
        vergen_response.push_str(&format!("rustc version: {version}\n"));
    }
    if let Some(commit_hash) = option_env!("VERGEN_RUSTC_COMMIT_HASH") {
        vergen_response.push_str(&format!("rustc commit hash: {commit_hash}\n"));
    }
    if let Some(commit_date) = option_env!("VERGEN_RUSTC_COMMIT_DATE") {
        vergen_response.push_str(&format!("rustc commit date: {commit_date}\n"));
    }
    if let Some(host_triple) = option_env!("VERGEN_RUSTC_HOST_TRIPLE") {
        vergen_response.push_str(&format!("rustc host triple: {host_triple}\n"));
    }
    if let Some(llvm_version) = option_env!("VERGEN_RUSTC_LLVM_VERSION") {
        vergen_response.push_str(&format!("rustc LLVM version: {llvm_version}\n"));
    }

    // sysinfo
    if let Some(cpu_brand) = option_env!("VERGEN_SYSINFO_CPU_BRAND") {
        vergen_response.push_str(&format!("cpu brand: {cpu_brand}\n"));
    }
    if let Some(cpu_name) = option_env!("VERGEN_SYSINFO_CPU_NAME") {
        vergen_response.push_str(&format!("cpu name: {cpu_name}\n"));
    }
    if let Some(cpu_vendor) = option_env!("VERGEN_SYSINFO_CPU_VENDOR") {
        vergen_response.push_str(&format!("cpu vendor: {cpu_vendor}\n"));
    }
    if let Some(cpu_core_count) = option_env!("VERGEN_SYSINFO_CPU_CORE_COUNT") {
        vergen_response.push_str(&format!("cpu core count: {cpu_core_count}\n"));
    }
    if let Some(cpu_frequency) = option_env!("VERGEN_SYSINFO_CPU_FREQUENCY") {
        vergen_response.push_str(&format!("cpu frequency: {cpu_frequency} MHz\n"));
    }
    if let Some(memory) = option_env!("VERGEN_SYSINFO_TOTAL_MEMORY") {
        vergen_response.push_str(&format!("total memory: {memory}\n"));
    }
    if let Some(name) = option_env!("VERGEN_SYSINFO_NAME") {
        vergen_response.push_str(&format!("system name: {name}\n"));
    }
    if let Some(os_version) = option_env!("VERGEN_SYSINFO_OS_VERSION") {
        vergen_response.push_str(&format!("OS version: {os_version}\n"));
    }
    if let Some(user) = option_env!("VERGEN_SYSINFO_USER") {
        vergen_response.push_str(&format!("build user: {user}\n"));
    }

    VergenResponse {
        response: vergen_response,
    }
}

/// Monitors a [`tokio::task::JoinHandle`] in the background and logs it's end
/// result.
pub fn monitor_standalone_task<
    T: Send + 'static,
    E: Debug + Send + 'static + From<BridgeError>,
    C: Send + 'static,
>(
    task_handle: tokio::task::JoinHandle<Result<T, E>>,
    task_name: &str,
    monitor_err_sender: tokio::sync::mpsc::Sender<Result<C, E>>,
) {
    let task_name = task_name.to_string();

    // Move task_handle into the spawned task to make it Send
    tokio::spawn(async move {
        match task_handle.await {
            Ok(Ok(_)) => {
                tracing::debug!("Task {} completed successfully", task_name);
            }
            Ok(Err(e)) => {
                tracing::error!("Task {} threw an error: {:?}", task_name, e);
                let _ = monitor_err_sender.send(Err(e)).await.inspect_err(|e| {
                    tracing::error!("Failed to send error to monitoring channel: {:?}", e)
                });
            }
            Err(e) => {
                if e.is_cancelled() {
                    // Task was cancelled, which is expected during cleanup
                    tracing::debug!("Task {} has been cancelled", task_name);
                    let _ = monitor_err_sender
                        .send(Err(Into::<BridgeError>::into(eyre::eyre!(
                            "Task was cancelled due to: {:?}",
                            e
                        ))
                        .into()))
                        .await
                        .inspect_err(|e| {
                            tracing::error!("Failed to send error to monitoring channel: {:?}", e)
                        });
                    return;
                }
                tracing::error!("Task {} has panicked: {:?}", task_name, e);
                let _ = monitor_err_sender
                    .send(Err(Into::<BridgeError>::into(eyre::eyre!(
                        "Task has panicked due to: {:?}",
                        e
                    ))
                    .into()))
                    .await
                    .inspect_err(|e| {
                        tracing::error!("Failed to send error to monitoring channel: {:?}", e)
                    });
            }
        }
    });
}

/// Delays the exit of the program for 15 seconds, to allow for logs to be flushed.
/// Then panics with the given arguments.
///
/// # Parameters
///
/// - `($($arg:tt)*)`: Arguments to pass to `panic!`, in the same manner as format! and println!
macro_rules! delayed_panic {
    ($($arg:tt)*) => {
        {
            eprintln!($($arg)*);
            eprintln!("Delaying exit for 15 seconds, to allow for logs to be flushed");
            std::thread::sleep(std::time::Duration::from_secs(15));
            panic!($($arg)*);
        }
    };
}

pub(crate) use delayed_panic;

#[derive(Debug, Clone, Default)]
pub struct AddMethodMiddlewareLayer;

impl<S> Layer<S> for AddMethodMiddlewareLayer {
    type Service = AddMethodMiddleware<S>;

    fn layer(&self, service: S) -> Self::Service {
        AddMethodMiddleware { inner: service }
    }
}

#[derive(Debug, Clone)]
pub struct AddMethodMiddleware<S> {
    inner: S,
}

type BoxFuture<'a, T> = Pin<Box<dyn std::future::Future<Output = T> + Send + 'a>>;

impl<S, ReqBody, ResBody> Service<http::Request<ReqBody>> for AddMethodMiddleware<S>
where
    S: Service<http::Request<ReqBody>, Response = http::Response<ResBody>> + Clone + Send + 'static,
    S::Future: Send + 'static,
    ReqBody: Send + 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut req: http::Request<ReqBody>) -> Self::Future {
        // See: https://docs.rs/tower/latest/tower/trait.Service.html#be-careful-when-cloning-inner-services
        let clone = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, clone);

        Box::pin(async move {
            let path = req.uri().path();

            let grpc_method =
                if let &[_, _, method] = &path.split("/").collect::<Vec<&str>>().as_slice() {
                    Some(method.to_string())
                } else {
                    None
                };

            if let Some(grpc_method) = grpc_method {
                if let Ok(grpc_method) = HeaderValue::from_str(&grpc_method) {
                    req.headers_mut().insert("grpc-method", grpc_method);
                }
            }

            // Do extra async work here...
            let response = inner.call(req).await?;

            Ok(response)
        })
    }
}

/// A trait for entities that have a name, operator, verifier, etc.
/// Used to distinguish between state machines with different owners in the database,
/// and to provide a human-readable name for the entity for task names.
pub trait NamedEntity: Sync + Send + 'static {
    /// A string identifier for this owner type used to distinguish between
    /// state machines with different owners in the database.
    ///
    /// ## Example
    /// "operator", "verifier", "user"
    const ENTITY_NAME: &'static str;

    /// Consumer ID for the tx sender task.
    const TX_SENDER_CONSUMER_ID: &'static str;

    /// Consumer ID for the finalized block task with no automation.
    const FINALIZED_BLOCK_CONSUMER_ID_NO_AUTOMATION: &'static str;

    /// Consumer ID for the finalized block task with automation.
    const FINALIZED_BLOCK_CONSUMER_ID_AUTOMATION: &'static str;
}

#[derive(Copy, Clone, Eq, Hash, PartialEq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct TxMetadata {
    pub deposit_outpoint: Option<OutPoint>,
    pub operator_xonly_pk: Option<XOnlyPublicKey>,
    pub round_idx: Option<RoundIndex>,
    pub kickoff_idx: Option<u32>,
    pub tx_type: TransactionType,
}

impl std::fmt::Debug for TxMetadata {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut dbg_struct = f.debug_struct("TxMetadata");
        if let Some(deposit_outpoint) = self.deposit_outpoint {
            dbg_struct.field("deposit_outpoint", &deposit_outpoint);
        }
        if let Some(operator_xonly_pk) = self.operator_xonly_pk {
            dbg_struct.field("operator_xonly_pk", &operator_xonly_pk);
        }
        if let Some(round_idx) = self.round_idx {
            dbg_struct.field("round_idx", &round_idx);
        }
        if let Some(kickoff_idx) = self.kickoff_idx {
            dbg_struct.field("kickoff_idx", &kickoff_idx);
        }
        dbg_struct.field("tx_type", &self.tx_type);
        dbg_struct.finish()
    }
}

/// Specifies the fee bumping strategy used for a transaction.
#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq, PartialOrd, Ord, sqlx::Type)]
#[sqlx(type_name = "fee_paying_type", rename_all = "lowercase")]
pub enum FeePayingType {
    /// Child-Pays-For-Parent: A new "child" transaction is created, spending an output
    /// from the original "parent" transaction. The child pays a high fee, sufficient
    /// to cover both its own cost and the parent's fee deficit, incentivizing miners
    /// to confirm both together. Specifically, we utilize "fee payer" UTXOs.
    CPFP,
    /// Replace-By-Fee: The original unconfirmed transaction is replaced with a new
    /// version that includes a higher fee. The original transaction must signal
    /// RBF enablement (e.g., via nSequence). Bitcoin Core's `bumpfee` RPC is often used.
    RBF,
    /// The transaction has already been funded and no fee is needed.
    /// Currently used for disprove tx as it has operator's collateral as input.
    NoFunding,
}

/// Information to re-sign an RBF transaction.
/// Specifically the merkle root of the taproot to keyspend with and the output index of the utxo to be
/// re-signed.
///
/// - Not needed for SinglePlusAnyoneCanPay RBF txs.
/// - Not needed for CPFP.
/// - Only signs for a keypath spend
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct RbfSigningInfo {
    pub vout: u32,
    pub tweak_merkle_root: Option<TapNodeHash>,
    #[cfg(test)]
    pub annex: Option<Vec<u8>>,
    #[cfg(test)]
    pub additional_taproot_output_count: Option<u32>,
}
pub trait Last20Bytes {
    fn last_20_bytes(&self) -> [u8; 20];
}

pub trait TryLast20Bytes {
    fn try_last_20_bytes(self) -> Result<[u8; 20], BridgeError>;
}

impl Last20Bytes for [u8; 32] {
    fn last_20_bytes(&self) -> [u8; 20] {
        self.try_last_20_bytes().expect("will not happen")
    }
}

pub trait ScriptBufExt {
    fn try_get_taproot_pk(&self) -> Result<XOnlyPublicKey, BridgeError>;
}

impl ScriptBufExt for ScriptBuf {
    fn try_get_taproot_pk(&self) -> Result<XOnlyPublicKey, BridgeError> {
        if !self.is_p2tr() {
            return Err(eyre::eyre!("Script is not a valid P2TR script (not 34 bytes)").into());
        }

        Ok(XOnlyPublicKey::from_slice(&self.as_bytes()[2..34])
            .wrap_err("Failed to parse XOnlyPublicKey from script")?)
    }
}

impl TryLast20Bytes for &[u8] {
    fn try_last_20_bytes(self) -> Result<[u8; 20], BridgeError> {
        if self.len() < 20 {
            return Err(eyre::eyre!("Input is too short to contain 20 bytes").into());
        }
        let mut result = [0u8; 20];

        result.copy_from_slice(&self[self.len() - 20..]);
        Ok(result)
    }
}

/// Wraps a future with a timeout, returning a `Status::deadline_exceeded` gRPC error
/// if the future does not complete within the specified duration.
///
/// This is useful for enforcing timeouts on individual asynchronous operations,
/// especially those involving network requests, to prevent them from hanging indefinitely.
///
/// # Arguments
///
/// * `duration`: The maximum `Duration` to wait for the future to complete.
/// * `description`: A string slice describing the operation, used in the timeout error message.
/// * `future`: The `Future` to execute. The future should return a `Result<T, BridgeError>`.
///
/// # Returns
///
/// Returns `Ok(T)` if the future completes successfully within the time limit.
/// Returns `Err(BridgeError)` if the future returns an error or if it times out.
/// A timeout results in a `BridgeError` that wraps a `tonic::Status::deadline_exceeded`.
pub async fn timed_request<F, T>(
    duration: Duration,
    description: &str,
    future: F,
) -> Result<T, BridgeError>
where
    F: Future<Output = Result<T, BridgeError>>,
{
    timed_request_base(duration, description, future)
        .await
        .map_err(|_| {
            Box::new(Status::deadline_exceeded(format!(
                "{description} timed out"
            )))
        })?
}

/// Wraps a future with a timeout and adds a debug span with the description.
///
/// # Arguments
///
/// * `duration`: The maximum `Duration` to wait for the future to complete.
/// * `description`: A string slice describing the operation, used in the timeout error message.
/// * `future`: The `Future` to execute. The future should return a `Result<T, BridgeError>`.
///
/// # Returns
///
/// Returns `Ok(Ok(T))` if the future completes successfully within the time limit, returns `Ok(Err(e))`
/// if the future returns an error, returns `Err(Elapsed)` if the request times out.
pub async fn timed_request_base<F, T>(
    duration: Duration,
    description: &str,
    future: F,
) -> Result<Result<T, BridgeError>, Elapsed>
where
    F: Future<Output = Result<T, BridgeError>>,
{
    timeout(duration, future)
        .instrument(debug_span!("timed_request", description = description))
        .await
}

/// Concurrently executes a collection of futures, applying a timeout to each one individually.
/// If any future fails or times out, the entire operation is aborted and an error is returned.
///
/// This utility is an extension of `futures::future::try_join_all` with added per-future
/// timeout logic and improved error reporting using optional IDs.
///
/// # Type Parameters
///
/// * `I`: An iterator that yields futures.
/// * `T`: The success type of the futures.
/// * `D`: A type that can be displayed, used for identifying futures in error messages.
///
/// # Arguments
///
/// * `duration`: The timeout `Duration` applied to each individual future in the iterator.
/// * `description`: A string slice describing the collective operation, used in timeout error messages.
/// * `ids`: An optional `Vec<D>` of identifiers corresponding to each future. If provided,
///   these IDs are used in error messages to specify which future failed or timed out.
/// * `iter`: An iterator producing the futures to be executed.
///
/// # Returns
///
/// Returns `Ok(Vec<T>)` containing the results of all futures if they all complete successfully.
/// Returns `Err(BridgeError)` if any future returns an error or times out. The error will be a combined error of all errors.
/// The error will be contextualized with the operation description and the specific future's ID if available.
pub async fn timed_try_join_all<I, T, D>(
    duration: Duration,
    description: &str,
    ids: Option<Vec<D>>,
    iter: I,
) -> Result<Vec<T>, BridgeError>
where
    D: Display,
    I: IntoIterator,
    I::Item: Future<Output = Result<T, BridgeError>>,
{
    let ids = Arc::new(ids);
    let results = join_all(iter.into_iter().enumerate().map(|item| {
        let ids = ids.clone();
        async move {
            let id = Option::as_ref(&ids).and_then(|ids| ids.get(item.0));

            timeout(duration, item.1)
                .await
                .map_err(|_| {
                    Box::new(Status::deadline_exceeded(format!(
                        "{} (id: {}) timed out",
                        description,
                        id.map(|id| id.to_string())
                            .unwrap_or_else(|| "n/a".to_string())
                    )))
                })?
                // Add the id to the error chain for easier debugging for other errors.
                .wrap_err_with(|| {
                    format!(
                        "Failed to join {}",
                        id.map(ToString::to_string).unwrap_or_else(|| "n/a".into())
                    )
                })
        }
    }))
    .instrument(debug_span!("timed_try_join_all", description = description))
    .await;

    collect_errors(results, description)
}

/// Collects errors from an iterator of results and returns a combined error if any failed.
///
/// # Parameters
/// * `results`: Iterator of results (errors should contain identifying information in their Debug representation)
/// * `prefix`: Prefix message for the combined error (e.g., "Operator key collection failures")
///
/// # Returns
/// * `Ok(Vec<T>)` containing all successful results if all results are successful
/// * `Err(BridgeError)` with a combined error message listing all failures
pub fn collect_errors<I, EIn, T>(results: I, prefix: &str) -> Result<Vec<T>, BridgeError>
where
    I: IntoIterator<Item = Result<T, EIn>>,
    EIn: std::fmt::Display,
{
    let mut errors = Vec::new();
    let mut successful_results = Vec::new();
    for result in results {
        match result {
            Ok(value) => successful_results.push(value),
            Err(e) => errors.push(format!("{e:#}")),
        }
    }
    if !errors.is_empty() {
        return Err(BridgeError::from(eyre::eyre!(
            "{}: {}",
            prefix,
            errors.join("; ")
        )));
    }
    Ok(successful_results)
}

/// Collects all errors (both outer and inner) from named task results and returns a combined error if any task failed.
///
/// This function is useful when you have multiple async tasks (e.g., from `tokio::spawn`) and want to
/// see all errors if multiple tasks fail, rather than just the first error.
///
/// # Parameters
/// * `task_results`: Iterator of tuples containing (task_name, Result<Result<T, E1>, E2>)
///   - `task_name`: A string-like identifier for the task (used in error messages)
///   - The nested Result represents: `Result<T, E1>` is the task's result, `E2` is typically a `JoinError`
///
/// # Returns
/// * `Ok(())` if all tasks completed successfully
/// * `Err(BridgeError)` with a combined error message listing all failures
pub fn flatten_join_named_results<T, E1, E2, S, R>(task_results: R) -> Result<(), BridgeError>
where
    R: IntoIterator<Item = (S, Result<Result<T, E1>, E2>)>,
    S: AsRef<str>,
    E1: std::fmt::Display,
    E2: std::fmt::Display,
{
    let mut task_errors = Vec::new();

    for (task_name, task_output) in task_results.into_iter() {
        match task_output {
            Ok(inner_result) => {
                if let Err(e) = inner_result {
                    let err_msg = format!("{} failed with error: {:#}", task_name.as_ref(), e);
                    task_errors.push(err_msg);
                }
            }
            Err(e) => {
                let err_msg = format!(
                    "{} task thread failed with error: {:#}",
                    task_name.as_ref(),
                    e
                );
                task_errors.push(err_msg);
            }
        }
    }

    if !task_errors.is_empty() {
        tracing::error!("Tasks failed with errors: {:#?}", task_errors);
        return Err(eyre::eyre!("Tasks failed with errors: {:#?}", task_errors).into());
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::io::Read;
    use tempfile::NamedTempFile;
    use tracing::level_filters::LevelFilter;

    #[test]
    #[ignore = "This test changes environment variables so it should not be run in CI since it might affect other tests."]
    fn test_ci_logging_setup() {
        let temp_file = NamedTempFile::new().expect("Failed to create temp file");
        let temp_path = temp_file.path().to_string_lossy().to_string();

        std::env::set_var("CI", "true");
        std::env::set_var("INFO_LOG_FILE", &temp_path);

        let result = initialize_logger(Some(LevelFilter::DEBUG));
        assert!(result.is_ok(), "Logger initialization should succeed");

        tracing::error!("Test error message");
        tracing::warn!("Test warn message");
        tracing::info!("Test info message");
        tracing::debug!(target: "ci", "Test CI debug message");
        tracing::debug!("Test debug message");

        std::thread::sleep(std::time::Duration::from_millis(100));

        let mut file_contents = String::new();
        let mut file = fs::File::open(&temp_path).expect("Failed to open log file");
        file.read_to_string(&mut file_contents)
            .expect("Failed to read log file");

        assert!(
            file_contents.contains("Test error message"),
            "Error message should be in file"
        );
        assert!(
            file_contents.contains("Test warn message"),
            "Warn message should be in file"
        );
        assert!(
            file_contents.contains("Test info message"),
            "Info message should be in file"
        );

        assert!(
            file_contents.contains("Test CI debug message"),
            "Debug message for CI should be in file"
        );

        assert!(
            !file_contents.contains("Test debug message"),
            "Debug message should not be in file"
        );

        std::env::remove_var("CI");
        std::env::remove_var("INFO_LOG_FILE");
    }
}
