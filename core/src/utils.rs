use crate::builder::transaction::TransactionType;
use crate::errors::BridgeError;
use crate::operator::RoundIndex;
use crate::rpc::clementine::VergenResponse;
use bitcoin::{OutPoint, TapNodeHash, XOnlyPublicKey};
use eyre::Context as _;
use futures::future::try_join_all;
use http::HeaderValue;
use serde::{Deserialize, Serialize};
use std::fmt::{Debug, Display};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::time::timeout;
use tonic::Status;
use tower::{Layer, Service};
use tracing::level_filters::LevelFilter;
use tracing::{debug_span, Instrument};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::{fmt, EnvFilter, Registry};

/// Initializes `tracing` as the logger.
///
/// # Parameters
///
/// - `level`: Level ranges from 0 to 5. 0 defaults to no logs but can be
///   overwritten with `RUST_LOG` env var. While other numbers sets log level from
///   lowest level (1) to highest level (5). Is is advised to use 0 on tests and
///   other values for binaries (get value from user).
///
/// # Returns
///
/// Returns `Err` if `tracing` can't be initialized. Multiple subscription error
/// is emitted and will return `Ok(())`.
pub fn initialize_logger(level: Option<LevelFilter>) -> Result<(), BridgeError> {
    // Configure JSON formatting with additional fields
    let json_layer = fmt::layer::<Registry>()
        .with_test_writer()
        // .with_timer(time::UtcTime::rfc_3339())
        .with_file(true)
        .with_line_number(true)
        .with_thread_ids(true)
        .with_thread_names(true)
        .with_target(true)
        // .with_current_span(true)
        // .with_span_list(true)
        // To see how long each span takes, uncomment this.
        // .with_span_events(FmtSpan::CLOSE)
        .json();

    // Standard human-readable layer for non-JSON output
    let standard_layer = fmt::layer()
        .with_test_writer()
        // .with_timer(time::UtcTime::rfc_3339())
        .with_file(true)
        .with_line_number(true)
        // To see how long each span takes, uncomment this.
        // .with_span_events(FmtSpan::CLOSE)
        .with_target(true);

    let filter = match level {
        Some(level) => EnvFilter::builder()
            .with_default_directive(level.into())
            .from_env_lossy(),
        None => EnvFilter::from_default_env(),
    };

    // Try to initialize tracing, depending on the `JSON_LOGS` env var
    let res = if std::env::var("JSON_LOGS").is_ok() {
        tracing_subscriber::util::SubscriberInitExt::try_init(
            tracing_subscriber::registry().with(json_layer).with(filter),
        )
    } else {
        tracing_subscriber::util::SubscriberInitExt::try_init(
            tracing_subscriber::registry()
                .with(standard_layer)
                .with(filter),
        )
    };

    if let Err(e) = res {
        // If it failed because of a re-initialization, do not care about
        // the error.
        if e.to_string() != "a global default trace dispatcher has already been set" {
            return Err(BridgeError::ConfigError(e.to_string()));
        }

        tracing::trace!("Tracing is already initialized, skipping without errors...");
    };

    Ok(())
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
    if let Some(memory) = option_env!("VERGEN_SYSINFO_MEMORY") {
        vergen_response.push_str(&format!("total memory: {memory} KB\n"));
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

/// Monitors a JoinHandle and aborts the process if the task completes with an error.
/// Returns a handle to the monitoring task that can be used to cancel it.
pub fn monitor_task_with_panic<T: Send + 'static, E: Debug + Send + 'static>(
    task_handle: tokio::task::JoinHandle<Result<T, E>>,
    task_name: &str,
) {
    let task_name = task_name.to_string();

    // Move task_handle into the spawned task to make it Send
    tokio::spawn(async move {
        match task_handle.await {
            Ok(Ok(_)) => {
                // Task completed successfully
                tracing::debug!("Task {} completed successfully", task_name);
            }
            Ok(Err(e)) => {
                // Task returned an error
                tracing::error!("Task {} failed with error: {:?}", task_name, e);
                panic!();
            }
            Err(e) => {
                if e.is_cancelled() {
                    // Task was cancelled, which is expected during cleanup
                    tracing::debug!("Task {} was cancelled", task_name);
                    return;
                }
                // Task panicked or was aborted
                tracing::error!("Task {} panicked: {:?}", task_name, e);
                panic!();
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

/// A trait for entities that have a name, operator, watchtower, verifier, etc.
/// Used to distinguish between state machines with different owners in the database,
/// and to provide a human-readable name for the entity for task names.
pub trait NamedEntity {
    /// A string identifier for this owner type used to distinguish between
    /// state machines with different owners in the database.
    ///
    /// ## Example
    /// "operator", "watchtower", "verifier", "user"
    const ENTITY_NAME: &'static str;
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
}
pub trait Last20Bytes {
    fn last_20_bytes(self) -> [u8; 20];
}

impl Last20Bytes for [u8; 32] {
    fn last_20_bytes(self) -> [u8; 20] {
        let mut result = [0u8; 20];
        result.copy_from_slice(&self[12..32]);
        result
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
    timeout(duration, future)
        .instrument(debug_span!("timed_request", description = description))
        .await
        .map_err(|_| Status::deadline_exceeded(format!("{} timed out", description)))?
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
/// Returns `Err(BridgeError)` if any future returns an error or times out.
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
    try_join_all(iter.into_iter().enumerate().map(|item| {
        let ids = ids.clone();
        async move {
            let id = Option::as_ref(&ids).map(|ids| ids.get(item.0)).flatten();

            timeout(duration, item.1)
                .await
                .map_err(|_| {
                    Status::deadline_exceeded(format!(
                        "{} (id: {}) timed out",
                        description,
                        id.map(|id| id.to_string())
                            .unwrap_or_else(|| "n/a".to_string())
                    ))
                })?
                // Add the id to the error chain for easier debugging for other errors.
                .wrap_err_with(|| {
                    format!(
                        "Failed to join {}",
                        id.map(ToString::to_string).unwrap_or_else(|| "n/a".into())
                    )
                })
                .map_err(Into::into)
        }
    }))
    .instrument(debug_span!("timed_try_join_all", description = description))
    .await
}
