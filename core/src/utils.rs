use crate::errors::BridgeError;
use std::fmt::Debug;
use tracing::level_filters::LevelFilter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::{fmt, EnvFilter, Registry};

pub fn usize_to_var_len_bytes(x: usize) -> Vec<u8> {
    let usize_bytes = (usize::BITS / 8) as usize;
    let bits = x.max(1).ilog2() + 1;
    let len = ((bits + 7) / 8) as usize;
    let empty = usize_bytes - len;
    let op_idx_bytes = x.to_be_bytes();
    let op_idx_bytes = &op_idx_bytes[empty..];
    op_idx_bytes.to_vec()
}

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
/// is emmitted and will return `Ok(())`.
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
        .json();

    // Standard human-readable layer for non-JSON output
    let standard_layer = fmt::layer()
        .with_test_writer()
        // .with_timer(time::UtcTime::rfc_3339())
        .with_file(true)
        .with_line_number(true)
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
