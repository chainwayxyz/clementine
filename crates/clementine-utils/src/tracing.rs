use clementine_errors::BridgeError;
use std::fs::File;
use tracing::level_filters::LevelFilter;
use tracing::Subscriber;
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
    let mut hook_builder =
        color_eyre::config::HookBuilder::default().add_frame_filter(Box::new(|frames| {
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
        }));

    // When JSON logs are enabled, use a theme without color codes.
    if is_json_logs() {
        hook_builder = hook_builder.theme(color_eyre::config::Theme::new());
    }

    let _ = hook_builder.install();

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
