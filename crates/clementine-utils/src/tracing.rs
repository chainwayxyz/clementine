use clementine_errors::BridgeError;
use std::{
    fs::{File, OpenOptions},
    io::{self, Write},
    path::{Path, PathBuf},
    sync::Mutex,
};
use tracing::level_filters::LevelFilter;
use tracing::Subscriber;
use tracing_subscriber::fmt::writer::MakeWriter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::{fmt, EnvFilter, Layer as TracingLayer, Registry};

static LOGGER_INIT_LOCK: Mutex<()> = Mutex::new(());

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
/// console. `INFO_LOG_DIR` enables per-test file logging, while `INFO_LOG_FILE`
/// writes all file logs to one file. If neither is set, only console logging is
/// used.
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
/// Returns `Err` in CI if the file logging cannot be initialized. Already
/// initialized loggers are left untouched, so this function can be called
/// multiple times safely.
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

    // When JSON logs are enabled, use a theme without color codes
    if is_json_logs() {
        hook_builder = hook_builder.theme(color_eyre::config::Theme::new());
    }

    let _ = hook_builder.install();

    let _guard = LOGGER_INIT_LOCK
        .lock()
        .expect("logger initialization lock poisoned");
    if tracing::dispatcher::has_been_set() {
        tracing::trace!("Tracing is already initialized, skipping without errors...");
        return Ok(());
    }

    if is_ci {
        if let Some(dir_path) = std::env::var("INFO_LOG_DIR").ok() {
            try_set_global_subscriber(env_subscriber_with_dir(&dir_path)?);
            tracing::trace!(
                "Using per-test file logging in CI, outputting under {}",
                dir_path
            );
        } else if let Some(file_path) = std::env::var("INFO_LOG_FILE").ok() {
            try_set_global_subscriber(env_subscriber_with_file(&file_path)?);
            tracing::trace!("Using file logging in CI, outputting to {}", file_path);
        } else {
            try_set_global_subscriber(env_subscriber_to_human(default_level));
            tracing::trace!("Using console logging in CI");
            tracing::warn!(
                "CI is set but INFO_LOG_DIR and INFO_LOG_FILE are missing, only console logs will be used."
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
    let log_path = PathBuf::from(path);
    if let Some(parent_dir) = log_path.parent() {
        std::fs::create_dir_all(parent_dir).map_err(|e| {
            BridgeError::ConfigError(format!(
                "Failed to create log directory '{}': {}",
                parent_dir.display(),
                e
            ))
        })?;
    }

    File::create(&log_path).map_err(|e| BridgeError::ConfigError(e.to_string()))?;
    Ok(env_subscriber_with_writer(CiFileWriter::new(log_path)))
}

fn env_subscriber_with_dir(path: &str) -> Result<Box<dyn Subscriber + Send + Sync>, BridgeError> {
    let log_dir = PathBuf::from(path);
    std::fs::create_dir_all(&log_dir).map_err(|e| {
        BridgeError::ConfigError(format!(
            "Failed to create per-test log directory '{}': {}",
            log_dir.display(),
            e
        ))
    })?;

    Ok(env_subscriber_with_writer(CiPerTestWriter::new(log_dir)))
}

fn env_subscriber_with_writer<W>(writer: W) -> Box<dyn Subscriber + Send + Sync>
where
    W: for<'writer> MakeWriter<'writer> + Send + Sync + 'static,
{
    let file_filter = EnvFilter::from_default_env()
        .add_directive("info".parse().expect("It should parse info level"))
        .add_directive("ci=debug".parse().expect("It should parse ci debug level"));

    let console_filter = EnvFilter::builder()
        .with_default_directive(LevelFilter::WARN.into())
        .from_env_lossy();

    let file_layer = fmt::layer()
        .with_writer(writer)
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

    Box::new(Registry::default().with(file_layer).with(console_layer))
}

#[derive(Clone)]
struct CiFileWriter {
    path: PathBuf,
}

impl CiFileWriter {
    fn new(path: PathBuf) -> Self {
        Self { path }
    }
}

impl<'a> MakeWriter<'a> for CiFileWriter {
    type Writer = RoutedLogWriter;

    fn make_writer(&'a self) -> Self::Writer {
        RoutedLogWriter {
            file: open_append(&self.path).ok(),
        }
    }
}

#[derive(Clone)]
struct CiPerTestWriter {
    dir: PathBuf,
}

impl CiPerTestWriter {
    fn new(dir: PathBuf) -> Self {
        Self { dir }
    }
}

impl<'a> MakeWriter<'a> for CiPerTestWriter {
    type Writer = RoutedLogWriter;

    fn make_writer(&'a self) -> Self::Writer {
        let log_name = current_test_thread_name().unwrap_or_else(|| "process".to_string());
        let path = self
            .dir
            .join(format!("{}.log", sanitize_file_component(&log_name)));
        RoutedLogWriter {
            file: open_append(&path).ok(),
        }
    }
}

struct RoutedLogWriter {
    file: Option<File>,
}

impl Write for RoutedLogWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if let Some(file) = &mut self.file {
            file.write_all(buf)?;
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        if let Some(file) = &mut self.file {
            file.flush()?;
        }
        Ok(())
    }
}

fn open_append(path: &Path) -> io::Result<File> {
    OpenOptions::new().create(true).append(true).open(path)
}

fn current_test_thread_name() -> Option<String> {
    let thread = std::thread::current();
    let name = thread.name()?;
    (!is_non_test_thread_name(name)).then(|| name.to_owned())
}

fn is_non_test_thread_name(name: &str) -> bool {
    matches!(
        name,
        "main" | "tokio-runtime-worker" | "rayon-worker" | "blocking" | "async-std/runtime"
    )
}

fn sanitize_file_component(input: &str) -> String {
    let mut sanitized = String::with_capacity(input.len());
    for ch in input.chars() {
        if ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_') {
            sanitized.push(ch);
        } else {
            sanitized.push('_');
        }
    }

    sanitized.truncate(180);
    sanitized
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
