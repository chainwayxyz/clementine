use std::time::Duration;
use tokio::sync::oneshot;
use tokio::sync::oneshot::error::TryRecvError;
use tokio::task::JoinHandle;
use tokio::time::sleep;
use tonic::async_trait;

use crate::errors::BridgeError;

pub mod manager;
pub mod payout_checker;

#[derive(Debug, Clone, Copy)]
pub enum TaskVariant {
    PayoutChecker,
    StateManager,
    FinalizedBlockFetcher,
    TxSender,
    BitcoinSyncer,
    Dummy,
}

/// Task trait defining the core behavior for cancelable background tasks
///
/// This trait is implemented by any struct that needs to run as a background task.
/// The run_once method contains the main logic of the task, and returns a bool
/// indicating whether it did work (true) or needs to wait (false).
#[async_trait]
pub trait Task: Send + Sync + 'static {
    type Output: Send + Sync + 'static + Sized;
    const VARIANT: TaskVariant;
    /// Run the task once, returning whether work was done
    ///
    /// Returns:
    /// - `Ok(true)` if the task did some work and is ready to run again immediately
    /// - `Ok(false)` if the task did not do work and should wait before running again
    /// - `Err(...)` if the task encountered an error
    async fn run_once(&mut self) -> Result<Self::Output, BridgeError>;
}

/// A trait for objects that can be converted into a Task
pub trait IntoTask {
    type Task: Task;

    /// Convert self into a Task
    fn into_task(self) -> Self::Task;
}

impl<T: Task> IntoTask for T {
    type Task = T;

    fn into_task(self) -> Self::Task {
        self
    }
}

/// A task that adds a certain delay after the inner task has run
/// to reduce polling frequency. When inner returns false, the delay is applied.
#[derive(Debug)]
pub struct WithDelay<T: Task>
where
    T::Output: Into<bool>,
{
    /// The task to poll
    inner: T,
    /// The interval between polls when no work is done
    poll_delay: Duration,
}

impl<T: Task> WithDelay<T>
where
    T::Output: Into<bool>,
{
    /// Create a new delayed task
    pub fn new(inner: T, poll_delay: Duration) -> Self {
        Self { inner, poll_delay }
    }
}

#[async_trait]
impl<T: Task> Task for WithDelay<T>
where
    T::Output: Into<bool>,
{
    type Output = bool;
    const VARIANT: TaskVariant = T::VARIANT;
    async fn run_once(&mut self) -> Result<bool, BridgeError> {
        // Run the inner task
        let did_work = self.inner.run_once().await?.into();

        // If the inner task did not do work, sleep for the poll delay
        if !did_work {
            sleep(self.poll_delay).await;
        }

        // Always return false since we've handled the waiting internally
        Ok(false)
    }
}

/// A task that can be canceled via a oneshot channel
#[derive(Debug)]
pub struct CancelableTask<T: Task> {
    /// The task to run
    inner: T,
    /// Receiver for cancellation signal
    cancel_rx: oneshot::Receiver<()>,
}

impl<T: Task> CancelableTask<T> {
    /// Create a new cancelable task with a cancellation channel
    pub fn new(inner: T, cancel_rx: oneshot::Receiver<()>) -> Self {
        Self { inner, cancel_rx }
    }
}

#[derive(Debug, Clone)]
pub enum CancelableResult<T> {
    Running(T),
    Cancelled,
}

#[async_trait]
impl<T: Task> Task for CancelableTask<T> {
    type Output = CancelableResult<T::Output>;
    const VARIANT: TaskVariant = T::VARIANT;

    async fn run_once(&mut self) -> Result<Self::Output, BridgeError> {
        // Check if we've been canceled
        if let Err(TryRecvError::Empty) = self.cancel_rx.try_recv() {
            // Run the inner task
            Ok(CancelableResult::Running(self.inner.run_once().await?))
        } else {
            Ok(CancelableResult::Cancelled)
        }
    }
}

#[derive(Debug)]
pub struct CancelableLoop<T: Task + Sized> {
    inner: CancelableTask<T>,
}

#[async_trait]
impl<T: Task + Sized> Task for CancelableLoop<T> {
    type Output = ();
    const VARIANT: TaskVariant = T::VARIANT;

    async fn run_once(&mut self) -> Result<Self::Output, BridgeError> {
        loop {
            match self.inner.run_once().await {
                Ok(CancelableResult::Running(_)) => {
                    tokio::task::yield_now().await;
                    continue;
                }
                Ok(CancelableResult::Cancelled) => return Ok(()),
                Err(e) => return Err(e),
            }
        }
    }
}

#[derive(Debug)]
pub struct BufferedErrors<T: Task + Sized>
where
    T::Output: Default,
{
    inner: T,
    buffer: Vec<BridgeError>,
    error_overflow_limit: usize,
}

impl<T: Task + Sized> BufferedErrors<T>
where
    T::Output: Default,
{
    pub fn new(inner: T, error_overflow_limit: usize) -> Self {
        Self {
            inner,
            buffer: Vec::new(),
            error_overflow_limit,
        }
    }
}

#[async_trait]
impl<T: Task + Sized + std::fmt::Debug> Task for BufferedErrors<T>
where
    T::Output: Default,
{
    type Output = T::Output;
    const VARIANT: TaskVariant = T::VARIANT;

    async fn run_once(&mut self) -> Result<Self::Output, BridgeError> {
        let result = self.inner.run_once().await;

        match result {
            Ok(output) => {
                self.buffer.clear(); // clear buffer on first success
                Ok(output)
            }
            Err(e) => {
                tracing::error!("Task error, suppressing due to buffer: {e:?}");
                self.buffer.push(e);
                if self.buffer.len() >= self.error_overflow_limit {
                    let mut base_error: eyre::Report =
                        self.buffer.pop().expect("just inserted above").into();

                    for error in std::mem::take(&mut self.buffer) {
                        base_error = base_error.wrap_err(error);
                    }

                    base_error = base_error.wrap_err(format!(
                        "Exiting due to {} consecutive errors, the following chain is the list of errors.",
                        self.error_overflow_limit
                    ));

                    Err(base_error.into())
                } else {
                    Ok(Default::default())
                }
            }
        }
    }
}

#[derive(Debug)]
pub struct Map<T: Task + Sized, F: Fn(T::Output) -> T::Output + Send + Sync + 'static> {
    inner: T,
    map: F,
}

#[async_trait]
impl<T: Task + Sized, F: Fn(T::Output) -> T::Output + Send + Sync + 'static> Task for Map<T, F> {
    type Output = T::Output;
    const VARIANT: TaskVariant = T::VARIANT;

    #[track_caller]
    async fn run_once(&mut self) -> Result<Self::Output, BridgeError> {
        let result = self.inner.run_once().await;
        let output = match result {
            Ok(output) => (self.map)(output),
            Err(e) => return Err(e),
        };
        Ok(output)
    }
}

/// A task that ignores errors from the inner task and returns a default value.
#[derive(Debug)]
pub struct IgnoreError<T: Task + Sized>
where
    T::Output: Default,
{
    inner: T,
}

#[async_trait]
impl<T: Task + Sized + std::fmt::Debug> Task for IgnoreError<T>
where
    T::Output: Default,
{
    type Output = T::Output;
    const VARIANT: TaskVariant = T::VARIANT;

    async fn run_once(&mut self) -> Result<Self::Output, BridgeError> {
        Ok(self
            .inner
            .run_once()
            .await
            .inspect_err(|e| {
                tracing::error!(task=?self.inner, "Task error, suppressing due to errors ignored: {e:?}");
            })
            .ok()
            .unwrap_or_default())
    }
}

pub trait TaskExt: Task + Sized {
    /// Skips running the task after cancellation using the sender.
    fn cancelable(self) -> (CancelableTask<Self>, oneshot::Sender<()>);

    /// Runs the task in an infinite loop until cancelled using the sender.
    fn cancelable_loop(self) -> (CancelableLoop<Self>, oneshot::Sender<()>);

    /// Adds the given delay after a run of the task when the task returns false.
    fn with_delay(self, poll_delay: Duration) -> WithDelay<Self>
    where
        Self::Output: Into<bool>;

    /// Spawns a [`tokio::task`] that runs the task once in the background.
    fn into_bg(self) -> JoinHandle<Result<Self::Output, BridgeError>>;

    /// Buffers consecutive errors until the task succeeds, emits all errors when there are
    /// more than `error_overflow_limit` consecutive errors.
    fn into_buffered_errors(self, error_overflow_limit: usize) -> BufferedErrors<Self>
    where
        Self::Output: Default;

    /// Maps the task's `Ok()` output using the given function.
    fn map<F: Fn(Self::Output) -> Self::Output + Send + Sync + 'static>(
        self,
        map: F,
    ) -> Map<Self, F>;

    /// Ignores errors from the task.
    fn ignore_error(self) -> IgnoreError<Self>
    where
        Self::Output: Default;
}

impl<T: Task + Sized> TaskExt for T {
    fn cancelable(self) -> (CancelableTask<Self>, oneshot::Sender<()>) {
        let (cancel_tx, cancel_rx) = oneshot::channel();
        (CancelableTask::new(self, cancel_rx), cancel_tx)
    }

    fn cancelable_loop(self) -> (CancelableLoop<Self>, oneshot::Sender<()>) {
        let (task, cancel_tx) = self.cancelable();
        (CancelableLoop { inner: task }, cancel_tx)
    }

    fn with_delay(self, poll_delay: Duration) -> WithDelay<Self>
    where
        Self::Output: Into<bool>,
    {
        WithDelay::new(self, poll_delay)
    }

    fn into_bg(mut self) -> JoinHandle<Result<Self::Output, BridgeError>> {
        tokio::spawn(async move { self.run_once().await })
    }

    fn into_buffered_errors(self, error_overflow_limit: usize) -> BufferedErrors<Self>
    where
        Self::Output: Default,
    {
        BufferedErrors::new(self, error_overflow_limit)
    }

    fn map<F: Fn(Self::Output) -> Self::Output + Send + Sync + 'static>(
        self,
        map: F,
    ) -> Map<Self, F> {
        Map { inner: self, map }
    }

    fn ignore_error(self) -> IgnoreError<Self>
    where
        Self::Output: Default,
    {
        IgnoreError { inner: self }
    }
}

#[cfg(test)]
mod tests;
