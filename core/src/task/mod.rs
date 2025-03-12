use std::time::Duration;
use tokio::sync::oneshot;
use tokio::sync::oneshot::error::TryRecvError;
use tokio::task::JoinHandle;
use tokio::time::sleep;
use tonic::async_trait;

use crate::errors::BridgeError;

pub mod manager;

/// Task trait defining the core behavior for cancelable background tasks
///
/// This trait is implemented by any struct that needs to run as a background task.
/// The run_once method contains the main logic of the task, and returns a bool
/// indicating whether it did work (true) or needs to wait (false).
#[async_trait]
pub trait Task: Send + Sync + 'static {
    type Output: Send + Sync + 'static + Sized;
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

/// A task that polls another task at regular intervals
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

    async fn run_once(&mut self) -> Result<Self::Output, BridgeError> {
        loop {
            match self.inner.run_once().await {
                Ok(CancelableResult::Running(_)) => {
                    continue;
                }
                Ok(CancelableResult::Cancelled) => return Ok(()),
                Err(e) => return Err(e),
            }
        }
    }
}

#[derive(Debug)]
pub struct BufferedError<T: Task + Sized>
where
    T::Output: Default,
{
    inner: T,
    buffer: Vec<BridgeError>,
    error_overflow_limit: usize,
}

impl<T: Task + Sized> BufferedError<T>
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
impl<T: Task + Sized> Task for BufferedError<T>
where
    T::Output: Default,
{
    type Output = T::Output;

    async fn run_once(&mut self) -> Result<Self::Output, BridgeError> {
        let result = self.inner.run_once().await;

        match result {
            Ok(output) => Ok(output),
            Err(e) => {
                self.buffer.push(e);
                if self.buffer.len() >= self.error_overflow_limit {
                    let mut base_error = eyre::eyre!("The task with buffered errors have failed, the following chain is the list of errors.");
                    for error in std::mem::take(&mut self.buffer) {
                        base_error = base_error.wrap_err(error);
                    }
                    Err(base_error.into())
                } else {
                    Ok(Default::default())
                }
            }
        }
    }
}

pub trait TaskExt: Task + Sized {
    fn into_cancelable(self) -> (CancelableTask<Self>, oneshot::Sender<()>);

    fn into_loop(self) -> (CancelableLoop<Self>, oneshot::Sender<()>);

    fn into_polling(self, poll_delay: Duration) -> WithDelay<Self>
    where
        Self::Output: Into<bool>;

    fn into_bg(self) -> JoinHandle<Result<Self::Output, BridgeError>>;

    fn into_error_buffered(self, error_overflow_limit: usize) -> BufferedError<Self>
    where
        Self::Output: Default;
}

impl<T: Task + Sized> TaskExt for T {
    fn into_cancelable(self) -> (CancelableTask<Self>, oneshot::Sender<()>) {
        let (cancel_tx, cancel_rx) = oneshot::channel();
        (CancelableTask::new(self, cancel_rx), cancel_tx)
    }

    fn into_loop(self) -> (CancelableLoop<Self>, oneshot::Sender<()>) {
        let (task, cancel_tx) = self.into_cancelable();
        (CancelableLoop { inner: task }, cancel_tx)
    }

    fn into_polling(self, poll_delay: Duration) -> WithDelay<Self>
    where
        Self::Output: Into<bool>,
    {
        WithDelay::new(self, poll_delay)
    }

    fn into_bg(mut self) -> JoinHandle<Result<Self::Output, BridgeError>> {
        tokio::spawn(async move { self.run_once().await })
    }

    fn into_error_buffered(self, error_overflow_limit: usize) -> BufferedError<Self>
    where
        Self::Output: Default,
    {
        BufferedError::new(self, error_overflow_limit)
    }
}
