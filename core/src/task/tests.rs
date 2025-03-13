use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

use tokio::time::sleep;
use tonic::async_trait;

use crate::builder::transaction::{ContractContext, TransactionType, TxHandler};
use crate::database::DatabaseTransaction;
use crate::errors::BridgeError;
use crate::states::context::Duty;
use crate::states::{block_cache, Owner};

use super::manager::BackgroundTaskManager;
use super::{CancelableResult, Task, TaskExt};

// A simple counter task that increments a counter each time it runs
#[derive(Debug, Clone)]
struct CounterTask {
    counter: Arc<Mutex<u32>>,
    work_to_do: u32,
    current_work: u32,
    one_time_fix_at: Option<u32>,
    should_error: bool,
}

impl CounterTask {
    fn new(counter: Arc<Mutex<u32>>, work_to_do: u32) -> Self {
        Self {
            counter,
            work_to_do,
            current_work: 0,
            should_error: false,
            one_time_fix_at: None,
        }
    }

    fn with_error(counter: Arc<Mutex<u32>>, work_to_do: u32, one_time_fix_at: Option<u32>) -> Self {
        Self {
            counter,
            work_to_do,
            current_work: 0,
            should_error: true,
            one_time_fix_at,
        }
    }
}

#[tonic::async_trait]
impl Task for CounterTask {
    type Output = bool;

    async fn run_once(&mut self) -> Result<Self::Output, BridgeError> {
        if self.should_error && self.one_time_fix_at != Some(*self.counter.lock().await) {
            return Err(BridgeError::Error("Task error".to_string()));
        }

        if self.current_work < self.work_to_do {
            let mut counter = self.counter.lock().await;
            *counter += 1;
            self.current_work += 1;
            Ok(true) // did work
        } else {
            Ok(false) // no work to do
        }
    }
}

// A task that sleeps for a specified duration
#[derive(Debug, Clone)]
struct SleepTask {
    duration: Duration,
}

impl SleepTask {
    fn new(duration: Duration) -> Self {
        Self { duration }
    }
}

#[tonic::async_trait]
impl Task for SleepTask {
    type Output = bool;

    async fn run_once(&mut self) -> Result<Self::Output, BridgeError> {
        sleep(self.duration).await;
        Ok(true)
    }
}

// Define an Owner for testing BackgroundTaskManager
#[derive(Debug, Clone)]
struct TestOwner;

#[async_trait]
impl Owner for TestOwner {
    const OWNER_TYPE: &'static str = "test_owner";

    async fn handle_duty(&self, _duty: Duty) -> Result<(), BridgeError> {
        // For testing purposes, just return OK
        Ok(())
    }

    async fn create_txhandlers(
        &self,
        _tx_type: TransactionType,
        _contract_context: ContractContext,
    ) -> Result<BTreeMap<TransactionType, TxHandler>, BridgeError> {
        // Return empty BTreeMap for testing
        Ok(BTreeMap::new())
    }

    async fn handle_finalized_block(
        &self,
        _dbtx: DatabaseTransaction<'_, '_>,
        _block_id: u32,
        _block_height: u32,
        _block_cache: Arc<block_cache::BlockCache>,
        _light_client_proof_wait_interval_secs: Option<u32>,
    ) -> Result<(), BridgeError> {
        Ok(())
    }
}

#[tokio::test]
async fn test_counter_task() {
    let counter = Arc::new(Mutex::new(0));
    let mut task = CounterTask::new(Arc::clone(&counter), 5);

    // Run the task 6 times, should increment counter 5 times
    for i in 0..6 {
        let result = task.run_once().await.unwrap();
        if i < 5 {
            assert!(result); // task did work
        } else {
            assert!(!result); // task did not do work
        }
    }

    assert_eq!(*counter.lock().await, 5);
}

#[tokio::test]
async fn test_with_delay() {
    let counter = Arc::new(Mutex::new(0));
    let task = CounterTask::new(Arc::clone(&counter), 1);
    let mut delayed_task = task.with_delay(Duration::from_millis(100));

    // First run should do work and return false (because of WithDelay)
    let start = Instant::now();
    let result = delayed_task.run_once().await.unwrap();
    assert!(!result);
    assert!(start.elapsed() < Duration::from_millis(100));
    assert_eq!(*counter.lock().await, 1);

    // Second run should not do work and wait for the delay
    let start = Instant::now();
    let result = delayed_task.run_once().await.unwrap();
    let elapsed = start.elapsed();
    assert!(!result);
    assert!(elapsed >= Duration::from_millis(100));
    {
        assert_eq!(*counter.lock().await, 1);
    }
}

#[tokio::test]
async fn test_cancelable_task() {
    let counter = Arc::new(Mutex::new(0));
    let task = CounterTask::new(Arc::clone(&counter), 5);

    let (mut cancelable_task, cancel_tx) = task.cancelable();

    // Run once, should increment counter
    let result = cancelable_task.run_once().await.unwrap();
    if let CancelableResult::Running(did_work) = result {
        assert!(did_work);
    } else {
        panic!("Expected Running result");
    }
    {
        assert_eq!(*counter.lock().await, 1);
    }

    // Cancel the task
    cancel_tx.send(()).unwrap();

    // Run again, should be cancelled
    let result = cancelable_task.run_once().await.unwrap();
    if let CancelableResult::Cancelled = result {
        // Expected
    } else {
        panic!("Expected Cancelled result");
    }

    // Counter should still be at 1
    {
        assert_eq!(*counter.lock().await, 1);
    }
}

#[tokio::test]
async fn test_cancelable_loop() {
    let counter = Arc::new(Mutex::new(0));
    let task = CounterTask::new(Arc::clone(&counter), 5);

    let (mut cancelable_loop, cancel_tx) = task.cancelable_loop();

    tokio::spawn(async move {
        sleep(Duration::from_millis(10)).await;
        cancel_tx.send(()).unwrap();
    });

    // Run the loop, should stop after counter reaches 3
    let result = tokio::time::timeout(Duration::from_millis(20), cancelable_loop.run_once()).await;
    assert!(result.is_ok());
    drop(cancelable_loop);

    // Counter should be at 3 (or slightly more if there was a race)
    let final_counter = *counter.lock().await;
    assert!((3..=5).contains(&final_counter));
}

#[tokio::test]
async fn test_into_bg() {
    let counter = Arc::new(Mutex::new(0));
    let task = CounterTask::new(Arc::clone(&counter), 1);

    // Spawn the task in the background
    let bg_handle = task.into_bg();

    // Wait for the task to complete
    let result = bg_handle.await.unwrap();

    // Check that the task completed successfully and did work
    assert!(result.is_ok());
    assert!(result.unwrap());

    // Counter should be incremented
    assert_eq!(*counter.lock().await, 1);
}

#[tokio::test]
async fn test_buffered_errors() {
    let counter = Arc::new(Mutex::new(0));
    let task = CounterTask::with_error(Arc::clone(&counter), 5, None);
    let mut buffered_task = task.into_buffered_errors(3);

    // First two errors should be buffered
    for _ in 0..2 {
        let result = buffered_task.run_once().await;
        assert!(result.is_ok());
    }

    // Third error should cause the task to fail
    let result = buffered_task.run_once().await;
    assert!(result.is_err());

    // Print the actual error message to understand its format
    let err = result.unwrap_err();
    let err_str = format!("{:?}", err);

    assert!(
        err_str.contains("Task error"),
        "Error does not contain the expected task error message: '{}'",
        err_str
    );

    assert!(
        err_str.contains("3 consecutive errors"),
        "Error does not contain '3 consecutive errors': '{}'",
        err_str
    );
}

#[tokio::test]
async fn test_buffered_errors_without_consecutive_errors() {
    let counter = Arc::new(Mutex::new(0));
    let task = CounterTask::with_error(Arc::clone(&counter), 5, Some(2));
    let mut buffered_task = task.into_buffered_errors(3);

    // First two errors should be buffered, then an Ok should reset and the next
    // two should also be buffered
    for _ in 0..2 {
        let result = buffered_task.run_once().await;
        assert!(result.is_ok());
    }

    *counter.lock().await = 2;

    for _ in 0..3 {
        let result = buffered_task.run_once().await;
        assert!(result.is_ok());
    }

    // Sixth error should cause the task to fail
    let result = buffered_task.run_once().await;
    assert!(result.is_err());

    // Print the actual error message to understand its format
    let err = result.unwrap_err();
    let err_str = format!("{:?}", err);

    assert!(
        err_str.contains("Task error"),
        "Error does not contain the expected task error message: '{}'",
        err_str
    );

    assert!(
        err_str.contains("3 consecutive errors"),
        "Error does not contain '3 consecutive errors': '{}'",
        err_str
    );
}

#[tokio::test]
async fn test_ignore_error() {
    let counter = Arc::new(Mutex::new(0));
    let task = CounterTask::with_error(Arc::clone(&counter), 5, None);
    let mut ignore_task = task.ignore_error();

    // Task errors should be ignored
    let result = ignore_task.run_once().await;
    assert!(result.is_ok());
    assert!(!result.unwrap()); // default value when error is ignored
}

#[tokio::test]
async fn test_map() {
    let counter = Arc::new(Mutex::new(0));
    let task = CounterTask::new(Arc::clone(&counter), 5);
    let mut map_task = task.map(|did_work| !did_work); // Invert the boolean

    // Run the task, counter should be incremented
    let result = map_task.run_once().await.unwrap();
    assert!(!result); // The original would return true, but we mapped it to !true = false
    assert_eq!(*counter.lock().await, 1);
}

#[tokio::test]
async fn test_task_manager() {
    let counter = Arc::new(Mutex::new(0));
    let mut manager = BackgroundTaskManager::<TestOwner>::default();

    // Add a task that increments the counter 5 times
    let task = CounterTask::new(Arc::clone(&counter), 5);
    manager.loop_and_monitor(task);

    // Sleep to give the task time to run
    sleep(Duration::from_millis(500)).await;

    // Counter should be at 5
    assert_eq!(*counter.lock().await, 5);

    // Graceful shutdown should allow the task to complete
    manager.graceful_shutdown().await;
}

#[tokio::test]
async fn test_task_manager_abort() {
    let counter = Arc::new(Mutex::new(0));
    let mut manager = BackgroundTaskManager::<TestOwner>::default();

    // Add a task that sleeps for a long time
    let task = SleepTask::new(Duration::from_secs(10));
    manager.loop_and_monitor(task);

    // Start a counter task too
    let task = CounterTask::new(Arc::clone(&counter), 100);
    manager.loop_and_monitor(task);

    // Sleep for a short time to let tasks start
    sleep(Duration::from_millis(100)).await;

    // Abort all tasks
    manager.abort_all();
}

#[tokio::test]
async fn test_task_manager_timeout() {
    let mut manager = BackgroundTaskManager::<TestOwner>::default();

    // Add a task that sleeps for a long time
    let task = SleepTask::new(Duration::from_secs(10));
    manager.loop_and_monitor(task);

    // Graceful shutdown with short timeout should abort the task
    let start = Instant::now();
    manager
        .graceful_shutdown_with_timeout(Duration::from_millis(200))
        .await;
    let elapsed = start.elapsed();

    // Should timeout and abort quickly
    assert!(elapsed < Duration::from_secs(1));
}
