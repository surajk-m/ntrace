// Multi-core infrastructure for ntrace
//
// This module provides the core infrastructure for distributing network scanning
// and traceroute operations across multiple CPU cores using OS-level threads,
// each with its own Tokio runtime.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use crossbeam::queue::SegQueue;
use tokio::sync::Mutex;

/// Work item types that can be distributed across worker threads
#[derive(Debug, Clone)]
pub enum WorkItem {
    /// Scan a specific port
    ScanPort(u16),
    /// Probe a specific TTL hop
    ProbeHop(u8),
    /// Signal to shutdown the worker thread
    Shutdown,
}

/// Statistics tracked per worker thread
#[derive(Debug, Clone, Default)]
pub struct ThreadStats {
    pub thread_id: usize,
    pub ports_scanned: usize,
    pub scan_time: Duration,
    pub errors: usize,
    pub cpu_time: Duration,
}

/// Work distribution strategy for load balancing
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkDistributionStrategy {
    /// Divide work into equal chunks upfront
    Static,
    /// Threads pull work dynamically as they complete tasks
    Dynamic,
    /// Combination of static initial distribution with dynamic work stealing
    Hybrid,
}

impl Default for WorkDistributionStrategy {
    fn default() -> Self {
        WorkDistributionStrategy::Hybrid
    }
}

/// Configuration for multi-core scanning
#[derive(Debug, Clone)]
pub struct MultiCoreConfig {
    /// Number of worker threads (None = auto-detect CPU cores)
    pub thread_count: Option<usize>,
    /// Work distribution strategy
    pub work_distribution: WorkDistributionStrategy,
    /// Enable work stealing between threads
    pub enable_work_stealing: bool,
    /// Pin threads to specific CPU cores
    pub cpu_affinity: Option<Vec<usize>>,
    /// Automatically adjust thread count based on system load
    pub auto_tune: bool,
}

impl Default for MultiCoreConfig {
    fn default() -> Self {
        MultiCoreConfig {
            thread_count: None,
            work_distribution: WorkDistributionStrategy::Hybrid,
            enable_work_stealing: true,
            cpu_affinity: None,
            auto_tune: false,
        }
    }
}

/// Global rate limiter for coordinating rate limits across all threads
pub struct GlobalRateLimiter {
    tokens: Arc<AtomicUsize>,
    rate: usize,
    last_refill: Arc<Mutex<Instant>>,
}

impl GlobalRateLimiter {
    /// Create a new rate limiter with the specified rate (operations per second)
    pub fn new(rate: usize) -> Self {
        GlobalRateLimiter {
            tokens: Arc::new(AtomicUsize::new(rate)),
            rate,
            last_refill: Arc::new(Mutex::new(Instant::now())),
        }
    }

    /// Acquire a token, waiting if necessary
    pub async fn acquire(&self) -> bool {
        loop {
            let current = self.tokens.load(Ordering::Relaxed);
            if current > 0 {
                if self
                    .tokens
                    .compare_exchange(current, current - 1, Ordering::Relaxed, Ordering::Relaxed)
                    .is_ok()
                {
                    return true;
                }
            } else {
                // Refill tokens if enough time has passed
                let mut last_refill = self.last_refill.lock().await;
                let elapsed = last_refill.elapsed();
                if elapsed >= Duration::from_secs(1) {
                    self.tokens.store(self.rate, Ordering::Relaxed);
                    *last_refill = Instant::now();
                } else {
                    // Wait for refill
                    drop(last_refill);
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            }
        }
    }
}

/// Worker thread that executes scanning work
pub struct WorkerThread {
    pub thread_id: usize,
    handle: Option<JoinHandle<()>>,
}

impl WorkerThread {
    /// Spawn a new worker thread
    pub fn spawn(
        thread_id: usize,
        work_queue: Arc<SegQueue<WorkItem>>,
        shutdown: Arc<AtomicBool>,
    ) -> Self {
        let handle = std::thread::spawn(move || {
            // Create dedicated Tokio runtime for this thread
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("Failed to create Tokio runtime");

            runtime.block_on(async {
                // Work loop
                while !shutdown.load(Ordering::Relaxed) {
                    if let Some(work) = work_queue.pop() {
                        match work {
                            WorkItem::Shutdown => break,
                            _ => {
                                // Work processing will be implemented in later tasks
                            }
                        }
                    } else {
                        // No work available, yield
                        tokio::task::yield_now().await;
                    }
                }
            });
        });

        WorkerThread {
            thread_id,
            handle: Some(handle),
        }
    }

    /// Wait for the worker thread to complete
    pub fn join(mut self) -> std::thread::Result<()> {
        if let Some(handle) = self.handle.take() {
            handle.join()
        } else {
            Ok(())
        }
    }
}

/// Manages a pool of worker threads
pub struct ThreadPoolManager {
    workers: Vec<WorkerThread>,
    work_queue: Arc<SegQueue<WorkItem>>,
    shutdown: Arc<AtomicBool>,
}

impl ThreadPoolManager {
    /// Create a new thread pool with the specified number of threads
    pub fn new(thread_count: usize) -> Self {
        let work_queue = Arc::new(SegQueue::new());
        let shutdown = Arc::new(AtomicBool::new(false));
        let mut workers = Vec::with_capacity(thread_count);

        for thread_id in 0..thread_count {
            workers.push(WorkerThread::spawn(
                thread_id,
                work_queue.clone(),
                shutdown.clone(),
            ));
        }

        ThreadPoolManager {
            workers,
            work_queue,
            shutdown,
        }
    }

    /// Distribute work items to the thread pool
    pub fn distribute_work(&self, items: Vec<WorkItem>) {
        for item in items {
            self.work_queue.push(item);
        }
    }

    /// Gracefully shutdown all worker threads
    pub fn shutdown(self) {
        // Signal shutdown
        self.shutdown.store(true, Ordering::Relaxed);

        // Push shutdown messages for each worker
        for _ in 0..self.workers.len() {
            self.work_queue.push(WorkItem::Shutdown);
        }

        // Wait for all workers to complete
        for worker in self.workers {
            let _ = worker.join();
        }
    }
}

/// Distributes work across threads according to the configured strategy
pub struct WorkDistributor {
    strategy: WorkDistributionStrategy,
}

impl WorkDistributor {
    /// Create a new work distributor with the specified strategy
    pub fn new(strategy: WorkDistributionStrategy) -> Self {
        WorkDistributor { strategy }
    }

    /// Distribute ports across threads according to the strategy
    pub fn distribute_ports(&self, ports: Vec<u16>, thread_count: usize) -> Vec<WorkItem> {
        match self.strategy {
            WorkDistributionStrategy::Static => self.distribute_static(ports, thread_count),
            WorkDistributionStrategy::Dynamic => self.distribute_dynamic(ports),
            WorkDistributionStrategy::Hybrid => self.distribute_hybrid(ports, thread_count),
        }
    }

    fn distribute_static(&self, ports: Vec<u16>, _thread_count: usize) -> Vec<WorkItem> {
        ports.into_iter().map(WorkItem::ScanPort).collect()
    }

    fn distribute_dynamic(&self, ports: Vec<u16>) -> Vec<WorkItem> {
        ports.into_iter().map(WorkItem::ScanPort).collect()
    }

    fn distribute_hybrid(&self, ports: Vec<u16>, _thread_count: usize) -> Vec<WorkItem> {
        ports.into_iter().map(WorkItem::ScanPort).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_work_item_creation() {
        let scan_port = WorkItem::ScanPort(80);
        let probe_hop = WorkItem::ProbeHop(5);
        let shutdown = WorkItem::Shutdown;

        match scan_port {
            WorkItem::ScanPort(port) => assert_eq!(port, 80),
            _ => panic!("Expected ScanPort"),
        }

        match probe_hop {
            WorkItem::ProbeHop(ttl) => assert_eq!(ttl, 5),
            _ => panic!("Expected ProbeHop"),
        }

        match shutdown {
            WorkItem::Shutdown => (),
            _ => panic!("Expected Shutdown"),
        }
    }

    #[test]
    fn test_multicore_config_default() {
        let config = MultiCoreConfig::default();
        assert_eq!(config.thread_count, None);
        assert_eq!(config.work_distribution, WorkDistributionStrategy::Hybrid);
        assert!(config.enable_work_stealing);
        assert_eq!(config.cpu_affinity, None);
        assert!(!config.auto_tune);
    }

    #[test]
    fn test_work_distribution_strategy() {
        let static_strategy = WorkDistributionStrategy::Static;
        let dynamic_strategy = WorkDistributionStrategy::Dynamic;
        let hybrid_strategy = WorkDistributionStrategy::Hybrid;

        assert_eq!(static_strategy, WorkDistributionStrategy::Static);
        assert_eq!(dynamic_strategy, WorkDistributionStrategy::Dynamic);
        assert_eq!(hybrid_strategy, WorkDistributionStrategy::Hybrid);
        assert_eq!(WorkDistributionStrategy::default(), WorkDistributionStrategy::Hybrid);
    }
}
