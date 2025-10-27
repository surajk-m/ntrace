/// # ntrace: A fast and secure network port scanner and protocol analyzer.
///
/// This library provides functionality for scanning TCP/UDP ports, detecting services,
/// and analyzing protocols on a target host. It is designed for penetration testing
/// and security auditing.
///
/// ## Features
///
/// - **Advanced Port Scanning**: Asynchronous TCP port scanning with configurable concurrency and rate limiting
/// - **Service Detection**: Identifies services running on open ports
/// - **Protocol Analysis**: Detects and analyzes common protocols
/// - **Flexible Port Selection**: Scan specific ports, ranges, or use predefined groups
/// - **Traceroute**: Trace the route packets take to a host with TCP, UDP, or ICMP
///
/// ## Example
///
/// ```rust,no_run
/// use ntrace::{Scanner, ScanConfig, Protocol, Target};
/// use std::net::IpAddr;
/// use std::str::FromStr;
/// use std::time::Duration;
///
/// #[tokio::main]
/// async fn main() -> Result<(), Box<dyn std::error::Error>> {
///     // Configure the scanner
///     let config = ScanConfig {
///         target: Target::Ip(IpAddr::from_str("192.168.1.1")?),
///         ports: vec![80, 443, 8080],
///         timeout: Duration::from_secs(2),
///         protocol: Protocol::Tcp,
///         batch_size: 100,
///         max_retries: 3,
///         retry_delay: Duration::from_millis(500),
///         fail_fast: false,
///     };
///
///     // Create and configure the scanner
///     let scanner = Scanner::new(config)
///         .with_rate_limit(1000)
///         .with_concurrency_limit(50);
///     
///     // Run the scan
///     let results = scanner.scan().await?;
///     
///     // Process results
///     for result in results {
///         if result.is_open {
///             println!(
///                 "Port {}: Open - Service: {}, Protocol: {}, Latency: {:?}",
///                 result.port,
///                 result.service.unwrap_or_else(|| "Unknown".to_string()),
///                 result.protocol_info.unwrap_or_else(|| "Unknown".to_string()),
///                 result.latency
///             );
///         }
///     }
///
///     Ok(())
/// }
/// ```
pub mod capability;
pub mod cli;
pub mod error;
pub mod multicore;
pub mod output;
pub mod protocol;
pub mod scanner;
pub mod services;
pub mod traceroute;

pub use capability::{ensure_cap_net_raw, has_cap_net_raw, try_set_cap_net_raw};
/// Command line interface for ntrace
pub use cli::Cli;
pub use error::NtraceError;
/// Multi-core infrastructure types
pub use multicore::{
    GlobalRateLimiter, MultiCoreConfig, ThreadPoolManager, ThreadStats, WorkDistributionStrategy,
    WorkDistributor, WorkItem, WorkerThread,
};
pub use output::ScanResult;
/// Protocol types and analyzer
pub use protocol::{Protocol, ProtocolAnalyzer, Target};
/// Core scanner functionality
pub use scanner::{PortResult, ScanConfig, Scanner};
/// Traceroute functionality
pub use traceroute::{TraceConfig, TraceResult, Tracer};
