use crate::error::NtraceError;
use crate::protocol::{Protocol, ProtocolAnalyzer};
use crate::services::get_service_name;
use log::{debug, info, warn};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use tokio::time::Instant;

/// Configuration for the scanner.
#[derive(Debug, Clone)]
pub struct ScanConfig {
    pub host: IpAddr,
    pub ports: Vec<u16>,
    pub timeout: Duration,
    pub protocol: Protocol,
    pub batch_size: usize,
}

/// Represents a single port scan result.
#[derive(Debug, Clone, serde::Serialize)]
pub struct PortResult {
    pub port: u16,
    pub is_open: bool,
    pub service: Option<String>,
    pub protocol_info: Option<String>,
    pub latency: Option<Duration>,
    pub scan_time: chrono::DateTime<chrono::Utc>,
}

/// Scanner for performing network port scans.
#[derive(Clone)]
pub struct Scanner {
    config: ScanConfig,
    analyzer: ProtocolAnalyzer,
    /// Rate limiting for scans (requests per second)
    rate_limit: Option<usize>,
    /// Maximum number of concurrent scans
    concurrency_limit: usize,
}

impl Scanner {
    /// Creates a new scanner with the given configuration.
    pub fn new(config: ScanConfig) -> Self {
        Scanner {
            config: config.clone(),
            analyzer: ProtocolAnalyzer::new(),
            rate_limit: None,
            concurrency_limit: config.batch_size,
        }
    }

    /// Set a rate limit (scans per second)
    pub fn with_rate_limit(mut self, rate: usize) -> Self {
        self.rate_limit = Some(rate);
        self
    }

    /// Set a concurrency limit (maximum parallel scans)
    pub fn with_concurrency_limit(mut self, limit: usize) -> Self {
        self.concurrency_limit = limit;
        self
    }

    /// Scans all configured ports in parallel and returns results.
    pub async fn scan(&self) -> Result<Vec<PortResult>, NtraceError> {
        let start_time = Instant::now();
        info!(
            "Starting scan of {} ports on {}",
            self.config.ports.len(),
            self.config.host
        );

        // Create a semaphore to limit concurrency
        let semaphore = Arc::new(Semaphore::new(self.concurrency_limit));
        let mut join_set = JoinSet::new();
        let mut results = Vec::with_capacity(self.config.ports.len());

        // Process all ports with controlled concurrency
        for &port in &self.config.ports {
            // Apply rate limiting if configured
            if let Some(rate) = self.rate_limit {
                let delay = Duration::from_secs_f64(1.0 / rate as f64);
                tokio::time::sleep(delay).await;
            }

            // Acquire a permit from the semaphore
            let permit = semaphore.clone().acquire_owned().await.unwrap();
            let config = self.config.clone();
            let analyzer = self.analyzer.clone();

            join_set.spawn(async move {
                let result = Self::scan_port(config, port, &analyzer).await;
                // Release the permit when done
                drop(permit);
                (port, result)
            });
        }

        // Collect all results
        while let Some(Ok((port, result))) = join_set.join_next().await {
            match result {
                Ok(port_result) => results.push(port_result),
                Err(e) => warn!("Failed to scan port {}: {}", port, e),
            }
        }

        // Sort results by port for consistent output
        results.sort_by_key(|r| r.port);

        let elapsed = start_time.elapsed();
        info!("Scan completed in {:.2}s", elapsed.as_secs_f64());

        Ok(results)
    }

    /// Scans a single port and performs protocol analysis if open.
    async fn scan_port(
        config: ScanConfig,
        port: u16,
        analyzer: &ProtocolAnalyzer,
    ) -> Result<PortResult, NtraceError> {
        let addr = SocketAddr::new(config.host, port);
        let port_start = Instant::now();
        debug!("Scanning port {}", port);

        // Default values
        let mut is_open = false;
        let mut latency = None;
        let mut service = None;
        let mut protocol_info = None;

        // Scan based on protocol
        match config.protocol {
            Protocol::Tcp => {
                let connect_start = Instant::now();
                let stream = tokio::time::timeout(config.timeout, TcpStream::connect(addr)).await;

                if let Ok(Ok(mut stream)) = stream {
                    is_open = true;
                    latency = Some(connect_start.elapsed());

                    // Try to detect service and protocol
                    service = match analyzer.detect_service(&mut stream, config.protocol).await {
                        Ok(s) => s,
                        Err(e) => {
                            debug!("Service detection error on port {}: {}", port, e);
                            None
                        }
                    };

                    // If no service was detected but port is well-known, use default service name
                    if service.is_none() {
                        let default_service = get_service_name(port);
                        if default_service != "unknown" {
                            service = Some(default_service.to_string());
                        }
                    }

                    // Analyze protocol details
                    protocol_info = match analyzer.analyze_protocol(&stream, config.protocol).await
                    {
                        Ok(p) => p,
                        Err(e) => {
                            debug!("Protocol analysis error on port {}: {}", port, e);
                            None
                        }
                    };
                } else if let Err(_) = stream {
                    debug!("Connection timeout on port {}", port);
                }
            }
            Protocol::Udp => {
                // UDP scanning would be implemented here
                // This is more complex as UDP is connectionless
                // A proper implementation would send a packet and listen for responses or ICMP errors
            }
        }

        let result = PortResult {
            port,
            is_open,
            service,
            protocol_info,
            latency,
            scan_time: chrono::Utc::now(),
        };

        debug!("Port {} scan completed in {:?}", port, port_start.elapsed());
        Ok(result)
    }

    /// Performs a quick ping scan to check if host is reachable
    pub async fn ping_host(&self) -> Result<bool, NtraceError> {
        // Try to connect to a few common ports to see if host is up
        let common_ports = [80, 443, 22, 25];

        for &port in &common_ports {
            let addr = SocketAddr::new(self.config.host, port);
            // Short timeout for ping
            let timeout = Duration::from_millis(500);

            if tokio::time::timeout(timeout, TcpStream::connect(addr))
                .await
                .is_ok()
            {
                return Ok(true);
            }
        }

        Ok(false)
    }
}
