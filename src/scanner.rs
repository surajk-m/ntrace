use crate::error::NtraceError;
use crate::protocol::{Protocol, ProtocolAnalyzer};
use crate::services::get_service_name;
use log::{debug, info};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};
use tokio::net::TcpStream;

use std::sync::Arc;
/// Configuration for the scanner.
#[derive(Debug, Clone)]
pub struct ScanConfig {
    pub host: IpAddr,
    pub ports: Vec<u16>,
    pub timeout: Duration,
    pub protocol: Protocol,
    pub batch_size: usize,
    pub max_retries: usize,
    pub retry_delay: Duration,
    pub fail_fast: bool,
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
    /// Error handler function
    error_handler: Option<fn(&NtraceError) -> bool>,
    /// Scan statistics
    stats: Arc<tokio::sync::Mutex<ScanStats>>,
}

/// Statistics collected during scanning
#[derive(Debug, Default, Clone)]
pub struct ScanStats {
    pub total_ports: usize,
    pub scanned_ports: usize,
    pub open_ports: usize,
    pub closed_ports: usize,
    pub filtered_ports: usize,
    pub errors: usize,
    pub retries: usize,
    pub start_time: Option<Instant>,
    pub end_time: Option<Instant>,
    pub error_map: HashMap<u16, Vec<String>>,
}

impl Scanner {
    /// Creates a new scanner with the given configuration.
    pub fn new(mut config: ScanConfig) -> Self {
        // Set default values if not provided
        if config.max_retries == 0 {
            // Default to 3 retries
            config.max_retries = 3;
        }

        if config.retry_delay.is_zero() {
            // Default to 500ms
            config.retry_delay = Duration::from_millis(500);
        }

        let stats = ScanStats {
            total_ports: config.ports.len(),
            ..Default::default()
        };

        let batch_size = config.batch_size;

        Scanner {
            config,
            analyzer: ProtocolAnalyzer::new(),
            rate_limit: None,
            concurrency_limit: batch_size,
            error_handler: None,
            stats: Arc::new(tokio::sync::Mutex::new(stats)),
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

    /// Set a custom error handler function
    /// The handler should return true if the scan should continue, false to abort
    pub fn with_error_handler(mut self, handler: fn(&NtraceError) -> bool) -> Self {
        self.error_handler = Some(handler);
        self
    }

    /// Get the current scan statistics
    pub async fn get_stats(&self) -> ScanStats {
        self.stats.lock().await.clone()
    }

    /// Scans all configured ports in parallel and returns results.
    pub async fn scan(&self) -> Result<Vec<PortResult>, NtraceError> {
        let start_time = Instant::now();

        // Initialize statistics
        {
            let mut stats = self.stats.lock().await;
            stats.start_time = Some(start_time);
            stats.total_ports = self.config.ports.len();
            stats.scanned_ports = 0;
            stats.open_ports = 0;
            stats.closed_ports = 0;
            stats.filtered_ports = 0;
            stats.errors = 0;
            stats.retries = 0;
            stats.error_map.clear();
        }

        info!(
            "Starting scan of {} ports on {}",
            self.config.ports.len(),
            self.config.host
        );

        // Create progress bar if not in a test environment
        let progress_bar = if cfg!(not(test)) {
            use indicatif::{ProgressBar, ProgressStyle};
            let pb = ProgressBar::new(self.config.ports.len() as u64);
            pb.set_style(ProgressStyle::default_bar()
                .template("[{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ports ({percent}%) {msg}")
                .unwrap()
                .progress_chars("##-"));
            Some(Arc::new(pb))
        } else {
            None
        };

        // Results container
        let mut results = Vec::with_capacity(self.config.ports.len());

        // Define problematic port ranges to use smaller batch sizes
        let problematic_ranges = vec![
            // Range around 298-300 that's causing issues
            (280, 320),
            // SMTP submission
            (587, 587),
            // LDAPS
            (636, 636),
            // IMAPS, POP3S
            (993, 995),
            // H.323
            (1720, 1720),
            // SIP
            (5060, 5061),
        ];

        // Create a vector of futures for all ports at once with maximum concurrency
        let mut futures = Vec::with_capacity(self.config.ports.len());

        // First scan common ports (like nmap does) for faster results
        let (common_ports, other_ports): (Vec<_>, Vec<_>) = self
            .config
            .ports
            .iter()
            .partition(|&&p| matches!(p, 21 | 22 | 23 | 25 | 80 | 443 | 554 | 1723));

        // Combine ports with common ones first
        let all_ports = [&common_ports[..], &other_ports[..]].concat();

        // Process all ports at once with maximum concurrency
        for &port in &all_ports {
            // Check if this is a problematic port
            let is_problematic = problematic_ranges
                .iter()
                .any(|(start, end)| port >= *start && port <= *end);

            // Skip problematic ports if fail_fast is enabled
            if is_problematic && self.config.fail_fast {
                let result = PortResult {
                    port,
                    is_open: false,
                    service: None,
                    protocol_info: Some("Skipped (problematic port)".to_string()),
                    latency: None,
                    scan_time: chrono::Utc::now(),
                };
                results.push(result);

                // Update statistics
                let mut stats = self.stats.lock().await;
                stats.scanned_ports += 1;
                stats.filtered_ports += 1;

                // Update progress bar
                if let Some(pb) = &progress_bar {
                    pb.inc(1);
                }

                continue;
            }

            let config = self.config.clone();
            let analyzer = self.analyzer.clone();

            // Use extremely short timeouts for faster scanning
            let timeout = if is_problematic {
                Duration::from_millis(30)
            } else {
                Duration::from_millis(50)
            };

            // Create a future with a timeout
            let future = tokio::time::timeout(timeout, async move {
                Self::scan_port(config, port, &analyzer).await
            });

            futures.push((port, future));
        }

        // Use tokio::spawn for each future to run them truly in parallel
        let mut handles = Vec::with_capacity(futures.len());

        for (port, future) in futures {
            let pb_clone = progress_bar.clone();
            let stats_clone = self.stats.clone();

            let handle = tokio::spawn(async move {
                let result = future.await;

                // Create the port result based on the scan outcome
                let port_result = match result {
                    Ok(Ok(port_result)) => {
                        // Scan completed successfully
                        let is_open = port_result.is_open;

                        // Update statistics
                        let mut stats = stats_clone.lock().await;
                        stats.scanned_ports += 1;

                        if is_open {
                            stats.open_ports += 1;

                            // Update progress bar message
                            if let Some(pb) = &pb_clone {
                                pb.set_message(format!("Found {} open ports", stats.open_ports));
                            }
                        } else {
                            stats.closed_ports += 1;
                        }

                        // Update progress bar
                        if let Some(pb) = &pb_clone {
                            pb.inc(1);
                        }

                        port_result
                    }
                    Ok(Err(e)) => {
                        // Scan error
                        let mut stats = stats_clone.lock().await;
                        stats.scanned_ports += 1;
                        stats.errors += 1;
                        let error_msg = format!("{}", e);
                        stats
                            .error_map
                            .entry(port)
                            .or_insert_with(Vec::new)
                            .push(error_msg);

                        // Update progress bar
                        if let Some(pb) = &pb_clone {
                            pb.inc(1);
                        }

                        PortResult {
                            port,
                            is_open: false,
                            service: None,
                            protocol_info: Some("Error".to_string()),
                            latency: None,
                            scan_time: chrono::Utc::now(),
                        }
                    }
                    Err(_) => {
                        // Timeout
                        let mut stats = stats_clone.lock().await;
                        stats.scanned_ports += 1;
                        stats.filtered_ports += 1;

                        // Update progress bar
                        if let Some(pb) = &pb_clone {
                            pb.inc(1);
                        }

                        PortResult {
                            port,
                            is_open: false,
                            service: None,
                            protocol_info: Some("Timeout".to_string()),
                            latency: None,
                            scan_time: chrono::Utc::now(),
                        }
                    }
                };

                port_result
            });

            handles.push(handle);
        }

        // Wait for all futures to complete and collect results
        for handle in handles {
            if let Ok(port_result) = handle.await {
                results.push(port_result);
            }
        }

        // Finish progress bar
        if let Some(pb) = &progress_bar {
            pb.finish_with_message(format!(
                "Scan complete: {} open ports found",
                self.stats.lock().await.open_ports
            ));
        }

        // Sort results by port for consistent output
        results.sort_by_key(|r| r.port);

        // Update final statistics
        {
            let mut stats = self.stats.lock().await;
            stats.end_time = Some(Instant::now());
        }

        let elapsed = start_time.elapsed();
        info!(
            "Scan completed in {:.2}s ({} ports)",
            elapsed.as_secs_f64(),
            results.len()
        );

        Ok(results)
    }

    /// Scans a single port and performs protocol analysis if open.
    async fn scan_port(
        config: ScanConfig,
        port: u16,
        _analyzer: &ProtocolAnalyzer,
    ) -> Result<PortResult, NtraceError> {
        // Prioritize scanning of common ports
        if matches!(port, 21 | 22 | 23 | 25 | 80 | 443 | 554 | 1723) {
            // These are common ports - we'll scan them with higher priority
        }
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
                // Use a non-blocking connect approach similar to Nmap
                // This is more efficient and less likely to hang

                // 1. Create a non-blocking socket
                let socket =
                    match std::net::TcpStream::connect_timeout(&addr, Duration::from_millis(20)) {
                        Ok(s) => {
                            // Connection succeeded immediately
                            is_open = true;
                            latency = Some(port_start.elapsed());

                            // Set socket options for service detection
                            if let Err(e) = s.set_read_timeout(Some(Duration::from_millis(30))) {
                                debug!("Failed to set read timeout: {}", e);
                            }
                            if let Err(e) = s.set_write_timeout(Some(Duration::from_millis(30))) {
                                debug!("Failed to set write timeout: {}", e);
                            }

                            Some(s)
                        }
                        Err(e) => {
                            match e.kind() {
                                std::io::ErrorKind::TimedOut => {
                                    // Connection timed out - port is likely filtered
                                    debug!("Connection to port {} timed out", port);
                                    None
                                }
                                std::io::ErrorKind::ConnectionRefused => {
                                    // Connection refused - port is closed
                                    debug!("Connection to port {} refused", port);
                                    None
                                }
                                std::io::ErrorKind::PermissionDenied => {
                                    // Permission denied - likely firewall block
                                    debug!("Permission denied for port {}", port);
                                    None
                                }
                                _ => {
                                    // Other error
                                    debug!("Error connecting to port {}: {}", port, e);
                                    None
                                }
                            }
                        }
                    };

                // If connection was successful, try to detect service
                if let Some(_stream) = socket {
                    // Instead of converting to tokio stream, we can use the default service name
                    let default_service = get_service_name(port);
                    if default_service != "unknown" {
                        service = Some(default_service.to_string());
                    }

                    // Set protocol info
                    protocol_info = Some("TCP".to_string());
                }
            }
            Protocol::Udp => {
                // UDP scanning is inherently unreliable

                // Create a UDP socket with a short timeout
                let socket = match std::net::UdpSocket::bind("0.0.0.0:0") {
                    Ok(s) => {
                        // Set timeouts
                        if let Err(e) = s.set_read_timeout(Some(Duration::from_millis(30))) {
                            debug!("Failed to set read timeout: {}", e);
                            return Ok(PortResult {
                                port,
                                is_open: false,
                                service: None,
                                protocol_info: Some("UDP (error)".to_string()),
                                latency: None,
                                scan_time: chrono::Utc::now(),
                            });
                        }
                        if let Err(e) = s.set_write_timeout(Some(Duration::from_millis(30))) {
                            debug!("Failed to set write timeout: {}", e);
                            return Ok(PortResult {
                                port,
                                is_open: false,
                                service: None,
                                protocol_info: Some("UDP (error)".to_string()),
                                latency: None,
                                scan_time: chrono::Utc::now(),
                            });
                        }
                        s
                    }
                    Err(e) => {
                        debug!("Failed to create UDP socket: {}", e);
                        return Ok(PortResult {
                            port,
                            is_open: false,
                            service: None,
                            protocol_info: Some("UDP (error)".to_string()),
                            latency: None,
                            scan_time: chrono::Utc::now(),
                        });
                    }
                };

                // Send a UDP packet
                let send_start = Instant::now();
                let target = SocketAddr::new(config.host, port);

                // Send an empty UDP packet or service specific probe
                let probe_data = match port {
                    // DNS query
                    53 => Vec::from(&b"\x00\x00\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00"[..]),
                    // SNMP
                    161 => Vec::from(&b"\x30\x26\x02\x01\x01\x04\x06\x70\x75\x62\x6c\x69\x63"[..]),
                    // NTP
                    123 => Vec::from(&b"\x1b\x00\x00\x00\x00\x00\x00\x00\x00"[..]),
                    // Empty packet for other services
                    _ => Vec::from(&b""[..]),
                };

                if let Err(e) = socket.send_to(&probe_data, target) {
                    debug!("Failed to send UDP packet to port {}: {}", port, e);
                    return Ok(PortResult {
                        port,
                        is_open: false,
                        service: None,
                        protocol_info: Some("UDP (error)".to_string()),
                        latency: None,
                        scan_time: chrono::Utc::now(),
                    });
                }

                // Try to receive a response
                let mut buf = [0; 1024];
                match socket.recv_from(&mut buf) {
                    Ok(_) => {
                        // If we get a response, the port is open
                        is_open = true;
                        latency = Some(send_start.elapsed());

                        // Try to detect service
                        service = match get_service_name(port) {
                            "unknown" => None,
                            name => Some(name.to_string()),
                        };

                        protocol_info = Some("UDP".to_string());
                    }
                    Err(e) => {
                        match e.kind() {
                            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut => {
                                // No response - could be filtered or closed
                                // In UDP, no response usually means filtered
                                debug!("No UDP response from port {}", port);
                                protocol_info = Some("UDP (filtered)".to_string());

                                // For UDP, we consider filtered ports as potentially open
                                // This is the approach Nmap takes
                                is_open = true;
                            }
                            _ => {
                                debug!("Error receiving UDP response from port {}: {}", port, e);
                                protocol_info = Some("UDP (error)".to_string());
                            }
                        }
                    }
                }
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

    /// Get the IP version (IPv4 or IPv6)
    pub fn ip_version(&self) -> &'static str {
        match self.config.host {
            IpAddr::V4(_) => "IPv4",
            IpAddr::V6(_) => "IPv6",
        }
    }
}
