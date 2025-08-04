use crate::error::NtraceError;
use crate::protocol::{Protocol, ProtocolAnalyzer, Target};
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
    pub target: Target,
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
    pub resolved_ip: Option<String>,
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

        let target_display = match &self.config.target {
            Target::Ip(ip) => ip.to_string(),
            Target::Domain(domain) => domain.clone(),
        };

        info!(
            "Starting scan of {} ports on {}",
            self.config.ports.len(),
            target_display
        );

        // For domain targets, resolve all IPs to scan all of them
        let target_ips = match &self.config.target {
            Target::Ip(ip) => vec![*ip],
            Target::Domain(domain) => {
                // Resolve domain to all IP addresses
                use tokio::net::lookup_host;

                // Try multiple service ports to get all possible IPs
                let mut all_ips = Vec::new();

                // Try common ports to get all possible IPs from load balancers
                for port in [80, 443, 8080, 21, 22, 25] {
                    if let Ok(addrs) = lookup_host(format!("{}:{}", domain, port)).await {
                        for addr in addrs {
                            let ip = addr.ip();
                            if !all_ips.contains(&ip) {
                                all_ips.push(ip);
                            }
                        }
                    }
                }

                if all_ips.is_empty() {
                    // Fallback to standard lookup if no IPs found
                    match lookup_host(format!("{}:80", domain)).await {
                        Ok(addrs) => {
                            // Collect all unique IPs (both IPv4 and IPv6)
                            let ips: Vec<IpAddr> = addrs.map(|addr| addr.ip()).collect();

                            if ips.is_empty() {
                                return Err(NtraceError::DnsError(format!(
                                    "No IP addresses found for domain: {}",
                                    domain
                                )));
                            }

                            debug!("Resolved domain {} to {} IP addresses", domain, ips.len());
                            all_ips = ips;
                        }
                        Err(e) => {
                            return Err(NtraceError::DnsError(format!(
                                "Could not resolve domain {}: {}",
                                domain, e
                            )));
                        }
                    }
                }

                debug!(
                    "Resolved domain {} to {} IP addresses",
                    domain,
                    all_ips.len()
                );
                all_ips
            }
        };

        // We'll use the total number of ports for the progress bar

        // First scan common ports (like nmap does) for faster results
        let (common_ports, other_ports): (Vec<_>, Vec<_>) = self
            .config
            .ports
            .iter()
            .partition(|&&p| matches!(p, 21 | 22 | 23 | 25 | 80 | 443 | 554 | 1723));

        // Combine ports with common ones first
        let all_ports = [&common_ports[..], &other_ports[..]].concat();

        // Create progress bar if not in a test environment
        let progress_bar = if cfg!(not(test)) {
            use indicatif::{ProgressBar, ProgressStyle};
            // Use ports count for length
            let pb = ProgressBar::new(self.config.ports.len() as u64);
            pb.set_style(ProgressStyle::default_bar()
                .template("[{elapsed_precise}] [{spinner:.green}] [{bar:40.cyan/blue}] {pos}/{len} ports ({percent}%) {msg}")
                .unwrap()
                .progress_chars("█▓▒░ ")
                .tick_strings(&["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]));

            // Reset the progress bar to ensure consistent counting
            pb.reset();

            // Enable steady tick for continuous updates even when no progress is made
            // Use fast tick rate for smaller port ranges to make the progress bar more responsive
            if all_ports.len() <= 1000 {
                // For small port ranges, use fast tick rate for more responsive updates
                pb.enable_steady_tick(std::time::Duration::from_millis(5));
            } else if self.config.fail_fast || self.config.timeout < Duration::from_millis(100) {
                pb.enable_steady_tick(std::time::Duration::from_millis(50));
            } else {
                pb.enable_steady_tick(std::time::Duration::from_millis(100));
            }

            pb.set_message("Scanning...".to_string());
            Some(Arc::new(pb))
        } else {
            None
        };

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

        // Use much larger batch sizes for faster scanning
        let batch_size = if self.config.ports.len() <= 200 {
            // For very small port ranges, use the entire range as one batch
            all_ports.len()
        } else if self.config.fail_fast || self.config.timeout < Duration::from_millis(100) {
            // Fast mode - use very large batches
            if all_ports.len() > 20000 {
                5000
            } else if all_ports.len() > 5000 {
                3000
            } else if all_ports.len() > 1000 {
                1000
            } else {
                // For smaller ranges, scan all at once
                all_ports.len()
            }
        } else if all_ports.len() > 20000 {
            4000
        } else if all_ports.len() > 10000 {
            3000
        } else if all_ports.len() > 5000 {
            2000
        } else if all_ports.len() > 1000 {
            1000
        } else {
            // For small ranges, scan all at once
            all_ports.len()
        };

        let mut results: Vec<PortResult> = Vec::with_capacity(all_ports.len());

        // Process ports in batches
        for port_batch in all_ports.chunks(batch_size) {
            // Create a vector of futures for this batch
            // *2 for potential multiple IPs
            let mut futures = Vec::with_capacity(port_batch.len() * 2);

            // Process ports in this batch
            for &port in port_batch {
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
                        resolved_ip: None,
                    };
                    results.push(result);

                    // Update statistics
                    let mut stats = self.stats.lock().await;
                    stats.scanned_ports += 1;
                    stats.filtered_ports += 1;

                    // Update progress bar for skipped ports
                    if let Some(pb) = &progress_bar {
                        pb.inc(1);
                    }

                    continue;
                }

                // Optimize IP scanning based on port range size
                let scan_ips = if self.config.ports.len() <= 200 {
                    // For small port ranges, only scan the first IP for speed
                    if !target_ips.is_empty() {
                        vec![target_ips[0]]
                    } else {
                        vec![]
                    }
                } else if self.config.ports.len() < 100 {
                    // For small port ranges, always scan all IPs
                    target_ips.clone()
                } else if (self.config.fail_fast
                    || self.config.timeout < Duration::from_millis(100))
                    && target_ips.len() > 1
                {
                    // In fast mode, always use just the first IP
                    vec![target_ips[0]]
                } else if self.config.ports.len() > 5000 && target_ips.len() > 1 {
                    // For medium and large port ranges, just use the first IP
                    vec![target_ips[0]]
                } else if target_ips.len() > 3 {
                    // If there are more than 3 IPs, just use the first 2 for better performance
                    vec![target_ips[0], target_ips[1]]
                } else {
                    // For smaller ranges with fewer IPs, scan all IPs
                    target_ips.clone()
                };

                for &ip in &scan_ips {
                    let mut config = self.config.clone();
                    // Override the target with the specific IP we're scanning
                    config.target = Target::Ip(ip);
                    let analyzer = self.analyzer.clone();

                    // Check if this is a common web port that needs special handling
                    let is_important_port =
                        matches!(port, 80 | 443 | 8080 | 8443 | 3000 | 6001 | 1723);

                    // Use aggressive timeouts but ensure we don't miss ports
                    let timeout = if self.config.ports.len() <= 200 {
                        // For very small port ranges
                        if matches!(port, 80 | 443 | 6001) {
                            // Important web ports and X11
                            Duration::from_millis(30)
                        } else if is_important_port {
                            Duration::from_millis(20)
                        } else if is_problematic {
                            Duration::from_millis(15)
                        } else {
                            Duration::from_millis(10)
                        }
                    } else if self.config.fail_fast
                        || self.config.timeout < Duration::from_millis(100)
                    {
                        // Fast mode - use very short timeouts
                        if matches!(port, 80 | 443 | 6001) {
                            // Important web ports and X11
                            Duration::from_millis(25)
                        } else if is_important_port {
                            Duration::from_millis(15)
                        } else if is_problematic {
                            Duration::from_millis(10)
                        } else {
                            Duration::from_millis(8)
                        }
                    } else if is_problematic {
                        Duration::from_millis(20)
                    } else if target_ips.len() > 1 {
                        // For multi IP domains
                        Duration::from_millis(15)
                    } else {
                        Duration::from_millis(12)
                    };

                    // Create a future with a timeout
                    let future = tokio::time::timeout(timeout, async move {
                        Self::scan_port(config, port, &analyzer).await
                    });

                    futures.push((port, future));
                }
            }

            // Use tokio::spawn for each future to run them truly in parallel
            let mut handles = Vec::with_capacity(futures.len());

            for (port, future) in futures {
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
                                // Just update the closed/open status
                            } else {
                                stats.closed_ports += 1;
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

                            // Update progress bar only once per port (not per IP)
                            // We'll handle this in the batch processing

                            PortResult {
                                port,
                                is_open: false,
                                service: None,
                                protocol_info: Some("Error".to_string()),
                                latency: None,
                                scan_time: chrono::Utc::now(),
                                resolved_ip: None,
                            }
                        }
                        Err(_) => {
                            // Timeout
                            let mut stats = stats_clone.lock().await;
                            stats.scanned_ports += 1;
                            stats.filtered_ports += 1;
                            PortResult {
                                port,
                                is_open: false,
                                service: None,
                                protocol_info: Some("Timeout".to_string()),
                                latency: None,
                                scan_time: chrono::Utc::now(),
                                resolved_ip: None,
                            }
                        }
                    };

                    port_result
                });

                handles.push(handle);
            }

            // Wait for all futures to complete and collect batch results
            let mut batch_results = Vec::with_capacity(handles.len());
            for handle in handles {
                if let Ok(port_result) = handle.await {
                    batch_results.push(port_result);
                }
            }

            // For domains with multiple IPs, merge results to show a port as open if it's open on any IP
            let mut port_map: HashMap<u16, Vec<PortResult>> = HashMap::new();
            for result in batch_results {
                port_map.entry(result.port).or_default().push(result);
            }

            // Process each port's results in this batch
            for (_port, port_results) in port_map {
                // If any result for this port is open, use that one
                if let Some(open_result) = port_results.iter().find(|r| r.is_open) {
                    results.push(open_result.clone());
                } else {
                    // Otherwise, just use the first result
                    if let Some(first_result) = port_results.first() {
                        results.push(first_result.clone());
                    }
                }

                // Update progress bar once per port (not per IP)
                if let Some(pb) = &progress_bar {
                    pb.inc(1);

                    // For smaller port ranges, force a redraw on every port for smoother visual updates
                    if all_ports.len() <= 1000 {
                        // Force a redraw to make progress more visible
                        pb.tick();

                        // For small ranges, add a tiny sleep every few ports to make progress more visible
                        // This is a balance between speed and visual feedback
                        if all_ports.len() <= 200 && results.len() % 10 == 0 {
                            std::thread::sleep(std::time::Duration::from_micros(500));
                        }
                    }
                }
            }

            // Eliminate delays between batches for maximum speed
            if batch_size < all_ports.len() {
                // Update the progress bar message to show we're still working
                if let Some(pb) = &progress_bar {
                    let scanned_so_far = results.len();
                    let percent_done =
                        (scanned_so_far as f64 / all_ports.len() as f64 * 100.0) as u64;
                    pb.set_message(format!("Scanning... {}% complete", percent_done));

                    // Force a redraw of the progress bar
                    pb.tick();
                }

                // Just yield to allow other tasks to run, no actual sleep
                tokio::task::yield_now().await;
            }
        }

        // Count the actual number of open ports in our results
        let open_ports_count = results.iter().filter(|r| r.is_open).count();

        // Update the stats with the actual count
        {
            let mut stats = self.stats.lock().await;
            stats.open_ports = open_ports_count;
        }

        // Finish progress bar
        if let Some(pb) = &progress_bar {
            pb.finish_with_message(format!(
                "Scan complete: {} open ports found",
                open_ports_count
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

        // Get the IP address to scan
        let ip = match &config.target {
            Target::Ip(ip) => *ip,
            Target::Domain(domain) => {
                // Resolve domain to IP address using tokio's async DNS resolver
                use tokio::net::lookup_host;

                // Use tokio's DNS resolver which is async compatible
                let mut addrs = match lookup_host(format!("{}:80", domain)).await {
                    Ok(addrs) => addrs,
                    Err(e) => {
                        return Err(NtraceError::DnsError(format!(
                            "Could not resolve domain {}: {}",
                            domain, e
                        )));
                    }
                };

                // Get the first IP address (either IPv4 or IPv6)
                match addrs.next() {
                    Some(addr) => addr.ip(),
                    None => {
                        return Err(NtraceError::DnsError(format!(
                            "No IP addresses found for domain: {}",
                            domain
                        )));
                    }
                }
            }
        };

        let addr = SocketAddr::new(ip, port);
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

                // Determine if we're scanning a domain (via IP that came from domain resolution)
                let is_domain_scan = match &config.target {
                    Target::Ip(_) => false,
                    Target::Domain(_) => true,
                };

                // Define important ports
                let is_important_port = matches!(port, 80 | 443 | 8080 | 8443 | 3000 | 6001 | 1723);

                // Use optimized timeouts for connection
                let connect_timeout = if matches!(port, 80 | 443 | 6001) {
                    // Important web ports and X11 need more time
                    if config.fail_fast || config.timeout < Duration::from_millis(100) {
                        // Fast mode
                        Duration::from_millis(200)
                    } else {
                        Duration::from_millis(300)
                    }
                } else if is_important_port {
                    // Other important ports
                    if config.fail_fast || config.timeout < Duration::from_millis(100) {
                        // Fast mode
                        Duration::from_millis(100)
                    } else {
                        Duration::from_millis(150)
                    }
                } else if config.fail_fast || config.timeout < Duration::from_millis(100) {
                    // Fast mode
                    Duration::from_millis(50)
                } else if is_domain_scan {
                    // Domain scanning
                    Duration::from_millis(80)
                } else {
                    // IP scanning
                    Duration::from_millis(50)
                };

                // For important ports, try multiple times to ensure we don't miss them
                let max_attempts = if matches!(port, 80 | 443 | 6001) {
                    // Critical ports get more retries
                    5
                } else if matches!(port, 8080 | 8443 | 3000 | 1723) {
                    // Other important ports
                    3
                } else {
                    // Regular ports
                    1
                };
                let mut socket = None;

                for attempt in 0..max_attempts {
                    // Increase timeout for each retry
                    let attempt_timeout = connect_timeout.mul_f32(1.0 + (attempt as f32 * 0.5));

                    // 1. Create a non-blocking socket
                    match std::net::TcpStream::connect_timeout(&addr, attempt_timeout) {
                        Ok(s) => {
                            // Connection succeeded
                            is_open = true;
                            latency = Some(port_start.elapsed());

                            // Set socket options for service detection
                            let read_timeout = if matches!(port, 80 | 443 | 6001) {
                                // Important ports need more time for service detection
                                if config.fail_fast || config.timeout < Duration::from_millis(100) {
                                    Duration::from_millis(100)
                                } else {
                                    Duration::from_millis(150)
                                }
                            } else if matches!(port, 8080 | 8443 | 3000 | 1723) {
                                // Other important ports
                                if config.fail_fast || config.timeout < Duration::from_millis(100) {
                                    Duration::from_millis(80)
                                } else {
                                    Duration::from_millis(100)
                                }
                            } else if config.fail_fast
                                || config.timeout < Duration::from_millis(100)
                            {
                                // Fast mode
                                Duration::from_millis(50)
                            } else if is_domain_scan {
                                Duration::from_millis(80)
                            } else {
                                Duration::from_millis(50)
                            };

                            if let Err(e) = s.set_read_timeout(Some(read_timeout)) {
                                debug!("Failed to set read timeout: {}", e);
                            }
                            if let Err(e) = s.set_write_timeout(Some(read_timeout)) {
                                debug!("Failed to set write timeout: {}", e);
                            }

                            socket = Some(s);
                            // Connection successful, exit retry loop
                            break;
                        }
                        Err(e) => {
                            match e.kind() {
                                std::io::ErrorKind::TimedOut => {
                                    // Connection timed out - port is likely filtered
                                    debug!(
                                        "Connection to port {} timed out (attempt {})",
                                        port,
                                        attempt + 1
                                    );
                                    // Continue to next attempt if we haven't reached max_attempts
                                }
                                std::io::ErrorKind::ConnectionRefused => {
                                    // Connection refused - port is closed
                                    debug!("Connection to port {} refused", port);
                                    // No need to retry if connection is refused
                                    break;
                                }
                                std::io::ErrorKind::PermissionDenied => {
                                    // Permission denied - likely firewall block
                                    debug!("Permission denied for port {}", port);
                                    // No need to retry if permission denied
                                    break;
                                }
                                _ => {
                                    // Other error
                                    debug!(
                                        "Error connecting to port {}: {} (attempt {})",
                                        port,
                                        e,
                                        attempt + 1
                                    );
                                    // Continue to next attempt if we haven't reached max_attempts
                                }
                            }
                        }
                    }
                }

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
                                resolved_ip: None,
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
                                resolved_ip: None,
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
                            resolved_ip: None,
                        });
                    }
                };

                // Send a UDP packet
                let send_start = Instant::now();

                let target = SocketAddr::new(ip, port);

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
                        resolved_ip: None,
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
                                protocol_info = Some("open|filtered".to_string());

                                // For UDP, we mark as open|filtered
                                is_open = false;
                            }
                            _ => {
                                debug!("Error receiving UDP response from port {}: {}", port, e);
                                protocol_info = Some("UDP (error)".to_string());
                            }
                        }
                    }
                }
            }
            Protocol::Icmp => {
                // For ICMP, we'll use a simple ping to check if the host responds
                let socket = match std::net::UdpSocket::bind("0.0.0.0:0") {
                    Ok(s) => {
                        // Set timeouts
                        if let Err(e) = s.set_read_timeout(Some(Duration::from_millis(500))) {
                            debug!("Failed to set read timeout: {}", e);
                            return Ok(PortResult {
                                port,
                                is_open: false,
                                service: None,
                                protocol_info: Some("ICMP (error)".to_string()),
                                latency: None,
                                scan_time: chrono::Utc::now(),
                                resolved_ip: None,
                            });
                        }
                        s
                    }
                    Err(e) => {
                        debug!("Failed to create socket: {}", e);
                        return Ok(PortResult {
                            port,
                            is_open: false,
                            service: None,
                            protocol_info: Some("ICMP (error)".to_string()),
                            latency: None,
                            scan_time: chrono::Utc::now(),
                            resolved_ip: None,
                        });
                    }
                };

                // For ICMP, we'll use a UDP socket to an unlikely port which should
                // trigger an ICMP "port unreachable" response if the host is up
                let start_time = Instant::now();

                // Send a packet to an unlikely port
                let target = SocketAddr::new(ip, 33434);
                let data = [0u8; 32];

                if let Err(e) = socket.send_to(&data, target) {
                    debug!("Failed to send ICMP probe: {}", e);
                    return Ok(PortResult {
                        port,
                        is_open: false,
                        service: None,
                        protocol_info: Some("ICMP (error)".to_string()),
                        latency: None,
                        scan_time: chrono::Utc::now(),
                        resolved_ip: None,
                    });
                }

                // Wait for response
                let mut buf = [0u8; 1024];
                match socket.recv_from(&mut buf) {
                    Ok(_) => {
                        // If we get a response, the host is up
                        is_open = true;
                        latency = Some(start_time.elapsed());
                        service = Some("icmp".to_string());
                        protocol_info = Some("ICMP".to_string());
                    }
                    Err(e) => {
                        // No response - host might be down or filtering ICMP
                        debug!("No ICMP response: {}", e);
                        protocol_info = Some("ICMP (no response)".to_string());
                    }
                }
            }
        }

        // Include resolved IP information for domain targets
        let resolved_ip = match &config.target {
            Target::Domain(_) => Some(ip.to_string()),
            Target::Ip(_) => None,
        };

        let result = PortResult {
            port,
            is_open,
            service,
            protocol_info,
            latency,
            scan_time: chrono::Utc::now(),
            resolved_ip,
        };

        debug!("Port {} scan completed in {:?}", port, port_start.elapsed());
        Ok(result)
    }

    /// Performs a quick ping scan to check if host is reachable
    pub async fn ping_host(&self) -> Result<bool, NtraceError> {
        // Try to connect to a few common ports to see if host is up
        let common_ports = [80, 443, 22, 25];

        // Get the IP address to ping
        let ip = match &self.config.target {
            Target::Ip(ip) => *ip,
            Target::Domain(domain) => {
                // Resolve domain to IP address using tokio's async DNS resolver
                use tokio::net::lookup_host;

                // Use tokio's DNS resolver which is async compatible
                let mut addrs = match lookup_host(format!("{}:80", domain)).await {
                    Ok(addrs) => addrs,
                    Err(e) => {
                        return Err(NtraceError::DnsError(format!(
                            "Could not resolve domain {}: {}",
                            domain, e
                        )));
                    }
                };

                // Get the first IP address (either IPv4 or IPv6)
                match addrs.next() {
                    Some(addr) => addr.ip(),
                    None => {
                        return Err(NtraceError::DnsError(format!(
                            "No IP addresses found for domain: {}",
                            domain
                        )));
                    }
                }
            }
        };

        for &port in &common_ports {
            let addr = SocketAddr::new(ip, port);
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

    /// Get the IP version (IPv4/IPv6) or "Domain"
    pub fn ip_version(&self) -> &'static str {
        match &self.config.target {
            Target::Ip(ip) => match ip {
                IpAddr::V4(_) => "IPv4",
                IpAddr::V6(_) => "IPv6",
            },
            Target::Domain(_) => "Domain",
        }
    }
}
