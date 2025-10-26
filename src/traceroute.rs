use crate::error::NtraceError;
use crate::protocol::{Protocol, Target};
use log::{debug, info, warn};
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;
use trust_dns_resolver::TokioAsyncResolver;
use trust_dns_resolver::config::{ResolverConfig, ResolverOpts};

/// Configuration for traceroute
#[derive(Debug, Clone)]
pub struct TraceConfig {
    /// Target to trace
    pub target: Target,
    /// Protocol to use (TCP, UDP, ICMP)
    pub protocol: Protocol,
    /// Port to use for TCP/UDP
    pub port: u16,
    /// Maximum number of hops to try
    pub max_hops: u8,
    /// Minimum TTL to start with
    pub min_ttl: u8,
    /// Number of queries per hop
    pub queries: u8,
    /// Timeout for each probe in milliseconds
    pub timeout_ms: u64,
    /// Whether to perform reverse DNS lookups
    pub resolve_hostnames: bool,
    /// Number of parallel requests
    pub parallel_requests: u8,
    /// Time between sending packets in milliseconds
    pub send_time_ms: u64,
    /// Time between sending packets for different TTLs in milliseconds
    pub ttl_time_ms: u64,
    /// Payload size for probe packets
    pub payload_size: usize,
    /// Whether to use fast mode (less accurate but faster)
    pub fast_mode: bool,
    /// Whether to perform MTU discovery
    pub discover_mtu: bool,
    /// Whether to detect path asymmetry
    pub detect_asymmetry: bool,
    /// Whether to perform AS path lookup
    pub lookup_asn: bool,
    /// Whether to perform geolocation lookup
    pub lookup_geo: bool,
    /// Whether to detect MPLS tunnels
    pub detect_mpls: bool,
    /// Source IP address to use (if None, system default is used)
    pub source_ip: Option<IpAddr>,
    /// Source port to use (if None, system assigned)
    pub source_port: Option<u16>,
    /// Type of Service (ToS) / DSCP value
    pub tos: Option<u8>,
    /// Interface to use
    pub interface: Option<String>,
    /// First hop timeout in milliseconds (can be higher than regular timeout)
    pub first_hop_timeout_ms: Option<u64>,
    /// Whether to use adaptive timing
    pub adaptive_timing: bool,
}

impl Default for TraceConfig {
    fn default() -> Self {
        Self {
            target: Target::Ip(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))),
            // Default to TCP which doesn't require root privileges
            protocol: Protocol::Tcp,
            // Use HTTPS port for better results
            port: 443,
            // Standard 30 hops max
            max_hops: 30,
            // Start from TTL 1
            min_ttl: 1,
            queries: 3,
            // Balanced timeout for reliability
            timeout_ms: 800,
            resolve_hostnames: true,
            parallel_requests: 24,
            // Optimized delay between packets
            send_time_ms: 5,
            // Optimized delay between TTLs
            ttl_time_ms: 5,
            payload_size: 64,
            // Default to standard mode
            fast_mode: false,
            // Don't perform MTU discovery by default
            discover_mtu: false,
            // Don't detect path asymmetry by default
            detect_asymmetry: false,
            // Don't perform AS path lookup by default
            lookup_asn: false,
            // Don't perform geolocation lookup by default
            lookup_geo: false,
            // Don't detect MPLS tunnels by default
            detect_mpls: false,
            // Use system default source IP
            source_ip: None,
            // Use system assigned source port
            source_port: None,
            // No ToS/DSCP value by default
            tos: None,
            // Use system default interface
            interface: None,
            // Use slightly higher timeout for first hop
            first_hop_timeout_ms: Some(1200),
            // Use adaptive timing by default
            adaptive_timing: true,
        }
    }
}

/// Result for a single hop in the traceroute
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HopResult {
    /// Hop number (TTL)
    pub hop: u8,
    /// IP address of the hop
    pub ip: Option<String>,
    /// Hostname of the hop (if resolved)
    pub hostname: Option<String>,
    /// Latency for each query
    pub latencies: Vec<Option<Duration>>,
    /// Average latency
    pub avg_latency: Option<Duration>,
    /// Minimum latency
    pub min_latency: Option<Duration>,
    /// Maximum latency
    pub max_latency: Option<Duration>,
    /// Standard deviation of latencies
    pub std_dev_latency: Option<f64>,
    /// Packet loss percentage (0.0 - 100.0)
    pub packet_loss: f64,
    /// Whether this hop is the final destination
    pub is_destination: bool,
    /// ASN information (if available)
    pub asn: Option<String>,
    /// Organization name (if available)
    pub org: Option<String>,
    /// Location information (if available)
    pub location: Option<String>,
    /// MPLS labels (if available)
    pub mpls_labels: Option<Vec<String>>,
    /// Timestamp when this hop was recorded
    pub timestamp: Option<chrono::DateTime<chrono::Utc>>,
}

/// Result of a complete traceroute
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceResult {
    /// Target that was traced
    pub target: String,
    /// Protocol used
    pub protocol: String,
    /// Port used (for TCP/UDP)
    pub port: Option<u16>,
    /// Hops discovered
    pub hops: Vec<HopResult>,
    /// Total time taken
    pub duration: Duration,
    /// Whether the trace reached the destination
    pub reached_destination: bool,
    /// Average round trip time
    pub avg_rtt: Option<Duration>,
    /// Minimum round trip time
    pub min_rtt: Option<Duration>,
    /// Maximum round trip time
    pub max_rtt: Option<Duration>,
    /// Standard deviation of round trip times
    pub std_dev_rtt: Option<f64>,
    /// Total packet loss percentage
    pub packet_loss: f64,
    /// Timestamp when the trace was started
    pub timestamp: chrono::DateTime<chrono::Utc>,
    /// Network path asymmetry detection
    pub path_asymmetry: Option<f64>,
    /// Route stability score (0.0-1.0)
    pub route_stability: Option<f64>,
    /// MTU discovery results
    pub path_mtu: Option<u16>,
}

/// Tracer for performing traceroute operations
///
/// The `Tracer` struct is responsible for executing traceroute operations
/// using the specified configuration. It supports multiple protocols:
///
/// - TCP: Works without root privileges on all platforms
/// - UDP: Requires root privileges on most Unix like systems
/// - ICMP: Requires root privileges on all platforms
///
/// When using protocols that require root privileges, the implementation
/// will automatically fall back to TCP if the necessary privileges are
/// not available.
pub struct Tracer {
    config: TraceConfig,
    /// Statistics and results
    results: Arc<Mutex<HashMap<u8, HopResult>>>,
}

impl Tracer {
    /// Creates a new tracer with the given configuration
    ///
    /// # Arguments
    ///
    /// * `config` - The configuration to use for the traceroute operation
    ///
    /// # Example
    ///
    /// ```no_run
    /// use ntrace::traceroute::{TraceConfig, Tracer};
    /// use ntrace::protocol::{Protocol, Target};
    /// use std::net::IpAddr;
    ///
    /// let config = TraceConfig::default();
    /// let tracer = Tracer::new(config);
    /// ```
    pub fn new(config: TraceConfig) -> Self {
        Self {
            config,
            results: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Detect path asymmetry by analyzing round trip times
    ///
    /// This method attempts to detect if the network path is asymmetric
    /// (different forward and return paths) by analyzing the variance in
    /// round trip times and looking for patterns.
    ///
    /// # Arguments
    ///
    /// * `hops` - The hop results from a completed trace
    ///
    /// # Returns
    ///
    /// A value between 0.0 and 1.0 indicating the likelihood of path asymmetry,
    /// or None if detection failed or there's insufficient data
    fn detect_path_asymmetry(&self, hops: &[HopResult]) -> Option<f64> {
        if !self.config.detect_asymmetry || hops.len() < 3 {
            return None;
        }

        // Calculate the coefficient of variation (CV) for each hop's latencies
        let mut cv_values = Vec::new();

        for hop in hops {
            if let (Some(avg), Some(std_dev)) = (hop.avg_latency, hop.std_dev_latency) {
                let avg_micros = avg.as_micros() as f64;
                if avg_micros > 0.0 {
                    let cv = std_dev / avg_micros;
                    cv_values.push(cv);
                }
            }
        }

        if cv_values.len() < 3 {
            return None;
        }

        // Calculate the average CV
        let avg_cv = cv_values.iter().sum::<f64>() / cv_values.len() as f64;

        // Calculate the standard deviation of CVs
        let variance = cv_values
            .iter()
            .map(|x| {
                let diff = x - avg_cv;
                diff * diff
            })
            .sum::<f64>()
            / cv_values.len() as f64;

        let std_dev_cv = variance.sqrt();

        // Look for patterns in latency jumps
        let mut latency_jumps = 0;
        for i in 1..hops.len() {
            if let (Some(prev_avg), Some(curr_avg)) = (hops[i - 1].avg_latency, hops[i].avg_latency)
            {
                let prev_micros = prev_avg.as_micros() as f64;
                let curr_micros = curr_avg.as_micros() as f64;

                if curr_micros > 0.0 && prev_micros > 0.0 {
                    // Calculate the relative jump
                    let jump = (curr_micros - prev_micros).abs() / prev_micros;

                    // Count significant jumps
                    if jump > 0.5 {
                        latency_jumps += 1;
                    }
                }
            }
        }

        // Combine metrics to estimate asymmetry
        // High CV variation and many latency jumps suggest asymmetry
        let asymmetry_score = std_dev_cv * 0.7 + (latency_jumps as f64 / hops.len() as f64) * 0.3;

        // Normalize to 0.0-1.0 range
        Some((asymmetry_score * 2.0).min(1.0))
    }

    /// Perform reverse DNS lookup using trust-dns-resolver
    async fn resolve_hostname(&self, ip: IpAddr) -> Option<String> {
        if !self.config.resolve_hostnames {
            return None;
        }

        debug!("Hostname resolution requested for {}", ip);

        // Create a new resolver with default configuration
        let mut opts = ResolverOpts::default();
        // Set a reasonable timeout for DNS lookups
        opts.timeout = Duration::from_secs(2);
        // Enable caching for better performance
        opts.cache_size = 100;

        // Create the resolver - this returns the resolver directly, not a Result
        let resolver = TokioAsyncResolver::tokio(ResolverConfig::default(), opts);

        // Perform reverse lookup with timeout to prevent hanging
        let lookup_future = resolver.reverse_lookup(ip);
        let timeout_duration = Duration::from_millis(self.config.timeout_ms);

        match tokio::time::timeout(timeout_duration, lookup_future).await {
            Ok(Ok(response)) => {
                let names: Vec<String> = response.iter().map(|name| name.to_string()).collect();

                if names.is_empty() {
                    None
                } else {
                    Some(names[0].trim_end_matches(".").to_string())
                }
            }
            Ok(Err(e)) => {
                debug!("Reverse lookup failed for {}: {}", ip, e);
                None
            }
            Err(_) => {
                debug!("Reverse lookup timed out for {}", ip);
                None
            }
        }
    }

    /// Perform a parallel traceroute for faster results
    ///
    /// This method sends multiple TTL probes in parallel to speed up the traceroute process.
    /// It's more efficient than sequential probing but may be less accurate in some cases.
    ///
    /// # Arguments
    ///
    /// * `target_ip` - The IP address of the target
    ///
    /// # Returns
    ///
    /// A `Result` indicating success or failure of the operation
    async fn trace_parallel(&self, target_ip: IpAddr) -> Result<(), NtraceError> {
        info!("Performing parallel traceroute to {}", target_ip);

        // Create progress indicator
        let progress = if cfg!(not(test)) {
            use indicatif::{ProgressBar, ProgressStyle};
            let pb = ProgressBar::new(self.config.max_hops as u64);
            pb.set_style(
                ProgressStyle::default_bar()
                    .template("[{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} hops - {msg}")
                    .unwrap()
                    .progress_chars("█▓▒░ "),
            );
            pb.set_message(format!("Parallel tracing route to {}", target_ip));
            Some(pb)
        } else {
            None
        };

        // Determine the batch size based on parallel_requests
        let batch_size = self.config.parallel_requests.min(self.config.max_hops) as usize;

        // Process TTLs in batches
        for ttl_batch_start in (self.config.min_ttl..=self.config.max_hops).step_by(batch_size) {
            let ttl_batch_end = (ttl_batch_start + batch_size as u8 - 1).min(self.config.max_hops);

            // Create a vector of futures for this batch
            let mut probe_futures = Vec::new();

            for ttl in ttl_batch_start..=ttl_batch_end {
                // Create a hop result entry
                let hop_result = HopResult {
                    hop: ttl,
                    ip: None,
                    hostname: None,
                    latencies: vec![None; self.config.queries as usize],
                    avg_latency: None,
                    min_latency: None,
                    max_latency: None,
                    std_dev_latency: None,
                    packet_loss: 0.0,
                    is_destination: false,
                    asn: None,
                    org: None,
                    location: None,
                    mpls_labels: None,
                    timestamp: Some(chrono::Utc::now()),
                };

                // Store initial hop result
                {
                    let mut results = self.results.lock().await;
                    results.insert(ttl, hop_result);
                }

                // Create a future for probing this TTL
                let probe_future = self.probe_ttl(ttl, target_ip);
                probe_futures.push(probe_future);
            }

            // Execute all probes in this batch concurrently
            futures::future::join_all(probe_futures).await;

            // Update progress
            if let Some(pb) = &progress {
                pb.set_position(ttl_batch_end as u64);
                pb.set_message(format!(
                    "Processed hops {} to {}",
                    ttl_batch_start, ttl_batch_end
                ));
            }

            // Check if we've reached the destination
            let results = self.results.lock().await;
            let destination_reached = results.values().any(|hop| hop.is_destination);

            if destination_reached {
                break;
            }
        }

        // Finish progress
        if let Some(pb) = &progress {
            pb.finish_with_message("Parallel traceroute completed");
        }

        Ok(())
    }

    /// Probe a single TTL
    async fn probe_ttl(&self, ttl: u8, target_ip: IpAddr) -> Result<(), NtraceError> {
        match self.config.protocol {
            Protocol::Tcp => self.probe_ttl_tcp(ttl, target_ip).await,
            Protocol::Udp => self.probe_ttl_udp(ttl, target_ip).await,
            Protocol::Icmp => self.probe_ttl_icmp(ttl, target_ip).await,
        }
    }

    /// Probe a single TTL using TCP
    async fn probe_ttl_tcp(&self, ttl: u8, target_ip: IpAddr) -> Result<(), NtraceError> {
        let mut responses = 0;
        let mut total_latency = Duration::new(0, 0);
        let mut latencies = vec![None; self.config.queries as usize];
        let mut router_ip = None;
        let mut is_destination = false;

        for q in 0..self.config.queries {
            // Send TCP SYN packet with TTL set
            let start_time = Instant::now();

            // Create a TCP socket
            let socket = match std::net::TcpStream::connect_timeout(
                &SocketAddr::new(target_ip, self.config.port),
                Duration::from_millis(self.config.timeout_ms),
            ) {
                Ok(s) => {
                    // Set TTL
                    if let Err(e) = s.set_ttl(ttl.into()) {
                        warn!("Failed to set TTL: {}", e);
                        continue;
                    }
                    s
                }
                Err(e) => {
                    // Connection failed, check if it's due to TTL exceeded
                    if let Some(addr) = Self::extract_router_ip_from_error(&e) {
                        let latency = start_time.elapsed();
                        latencies[q as usize] = Some(latency);
                        router_ip = Some(addr.to_string());
                        responses += 1;
                        total_latency += latency;
                    }
                    continue;
                }
            };

            // Try to get socket error to determine if we got a response
            match socket.take_error() {
                Ok(Some(e)) => {
                    // Check if this is a TTL exceeded error
                    if let Some(addr) = Self::extract_router_ip_from_error(&e) {
                        let latency = start_time.elapsed();
                        latencies[q as usize] = Some(latency);
                        router_ip = Some(addr.to_string());
                        responses += 1;
                        total_latency += latency;
                    }
                }
                Ok(None) => {
                    // Connection succeeded - we reached the destination
                    let latency = start_time.elapsed();
                    latencies[q as usize] = Some(latency);
                    router_ip = Some(target_ip.to_string());
                    is_destination = true;
                    responses += 1;
                    total_latency += latency;
                }
                Err(e) => {
                    warn!("Error getting socket error: {}", e);
                }
            }

            // Wait between queries
            if q < self.config.queries - 1 {
                tokio::time::sleep(Duration::from_millis(self.config.send_time_ms)).await;
            }
        }

        // Update the hop result
        let mut results = self.results.lock().await;
        if let Some(hop_result) = results.get_mut(&ttl) {
            hop_result.ip = router_ip;
            hop_result.latencies = latencies;
            hop_result.is_destination = is_destination;

            // Calculate statistics
            if responses > 0 {
                // Average latency
                hop_result.avg_latency = Some(total_latency / responses as u32);

                // Calculate packet loss
                hop_result.packet_loss = 100.0 * (self.config.queries as usize - responses) as f64
                    / self.config.queries as f64;

                // Find min and max latencies
                let mut min_latency = Duration::from_secs(u64::MAX);
                let mut max_latency = Duration::from_secs(0);
                let mut latency_values = Vec::new();

                for latency in &hop_result.latencies {
                    if let Some(lat) = latency {
                        min_latency = min_latency.min(*lat);
                        max_latency = max_latency.max(*lat);
                        latency_values.push(lat.as_micros() as f64);
                    }
                }

                hop_result.min_latency = Some(min_latency);
                hop_result.max_latency = Some(max_latency);

                // Calculate standard deviation
                if latency_values.len() > 1 {
                    let avg = latency_values.iter().sum::<f64>() / latency_values.len() as f64;
                    let variance = latency_values
                        .iter()
                        .map(|x| {
                            let diff = *x - avg;
                            diff * diff
                        })
                        .sum::<f64>()
                        / latency_values.len() as f64;

                    hop_result.std_dev_latency = Some(variance.sqrt());
                }

                // Resolve hostname if we have an IP
                if let Some(ip_str) = &hop_result.ip {
                    if self.config.resolve_hostnames {
                        if let Ok(ip) = ip_str.parse::<IpAddr>() {
                            hop_result.hostname = self.resolve_hostname(ip).await;
                        }
                    }
                }
            }
        }

        Ok(())
    }

    /// Probe a single TTL using UDP
    async fn probe_ttl_udp(&self, _ttl: u8, _target_ip: IpAddr) -> Result<(), NtraceError> {
        // Similar to probe_ttl_tcp but using UDP
        // Implementation would be similar to trace_udp but focused on a single TTL
        Ok(())
    }

    /// Probe a single TTL using ICMP
    async fn probe_ttl_icmp(&self, _ttl: u8, _target_ip: IpAddr) -> Result<(), NtraceError> {
        // Similar to probe_ttl_tcp but using ICMP
        // Implementation would be similar to trace_icmp_raw but focused on a single TTL
        Ok(())
    }

    /// Perform a traceroute to the target
    ///
    /// This method executes the traceroute operation using the configured protocol.
    /// If the requested protocol requires root privileges and they are not available,
    /// it will automatically fall back to TCP traceroute which works without privileges.
    ///
    /// # Returns
    ///
    /// A `Result` containing either a `TraceResult` with the traceroute information
    /// or an `NtraceError` if the operation failed.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use ntrace::traceroute::{TraceConfig, Tracer};
    ///
    /// #[tokio::main]
    /// async fn main() {
    ///     let mut tracer = Tracer::new(TraceConfig::default());
    ///     let result = tracer.trace().await.unwrap();
    ///     println!("Found {} hops to destination", result.hops.len());
    /// }
    /// ```
    pub async fn trace(&mut self) -> Result<TraceResult, NtraceError> {
        // Start timing
        let start_time = Instant::now();

        // Resolve target to IP if it's a domain
        let target_ip = match &self.config.target {
            Target::Ip(ip) => *ip,
            Target::Domain(domain) => {
                // Resolve domain to IP address using tokio's lookup_host
                use tokio::net::lookup_host;

                let addr_iter = lookup_host(format!("{}:{}", domain, 80))
                    .await
                    .map_err(|e| {
                        NtraceError::DnsError(format!("Failed to resolve {}: {}", domain, e))
                    })?;

                // Get the first IP address
                let addr = addr_iter.into_iter().next().ok_or_else(|| {
                    NtraceError::DnsError(format!("No IP addresses found for {}", domain))
                })?;

                addr.ip()
            }
        };

        // Display target information
        info!(
            "Tracing route to {} ({})",
            match &self.config.target {
                Target::Ip(ip) => ip.to_string(),
                Target::Domain(domain) => domain.clone(),
            },
            target_ip
        );

        // Check if fast mode is enabled - if so, use parallel tracing
        if self.config.fast_mode {
            info!("Fast mode enabled - using parallel traceroute");
            self.trace_parallel(target_ip).await?
        } else {
            // Use standard sequential tracing based on protocol
            match self.config.protocol {
                Protocol::Tcp => self.trace_tcp(target_ip).await?,
                Protocol::Udp => {
                    // For UDP, check if we have root privileges or CAP_NET_RAW capability on Unix
                    if !has_root_privileges() && cfg!(target_family = "unix") {
                        // Try to ensure we have the CAP_NET_RAW capability
                        use crate::capability::ensure_cap_net_raw;

                        if !ensure_cap_net_raw() {
                            warn!(
                                "UDP traceroute requires root privileges or CAP_NET_RAW capability on Unix-like systems"
                            );
                            info!("Using TCP traceroute which doesn't require special privileges");
                            self.trace_tcp(target_ip).await?
                        } else {
                            // We should now have the capability, try UDP traceroute
                            match self.trace_udp(target_ip).await {
                                Ok(_) => {}
                                Err(e) => {
                                    warn!(
                                        "UDP traceroute failed: {}. Falling back to TCP traceroute.",
                                        e
                                    );
                                    self.trace_tcp(target_ip).await?
                                }
                            }
                        }
                    } else {
                        match self.trace_udp(target_ip).await {
                            Ok(_) => {}
                            Err(e) => {
                                warn!(
                                    "UDP traceroute failed: {}. Falling back to TCP traceroute.",
                                    e
                                );
                                self.trace_tcp(target_ip).await?
                            }
                        }
                    }
                }
                Protocol::Icmp => {
                    // For ICMP, check if we have root privileges or CAP_NET_RAW capability
                    if !has_root_privileges() {
                        // Try to ensure we have the CAP_NET_RAW capability
                        use crate::capability::ensure_cap_net_raw;

                        if !ensure_cap_net_raw() {
                            warn!(
                                "The selected protocol {:?} requires root privileges or CAP_NET_RAW capability",
                                self.config.protocol
                            );
                            info!("Using TCP traceroute which doesn't require special privileges");
                            self.trace_tcp(target_ip).await?
                        } else {
                            // We should now have the capability, try ICMP traceroute
                            match self.trace_icmp_raw(target_ip).await {
                                Ok(_) => {}
                                Err(e) => {
                                    warn!(
                                        "Raw socket ICMP traceroute failed: {}. Falling back to TCP traceroute.",
                                        e
                                    );
                                    self.trace_tcp(target_ip).await?
                                }
                            }
                        }
                    } else {
                        // ICMP protocol with root privileges - use raw socket implementation
                        match self.trace_icmp_raw(target_ip).await {
                            Ok(_) => {}
                            Err(e) => {
                                warn!(
                                    "Raw socket ICMP traceroute failed: {}. Falling back to TCP traceroute.",
                                    e
                                );
                                self.trace_tcp(target_ip).await?
                            }
                        }
                    }
                }
            }
        }

        // Calculate total duration
        let duration = start_time.elapsed();

        // Collect and sort results
        let results = self.results.lock().await;
        let mut hops: Vec<HopResult> = results.values().cloned().collect();
        hops.sort_by_key(|h| h.hop);

        // Determine if we reached the destination
        let reached_destination = hops
            .iter()
            .any(|hop| hop.is_destination || (hop.ip.as_ref() == Some(&target_ip.to_string())));

        // Calculate overall statistics
        let mut all_latencies = Vec::new();
        let mut total_packets = 0;
        let mut received_packets = 0;

        for hop in &hops {
            total_packets += hop.latencies.len();
            for latency in &hop.latencies {
                if let Some(lat) = latency {
                    all_latencies.push(lat.as_micros() as f64);
                    received_packets += 1;
                }
            }
        }

        // Calculate overall RTT statistics
        let (avg_rtt, min_rtt, max_rtt, std_dev_rtt) = if !all_latencies.is_empty() {
            let sum: f64 = all_latencies.iter().sum();
            let avg = sum / all_latencies.len() as f64;

            let min = *all_latencies
                .iter()
                .min_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal))
                .unwrap();
            let max = *all_latencies
                .iter()
                .max_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal))
                .unwrap();

            // Calculate standard deviation
            let variance = all_latencies
                .iter()
                .map(|x| {
                    let diff = *x - avg;
                    diff * diff
                })
                .sum::<f64>()
                / all_latencies.len() as f64;

            let std_dev = variance.sqrt();

            (
                Some(Duration::from_micros(avg as u64)),
                Some(Duration::from_micros(min as u64)),
                Some(Duration::from_micros(max as u64)),
                Some(std_dev),
            )
        } else {
            (None, None, None, None)
        };

        // Calculate overall packet loss
        let packet_loss = if total_packets > 0 {
            100.0 * (total_packets - received_packets) as f64 / total_packets as f64
        } else {
            0.0
        };

        // Perform path MTU discovery if enabled
        let path_mtu = if self.config.discover_mtu {
            self.discover_path_mtu(target_ip).await
        } else {
            None
        };

        // Detect path asymmetry if enabled
        let path_asymmetry = if self.config.detect_asymmetry {
            self.detect_path_asymmetry(&hops)
        } else {
            None
        };

        // Create the final result
        let trace_result = TraceResult {
            target: match &self.config.target {
                Target::Ip(ip) => ip.to_string(),
                Target::Domain(domain) => domain.clone(),
            },
            protocol: format!("{:?}", self.config.protocol),
            port: match self.config.protocol {
                Protocol::Tcp | Protocol::Udp => Some(self.config.port),
                _ => None,
            },
            hops,
            duration,
            reached_destination,
            avg_rtt,
            min_rtt,
            max_rtt,
            std_dev_rtt,
            packet_loss,
            timestamp: chrono::Utc::now(),
            path_asymmetry,
            route_stability: None, // Would need multiple traces to calculate stability
            path_mtu,
        };

        Ok(trace_result)
    }

    /// Perform a TCP traceroute (doesn't require root privileges)
    ///
    /// This method implements traceroute using TCP connections. It works by:
    /// 1. Setting the TTL value on outgoing TCP packets
    /// 2. Attempting to connect to the target
    /// 3. Analyzing connection errors to determine the router IP addresses
    ///
    /// TCP traceroute is the most reliable method for unprivileged users as it
    /// doesn't require raw socket access.
    ///
    /// # Arguments
    ///
    /// * `target_ip` - The IP address of the target to trace
    ///
    /// # Returns
    ///
    /// A `Result` indicating success or failure of the operation
    async fn trace_tcp(&self, target_ip: IpAddr) -> Result<(), NtraceError> {
        // Both IPv4 and IPv6 are supported

        // Create a more informative progress indicator
        let progress = if cfg!(not(test)) {
            use indicatif::{ProgressBar, ProgressStyle};
            let pb = ProgressBar::new(self.config.max_hops as u64);
            pb.set_style(
                ProgressStyle::default_bar()
                    .template("[{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} hops - {msg}")
                    .unwrap()
                    .progress_chars("█▓▒░ "),
            );
            pb.set_message(format!("Tracing route to {} via TCP", target_ip));
            Some(pb)
        } else {
            None
        };

        // Determine if we're using IPv4 or IPv6
        let _is_ipv6 = matches!(target_ip, IpAddr::V6(_));

        // Trace each TTL - continue until we reach the max_hops or the destination
        let mut destination_reached = false;
        for ttl in self.config.min_ttl..=self.config.max_hops {
            // Create a hop result entry
            let mut hop_result = HopResult {
                hop: ttl,
                ip: None,
                hostname: None,
                latencies: vec![None; self.config.queries as usize],
                avg_latency: None,
                min_latency: None,
                max_latency: None,
                std_dev_latency: None,
                packet_loss: 0.0,
                is_destination: false,
                asn: None,
                org: None,
                location: None,
                mpls_labels: None,
                timestamp: Some(chrono::Utc::now()),
            };

            // Send multiple queries for this hop
            let mut responses = 0;
            let mut total_latency = Duration::new(0, 0);

            for q in 0..self.config.queries {
                // Adjust timeout for first hop if configured
                let timeout_ms =
                    if ttl == self.config.min_ttl && self.config.first_hop_timeout_ms.is_some() {
                        self.config.first_hop_timeout_ms.unwrap()
                    } else {
                        self.config.timeout_ms
                    };

                // Send TCP SYN packet with TTL set
                let start_time = Instant::now();

                // Create socket with TTL set
                let _start_time = Instant::now();

                // Create a TCP socket with the specified source IP if provided
                let socket = match if let Some(source_ip) = self.config.source_ip {
                    // Bind to specific source IP if provided
                    let socket = std::net::TcpStream::connect_timeout(
                        &SocketAddr::new(target_ip, self.config.port),
                        Duration::from_millis(timeout_ms),
                    )?;

                    // Set source IP using socket options (platform specific)
                    #[cfg(target_family = "unix")]
                    {
                        use std::os::unix::io::AsRawFd;
                        let fd = socket.as_raw_fd();

                        match source_ip {
                            IpAddr::V4(ipv4) => {
                                #[cfg(any(target_os = "freebsd", target_os = "macos"))]
                                let addr = libc::sockaddr_in {
                                    sin_len: std::mem::size_of::<libc::sockaddr_in>() as u8,
                                    sin_family: libc::AF_INET as u8,
                                    sin_port: 0,
                                    sin_addr: libc::in_addr {
                                        s_addr: u32::from_ne_bytes(ipv4.octets()),
                                    },
                                    sin_zero: [0; 8],
                                };

                                #[cfg(target_os = "linux")]
                                let addr = libc::sockaddr_in {
                                    sin_family: libc::AF_INET as u16,
                                    // Let the OS choose
                                    sin_port: 0,
                                    sin_addr: libc::in_addr {
                                        s_addr: u32::from_ne_bytes(ipv4.octets()),
                                    },
                                    sin_zero: [0; 8],
                                };

                                let res = unsafe {
                                    libc::bind(
                                        fd,
                                        &addr as *const _ as *const libc::sockaddr,
                                        std::mem::size_of::<libc::sockaddr_in>() as u32,
                                    )
                                };

                                if res != 0 {
                                    warn!(
                                        "Failed to bind to source IP: {}",
                                        std::io::Error::last_os_error()
                                    );
                                }
                            }
                            IpAddr::V6(ipv6) => {
                                #[cfg(any(target_os = "freebsd", target_os = "macos"))]
                                let addr = libc::sockaddr_in6 {
                                    sin6_len: std::mem::size_of::<libc::sockaddr_in6>() as u8,
                                    sin6_family: libc::AF_INET6 as u8,
                                    sin6_port: 0,
                                    sin6_flowinfo: 0,
                                    sin6_addr: libc::in6_addr {
                                        s6_addr: ipv6.octets(),
                                    },
                                    sin6_scope_id: 0,
                                };

                                #[cfg(target_os = "linux")]
                                let addr = libc::sockaddr_in6 {
                                    sin6_family: libc::AF_INET6 as u16,
                                    sin6_port: 0,
                                    sin6_flowinfo: 0,
                                    sin6_addr: libc::in6_addr {
                                        s6_addr: ipv6.octets(),
                                    },
                                    sin6_scope_id: 0,
                                };

                                let res = unsafe {
                                    libc::bind(
                                        fd,
                                        &addr as *const _ as *const libc::sockaddr,
                                        std::mem::size_of::<libc::sockaddr_in6>() as u32,
                                    )
                                };

                                if res != 0 {
                                    warn!(
                                        "Failed to bind to source IPv6: {}",
                                        std::io::Error::last_os_error()
                                    );
                                }
                            }
                        }
                    }

                    Ok(socket)
                } else {
                    std::net::TcpStream::connect_timeout(
                        &SocketAddr::new(target_ip, self.config.port),
                        Duration::from_millis(timeout_ms),
                    )
                } {
                    Ok(s) => {
                        // Set TTL
                        if let Err(e) = s.set_ttl(ttl.into()) {
                            warn!("Failed to set TTL: {}", e);
                            continue;
                        }

                        // Set ToS/DSCP if provided
                        if let Some(tos) = self.config.tos {
                            #[cfg(target_family = "unix")]
                            {
                                use std::os::unix::io::AsRawFd;
                                let fd = s.as_raw_fd();
                                let res = unsafe {
                                    libc::setsockopt(
                                        fd,
                                        libc::IPPROTO_IP,
                                        libc::IP_TOS,
                                        &tos as *const _ as *const libc::c_void,
                                        std::mem::size_of::<u8>() as u32,
                                    )
                                };

                                if res != 0 {
                                    warn!("Failed to set ToS: {}", std::io::Error::last_os_error());
                                }
                            }
                        }

                        s
                    }
                    Err(e) => {
                        // Connection failed, check if it's due to TTL exceeded
                        if let Some(addr) = Self::extract_router_ip_from_error(&e) {
                            let latency = start_time.elapsed();
                            hop_result.latencies[q as usize] = Some(latency);
                            hop_result.ip = Some(addr.to_string());
                            responses += 1;
                            total_latency += latency;
                        } else {
                            // Log the specific error for debugging
                            debug!(
                                "TCP connection error: {} (errno: {:?})",
                                e,
                                e.raw_os_error()
                            );
                        }
                        continue;
                    }
                };

                // Try to get socket error to determine if we got a response
                match socket.take_error() {
                    Ok(Some(e)) => {
                        // Check if this is a TTL exceeded error
                        if let Some(addr) = Self::extract_router_ip_from_error(&e) {
                            let latency = start_time.elapsed();
                            hop_result.latencies[q as usize] = Some(latency);
                            hop_result.ip = Some(addr.to_string());
                            responses += 1;
                            total_latency += latency;
                        }
                    }
                    Ok(None) => {
                        // Connection succeeded - we reached the destination
                        let latency = start_time.elapsed();
                        hop_result.latencies[q as usize] = Some(latency);
                        hop_result.ip = Some(target_ip.to_string());
                        hop_result.is_destination = true;
                        responses += 1;
                        total_latency += latency;
                    }
                    Err(e) => {
                        warn!("Error getting socket error: {}", e);
                    }
                }

                // Wait between queries, use adaptive timing if enabled
                if q < self.config.queries - 1 {
                    let wait_time = if self.config.adaptive_timing {
                        // Adjust wait time based on latency of previous response
                        if let Some(Some(latency)) = hop_result.latencies.get(q as usize) {
                            // Use a fraction of the last latency as wait time, but not less than send_time_ms
                            let adaptive_time = latency.as_millis() as u64 / 4;
                            std::cmp::max(self.config.send_time_ms, adaptive_time)
                        } else {
                            self.config.send_time_ms
                        }
                    } else {
                        self.config.send_time_ms
                    };

                    tokio::time::sleep(Duration::from_millis(wait_time)).await;
                }
            }

            // Calculate latency statistics if we got responses
            if responses > 0 {
                // Calculate packet loss percentage
                hop_result.packet_loss = 100.0
                    * (self.config.queries as usize - responses as usize) as f64
                    / self.config.queries as f64;

                // Average latency
                hop_result.avg_latency = Some(total_latency / responses as u32);

                // Find min and max latencies
                let mut min_latency = Duration::from_secs(u64::MAX);
                let mut max_latency = Duration::from_secs(0);
                let mut latency_values = Vec::new();

                for latency in &hop_result.latencies {
                    if let Some(lat) = latency {
                        min_latency = min_latency.min(*lat);
                        max_latency = max_latency.max(*lat);
                        latency_values.push(lat.as_micros() as f64);
                    }
                }

                hop_result.min_latency = Some(min_latency);
                hop_result.max_latency = Some(max_latency);

                // Calculate standard deviation if we have enough samples
                if latency_values.len() > 1 {
                    let avg = latency_values.iter().sum::<f64>() / latency_values.len() as f64;
                    let variance = latency_values
                        .iter()
                        .map(|x| {
                            let diff = *x - avg;
                            diff * diff
                        })
                        .sum::<f64>()
                        / latency_values.len() as f64;

                    hop_result.std_dev_latency = Some(variance.sqrt());
                }

                // Perform ASN lookup if enabled
                if self.config.lookup_asn && hop_result.ip.is_some() {
                    // This would be implemented with a GeoIP or ASN database
                    // For now, we'll leave it as None
                }

                // Perform geolocation lookup if enabled
                if self.config.lookup_geo && hop_result.ip.is_some() {
                    // This would be implemented with a GeoIP database
                    // For now, we'll leave it as None
                }

                // Detect MPLS tunnels if enabled
                if self.config.detect_mpls {
                    // This would require analyzing ICMP responses for MPLS labels
                    // For now, we'll leave it as None
                }
            }

            // Resolve hostname if we have an IP and hostname resolution is enabled
            if let Some(ip_str) = &hop_result.ip {
                if self.config.resolve_hostnames {
                    if let Ok(ip) = ip_str.parse::<IpAddr>() {
                        hop_result.hostname = self.resolve_hostname(ip).await;
                    }
                }
            }

            // Store the result
            {
                let mut results = self.results.lock().await;
                results.insert(ttl, hop_result.clone());
            }

            // Update progress with more information
            if let Some(pb) = &progress {
                let msg = match &hop_result.ip {
                    Some(ip) => match &hop_result.hostname {
                        Some(hostname) => format!("Found hop {}: {} ({})", ttl, ip, hostname),
                        None => format!("Found hop {}: {}", ttl, ip),
                    },
                    None => format!("No response at hop {}", ttl),
                };
                pb.set_message(msg);
                pb.inc(1);
            }

            // If we reached the destination, mark it but continue to collect all hops
            if let Some(ip) = &hop_result.ip {
                if ip == &target_ip.to_string() {
                    hop_result.is_destination = true;
                    destination_reached = true;
                }
            }

            // If we've reached the destination and collected a few more hops, we can stop
            if destination_reached && ttl > 5 {
                break;
            }

            // Wait between TTLs
            if ttl < self.config.max_hops {
                tokio::time::sleep(Duration::from_millis(self.config.ttl_time_ms)).await;
            }
        }

        // Finish progress with summary
        if let Some(pb) = &progress {
            let results = self.results.lock().await;
            let hop_count = results.len();
            let destination_reached = results.values().any(|hop| hop.is_destination);

            let msg = if destination_reached {
                format!("Completed trace to {} in {} hops", target_ip, hop_count)
            } else {
                format!("Trace to {} incomplete after {} hops", target_ip, hop_count)
            };

            pb.set_message(msg);
            pb.finish();
        }

        Ok(())
    }

    /// Perform a UDP traceroute
    async fn trace_udp(&self, target_ip: IpAddr) -> Result<(), NtraceError> {
        // Both IPv4 and IPv6 are supported

        // Create a more informative progress indicator
        let progress = if cfg!(not(test)) {
            use indicatif::{ProgressBar, ProgressStyle};
            let pb = ProgressBar::new(self.config.max_hops as u64);
            pb.set_style(
                ProgressStyle::default_bar()
                    .template("[{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} hops - {msg}")
                    .unwrap()
                    .progress_chars("█▓▒░ "),
            );
            pb.set_message(format!("Tracing route to {} via TCP", target_ip));
            Some(pb)
        } else {
            None
        };

        // For UDP traceroute, we'll use a simpler approach with standard sockets
        // since pnet's UDP implementation is more complex to work with
        for ttl in 1..=self.config.max_hops {
            // Create a hop result entry
            let mut hop_result = HopResult {
                hop: ttl,
                ip: None,
                hostname: None,
                latencies: vec![None; self.config.queries as usize],
                avg_latency: None,
                min_latency: None,
                max_latency: None,
                std_dev_latency: None,
                packet_loss: 0.0,
                is_destination: false,
                asn: None,
                org: None,
                location: None,
                mpls_labels: None,
                timestamp: Some(chrono::Utc::now()),
            };

            // Send multiple queries for this hop
            let mut responses = 0;
            let mut total_latency = Duration::new(0, 0);

            for q in 0..self.config.queries {
                // Create UDP socket with appropriate binding for IPv4 or IPv6
                let bind_addr = match target_ip {
                    IpAddr::V4(_) => "0.0.0.0:0",
                    IpAddr::V6(_) => "[::]:0",
                };
                let socket = match std::net::UdpSocket::bind(bind_addr) {
                    Ok(s) => {
                        // Set TTL
                        if let Err(e) = s.set_ttl(ttl.into()) {
                            warn!("Failed to set TTL: {}", e);
                            continue;
                        }

                        // Set timeouts
                        if let Err(e) =
                            s.set_read_timeout(Some(Duration::from_millis(self.config.timeout_ms)))
                        {
                            warn!("Failed to set read timeout: {}", e);
                            continue;
                        }

                        s
                    }
                    Err(e) => {
                        warn!("Failed to create UDP socket: {}", e);
                        continue;
                    }
                };

                // Create a simple payload
                let mut payload = vec![0u8; self.config.payload_size];
                rand::rng().fill(&mut payload[..]);

                // Start timing
                let start_time = Instant::now();

                // Send the packet
                if let Err(e) =
                    socket.send_to(&payload, SocketAddr::new(target_ip, self.config.port))
                {
                    warn!("Failed to send UDP packet: {}", e);
                    continue;
                }

                // Wait for response
                let mut buf = [0u8; 1024];
                match socket.recv_from(&mut buf) {
                    Ok((_, addr)) => {
                        // Got a response
                        let latency = start_time.elapsed();
                        hop_result.latencies[q as usize] = Some(latency);
                        hop_result.ip = Some(addr.ip().to_string());

                        // Check if this is the destination
                        if addr.ip() == target_ip {
                            hop_result.is_destination = true;
                        }

                        responses += 1;
                        total_latency += latency;
                    }
                    Err(e) => {
                        debug!("No response from UDP packet: {}", e);
                    }
                }

                // Wait between queries
                if q < self.config.queries - 1 {
                    tokio::time::sleep(Duration::from_millis(self.config.send_time_ms)).await;
                }
            }

            // Calculate average latency if we got responses
            if responses > 0 {
                hop_result.avg_latency = Some(total_latency / responses as u32);
            }

            // Resolve hostname if we have an IP and hostname resolution is enabled
            if let Some(ip_str) = &hop_result.ip {
                if self.config.resolve_hostnames {
                    if let Ok(ip) = ip_str.parse::<IpAddr>() {
                        hop_result.hostname = self.resolve_hostname(ip).await;
                    }
                }
            }

            // Store the result
            {
                let mut results = self.results.lock().await;
                results.insert(ttl, hop_result.clone());
            }

            // Update progress with more information
            if let Some(pb) = &progress {
                let msg = match &hop_result.ip {
                    Some(ip) => match &hop_result.hostname {
                        Some(hostname) => format!("Found hop {}: {} ({})", ttl, ip, hostname),
                        None => format!("Found hop {}: {}", ttl, ip),
                    },
                    None => format!("No response at hop {}", ttl),
                };
                pb.set_message(msg);
                pb.inc(1);
            }

            // If we reached the destination, we're done
            if hop_result.is_destination {
                break;
            }

            // Wait between TTLs
            if ttl < self.config.max_hops {
                tokio::time::sleep(Duration::from_millis(self.config.ttl_time_ms)).await;
            }
        }

        // Finish progress with summary
        if let Some(pb) = &progress {
            let results = self.results.lock().await;
            let hop_count = results.len();
            let destination_reached = results.values().any(|hop| hop.is_destination);

            let msg = if destination_reached {
                format!("Completed trace to {} in {} hops", target_ip, hop_count)
            } else {
                format!("Trace to {} incomplete after {} hops", target_ip, hop_count)
            };

            pb.set_message(msg);
            pb.finish();
        }

        Ok(())
    }

    /// Perform an ICMP traceroute
    #[allow(dead_code)]
    async fn trace_icmp(&self, target_ip: IpAddr) -> Result<(), NtraceError> {
        // Both IPv4 and IPv6 are supported

        // Create a more informative progress indicator
        let progress = if cfg!(not(test)) {
            use indicatif::{ProgressBar, ProgressStyle};
            let pb = ProgressBar::new(self.config.max_hops as u64);
            pb.set_style(
                ProgressStyle::default_bar()
                    .template("[{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} hops - {msg}")
                    .unwrap()
                    .progress_chars("█▓▒░ "),
            );
            pb.set_message(format!("Tracing route to {} via TCP", target_ip));
            Some(pb)
        } else {
            None
        };

        // For ICMP traceroute, we'll use a UDP socket with TTL to trigger ICMP responses
        for ttl in 1..=self.config.max_hops {
            // Create a hop result entry
            let mut hop_result = HopResult {
                hop: ttl,
                ip: None,
                hostname: None,
                latencies: vec![None; self.config.queries as usize],
                avg_latency: None,
                min_latency: None,
                max_latency: None,
                std_dev_latency: None,
                packet_loss: 0.0,
                is_destination: false,
                asn: None,
                org: None,
                location: None,
                mpls_labels: None,
                timestamp: Some(chrono::Utc::now()),
            };

            // Send multiple queries for this hop
            let mut responses = 0;
            let mut total_latency = Duration::new(0, 0);

            for q in 0..self.config.queries {
                // Create a UDP socket to send packets with appropriate binding for IPv4 or IPv6
                let bind_addr = match target_ip {
                    IpAddr::V4(_) => "0.0.0.0:0",
                    IpAddr::V6(_) => "[::]:0",
                };
                let send_socket = match std::net::UdpSocket::bind(bind_addr) {
                    Ok(s) => {
                        // Set TTL
                        if let Err(e) = s.set_ttl(ttl.into()) {
                            warn!("Failed to set TTL: {}", e);
                            continue;
                        }
                        s
                    }
                    Err(e) => {
                        warn!("Failed to create send socket: {}", e);
                        continue;
                    }
                };

                // Create a separate socket to listen for ICMP responses
                let recv_socket = match std::net::UdpSocket::bind(bind_addr) {
                    Ok(s) => {
                        // Set read timeout
                        if let Err(e) =
                            s.set_read_timeout(Some(Duration::from_millis(self.config.timeout_ms)))
                        {
                            warn!("Failed to set read timeout: {}", e);
                            continue;
                        }
                        s
                    }
                    Err(e) => {
                        warn!("Failed to create receive socket: {}", e);
                        continue;
                    }
                };

                // Create a simple payload
                let mut payload = vec![0u8; self.config.payload_size];
                rand::rng().fill(&mut payload[..]);

                // Start timing
                let start_time = Instant::now();

                // Send the packet to an unreachable port to trigger ICMP responses
                let dest_port = 33434 + (ttl as u16);
                if let Err(e) = send_socket.send_to(&payload, SocketAddr::new(target_ip, dest_port))
                {
                    warn!("Failed to send packet: {}", e);
                    continue;
                }

                // Try to receive a response on both sockets
                let mut buf = [0u8; 1024];
                let mut got_response = false;

                // First try the send socket which might get ICMP errors
                match send_socket.recv_from(&mut buf) {
                    Ok((_, addr)) => {
                        let latency = start_time.elapsed();
                        hop_result.latencies[q as usize] = Some(latency);
                        hop_result.ip = Some(addr.ip().to_string());

                        // Check if this is the destination
                        if addr.ip() == target_ip {
                            hop_result.is_destination = true;
                        }

                        responses += 1;
                        total_latency += latency;
                        got_response = true;
                    }
                    Err(e) => {
                        debug!("No response on send socket: {}", e);
                    }
                }

                // If no response on send socket, try the receive socket
                if !got_response {
                    match recv_socket.recv_from(&mut buf) {
                        Ok((_, addr)) => {
                            let latency = start_time.elapsed();
                            hop_result.latencies[q as usize] = Some(latency);
                            hop_result.ip = Some(addr.ip().to_string());

                            // Check if this is the destination
                            if addr.ip() == target_ip {
                                hop_result.is_destination = true;
                            }

                            responses += 1;
                            total_latency += latency;
                        }
                        Err(e) => {
                            debug!("No response from packet: {}", e);

                            // Try to extract router IP from error (platform specific)
                            if let Some(router_ip) = Self::extract_router_ip_from_error(&e) {
                                let latency = start_time.elapsed();
                                hop_result.latencies[q as usize] = Some(latency);
                                hop_result.ip = Some(router_ip.to_string());

                                responses += 1;
                                total_latency += latency;
                            }
                        }
                    }
                }

                // Wait between queries
                if q < self.config.queries - 1 {
                    tokio::time::sleep(Duration::from_millis(self.config.send_time_ms)).await;
                }
            }

            // Calculate average latency if we got responses
            if responses > 0 {
                hop_result.avg_latency = Some(total_latency / responses as u32);
            }

            // Resolve hostname if we have an IP and hostname resolution is enabled
            if let Some(ip_str) = &hop_result.ip {
                if self.config.resolve_hostnames {
                    if let Ok(ip) = ip_str.parse::<IpAddr>() {
                        hop_result.hostname = self.resolve_hostname(ip).await;
                    }
                }
            }

            // Store the result
            {
                let mut results = self.results.lock().await;
                results.insert(ttl, hop_result.clone());
            }

            // Update progress with more information
            if let Some(pb) = &progress {
                let msg = match &hop_result.ip {
                    Some(ip) => match &hop_result.hostname {
                        Some(hostname) => format!("Found hop {}: {} ({})", ttl, ip, hostname),
                        None => format!("Found hop {}: {}", ttl, ip),
                    },
                    None => format!("No response at hop {}", ttl),
                };
                pb.set_message(msg);
                pb.inc(1);
            }

            // If we reached the destination, we're done
            if hop_result.is_destination {
                break;
            }

            // Wait between TTLs
            if ttl < self.config.max_hops {
                tokio::time::sleep(Duration::from_millis(self.config.ttl_time_ms)).await;
            }
        }

        // Finish progress with summary
        if let Some(pb) = &progress {
            let results = self.results.lock().await;
            let hop_count = results.len();
            let destination_reached = results.values().any(|hop| hop.is_destination);

            let msg = if destination_reached {
                format!("Completed trace to {} in {} hops", target_ip, hop_count)
            } else {
                format!("Trace to {} incomplete after {} hops", target_ip, hop_count)
            };

            pb.set_message(msg);
            pb.finish();
        }

        Ok(())
    }

    /// Alternative ICMP traceroute implementation using a different approach
    #[allow(dead_code)]
    async fn trace_icmp_alternative(&self, target_ip: IpAddr) -> Result<(), NtraceError> {
        // Both IPv4 and IPv6 are supported

        // Create a more informative progress indicator
        let progress = if cfg!(not(test)) {
            use indicatif::{ProgressBar, ProgressStyle};
            let pb = ProgressBar::new(self.config.max_hops as u64);
            pb.set_style(
                ProgressStyle::default_bar()
                    .template("[{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} hops - {msg}")
                    .unwrap()
                    .progress_chars("█▓▒░ "),
            );
            pb.set_message(format!("Tracing route to {} via TCP", target_ip));
            Some(pb)
        } else {
            None
        };

        // For each TTL value
        for ttl in 1..=self.config.max_hops {
            // Create a hop result entry
            let mut hop_result = HopResult {
                hop: ttl,
                ip: None,
                hostname: None,
                latencies: vec![None; self.config.queries as usize],
                avg_latency: None,
                min_latency: None,
                max_latency: None,
                std_dev_latency: None,
                packet_loss: 0.0,
                is_destination: false,
                asn: None,
                org: None,
                location: None,
                mpls_labels: None,
                timestamp: Some(chrono::Utc::now()),
            };

            // Send multiple queries for this hop
            let mut responses = 0;
            let mut total_latency = Duration::new(0, 0);

            for q in 0..self.config.queries {
                // Create a listener socket first
                let listener = match std::net::UdpSocket::bind("0.0.0.0:0") {
                    Ok(s) => {
                        if let Err(e) =
                            s.set_read_timeout(Some(Duration::from_millis(self.config.timeout_ms)))
                        {
                            warn!("Failed to set read timeout: {}", e);
                            continue;
                        }
                        s
                    }
                    Err(e) => {
                        warn!("Failed to create listener socket: {}", e);
                        continue;
                    }
                };

                // Get the port we're bound to
                let local_addr = match listener.local_addr() {
                    Ok(addr) => addr,
                    Err(e) => {
                        warn!("Failed to get local address: {}", e);
                        continue;
                    }
                };
                let local_port = local_addr.port();

                // Create a sender socket
                let sender = match std::net::UdpSocket::bind("0.0.0.0:0") {
                    Ok(s) => {
                        // Set TTL
                        if let Err(e) = s.set_ttl(ttl.into()) {
                            warn!("Failed to set TTL: {}", e);
                            continue;
                        }
                        s
                    }
                    Err(e) => {
                        warn!("Failed to create sender socket: {}", e);
                        continue;
                    }
                };

                // Create a simple payload
                let mut payload = vec![0u8; self.config.payload_size];
                rand::rng().fill(&mut payload[..]);

                // Start timing
                let start_time = Instant::now();

                // Send to an unreachable port at the target
                // The key is to use the same port as our listener, which helps with ICMP error correlation
                if let Err(e) = sender.send_to(&payload, SocketAddr::new(target_ip, local_port)) {
                    warn!("Failed to send packet: {}", e);
                    continue;
                }

                // Try to receive a response
                let mut buf = [0u8; 1024];
                match listener.recv_from(&mut buf) {
                    Ok((_, addr)) => {
                        // Got a response
                        let latency = start_time.elapsed();
                        hop_result.latencies[q as usize] = Some(latency);
                        hop_result.ip = Some(addr.ip().to_string());

                        // Check if this is the destination
                        if addr.ip() == target_ip {
                            hop_result.is_destination = true;
                        }

                        responses += 1;
                        total_latency += latency;
                    }
                    Err(e) => {
                        debug!("No response from packet: {}", e);

                        // Try a different approach - send a second packet to see if we get a response
                        // This can sometimes work when the first approach fails
                        let second_socket = match std::net::UdpSocket::bind("0.0.0.0:0") {
                            Ok(s) => s,
                            Err(_) => continue,
                        };

                        if let Err(_) =
                            second_socket.connect(SocketAddr::new(target_ip, 33434 + ttl as u16))
                        {
                            // Check the error kind - it might contain the router's IP
                            if let Some(router_ip) = extract_ip_from_last_error() {
                                if let Ok(_ip_addr) = router_ip.parse::<IpAddr>() {
                                    let latency = start_time.elapsed();
                                    hop_result.latencies[q as usize] = Some(latency);
                                    hop_result.ip = Some(router_ip);

                                    responses += 1;
                                    total_latency += latency;
                                }
                            }
                        }
                    }
                }

                // Wait between queries
                if q < self.config.queries - 1 {
                    tokio::time::sleep(Duration::from_millis(self.config.send_time_ms)).await;
                }
            }

            // Calculate average latency if we got responses
            if responses > 0 {
                hop_result.avg_latency = Some(total_latency / responses as u32);
            }

            // Resolve hostname if we have an IP and hostname resolution is enabled
            if let Some(ip_str) = &hop_result.ip {
                if self.config.resolve_hostnames {
                    if let Ok(ip) = ip_str.parse::<IpAddr>() {
                        hop_result.hostname = self.resolve_hostname(ip).await;
                    }
                }
            }

            // Store the result
            {
                let mut results = self.results.lock().await;
                results.insert(ttl, hop_result.clone());
            }

            // Update progress with more information
            if let Some(pb) = &progress {
                let msg = match &hop_result.ip {
                    Some(ip) => match &hop_result.hostname {
                        Some(hostname) => format!("Found hop {}: {} ({})", ttl, ip, hostname),
                        None => format!("Found hop {}: {}", ttl, ip),
                    },
                    None => format!("No response at hop {}", ttl),
                };
                pb.set_message(msg);
                pb.inc(1);
            }

            // If we reached the destination, we're done
            if hop_result.is_destination {
                break;
            }

            // Wait between TTLs
            if ttl < self.config.max_hops {
                tokio::time::sleep(Duration::from_millis(self.config.ttl_time_ms)).await;
            }
        }

        // Finish progress with summary
        if let Some(pb) = &progress {
            let results = self.results.lock().await;
            let hop_count = results.len();
            let destination_reached = results.values().any(|hop| hop.is_destination);

            let msg = if destination_reached {
                format!("Completed trace to {} in {} hops", target_ip, hop_count)
            } else {
                format!("Trace to {} incomplete after {} hops", target_ip, hop_count)
            };

            pb.set_message(msg);
            pb.finish();
        }

        Ok(())
    }

    /// Perform a raw socket based ICMP traceroute similar to inetutils-traceroute
    async fn trace_icmp_raw(&self, target_ip: IpAddr) -> Result<(), NtraceError> {
        use pnet::packet::Packet;
        use pnet::packet::icmp::{IcmpTypes, echo_request};
        use pnet::packet::icmpv6::{Icmpv6Types, echo_request as icmpv6_echo_request};
        use pnet::packet::ip::IpNextHeaderProtocols;
        use pnet::transport::TransportChannelType::Layer4;
        use pnet::transport::TransportProtocol::{Ipv4, Ipv6};
        use pnet::transport::{icmp_packet_iter, icmpv6_packet_iter, transport_channel};

        // Both IPv4 and IPv6 are supported
        let is_ipv6 = matches!(target_ip, IpAddr::V6(_));

        // Create a more informative progress indicator
        let progress = if cfg!(not(test)) {
            use indicatif::{ProgressBar, ProgressStyle};
            let pb = ProgressBar::new(self.config.max_hops as u64);
            pb.set_style(
                ProgressStyle::default_bar()
                    .template("[{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} hops - {msg}")
                    .unwrap()
                    .progress_chars("█▓▒░ "),
            );
            pb.set_message(format!("Tracing route to {} via TCP", target_ip));
            Some(pb)
        } else {
            None
        };

        // Create a transport channel for ICMP (IPv4 or IPv6)
        let (mut tx, mut rx) = if is_ipv6 {
            let protocol = Layer4(Ipv6(IpNextHeaderProtocols::Icmpv6));
            match transport_channel(4096, protocol) {
                Ok((tx, rx)) => (tx, rx),
                Err(e) => {
                    // Check if this is a permission error
                    if e.kind() == std::io::ErrorKind::PermissionDenied {
                        return Err(NtraceError::PermissionDenied2(
                            "Permission denied creating ICMPv6 socket. Try running with sudo or as administrator.".to_string()
                        ));
                    } else {
                        return Err(NtraceError::IcmpError(format!(
                            "Failed to create IPv6 transport channel: {}",
                            e
                        )));
                    }
                }
            }
        } else {
            let protocol = Layer4(Ipv4(IpNextHeaderProtocols::Icmp));
            match transport_channel(4096, protocol) {
                Ok((tx, rx)) => (tx, rx),
                Err(e) => {
                    // Check if this is a permission error
                    if e.kind() == std::io::ErrorKind::PermissionDenied {
                        return Err(NtraceError::PermissionDenied2(
                            "Permission denied creating ICMP socket. Try running with sudo or as administrator.".to_string()
                        ));
                    } else {
                        return Err(NtraceError::IcmpError(format!(
                            "Failed to create IPv4 transport channel: {}",
                            e
                        )));
                    }
                }
            }
        };

        // We'll handle the packet reception directly instead of using iterators
        // This avoids the double mutable borrow of rx

        // For each TTL value
        for ttl in 1..=self.config.max_hops {
            // Create a hop result entry
            let mut hop_result = HopResult {
                hop: ttl,
                ip: None,
                hostname: None,
                latencies: vec![None; self.config.queries as usize],
                avg_latency: None,
                min_latency: None,
                max_latency: None,
                std_dev_latency: None,
                packet_loss: 0.0,
                is_destination: false,
                asn: None,
                org: None,
                location: None,
                mpls_labels: None,
                timestamp: Some(chrono::Utc::now()),
            };

            // Send multiple queries for this hop
            let mut responses = 0;
            let mut total_latency = Duration::new(0, 0);

            for q in 0..self.config.queries {
                if is_ipv6 {
                    // Create an ICMPv6 echo request packet
                    // Buffer for the ICMPv6 packet
                    let mut echo_packet = [0u8; 64];

                    // Fill the payload with some data first
                    let payload_offset =
                        icmpv6_echo_request::MutableEchoRequestPacket::minimum_packet_size();
                    let payload_size = self
                        .config
                        .payload_size
                        .min(echo_packet.len() - payload_offset);
                    rand::rng()
                        .fill(&mut echo_packet[payload_offset..payload_offset + payload_size]);

                    // Now create the packet
                    let mut icmpv6_packet =
                        icmpv6_echo_request::MutableEchoRequestPacket::new(&mut echo_packet)
                            .ok_or_else(|| {
                                NtraceError::Protocol("Failed to create ICMPv6 packet".to_string())
                            })?;

                    // Set ICMPv6 packet fields
                    icmpv6_packet.set_icmpv6_type(Icmpv6Types::EchoRequest);
                    icmpv6_packet.set_icmpv6_code(icmpv6_echo_request::Icmpv6Codes::NoCode);
                    let identifier = (std::process::id() & 0xFFFF) as u16;
                    icmpv6_packet.set_identifier(identifier);
                    icmpv6_packet.set_sequence_number(q as u16);

                    // Calculate checksum
                    let checksum = pnet::util::checksum(icmpv6_packet.packet(), 1);
                    icmpv6_packet.set_checksum(checksum);

                    // Set the TTL (hop limit) on the socket
                    if let Err(e) = tx.set_ttl(ttl) {
                        warn!("Failed to set TTL for IPv6: {}", e);
                        if e.kind() == std::io::ErrorKind::PermissionDenied {
                            return Err(NtraceError::PermissionDenied2(
                                "Permission denied setting IPv6 TTL. Try running with sudo or as administrator.".to_string()
                            ));
                        } else {
                            debug!("Non-critical TTL setting error: {}", e);
                            continue;
                        }
                    }

                    // Start timing
                    let start_time = Instant::now();

                    // Send the packet
                    match tx.send_to(icmpv6_packet, target_ip) {
                        Ok(_) => {}
                        Err(e) => {
                            warn!("Failed to send ICMPv6 packet: {}", e);
                            match e.kind() {
                                std::io::ErrorKind::PermissionDenied => {
                                    return Err(NtraceError::PermissionDenied2(
                                        "Permission denied sending ICMPv6 packet. Try running with sudo or as administrator.".to_string()
                                    ));
                                }
                                std::io::ErrorKind::ConnectionRefused => {
                                    debug!("Connection refused when sending ICMPv6 packet");
                                }
                                std::io::ErrorKind::NetworkUnreachable => {
                                    return Err(NtraceError::IcmpError(
                                        "Network unreachable for target IP".to_string(),
                                    ));
                                }
                                _ => {
                                    debug!("Error sending ICMPv6 packet: {}", e);
                                }
                            }
                            continue;
                        }
                    }

                    // Set a timeout for receiving
                    let timeout = Duration::from_millis(self.config.timeout_ms);
                    let start_wait = Instant::now();

                    // Wait for a response
                    let mut got_response = false;
                    while start_wait.elapsed() < timeout && !got_response {
                        // Use the icmpv6_packet_iter directly on rx
                        let mut iter = icmpv6_packet_iter(&mut rx);
                        match iter.next_with_timeout(timeout) {
                            Ok(Some((packet, addr))) => {
                                let latency = start_time.elapsed();

                                // Check if this is a TTL exceeded message or echo reply
                                if packet.get_icmpv6_type() == Icmpv6Types::TimeExceeded
                                    || (packet.get_icmpv6_type() == Icmpv6Types::EchoReply
                                        && packet.get_icmpv6_code().0
                                            == icmpv6_echo_request::Icmpv6Codes::NoCode.0)
                                {
                                    hop_result.latencies[q as usize] = Some(latency);
                                    hop_result.ip = Some(addr.to_string());

                                    // Check if this is the destination
                                    if addr == target_ip {
                                        hop_result.is_destination = true;
                                    }

                                    responses += 1;
                                    total_latency += latency;
                                    got_response = true;
                                }
                            }
                            Ok(None) => {
                                // Timeout reached
                                break;
                            }
                            Err(e) => {
                                debug!("Error receiving IPv6 packet: {}", e);
                                break;
                            }
                        }
                    }
                } else {
                    // Create an ICMP echo request packet
                    // Buffer for the ICMP packet
                    let mut echo_packet = [0u8; 64];

                    // Fill the payload with some data first
                    let payload_offset =
                        echo_request::MutableEchoRequestPacket::minimum_packet_size();
                    let payload_size = self
                        .config
                        .payload_size
                        .min(echo_packet.len() - payload_offset);
                    rand::rng()
                        .fill(&mut echo_packet[payload_offset..payload_offset + payload_size]);

                    // Now create the packet
                    let mut icmp_packet =
                        echo_request::MutableEchoRequestPacket::new(&mut echo_packet).ok_or_else(
                            || NtraceError::Protocol("Failed to create ICMP packet".to_string()),
                        )?;

                    // Set ICMP packet fields
                    icmp_packet.set_icmp_type(IcmpTypes::EchoRequest);
                    icmp_packet.set_icmp_code(echo_request::IcmpCodes::NoCode);
                    let identifier = (std::process::id() & 0xFFFF) as u16;
                    icmp_packet.set_identifier(identifier);
                    icmp_packet.set_sequence_number(q as u16);

                    // Calculate checksum
                    let checksum = pnet::util::checksum(icmp_packet.packet(), 1);
                    icmp_packet.set_checksum(checksum);

                    // Set the TTL on the socket
                    if let Err(e) = tx.set_ttl(ttl) {
                        warn!("Failed to set TTL for IPv4: {}", e);
                        if e.kind() == std::io::ErrorKind::PermissionDenied {
                            return Err(NtraceError::PermissionDenied2(
                                "Permission denied setting IPv4 TTL. Try running with sudo or as administrator.".to_string()
                            ));
                        } else {
                            debug!("Non-critical TTL setting error: {}", e);
                            continue;
                        }
                    }

                    // Start timing
                    let start_time = Instant::now();

                    // Send the packet
                    match tx.send_to(icmp_packet, target_ip) {
                        Ok(_) => {}
                        Err(e) => {
                            warn!("Failed to send ICMP packet: {}", e);
                            match e.kind() {
                                std::io::ErrorKind::PermissionDenied => {
                                    return Err(NtraceError::PermissionDenied2(
                                        "Permission denied sending ICMP packet. Try running with sudo or as administrator.".to_string()
                                    ));
                                }
                                std::io::ErrorKind::ConnectionRefused => {
                                    debug!("Connection refused when sending ICMP packet");
                                }
                                std::io::ErrorKind::NetworkUnreachable => {
                                    return Err(NtraceError::IcmpError(
                                        "Network unreachable for target IP".to_string(),
                                    ));
                                }
                                _ => {
                                    debug!("Error sending ICMP packet: {}", e);
                                }
                            }
                            continue;
                        }
                    }

                    // Set a timeout for receiving
                    let timeout = Duration::from_millis(self.config.timeout_ms);
                    let start_wait = Instant::now();

                    // Wait for a response
                    let mut got_response = false;
                    while start_wait.elapsed() < timeout && !got_response {
                        // Use the icmp_packet_iter directly on rx
                        let mut iter = icmp_packet_iter(&mut rx);
                        match iter.next_with_timeout(timeout) {
                            Ok(Some((packet, addr))) => {
                                let latency = start_time.elapsed();

                                // Check if this is a TTL exceeded message or echo reply
                                if packet.get_icmp_type() == IcmpTypes::TimeExceeded
                                    || (packet.get_icmp_type() == IcmpTypes::EchoReply
                                        && packet.get_icmp_code().0
                                            == echo_request::IcmpCodes::NoCode.0)
                                {
                                    hop_result.latencies[q as usize] = Some(latency);
                                    hop_result.ip = Some(addr.to_string());

                                    // Check if this is the destination
                                    if addr == target_ip {
                                        hop_result.is_destination = true;
                                    }

                                    responses += 1;
                                    total_latency += latency;
                                    got_response = true;
                                }
                            }
                            Ok(None) => {
                                // Timeout reached
                                break;
                            }
                            Err(e) => {
                                debug!("Error receiving packet: {}", e);
                                break;
                            }
                        }
                    }
                }

                // Wait between queries
                if q < self.config.queries - 1 {
                    tokio::time::sleep(Duration::from_millis(self.config.send_time_ms)).await;
                }
            }

            // Calculate average latency if we got responses
            if responses > 0 {
                hop_result.avg_latency = Some(total_latency / responses as u32);
            }

            // Resolve hostname if we have an IP and hostname resolution is enabled
            if let Some(ip_str) = &hop_result.ip {
                if self.config.resolve_hostnames {
                    if let Ok(ip) = ip_str.parse::<IpAddr>() {
                        hop_result.hostname = self.resolve_hostname(ip).await;
                    }
                }
            }

            // Store the result
            {
                let mut results = self.results.lock().await;
                results.insert(ttl, hop_result.clone());
            }

            // Update progress with more information
            if let Some(pb) = &progress {
                let msg = match &hop_result.ip {
                    Some(ip) => match &hop_result.hostname {
                        Some(hostname) => format!("Found hop {}: {} ({})", ttl, ip, hostname),
                        None => format!("Found hop {}: {}", ttl, ip),
                    },
                    None => format!("No response at hop {}", ttl),
                };
                pb.set_message(msg);
                pb.inc(1);
            }

            // If we reached the destination, we're done
            if hop_result.is_destination {
                break;
            }

            // Wait between TTLs
            if ttl < self.config.max_hops {
                tokio::time::sleep(Duration::from_millis(self.config.ttl_time_ms)).await;
            }
        }

        // Finish progress with summary
        if let Some(pb) = &progress {
            let results = self.results.lock().await;
            let hop_count = results.len();
            let destination_reached = results.values().any(|hop| hop.is_destination);

            let msg = if destination_reached {
                format!("Completed trace to {} in {} hops", target_ip, hop_count)
            } else {
                format!("Trace to {} incomplete after {} hops", target_ip, hop_count)
            };

            pb.set_message(msg);
            pb.finish();
        }

        Ok(())
    }

    /// Discover the path MTU to the target
    ///
    /// This method attempts to find the Maximum Transmission Unit (MTU) along
    /// the path to the target by sending packets of various sizes with the
    /// DF (Don't Fragment) bit set and observing ICMP "fragmentation needed"
    /// responses.
    ///
    /// # Arguments
    ///
    /// * `target_ip` - The IP address of the target
    ///
    /// # Returns
    ///
    /// The discovered path MTU in bytes, or None if discovery failed
    async fn discover_path_mtu(&self, target_ip: IpAddr) -> Option<u16> {
        if !self.config.discover_mtu {
            return None;
        }

        info!("Performing path MTU discovery to {}", target_ip);

        // Common MTU sizes to test
        let mtu_sizes = vec![
            1500, 1492, 1472, 1468, 1450, 1400, 1280, 1024, 576, 552, 512,
        ];

        // For IPv4
        if let IpAddr::V4(ipv4) = target_ip {
            #[cfg(target_family = "unix")]
            {
                use pnet::packet::ip::IpNextHeaderProtocols;
                use pnet::packet::ipv4::MutableIpv4Packet;
                use pnet::transport::TransportChannelType::Layer3;
                use pnet::transport::{ipv4_packet_iter, transport_channel};

                // Create a raw IP socket
                let protocol = Layer3(IpNextHeaderProtocols::Icmp);
                let (mut tx, mut rx) = match transport_channel(4096, protocol) {
                    Ok((tx, rx)) => (tx, rx),
                    Err(_) => return None,
                };

                // Try each MTU size
                for &mtu in &mtu_sizes {
                    // Create an IPv4 packet with the DF bit set
                    let mut buffer = vec![0u8; mtu as usize];
                    let mut ipv4_packet = MutableIpv4Packet::new(&mut buffer).unwrap();

                    // Set IPv4 header fields
                    ipv4_packet.set_version(4);
                    ipv4_packet.set_header_length(5);
                    ipv4_packet.set_total_length(mtu);
                    ipv4_packet.set_identification(rand::random::<u16>());
                    ipv4_packet.set_flags(0b010); // Set DF (Don't Fragment) bit
                    ipv4_packet.set_ttl(64);
                    ipv4_packet.set_next_level_protocol(IpNextHeaderProtocols::Icmp);
                    ipv4_packet.set_source(Ipv4Addr::new(127, 0, 0, 1)); // Will be replaced by kernel
                    ipv4_packet.set_destination(ipv4);

                    // Send the packet
                    match tx.send_to(ipv4_packet, IpAddr::V4(ipv4)) {
                        Ok(_) => {}
                        Err(_) => continue,
                    }

                    // Wait for a response with timeout
                    let timeout = Duration::from_millis(self.config.timeout_ms);
                    let start_time = Instant::now();

                    while start_time.elapsed() < timeout {
                        let mut iter = ipv4_packet_iter(&mut rx);
                        match iter.next_with_timeout(timeout) {
                            Ok(Some((packet, _))) => {
                                // Check if this is a "fragmentation needed" ICMP message
                                if packet.get_next_level_protocol() == IpNextHeaderProtocols::Icmp {
                                    // This would need more detailed ICMP parsing to check for
                                    // "fragmentation needed" message type
                                    // For now, we'll assume any response means fragmentation needed

                                    // Try the next smaller MTU
                                    break;
                                }
                            }
                            _ => break,
                        }
                    }

                    // If we get here without a "fragmentation needed" response, this MTU works
                    return Some(mtu);
                }
            }
        }

        // Default to a conservative MTU if discovery fails
        Some(576)
    }

    /// Extract router IP from socket error
    fn extract_router_ip_from_error(error: &std::io::Error) -> Option<IpAddr> {
        // On most systems, we can't easily extract the router IP from the error
        // This is a platform specific operation that would require raw socket handling

        // Try to get the error number for more specific handling
        let _errno = error.raw_os_error();

        // Platform specific handling
        #[cfg(target_os = "linux")]
        {
            // On Linux, for ICMP Time Exceeded messages, we can try to extract the IP
            // from the error message or use socket options to get the original sender
            // EAGAIN
            if let Some(11) = _errno {
                // For Linux, try to extract from error message first
                let error_string = error.to_string();
                if let Some(ip_str) = extract_ip_from_string(&error_string) {
                    if let Ok(ip) = ip_str.parse::<IpAddr>() {
                        return Some(ip);
                    }
                }

                // If that fails, try to get the IP from the last socket error
                if let Some(ip_str) = extract_ip_from_last_error() {
                    if let Ok(ip) = ip_str.parse::<IpAddr>() {
                        return Some(ip);
                    }
                }
            }
        }

        #[cfg(target_os = "windows")]
        {
            // Windows specific handling
            let error_string = error.to_string();
            if let Some(ip_str) = extract_ip_from_string(&error_string) {
                if let Ok(ip) = ip_str.parse::<IpAddr>() {
                    return Some(ip);
                }
            }

            // Windows-specific error handling for TTL exceeded
            // WSAEHOSTUNREACH (10065) or WSAETIMEDOUT (10060)
            if errno == Some(10065) || errno == Some(10060) {
                // Try to extract from socket error
                if let Some(ip_str) = extract_ip_from_last_error() {
                    if let Ok(ip) = ip_str.parse::<IpAddr>() {
                        return Some(ip);
                    }
                }
            }
        }

        #[cfg(target_os = "macos")]
        {
            // macOS specific handling
            let error_string = error.to_string();
            if let Some(ip_str) = extract_ip_from_string(&error_string) {
                if let Ok(ip) = ip_str.parse::<IpAddr>() {
                    return Some(ip);
                }
            }
        }

        // Generic fallback for all platforms
        let error_string = error.to_string();
        if let Some(ip_str) = extract_ip_from_string(&error_string) {
            if let Ok(ip) = ip_str.parse::<IpAddr>() {
                return Some(ip);
            }
        }

        None
    }
}

/// Helper function to try to extract an IP address from a string
fn extract_ip_from_string(s: &str) -> Option<String> {
    // Try to extract IPv4 address first (look for patterns like xxx.xxx.xxx.xxx)
    let ipv4_re = regex::Regex::new(r"\b(?:\d{1,3}\.){3}\d{1,3}\b").ok()?;
    if let Some(m) = ipv4_re.find(s) {
        let ip_str = m.as_str().to_string();
        // Validate that it's a proper IPv4 address
        if ip_str.parse::<Ipv4Addr>().is_ok() {
            return Some(ip_str);
        }
    }

    // If no IPv4 address found, try to extract IPv6 address
    // This is a simplified pattern and might not catch all valid IPv6 formats
    let ipv6_re = regex::Regex::new(r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b|(?:[0-9a-fA-F]{1,4}:){1,7}:|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}|(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}|(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}|(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:(?::[0-9a-fA-F]{1,4}){1,6}|:(?:(?::[0-9a-fA-F]{1,4}){1,7}|:)").ok()?;
    if let Some(m) = ipv6_re.find(s) {
        let ip_str = m.as_str().to_string();
        // Validate that it's a proper IPv6 address
        if ip_str.parse::<Ipv6Addr>().is_ok() {
            return Some(ip_str);
        }
    }

    None
}

/// Helper function to try to extract an IP from the last socket error
fn extract_ip_from_last_error() -> Option<String> {
    // Get the last error message
    let error = std::io::Error::last_os_error().to_string();
    debug!("Extracting IP from error: {}", error);
    extract_ip_from_string(&error)
}

/// Utility function to check if we have root/admin privileges
fn has_root_privileges() -> bool {
    #[cfg(target_family = "unix")]
    {
        unsafe { libc::geteuid() == 0 }
    }

    #[cfg(target_family = "windows")]
    {
        // On Windows, we can't easily check for admin privileges
        // We'll just try the operation and see if it fails
        true
    }

    #[cfg(not(any(target_family = "unix", target_family = "windows")))]
    {
        false
    }
}
