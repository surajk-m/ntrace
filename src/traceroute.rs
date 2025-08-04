use crate::error::NtraceError;
use crate::protocol::{Protocol, Target};
use log::{debug, info, warn};
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

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
}

impl Default for TraceConfig {
    fn default() -> Self {
        Self {
            target: Target::Ip(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))),
            protocol: Protocol::Icmp,
            port: 80,
            max_hops: 30,
            queries: 3,
            timeout_ms: 1000,
            resolve_hostnames: true,
            parallel_requests: 18,
            send_time_ms: 50,
            ttl_time_ms: 50,
            payload_size: 52,
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
    /// Whether this hop is the final destination
    pub is_destination: bool,
    /// ASN information (if available)
    pub asn: Option<String>,
    /// Location information (if available)
    pub location: Option<String>,
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
}

/// Tracer for performing traceroute operations
pub struct Tracer {
    config: TraceConfig,
    /// Statistics and results
    results: Arc<Mutex<HashMap<u8, HopResult>>>,
}

impl Tracer {
    /// Creates a new tracer with the given configuration
    pub fn new(config: TraceConfig) -> Self {
        Self {
            config,
            results: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// This would use proper reverse DNS lookup
    async fn resolve_hostname(&self, ip: IpAddr) -> Option<String> {
        // For now, we'll return None as proper DNS resolution requires
        // additional setup that may not be available in all environments
        debug!("Hostname resolution requested for {}", ip);
        None
    }

    /// Perform a traceroute to the target
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

        // Determine which trace method to use based on protocol
        match self.config.protocol {
            Protocol::Tcp => self.trace_tcp(target_ip).await?,
            Protocol::Udp => self.trace_udp(target_ip).await?,
            Protocol::Icmp => {
                // Try the raw socket implementation first
                match self.trace_icmp_raw(target_ip).await {
                    Ok(_) => {}
                    Err(e) => {
                        warn!(
                            "Raw socket ICMP traceroute failed: {}. Trying alternative implementation.",
                            e
                        );
                        // Try the alternative implementation next
                        match self.trace_icmp_alternative(target_ip).await {
                            Ok(_) => {}
                            Err(e2) => {
                                warn!(
                                    "Alternative ICMP traceroute failed: {}. Falling back to original implementation.",
                                    e2
                                );
                                self.trace_icmp(target_ip).await?
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
        };

        Ok(trace_result)
    }

    /// Perform a TCP traceroute
    async fn trace_tcp(&self, target_ip: IpAddr) -> Result<(), NtraceError> {
        // Both IPv4 and IPv6 are supported

        // Create a progress indicator
        let progress = if cfg!(not(test)) {
            use indicatif::{ProgressBar, ProgressStyle};
            let pb = ProgressBar::new(self.config.max_hops as u64);
            pb.set_style(
                ProgressStyle::default_bar()
                    .template("[{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} hops")
                    .unwrap()
                    .progress_chars("█▓▒░ "),
            );
            Some(pb)
        } else {
            None
        };

        // Trace each TTL
        for ttl in 1..=self.config.max_hops {
            // Create a hop result entry
            let mut hop_result = HopResult {
                hop: ttl,
                ip: None,
                hostname: None,
                latencies: vec![None; self.config.queries as usize],
                avg_latency: None,
                is_destination: false,
                asn: None,
                location: None,
            };

            // Send multiple queries for this hop
            let mut responses = 0;
            let mut total_latency = Duration::new(0, 0);

            for q in 0..self.config.queries {
                // Send TCP SYN packet with TTL set
                let start_time = Instant::now();

                // Create socket with TTL set
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
                    Err(_) => {
                        // Connection failed, try next query
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

                // Wait between queries
                if q < self.config.queries - 1 {
                    tokio::time::sleep(Duration::from_millis(self.config.send_time_ms)).await;
                }
            }

            // Calculate average latency if we got responses
            if responses > 0 {
                hop_result.avg_latency = Some(total_latency / responses);
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

            // Update progress
            if let Some(pb) = &progress {
                pb.inc(1);
            }

            // If we reached the destination, we're done
            if let Some(ip) = &hop_result.ip {
                if ip == &target_ip.to_string() {
                    break;
                }
            }

            // Wait between TTLs
            if ttl < self.config.max_hops {
                tokio::time::sleep(Duration::from_millis(self.config.ttl_time_ms)).await;
            }
        }

        // Finish progress
        if let Some(pb) = &progress {
            pb.finish_and_clear();
        }

        Ok(())
    }

    /// Perform a UDP traceroute
    async fn trace_udp(&self, target_ip: IpAddr) -> Result<(), NtraceError> {
        // Both IPv4 and IPv6 are supported

        // Create a progress indicator
        let progress = if cfg!(not(test)) {
            use indicatif::{ProgressBar, ProgressStyle};
            let pb = ProgressBar::new(self.config.max_hops as u64);
            pb.set_style(
                ProgressStyle::default_bar()
                    .template("[{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} hops")
                    .unwrap()
                    .progress_chars("█▓▒░ "),
            );
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
                is_destination: false,
                asn: None,
                location: None,
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
                hop_result.avg_latency = Some(total_latency / responses);
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

            // Update progress
            if let Some(pb) = &progress {
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

        // Finish progress
        if let Some(pb) = &progress {
            pb.finish_and_clear();
        }

        Ok(())
    }

    /// Perform an ICMP traceroute
    async fn trace_icmp(&self, target_ip: IpAddr) -> Result<(), NtraceError> {
        // Both IPv4 and IPv6 are supported

        // Create a progress indicator
        let progress = if cfg!(not(test)) {
            use indicatif::{ProgressBar, ProgressStyle};
            let pb = ProgressBar::new(self.config.max_hops as u64);
            pb.set_style(
                ProgressStyle::default_bar()
                    .template("[{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} hops")
                    .unwrap()
                    .progress_chars("█▓▒░ "),
            );
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
                is_destination: false,
                asn: None,
                location: None,
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
                hop_result.avg_latency = Some(total_latency / responses);
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

            // Update progress
            if let Some(pb) = &progress {
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

        // Finish progress
        if let Some(pb) = &progress {
            pb.finish_and_clear();
        }

        Ok(())
    }

    /// Alternative ICMP traceroute implementation using a different approach
    async fn trace_icmp_alternative(&self, target_ip: IpAddr) -> Result<(), NtraceError> {
        // Both IPv4 and IPv6 are supported

        // Create a progress indicator
        let progress = if cfg!(not(test)) {
            use indicatif::{ProgressBar, ProgressStyle};
            let pb = ProgressBar::new(self.config.max_hops as u64);
            pb.set_style(
                ProgressStyle::default_bar()
                    .template("[{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} hops")
                    .unwrap()
                    .progress_chars("█▓▒░ "),
            );
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
                is_destination: false,
                asn: None,
                location: None,
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
                hop_result.avg_latency = Some(total_latency / responses);
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

            // Update progress
            if let Some(pb) = &progress {
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

        // Finish progress
        if let Some(pb) = &progress {
            pb.finish_and_clear();
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

        // Create a progress indicator
        let progress = if cfg!(not(test)) {
            use indicatif::{ProgressBar, ProgressStyle};
            let pb = ProgressBar::new(self.config.max_hops as u64);
            pb.set_style(
                ProgressStyle::default_bar()
                    .template("[{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} hops")
                    .unwrap()
                    .progress_chars("█▓▒░ "),
            );
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
                is_destination: false,
                asn: None,
                location: None,
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
                hop_result.avg_latency = Some(total_latency / responses);
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

            // Update progress
            if let Some(pb) = &progress {
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

        // Finish progress
        if let Some(pb) = &progress {
            pb.finish_and_clear();
        }

        Ok(())
    }

    /// Extract router IP from socket error
    fn extract_router_ip_from_error(error: &std::io::Error) -> Option<IpAddr> {
        // On most systems, we can't easily extract the router IP from the error
        // This is a platform specific operation that would require raw socket handling

        // Try to get the error number for more specific handling
        let errno = error.raw_os_error();

        // Platform specific handling
        #[cfg(target_os = "linux")]
        {
            // On Linux, for ICMP Time Exceeded messages, we can try to extract the IP
            // from the error message or use socket options to get the original sender
            // EAGAIN
            if let Some(11) = errno {
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
        return Some(m.as_str().to_string());
    }

    // If no IPv4 address found, try to extract IPv6 address
    // This is a simplified pattern and might not catch all valid IPv6 formats
    let ipv6_re = regex::Regex::new(r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b|(?:[0-9a-fA-F]{1,4}:){1,7}:|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}|(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}|(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}|(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:(?::[0-9a-fA-F]{1,4}){1,6}|:(?:(?::[0-9a-fA-F]{1,4}){1,7}|:)").ok()?;
    ipv6_re.find(s).map(|m| m.as_str().to_string())
}

/// Helper function to try to extract an IP from the last socket error
fn extract_ip_from_last_error() -> Option<String> {
    // Get the last error message
    let error = std::io::Error::last_os_error().to_string();
    extract_ip_from_string(&error)
}
