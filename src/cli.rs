use crate::protocol::Target;
use crate::traceroute::TraceConfig;
use clap::Parser;
use std::net::IpAddr;
use std::str::FromStr;
use std::time::Duration;

#[derive(Parser, Debug)]
#[command(
    name = "ntrace",
    version = "0.1.3",
    about = "Network port scanner and protocol analyzer",
    long_about = "ntrace is a tool for scanning TCP/UDP ports, analyzing network protocols, and performing traceroute.",
    next_line_help = true,
    after_help = "EXAMPLES:
    ntrace -H 192.168.1.1
    ntrace -H wikipedia.org -p 1-1000
    ntrace -H 10.0.0.1 -p 80,443,8080
    ntrace -H 192.168.1.1 -p common --fast
    ntrace -H wikipedia.org -o results.json
    ntrace trace 1.1.1.1 --tcp --port 443 --max-hops 20
    ntrace trace google.com --queries 5 --no-rdns"
)]

pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Command>,

    #[arg(
        short = 'H',
        long,
        help = "Target IP address, hostname, or web domain (e.g., 192.168.1.1, wikipedia.org)",
        group = "ip_version",
        help_heading = "TARGET SPECIFICATION"
    )]
    pub host: Option<String>,

    #[arg(
        long,
        help = "Force IPv6 scanning",
        group = "ip_version",
        help_heading = "TARGET SPECIFICATION"
    )]
    pub ipv6: bool,

    #[arg(
        long,
        help = "Force IPv4 scanning",
        group = "ip_version",
        help_heading = "TARGET SPECIFICATION"
    )]
    pub ipv4: bool,

    #[arg(
        short,
        long,
        default_value = "1-1000",
        help = "Port range to scan (e.g., 1-1000, 80,443, or predefined groups)",
        long_help = "Port range to scan. Can be individual ports (80,443), ranges (1-1000), or predefined groups:\n  \
                    common: Most common ports\n  \
                    well-known: Standard ports (1-1023)\n  \
                    registered: Registered ports (1024-49151)\n  \
                    dynamic: Dynamic ports (49152-65535)\n  \
                    all: All ports (1-65535)",
        help_heading = "PORT SPECIFICATION"
    )]
    pub ports: String,

    #[arg(
        short = 'P',
        long,
        default_value = "tcp",
        help = "Protocol to scan (tcp, udp)",
        help_heading = "SCAN TECHNIQUES"
    )]
    pub protocol: String,

    #[arg(
        short,
        long,
        help = "Perform service detection",
        default_value_t = true,
        help_heading = "SCAN TECHNIQUES"
    )]
    pub service_detection: bool,

    #[arg(
        long,
        help = "Aggressive scan (more intrusive probes)",
        help_heading = "SCAN TECHNIQUES"
    )]
    pub aggressive: bool,

    #[arg(
        long,
        default_value_t = 2.0,
        help = "Timeout for each port scan in seconds",
        help_heading = "SCAN PERFORMANCE"
    )]
    pub timeout: f32,

    #[arg(
        long,
        default_value_t = 100,
        help = "Batch size for parallel scanning",
        help_heading = "SCAN PERFORMANCE"
    )]
    pub batch_size: usize,

    #[arg(
        long,
        help = "Rate limit in packets per second",
        default_value_t = 1000,
        help_heading = "SCAN PERFORMANCE"
    )]
    pub rate_limit: usize,

    #[arg(
        long,
        help = "Fast scan with shorter timeouts (less accurate)",
        help_heading = "SCAN PERFORMANCE"
    )]
    pub fast: bool,

    #[arg(
        long,
        help = "Skip host discovery (ping)",
        help_heading = "HOST DISCOVERY"
    )]
    pub skip_discovery: bool,

    #[arg(
        short,
        long,
        help = "Output file path (.json or .csv)",
        help_heading = "OUTPUT OPTIONS"
    )]
    pub output: Option<String>,

    #[arg(
        short = 'v',
        long,
        help = "Verbose output (show closed ports)",
        help_heading = "OUTPUT OPTIONS"
    )]
    pub verbose: bool,

    #[arg(
        long,
        help = "Skip problematic ports that often cause hangs",
        help_heading = "MISC OPTIONS"
    )]
    pub skip_problematic: bool,

    #[arg(
        long,
        help = "Use SYN scanning for faster results (requires root/admin privileges)",
        help_heading = "SCAN TECHNIQUES"
    )]
    pub syn_scan: bool,
}

#[derive(Parser, Debug)]
pub enum Command {
    /// Trace the route to a host
    #[command(name = "trace")]
    Trace {
        /// Target IP address or hostname to trace
        target: String,

        /// Use TCP packets for traceroute (default is ICMP)
        #[arg(long = "tcp", short = 'T')]
        use_tcp: bool,

        /// Use UDP packets for traceroute
        #[arg(long = "udp", short = 'U')]
        use_udp: bool,

        /// Port to use for TCP/UDP traceroute
        #[arg(long, short = 'p', default_value = "80")]
        port: u16,

        /// Maximum number of hops to try
        #[arg(long = "max-hops", short = 'm', default_value = "30")]
        max_hops: u8,

        /// Number of queries per hop
        #[arg(long, short = 'q', default_value = "3")]
        queries: u8,

        /// Disable reverse DNS lookups
        #[arg(long = "no-rdns", short = 'n')]
        no_rdns: bool,

        /// Always perform reverse DNS lookups
        #[arg(long = "always-rdns", short = 'a')]
        always_rdns: bool,

        /// Number of parallel requests
        #[arg(long = "parallel-requests", default_value = "18")]
        parallel_requests: u8,

        /// Time between sending packets in milliseconds
        #[arg(long = "send-time", short = 'z', default_value = "50")]
        send_time_ms: u64,

        /// Time between sending packets for different TTLs in milliseconds
        #[arg(long = "ttl-time", short = 'i', default_value = "50")]
        ttl_time_ms: u64,

        /// Timeout for each probe in milliseconds
        #[arg(long = "timeout", default_value = "1000")]
        timeout_ms: u64,

        /// Payload size for probe packets
        #[arg(long = "psize", default_value = "52")]
        payload_size: usize,

        /// Print route path by ASN and location
        #[arg(long = "route-path", short = 'P')]
        route_path: bool,

        /// Output trace results as table
        #[arg(long = "table", short = 't')]
        table: bool,

        /// Output trace results as JSON
        #[arg(long = "json", short = 'j')]
        json: bool,

        /// Output file path (.json or .txt)
        #[arg(long = "output", short = 'o')]
        output: Option<String>,
    },
}

impl Cli {
    pub fn to_config(&self) -> Result<crate::scanner::ScanConfig, anyhow::Error> {
        // If using a subcommand, return early
        if self.command.is_some() {
            return Err(anyhow::anyhow!("Using a subcommand"));
        }

        // Host must be provided when not using a subcommand
        let host = self
            .host
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Host is required"))?;

        // Parse host (support both IP addresses, hostnames, and web domains)
        let target = match IpAddr::from_str(host) {
            Ok(ip) => {
                // Check if we need to enforce IP version
                if self.ipv4 && ip.is_ipv6() {
                    return Err(anyhow::anyhow!(
                        "IPv6 address provided but --ipv4 flag was set"
                    ));
                } else if self.ipv6 && ip.is_ipv4() {
                    return Err(anyhow::anyhow!(
                        "IPv4 address provided but --ipv6 flag was set"
                    ));
                }
                Target::Ip(ip)
            }
            Err(_) => {
                // Check if this looks like a domain name
                if host.contains('.') && !host.starts_with('.') && !host.ends_with('.') {
                    // For CLI parsing, we'll just store the domain and resolve it later
                    // This avoids the async runtime issues with DNS resolution
                    Target::Domain(host.clone())
                } else {
                    // Not a valid IP or domain
                    return Err(anyhow::anyhow!("Invalid host: {}", host));
                }
            }
        };

        // Parse ports
        let ports = self.parse_ports()?;

        // Parse protocol
        let protocol = match self.protocol.to_lowercase().as_str() {
            "tcp" => crate::Protocol::Tcp,
            "udp" => crate::Protocol::Udp,
            _ => return Err(anyhow::anyhow!("Unsupported protocol: {}", self.protocol)),
        };

        // Create config
        Ok(crate::scanner::ScanConfig {
            target,
            ports,
            timeout: if self.fast {
                Duration::from_millis(100)
            } else {
                Duration::from_secs_f32(self.timeout)
            },
            protocol,
            batch_size: self.batch_size,
            // Fewer retries in fast mode
            max_retries: if self.fast { 1 } else { 3 },
            retry_delay: if self.fast {
                Duration::from_millis(100)
            } else {
                Duration::from_millis(500)
            },
            // Fail fast in fast mode or when skipping problematic ports
            fail_fast: self.fast || self.skip_problematic,
        })
    }

    pub fn to_trace_config(&self) -> Result<TraceConfig, anyhow::Error> {
        if let Some(Command::Trace {
            target,
            use_tcp,
            use_udp,
            port,
            max_hops,
            queries,
            no_rdns,
            always_rdns,
            parallel_requests,
            send_time_ms,
            ttl_time_ms,
            timeout_ms,
            payload_size,
            ..
        }) = &self.command
        {
            // Parse target (support both IP addresses and hostnames)
            let target_obj = match IpAddr::from_str(target) {
                Ok(ip) => {
                    // Check if we need to enforce IP version
                    if self.ipv4 && ip.is_ipv6() {
                        return Err(anyhow::anyhow!(
                            "IPv6 address provided but --ipv4 flag was set"
                        ));
                    } else if self.ipv6 && ip.is_ipv4() {
                        return Err(anyhow::anyhow!(
                            "IPv4 address provided but --ipv6 flag was set"
                        ));
                    }
                    Target::Ip(ip)
                }
                Err(_) => {
                    // Check if this looks like a domain name
                    if target.contains('.') && !target.starts_with('.') && !target.ends_with('.') {
                        Target::Domain(target.clone())
                    } else {
                        // Not a valid IP or domain
                        return Err(anyhow::anyhow!("Invalid target: {}", target));
                    }
                }
            };

            // Determine protocol
            let protocol = if *use_tcp {
                crate::Protocol::Tcp
            } else if *use_udp {
                crate::Protocol::Udp
            } else {
                crate::Protocol::Icmp
            };

            // Determine hostname resolution
            let resolve_hostnames = !no_rdns || *always_rdns;

            Ok(TraceConfig {
                target: target_obj,
                protocol,
                port: *port,
                max_hops: *max_hops,
                queries: *queries,
                timeout_ms: *timeout_ms,
                resolve_hostnames,
                parallel_requests: *parallel_requests,
                send_time_ms: *send_time_ms,
                ttl_time_ms: *ttl_time_ms,
                payload_size: *payload_size,
            })
        } else {
            Err(anyhow::anyhow!("Not a trace command"))
        }
    }

    pub fn parse_ports(&self) -> Result<Vec<u16>, anyhow::Error> {
        let mut ports = Vec::new();

        // Handle predefined port groups
        match self.ports.to_lowercase().as_str() {
            "common" => {
                // Common ports for quick scanning
                ports.extend_from_slice(&[
                    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723,
                    3306, 3389, 5900, 8080,
                ]);
            }
            "well-known" => {
                // Well known ports (1-1023)
                ports.extend(1..=1023);
            }
            "registered" => {
                // Registered ports (1024-49151)
                ports.extend(1024..=49151);
            }
            "dynamic" => {
                // Dynamic ports (49152-65535)
                ports.extend(49152..=65535);
            }
            "all" => {
                // All ports (1-65535)
                ports.extend(1..=65535);
            }
            _ => {
                // Parse custom port specification (e.g., "80,443,8080" or "1-1000")
                for part in self.ports.split(',') {
                    if part.contains('-') {
                        // Port range
                        let range: Vec<&str> = part.split('-').collect();
                        if range.len() == 2 {
                            let start = range[0].parse::<u16>()?;
                            let end = range[1].parse::<u16>()?;
                            ports.extend(start..=end);
                        } else {
                            return Err(anyhow::anyhow!("Invalid port range: {}", part));
                        }
                    } else {
                        // Single port
                        ports.push(part.parse::<u16>()?);
                    }
                }
            }
        }

        // Remove duplicates
        ports.sort();
        ports.dedup();

        Ok(ports)
    }
}
