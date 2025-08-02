use crate::protocol::Target;
use clap::Parser;
use std::net::IpAddr;
use std::str::FromStr;
use std::time::Duration;

#[derive(Parser, Debug)]
#[command(
    name = "ntrace",
    version = "0.1.0",
    about = "Network port scanner and protocol analyzer",
    long_about = "ntrace is a fast and secure tool for scanning TCP/UDP ports and analyzing network protocols."
)]
pub struct Cli {
    #[arg(
        short = 'H',
        long,
        help = "Target IP address, hostname, or web domain (e.g., 192.168.1.1,  wikipedia.org)"
    )]
    pub host: String,

    #[arg(long, help = "Force IPv6 scanning")]
    pub ipv6: bool,

    #[arg(long, help = "Force IPv4 scanning")]
    pub ipv4: bool,

    #[arg(
        short,
        long,
        default_value = "1-1000",
        help = "Port range to scan (e.g., 1-1000, 80,443, or common)"
    )]
    pub ports: String,

    #[arg(
        long,
        default_value_t = 2.0,
        help = "Timeout for each port scan in seconds"
    )]
    pub timeout: f32,

    #[arg(long, default_value_t = 100, help = "Batch size for parallel scanning")]
    pub batch_size: usize,

    #[arg(
        short = 'P',
        long,
        default_value = "tcp",
        help = "Protocol to scan (tcp, udp)"
    )]
    pub protocol: String,

    #[arg(short, long, help = "Output file path (.json or .csv)")]
    pub output: Option<String>,

    #[arg(
        short,
        long,
        help = "Perform service detection",
        default_value_t = true
    )]
    pub service_detection: bool,

    #[arg(short = 'v', long, help = "Verbose output (show closed ports)")]
    pub verbose: bool,

    #[arg(
        long,
        help = "Rate limit in packets per second",
        default_value_t = 1000
    )]
    pub rate_limit: usize,

    #[arg(long, help = "Skip host discovery (ping)")]
    pub skip_discovery: bool,

    #[arg(long, help = "Aggressive scan (more intrusive probes)")]
    pub aggressive: bool,

    #[arg(long, help = "Fast scan with shorter timeouts (less accurate)")]
    pub fast: bool,

    #[arg(long, help = "Skip problematic ports that often cause hangs")]
    pub skip_problematic: bool,
}

impl Cli {
    pub fn to_config(&self) -> Result<crate::scanner::ScanConfig, anyhow::Error> {
        // Parse host (support both IP addresses, hostnames, and web domains)
        let target = match IpAddr::from_str(&self.host) {
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
                if self.host.contains('.')
                    && !self.host.starts_with('.')
                    && !self.host.ends_with('.')
                {
                    // For CLI parsing, we'll just store the domain and resolve it later
                    // This avoids the async runtime issues with DNS resolution
                    Target::Domain(self.host.clone())
                } else {
                    // Not a valid IP or domain
                    return Err(anyhow::anyhow!("Invalid host: {}", self.host));
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
