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
    #[arg(short = 'H', long, help = "Target host IP address or hostname")]
    pub host: String,

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
}

impl Cli {
    pub fn to_config(&self) -> Result<crate::scanner::ScanConfig, anyhow::Error> {
        // Parse host (support both IP addresses and hostnames)
        let host = match IpAddr::from_str(&self.host) {
            Ok(ip) => ip,
            Err(_) => {
                // Try to resolve hostname
                use trust_dns_resolver::Resolver;
                use trust_dns_resolver::config::{ResolverConfig, ResolverOpts};

                let resolver = Resolver::new(ResolverConfig::default(), ResolverOpts::default())?;
                match resolver.lookup_ip(&self.host)?.iter().next() {
                    Some(ip) => ip,
                    None => {
                        return Err(anyhow::anyhow!("Could not resolve hostname: {}", self.host));
                    }
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
            host,
            ports,
            timeout: Duration::from_secs_f32(self.timeout),
            protocol,
            batch_size: self.batch_size,
        })
    }

    pub fn parse_ports(&self) -> Result<Vec<u16>, anyhow::Error> {
        let mut ports = Vec::new();

        // Handle special keywords
        match self.ports.to_lowercase().as_str() {
            "common" => {
                // Common ports for quick scanning
                return Ok(vec![
                    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723,
                    3306, 3389, 5900, 8080, 8443,
                ]);
            }
            "all" => {
                // All ports (1-65535)
                return Ok((1..=65535).collect());
            }
            "well-known" => {
                // Well-known ports (1-1023)
                return Ok((1..=1023).collect());
            }
            "registered" => {
                // Registered ports (1024-49151)
                return Ok((1024..=49151).collect());
            }
            "dynamic" => {
                // Dynamic ports (49152-65535)
                return Ok((49152..=65535).collect());
            }
            _ => {}
        }

        // Parse range or comma separated list
        if self.ports.contains('-') {
            let parts: Vec<&str> = self.ports.split('-').collect();
            if parts.len() != 2 {
                return Err(anyhow::anyhow!("Invalid port range: {}", self.ports));
            }
            let start: u16 = parts[0].parse()?;
            let end: u16 = parts[1].parse()?;
            ports.extend(start..=end);
        } else if self.ports.contains(',') {
            for port in self.ports.split(',') {
                ports.push(port.parse()?);
            }
        } else {
            // Single port
            ports.push(self.ports.parse()?);
        }

        Ok(ports)
    }
}
