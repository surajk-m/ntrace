use clap::Parser;
use std::net::IpAddr;
use std::str::FromStr;
use std::time::Duration;

#[derive(Parser, Debug)]
#[command(
    name = "ntrace",
    version = "0.1.0",
    about = "Network port scanner and protocol analyzer",
    long_about = "ntrace is a tool for scanning TCP ports and analyzing protocols."
)]
pub struct Cli {
    #[arg(short, long, help = "Target host IP address")]
    pub host: String,

    #[arg(
        short,
        long,
        default_value = "1-1000",
        help = "Port range to scan (e.g., 1-1000 or 80,443)"
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
        long,
        default_value = "tcp",
        help = "Protocol to scan (tcp only for now)"
    )]
    pub protocol: String,

    #[arg(long, help = "Output JSON file path")]
    pub output: Option<String>,
}

impl Cli {
    pub fn to_config(&self) -> Result<crate::scanner::ScanConfig, anyhow::Error> {
        let host = IpAddr::from_str(&self.host)?;
        let ports = self.parse_ports()?;
        let protocol = match self.protocol.to_lowercase().as_str() {
            "tcp" => crate::Protocol::Tcp,
            _ => return Err(anyhow::anyhow!("Unsupported protocol: {}", self.protocol)),
        };
        Ok(crate::scanner::ScanConfig {
            host,
            ports,
            timeout: Duration::from_secs_f32(self.timeout),
            protocol,
            batch_size: self.batch_size,
        })
    }

    fn parse_ports(&self) -> Result<Vec<u16>, anyhow::Error> {
        let mut ports = Vec::new();
        if self.ports.contains('-') {
            let parts: Vec<&str> = self.ports.split('-').collect();
            if parts.len() != 2 {
                return Err(anyhow::anyhow!("Invalid port range: {}", self.ports));
            }
            let start: u16 = parts[0].parse()?;
            let end: u16 = parts[1].parse()?;
            ports.extend(start..=end);
        } else {
            for port in self.ports.split(',') {
                ports.push(port.parse()?);
            }
        }
        Ok(ports)
    }
}
