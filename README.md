# ntrace

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

A fast and secure network port scanner and protocol analyzer written in Rust.

## Features

- **Advanced Port Scanning**: Asynchronous TCP/UDP port scanning with configurable concurrency and rate limiting
- **Service Detection**: Identifies services running on open ports using multiple methods:
  - Banner grabbing
  - Active probing
  - Well known port database
- **Protocol Analysis**: Detects and analyzes protocols (HTTP, TLS, SSH, etc.)
- **Multiple Output Formats**: JSON and CSV output for integration with other tools
- **Hostname Resolution**: Supports both IP addresses and hostnames as targets
- **Flexible Port Selection**: Scan specific ports, ranges, or use predefined groups (common, well known, all)

## Installation

### From Cargo

```bash
cargo install ntrace
```

### From Source

```bash
git clone https://github.com/surajk-m/ntrace.git
cd ntrace
cargo build --release
```

The binary will be available at `target/release/ntrace`.

## Usage

### Basic Usage

```bash
# Scan default ports (1-1000) on a target
ntrace -H 192.168.1.1

# Scan specific ports
ntrace -H 192.168.1.1 -p 80,443

# Scan a port range
ntrace -H 192.168.1.1 -p 1-100

# Scan common ports
ntrace -H 192.168.1.1 -p common
```

### Advanced Options

```bash
# Verbose output (show closed ports)
ntrace -H 192.168.1.1 -v

# Set custom timeout
ntrace -H 192.168.1.1 --timeout 5.0

# Set batch size for parallel scanning
ntrace -H 192.168.1.1 --batch-size 200

# Use UDP protocol instead of TCP
ntrace -H 192.168.1.1 -P udp

# Skip host discovery (ping)
ntrace -H 192.168.1.1 --skip-discovery

# Save results to a file (JSON or CSV)
ntrace -H 192.168.1.1 -o results.json
ntrace -H 192.168.1.1 -o results.csv

# Aggressive scan (more intrusive probes)
ntrace -H 192.168.1.1 --aggressive
```

### Port Selection Options

- `common`: Scans commonly used ports
- `well-known`: Scans well known ports (1-1023)
- `all`: Scans all ports (1-65535)
- `registered`: Scans registered ports (1024-49151)
- `dynamic`: Scans dynamic ports (49152-65535)

## Scan Examples

### Basic TCP Scan

Scan the most common ports on a web server:

```bash
ntrace -H wikipedia.org -p common
```

Output:
```
=============================================================
  _   _ _____                    
 | \ | |_   _| __ __ _  ___ ___ 
 |  \| | | || '__/ _` |/ __/ _ \
 | |\  | | || | | (_| | (_|  __/
 |_| \_| |_||_|  \__,_|\___\___|
                                 
 Network Port Scanner & Protocol Analyzer v0.1.0
=============================================================

Starting scan of 20 ports on wikipedia.org...
[00:00:02] Scan completed in 2.34s

Results for wikipedia.org (resolved to 93.184.216.34):
PORT    STATE   SERVICE         PROTOCOL    LATENCY
80      open    http            TCP         124.3ms
443     open    https           TLS/SSL     125.1ms

Summary: 2 open ports, 18 closed ports out of 20 scanned
```

### Comprehensive Web Server Analysis

Scan all web-related ports with verbose output:

```bash
ntrace -H wikipedia.org -p 80,443,8080,8443 -v
```

### Network Service Discovery

Discover all services on a local network device:

```bash
ntrace -H 192.168.1.1 -p well-known --service-detection
```

### Fast Network Sweep

Quickly check if common services are running:

```bash
ntrace -H 192.168.1.1 --fast -p common
```

### UDP Service Detection

Scan for common UDP services:

```bash
ntrace -H 192.168.1.1 -P udp -p 53,67,123,161
```

> **Note about UDP scanning**: Unlike TCP, UDP is connectionless and doesn't have a handshake mechanism. This makes it difficult to determine if a port is truly open or closed. In UDP scanning:
> - `open`: The port sent back a UDP response (definite open)
> - `open|filtered`: No response was received, which could mean either the port is open but the service didn't respond, or a firewall is filtering the port
> - `closed`: An ICMP "port unreachable" message was received

Output:
```
=============================================================
  _   _ _____                    
 | \ | |_   _| __ __ _  ___ ___ 
 |  \| | | || '__/ _` |/ __/ _ \
 | |\  | | || | | (_| | (_|  __/
 |_| \_| |_||_|  \__,_|\___\___|
                                 
 Network Port Scanner & Protocol Analyzer v0.1.0
=============================================================

Starting scan of 4 ports on 192.168.1.1...
[00:00:03] Scan completed in 3.12s

Results for 192.168.1.1:
PORT    STATE           SERVICE         PROTOCOL    LATENCY
53      open            domain          DNS         45.7ms
123     open            ntp             NTP         67.2ms
67      open|filtered   dhcp            UDP         -
161     open|filtered   snmp            UDP         -

Summary: 2 open ports, 2 open|filtered ports out of 4 scanned
```

### Exporting Scan Results

Scan and save results in JSON format for further analysis:

```bash
ntrace -H wikipedia.org -p 1-1000 -o scan-results.json
```

## Library Usage

ntrace can also be used as a library in your Rust projects:

```rust
use ntrace::{Scanner, ScanConfig, Protocol, PortResult};
use std::net::IpAddr;
use std::str::FromStr;
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Configure the scanner
    let config = ScanConfig {
        host: IpAddr::from_str("192.168.1.1")?,
        ports: vec![80, 443, 8080],
        timeout: Duration::from_secs(2),
        protocol: Protocol::Tcp,
        batch_size: 100,
    };

    // Create and configure the scanner
    let scanner = Scanner::new(config)
        .with_rate_limit(1000)
        .with_concurrency_limit(50);
    
    // Run the scan
    let results = scanner.scan().await?;
    
    // Process results
    for result in results {
        if result.is_open {
            println!(
                "Port {}: Open - Service: {}, Protocol: {}, Latency: {:?}",
                result.port,
                result.service.unwrap_or_else(|| "Unknown".to_string()),
                result.protocol_info.unwrap_or_else(|| "Unknown".to_string()),
                result.latency
            );
        }
    }

    Ok(())
}
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.