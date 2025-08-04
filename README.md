# ntrace

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

A fast network port scanner, protocol analyzer, and traceroute utility written in Rust.

## Features

- **Advanced Port Scanning**: Asynchronous TCP/UDP port scanning with configurable concurrency and rate limiting
- **Service Detection**: Identifies services running on open ports using multiple methods:
  - Banner grabbing
  - Active probing
  - Well known port database
- **Protocol Analysis**: Detects and analyzes protocols (HTTP, TLS, SSH, etc.)
- **Advanced Traceroute**: Trace the network path to a target using various protocols (ICMP, TCP, UDP) with:
  - Parallel tracing for up to 5x faster results
  - Path MTU discovery
  - Path asymmetry detection
  - Detailed latency statistics (min/max/avg/std-dev)
  - Packet loss calculation
  - Adaptive timing for better reliability
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

### Using the Built Binary

After building the binary, you can use it directly:

```bash
# Port scanning
./target/release/ntrace -H wikipedia.org -p 80,443,8080

# Traceroute will automatically handle permissions for ICMP
./target/release/ntrace trace wikipedia.org

# The tool will automatically request sudo access to set CAP_NET_RAW capability if needed
# Or you can manually set the capability:
sudo setcap cap_net_raw+ep /path/to/ntrace

# UDP port scanning
./target/release/ntrace -H 192.168.1.1 -P udp -p 53,123,161 -v
```

You can also move the binary to a directory in your PATH for easier access:

```bash
# On Linux/macOS
sudo cp ./target/release/ntrace /usr/local/bin/
ntrace -h 

# On Windows (PowerShell with Administrator privileges)
Copy-Item .\target\release\ntrace.exe -Destination "C:\Windows\System32\"
ntrace -h
```

### Platform Specific Examples

#### Linux
```bash
ntrace trace google.com
```
```bash
# Full port scan with service detection
./target/release/ntrace -H scanme.nmap.org -p well-known --service-detection

# Fast traceroute with table output and parallel processing
./target/release/ntrace trace cloudflare.com --table --fast-mode
```

#### Windows
```bash
# Scan a local network device
.\target\release\ntrace.exe -H 192.168.1.1 -p common

# TCP traceroute with parallel processing
.\target\release\ntrace.exe trace microsoft.com --tcp --fast-mode
```

#### macOS
```bash
# Scan multiple ports with JSON output
./target/release/ntrace -H apple.com -p 80,443,8080 -o results.json

# ICMP traceroute with maximum 20 hops
./target/release/ntrace trace github.com --max-hops 20
```

### Advanced Command Examples

Here are some more advanced examples that combine multiple features:

```bash
# Comprehensive network analysis: port scan followed by traceroute to open ports
./target/release/ntrace -H wikipedia.org -p 80,443 -v
./target/release/ntrace trace wikipedia.org --port 80 --table

# Security audit: scan all well-known ports with aggressive service detection
./target/release/ntrace -H target-server.com -p well-known --aggressive --service-detection

# Network troubleshooting: compare fast TCP and standard ICMP traceroute results
./target/release/ntrace trace problem-server.com --tcp --fast-mode --port 443 -o tcp-trace.json
./target/release/ntrace trace problem-server.com -o icmp-trace.json

# Performance testing: scan with different batch sizes and compare
time ./target/release/ntrace -H performance-test.com -p 1-1000 --batch-size 50
time ./target/release/ntrace -H performance-test.com -p 1-1000 --batch-size 200

# Advanced traceroute with parallel processing for faster results
./target/release/ntrace trace google.com --tcp --fast-mode

# Comprehensive network path analysis
./target/release/ntrace trace cloudflare.com --tcp --fast-mode --max-hops 20 --table
```

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

### Traceroute Usage

```bash
# Basic ICMP traceroute (requires sudo/root privileges)
ntrace trace google.com

# TCP traceroute (can work without sudo for basic functionality)
ntrace trace google.com --tcp

# UDP traceroute
ntrace trace google.com --udp

# Specify maximum hops
ntrace trace google.com --max-hops 15

# Specify port for TCP/UDP traceroute
ntrace trace google.com --tcp --port 443

# Output trace results as table
ntrace trace google.com --table

# Save trace results to a file
ntrace trace google.com --output trace-results.json

# Fast mode with parallel tracing (up to 5x faster)
ntrace trace google.com --fast-mode

# Combine options for optimal performance
ntrace trace cloudflare.com --tcp --fast-mode --max-hops 20
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

# Ultra fast scanning mode
ntrace -H 192.168.1.1 --fast
```

### Advanced Traceroute Features

ntrace offers several advanced traceroute capabilities that make it more powerful than traditional traceroute tools:

```bash
# Parallel traceroute for faster results (up to 5x faster)
ntrace trace example.com --fast-mode

# Combine parallel processing with TCP for reliable results
ntrace trace example.com --tcp --fast-mode

# Detailed statistics with table output
ntrace trace example.com --tcp --fast-mode --table

# Control the number of parallel requests
ntrace trace example.com --fast-mode --parallel-requests 24

# Customize timing parameters for better reliability
ntrace trace example.com --send-time 5 --ttl-time 5 --timeout 800
```

These advanced features provide:

- **Parallel Processing**: Trace multiple hops simultaneously for faster results
- **Detailed Statistics**: Min/max/avg latency, standard deviation, packet loss
- **Adaptive Timing**: Automatically adjust timing based on network conditions
- **Flexible Protocol Support**: Choose between TCP, UDP, and ICMP based on your needs

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

### Traceroute Example

Trace the network path to Google using ICMP:

```bash
ntrace trace google.com
```

Or use the faster parallel traceroute with TCP:

```bash
ntrace trace google.com --tcp --fast-mode
```

Output:
```
╔══════════════════════════════════════════════════════════╗
║                                                          ║
║   _   _ _____                                            ║
║  | \ | |_   _| __ __ _  ___ ___                          ║
║  |  \| | | || '__/ _` |/ __/ _ \                         ║
║  | |\  | | || | | (_| | (_|  __/                         ║
║  |_| \_| |_||_|  \__,_|\___\___|                         ║
║                                                          ║
║  Traceroute & Network Path Analyzer v0.1.3               ║
║                                                          ║
╚══════════════════════════════════════════════════════════╝

Starting traceroute to google.com using Icmp...

╔════════════════════════════════════════════════════════════════════╗
║  TRACEROUTE RESULTS                                                ║
╠════════════════════════════════════════════════════════════════════╣
║ Target: google.com                                                 ║
║ Protocol: Icmp                                                     ║
║ Duration: 15.77 seconds                                            ║
║ Hops: 16                                                           ║
║ Destination Reached: Yes                                           ║
╠════════════════════════════════════════════════════════════════════╣
║ HOP        IP                HOSTNAME           LATENCY            ║
╠════════════════════════════════════════════════════════════════════╣
║    1     172.21.96.1                 -               0.44ms        ║
║    2    192.168.29.1                 -               3.19ms        ║
║    3     10.50.144.1                 -               5.26ms        ║
║    4    172.31.5.101                 -               4.87ms        ║
║    5   192.168.86.238                -               3.96ms        ║
║    6    172.26.104.52                -               3.99ms        ║
║    7   172.26.104.146                -               8.50ms        ║
║    8    192.168.85.56                -               5.13ms        ║
║    9          *                      -                 *           ║
║   10          *                      -                 *           ║
║   11          *                      -                 *           ║
║   12          *                      -                 *           ║
║   13    173.194.121.8                -              34.54ms        ║
║   14   192.178.110.227               -              33.98ms        ║
║   15    72.14.233.59                 -              33.37ms        ║
║   16 → 142.250.183.110 ←             -              35.66ms        ║
╚════════════════════════════════════════════════════════════════════╝
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

### Ultra Fast Scanning

For maximum speed (up to 10x faster than regular scanning), use fast mode:

```bash
ntrace -H 192.168.1.1 --fast -p 1-10000
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
use ntrace::{Scanner, ScanConfig, Protocol, Target};
use std::net::IpAddr;
use std::str::FromStr;
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Configure the scanner
    let config = ScanConfig {
        target: Target::Ip(IpAddr::from_str("192.168.1.1")?),
        ports: vec![80, 443, 8080],
        timeout: Duration::from_secs(2),
        protocol: Protocol::Tcp,
        batch_size: 100,
        max_retries: 3,
        retry_delay: Duration::from_millis(500),
        fail_fast: false,
    };

    // Create and configure the scanner
    let scanner = Scanner::new(config)
        .with_rate_limit(1000)
        .with_concurrency_limit(50)
    
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