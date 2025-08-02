# ntrace

A fast and secure network port scanner and protocol analyzer written in Rust.

## Features
- Asynchronous TCP/UDP port scanning.
- Service detection via banner grabbing.
- Protocol analysis (e.g., TLS version detection).
- JSON output for integration with other tools.
- Configurable timeout and protocol support.

## Installation
```bash
cargo install ntrace


### **examples/scan.rs**
```rust
use ntrace::{Scanner, ScanConfig, Protocol};
use std::net::IpAddr;
use std::str::FromStr;
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = ScanConfig {
        host: IpAddr::from_str("127.0.0.1")?,
        ports: vec![80, 443],
        timeout: Duration::from_secs(2),
        protocol: Protocol::Tcp,
        batch_size: 10,
    };

    let scanner = Scanner::new(config);
    let results = scanner.scan().await?;
    for result in results {
        println!("Port {}: {:?}", result.port, result);
    }

    Ok(())
}
