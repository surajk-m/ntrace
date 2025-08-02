use crate::error::NtraceError;
use crate::protocol::{Protocol, ProtocolAnalyzer};
use log::{debug, info};
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::task::JoinSet;

/// Configuration for the scanner.
#[derive(Debug, Clone)]
pub struct ScanConfig {
    pub host: IpAddr,
    pub ports: Vec<u16>,
    pub timeout: Duration,
    pub protocol: Protocol,
    pub batch_size: usize,
}

/// Represents a single port scan result.
#[derive(Debug, Clone, serde::Serialize)]
pub struct PortResult {
    pub port: u16,
    pub is_open: bool,
    pub service: Option<String>,
    pub protocol_info: Option<String>,
}

/// Scanner for performing network port scans.
#[derive(Clone)]
pub struct Scanner {
    config: ScanConfig,
    analyzer: ProtocolAnalyzer,
}

impl Scanner {
    /// Creates a new scanner with the given configuration.
    pub fn new(config: ScanConfig) -> Self {
        Scanner {
            config,
            analyzer: ProtocolAnalyzer::new(),
        }
    }

    /// Scans all configured ports in parallel and returns results.
    pub async fn scan(&self) -> Result<Vec<PortResult>, NtraceError> {
        let mut join_set = JoinSet::new();
        let mut results = Vec::new();
        let batch_size = self.config.batch_size;

        // Process ports in batches for controlled parallelism
        for chunk in self.config.ports.chunks(batch_size) {
            for &port in chunk {
                let config = self.config.clone();
                let analyzer = self.analyzer.clone();
                join_set.spawn(async move {
                    let result = Self::scan_port(config, port, &analyzer).await;
                    (port, result)
                });
            }

            // Collect results from current batch
            while let Some(Ok((port, result))) = join_set.join_next().await {
                match result {
                    Ok(port_result) => results.push(port_result),
                    Err(e) => debug!("Failed to scan port {}: {}", port, e),
                }
            }
        }

        // Sort results by port for consistent output
        results.sort_by_key(|r| r.port);
        Ok(results)
    }

    /// Scans a single port and performs protocol analysis if open.
    async fn scan_port(
        config: ScanConfig,
        port: u16,
        analyzer: &ProtocolAnalyzer,
    ) -> Result<PortResult, NtraceError> {
        let addr = SocketAddr::new(config.host, port);
        info!("Scanning port {}", port);

        let stream = tokio::time::timeout(config.timeout, TcpStream::connect(addr)).await;
        let is_open = stream.is_ok();

        let mut result = PortResult {
            port,
            is_open,
            service: None,
            protocol_info: None,
        };

        if let Ok(Ok(mut stream)) = stream {
            result.service = analyzer
                .detect_service(&mut stream, config.protocol)
                .await?;
            result.protocol_info = analyzer.analyze_protocol(&stream, config.protocol)?;
        }

        Ok(result)
    }
}
