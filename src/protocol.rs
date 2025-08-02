use crate::error::NtraceError;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

#[derive(Debug, Clone, Copy)]
pub enum Protocol {
    Tcp,
    // Add UDP, HTTP, etc., for future extensibility
}

#[derive(Clone)]
pub struct ProtocolAnalyzer;

impl ProtocolAnalyzer {
    pub fn new() -> Self {
        ProtocolAnalyzer
    }

    /// Detects the service running on the port via banner grabbing.
    pub async fn detect_service(
        &self,
        stream: &mut TcpStream,
        protocol: Protocol,
    ) -> Result<Option<String>, NtraceError> {
        match protocol {
            Protocol::Tcp => {
                let mut buffer = [0; 1024];
                // Send a simple HTTP request to detect HTTP or other services
                stream
                    .write_all(b"HEAD / HTTP/1.0\r\n\r\n")
                    .await
                    .map_err(|e| NtraceError::Network(e))?;
                stream.flush().await.map_err(|e| NtraceError::Network(e))?;

                let response = match stream.read(&mut buffer).await {
                    Ok(n) if n > 0 => String::from_utf8_lossy(&buffer[..n]).into_owned(),
                    _ => return Ok(None),
                };

                if response.contains("HTTP") {
                    Ok(Some("HTTP".to_string()))
                } else if response.contains("SSH") {
                    Ok(Some("SSH".to_string()))
                } else {
                    Ok(None)
                }
            }
        }
    }

    /// Analyzes protocol details 
    // placeholder for future enhancements.
    pub fn analyze_protocol(
        &self,
        _stream: &TcpStream,
        protocol: Protocol,
    ) -> Result<Option<String>, NtraceError> {
        match protocol {
            // Placeholder for TLS analysis, etc.
            Protocol::Tcp => Ok(None),
        }
    }
}
