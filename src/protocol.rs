use crate::error::NtraceError;
use crate::services::{PROTOCOL_SIGNATURES, SERVICE_PROBES, get_service_name};
use log::{debug, trace};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Protocol {
    Tcp,
    Udp,
    Icmp,
    // Add more protocols
}

/// Represents a scan target, which can be either an IP address or a domain name
#[derive(Debug, Clone, PartialEq)]
pub enum Target {
    /// An IP address (IPv4 or IPv6)
    Ip(std::net::IpAddr),
    /// A domain name (e.g., "wikipedia.org")
    Domain(String),
}

#[derive(Clone)]
pub struct ProtocolAnalyzer {
    // Timeout for service detection probes
    probe_timeout: Duration,
}

impl ProtocolAnalyzer {
    pub fn new() -> Self {
        ProtocolAnalyzer {
            probe_timeout: Duration::from_millis(500),
        }
    }

    /// Create a new analyzer with a custom probe timeout
    pub fn with_timeout(probe_timeout: Duration) -> Self {
        ProtocolAnalyzer { probe_timeout }
    }

    /// Detects the service running on the port via banner grabbing and probing.
    pub async fn detect_service(
        &self,
        stream: &mut TcpStream,
        protocol: Protocol,
    ) -> Result<Option<String>, NtraceError> {
        match protocol {
            Protocol::Tcp => {
                // Try to get initial banner without sending anything
                let service = self.try_banner_grab(stream).await?;
                if service.is_some() {
                    return Ok(service);
                }

                // If no banner, try active probing
                self.try_service_probes(stream).await
            }
            Protocol::Udp => {
                // UDP service detection based on port number and responses
                let port = match stream.peer_addr() {
                    Ok(addr) => addr.port(),
                    Err(_) => return Ok(None),
                };

                // Common UDP services by port
                let service = match port {
                    53 => Some("domain"),
                    67 | 68 => Some("dhcp"),
                    69 => Some("tftp"),
                    123 => Some("ntp"),
                    161 => Some("snmp"),
                    162 => Some("snmptrap"),
                    500 => Some("isakmp"),
                    514 => Some("syslog"),
                    520 => Some("rip"),
                    1194 => Some("openvpn"),
                    1900 => Some("upnp"),
                    5353 => Some("mdns"),
                    _ => None,
                };

                if let Some(svc) = service {
                    return Ok(Some(svc.to_string()));
                }

                // For unknown ports, check the well known services database
                let default_service = get_service_name(port);
                if default_service != "unknown" {
                    return Ok(Some(default_service.to_string()));
                }

                Ok(None)
            }
            Protocol::Icmp => {
                // ICMP doesn't have services in the traditional sense
                // but we can identify the ICMP type
                Ok(Some("icmp".to_string()))
            }
        }
    }

    /// Tries to grab a banner without sending any data
    async fn try_banner_grab(&self, stream: &mut TcpStream) -> Result<Option<String>, NtraceError> {
        let mut buffer = [0; 2048];

        // Set read timeout
        match timeout(self.probe_timeout, stream.read(&mut buffer)).await {
            Ok(Ok(n)) if n > 0 => {
                let banner = String::from_utf8_lossy(&buffer[..n]).into_owned();
                trace!("Received banner: {}", banner);

                // Check for known protocol signatures
                for (pattern, protocol_name) in PROTOCOL_SIGNATURES.iter() {
                    if banner.contains(pattern) {
                        return Ok(Some(protocol_name.to_string()));
                    }
                }

                // No known signature found
                Ok(None)
            }
            _ => Ok(None),
        }
    }

    /// Tries different service probes to identify the service
    async fn try_service_probes(
        &self,
        stream: &mut TcpStream,
    ) -> Result<Option<String>, NtraceError> {
        // Get the port number for well known service lookup
        let port = match stream.peer_addr() {
            Ok(addr) => addr.port(),
            Err(_) => return Ok(None),
        };

        // First check if this is a well known port
        let default_service = get_service_name(port);
        if default_service != "unknown" {
            debug!(
                "Detected service on port {}: {} (by port number)",
                port, default_service
            );
            return Ok(Some(default_service.to_string()));
        }

        // Try each probe
        for probe in SERVICE_PROBES.iter() {
            // Clone the stream for each probe attempt
            if let Ok(mut probe_stream) = TcpStream::connect(stream.peer_addr()?).await {
                debug!("Trying {} probe on port {}", probe.name, port);

                // Send the probe data
                if probe_stream.write_all(probe.probe_data).await.is_ok()
                    && probe_stream.flush().await.is_ok()
                {
                    let mut buffer = [0; 2048];
                    // Wait for response with timeout
                    match timeout(self.probe_timeout, probe_stream.read(&mut buffer)).await {
                        Ok(Ok(n)) if n > 0 => {
                            let response = String::from_utf8_lossy(&buffer[..n]);
                            if response.contains(probe.signature) {
                                debug!(
                                    "Detected service on port {}: {} (by probe)",
                                    port, probe.name
                                );
                                return Ok(Some(probe.name.to_string()));
                            }
                        }
                        _ => continue,
                    }
                }
            }
        }

        // No service detected
        Ok(None)
    }

    /// Analyzes protocol details to determine version and features
    pub async fn analyze_protocol(
        &self,
        stream: &TcpStream,
        protocol: Protocol,
    ) -> Result<Option<String>, NtraceError> {
        match protocol {
            Protocol::Tcp => {
                // Get the port number
                let port = match stream.peer_addr() {
                    Ok(addr) => addr.port(),
                    Err(_) => return Ok(None),
                };

                // Try to determine protocol details based on port
                match port {
                    80 | 8080 | 8000 => self.analyze_http(stream).await,
                    443 | 8443 => self.analyze_tls(stream).await,
                    22 => self.analyze_ssh(stream).await,
                    21 => self.analyze_ftp(stream).await,
                    25 | 587 => self.analyze_smtp(stream).await,
                    _ => Ok(None),
                }
            }
            Protocol::Udp => {
                // Get the port number
                let port = match stream.peer_addr() {
                    Ok(addr) => addr.port(),
                    Err(_) => return Ok(None),
                };

                // Analyze UDP protocol based on port
                match port {
                    53 => self.analyze_dns().await,
                    123 => self.analyze_ntp().await,
                    161 | 162 => self.analyze_snmp().await,
                    500 => self.analyze_ipsec().await,
                    1194 => self.analyze_openvpn().await,
                    _ => Ok(Some("UDP".to_string())),
                }
            }
            Protocol::Icmp => {
                // For ICMP, we just return the protocol type
                Ok(Some("ICMP".to_string()))
            }
        }
    }

    /// Analyze HTTP protocol details
    async fn analyze_http(&self, _stream: &TcpStream) -> Result<Option<String>, NtraceError> {
        // In a production version, this would connect and determine HTTP version, server type, etc.
        Ok(Some("HTTP".to_string()))
    }

    /// Analyze TLS/SSL protocol details
    async fn analyze_tls(&self, _stream: &TcpStream) -> Result<Option<String>, NtraceError> {
        // In a production version, this would determine TLS version, cipher suites, etc.
        Ok(Some("TLS/SSL".to_string()))
    }

    /// Analyze SSH protocol details
    async fn analyze_ssh(&self, _stream: &TcpStream) -> Result<Option<String>, NtraceError> {
        // In a production version, this would determine SSH version, supported auth methods, etc.
        Ok(Some("SSH".to_string()))
    }

    /// Analyze FTP protocol details
    async fn analyze_ftp(&self, _stream: &TcpStream) -> Result<Option<String>, NtraceError> {
        // In a production version, this would determine FTP version, supported commands, etc.
        Ok(Some("FTP".to_string()))
    }

    /// Analyze SMTP protocol details
    async fn analyze_smtp(&self, _stream: &TcpStream) -> Result<Option<String>, NtraceError> {
        // In a production version, this would determine SMTP version, supported extensions, etc.
        Ok(Some("SMTP".to_string()))
    }

    /// Analyze DNS protocol details (UDP)
    async fn analyze_dns(&self) -> Result<Option<String>, NtraceError> {
        // In a production version, this would determine DNS server type, version, etc.
        Ok(Some("DNS".to_string()))
    }

    /// Analyze NTP protocol details (UDP)
    async fn analyze_ntp(&self) -> Result<Option<String>, NtraceError> {
        // In a production version, this would determine NTP version, mode, etc.
        Ok(Some("NTP".to_string()))
    }

    /// Analyze SNMP protocol details (UDP)
    async fn analyze_snmp(&self) -> Result<Option<String>, NtraceError> {
        // In a production version, this would determine SNMP version, community strings, etc.
        Ok(Some("SNMP".to_string()))
    }

    /// Analyze IPsec/ISAKMP protocol details (UDP)
    async fn analyze_ipsec(&self) -> Result<Option<String>, NtraceError> {
        // In a production version, this would determine IPsec version, supported transforms, etc.
        Ok(Some("IPsec/ISAKMP".to_string()))
    }

    /// Analyze OpenVPN protocol details (UDP)
    async fn analyze_openvpn(&self) -> Result<Option<String>, NtraceError> {
        // In a production version, this would determine OpenVPN version, etc.
        Ok(Some("OpenVPN".to_string()))
    }
}
