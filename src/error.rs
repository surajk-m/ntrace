use std::time::Duration;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum NtraceError {
    #[error("Network error: {0}")]
    Network(#[from] std::io::Error),

    #[error("Invalid IP address: {0}")]
    InvalidIp(String),

    #[error("Protocol analysis failed: {0}")]
    Protocol(String),

    #[error("Timeout occurred while scanning port {0}")]
    Timeout(u16),

    #[error("Connection refused on port {0}")]
    ConnectionRefused(u16),

    #[error("Connection reset on port {0}")]
    ConnectionReset(u16),

    #[error("Permission denied when accessing port {0}")]
    PermissionDenied(u16),

    #[error("DNS resolution failed: {0}")]
    DnsResolutionFailed(String),

    #[error("DNS error: {0}")]
    DnsError(String),

    #[error("Rate limit exceeded")]
    RateLimitExceeded,

    #[error("Maximum retries ({0}) exceeded")]
    MaxRetriesExceeded(usize),

    #[error("Invalid port range: {0}")]
    InvalidPortRange(String),

    #[error("UDP scan error on port {0}: {1}")]
    UdpScanError(u16, String),

    #[error("Service detection failed: {0}")]
    ServiceDetectionFailed(String),

    #[error("Scan interrupted")]
    ScanInterrupted,

    #[error("Failed to parse response from port {0}: {1}")]
    ResponseParseError(u16, String),

    #[error("TLS error: {0}")]
    TlsError(String),
}

/// Determines if an error is recoverable and worth retrying
pub fn is_recoverable_error(err: &NtraceError) -> bool {
    match err {
        NtraceError::Network(io_err) => {
            // Check if the IO error is recoverable
            matches!(
                io_err.kind(),
                std::io::ErrorKind::TimedOut
                    | std::io::ErrorKind::Interrupted
                    | std::io::ErrorKind::WouldBlock
            )
        }
        NtraceError::Timeout(_) => true,
        NtraceError::RateLimitExceeded => true,
        _ => false,
    }
}

/// Calculates backoff duration for retries
pub fn calculate_backoff(attempt: usize, base_delay: Duration) -> Duration {
    // Exponential backoff with jitter
    let max_delay = Duration::from_secs(30);
    let exp_backoff = base_delay.mul_f64(1.5f64.powi(attempt as i32));

    // Add jitter (±20%)
    let jitter_factor = 0.8 + (rand::random::<f64>() * 0.4);
    let with_jitter = exp_backoff.mul_f64(jitter_factor);

    // Cap at max delay
    std::cmp::min(with_jitter, max_delay)
}
