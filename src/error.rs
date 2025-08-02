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
}
