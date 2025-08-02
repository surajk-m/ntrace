/// ntrace: A fast and secure network port scanner and protocol analyzer.
///
/// This library provides functionality for scanning TCP/UDP ports, detecting services,
/// and analyzing protocols on a target host. It is designed for penetration testing
/// and security auditing.
pub mod cli;
pub mod error;
pub mod output;
pub mod protocol;
pub mod scanner;

pub use cli::Cli;
pub use error::NtraceError;
pub use output::ScanResult;
pub use protocol::Protocol;
pub use scanner::Scanner;
