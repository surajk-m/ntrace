use ntrace::protocol::Protocol;
use ntrace::scanner::{ScanConfig, Scanner};
use std::net::IpAddr;
use std::str::FromStr;
use tokio_test::block_on;

#[test]
fn test_scanner() {
    let config = ScanConfig {
        target: ntrace::protocol::Target::Ip(IpAddr::from_str("127.0.0.1").unwrap()),
        ports: vec![80, 443],
        timeout: std::time::Duration::from_secs(2),
        protocol: Protocol::Tcp,
        batch_size: 10,
        max_retries: 3,
        retry_delay: std::time::Duration::from_millis(500),
        fail_fast: false,
    };
    let scanner = Scanner::new(config);
    let results = block_on(scanner.scan()).unwrap();
    assert!(!results.is_empty());
}
