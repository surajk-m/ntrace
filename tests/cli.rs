use clap::Parser;
use ntrace::cli::Cli;

#[test]
fn test_cli_parsing() {
    // Test basic CLI parsing
    let args = vec!["ntrace", "-H", "192.168.1.1"];
    let cli = Cli::parse_from(args);

    assert_eq!(cli.host, "192.168.1.1");
    assert_eq!(cli.ports, "1-1000");
    assert_eq!(cli.protocol, "tcp");
    assert_eq!(cli.timeout, 2.0);
    assert_eq!(cli.batch_size, 100);
    assert_eq!(cli.service_detection, true);
    assert_eq!(cli.verbose, false);
    assert_eq!(cli.rate_limit, 1000);
    assert_eq!(cli.skip_discovery, false);
    assert_eq!(cli.aggressive, false);
}

#[test]
fn test_cli_with_options() {
    // Test CLI parsing with options
    let args = vec![
        "ntrace",
        "-H",
        "example.com",
        "-p",
        "80,443",
        "-P",
        "tcp",
        "--timeout",
        "5.0",
        "--batch-size",
        "50",
        "-v",
        "--skip-discovery",
    ];
    let cli = Cli::parse_from(args);

    assert_eq!(cli.host, "example.com");
    assert_eq!(cli.ports, "80,443");
    assert_eq!(cli.protocol, "tcp");
    assert_eq!(cli.timeout, 5.0);
    assert_eq!(cli.batch_size, 50);
    assert_eq!(cli.verbose, true);
    assert_eq!(cli.skip_discovery, true);
}

#[test]
fn test_port_parsing() {
    // Test port range parsing
    let args = vec!["ntrace", "-H", "192.168.1.1", "-p", "1-100"];
    let cli = Cli::parse_from(args);
    let ports = cli.parse_ports().unwrap();

    assert_eq!(ports.len(), 100);
    assert_eq!(ports[0], 1);
    assert_eq!(ports[99], 100);

    // Test comma separated ports
    let args = vec!["ntrace", "-H", "192.168.1.1", "-p", "22,80,443"];
    let cli = Cli::parse_from(args);
    let ports = cli.parse_ports().unwrap();

    assert_eq!(ports.len(), 3);
    assert_eq!(ports[0], 22);
    assert_eq!(ports[1], 80);
    assert_eq!(ports[2], 443);

    // Test special keywords
    let args = vec!["ntrace", "-H", "192.168.1.1", "-p", "common"];
    let cli = Cli::parse_from(args);
    let ports = cli.parse_ports().unwrap();

    assert!(ports.contains(&22));
    assert!(ports.contains(&80));
    assert!(ports.contains(&443));
}
