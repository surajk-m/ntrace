use once_cell::sync::Lazy;
use std::collections::HashMap;

/// A database of well known port numbers and their corresponding services.
pub static PORT_SERVICES: Lazy<HashMap<u16, &'static str>> = Lazy::new(|| {
    let mut map = HashMap::new();
    // Well-known ports (0-1023)
    map.insert(1, "tcpmux");
    map.insert(7, "echo");
    map.insert(20, "ftp-data");
    map.insert(21, "ftp");
    map.insert(22, "ssh");
    map.insert(23, "telnet");
    map.insert(25, "smtp");
    map.insert(53, "domain");
    map.insert(80, "http");
    map.insert(110, "pop3");
    map.insert(111, "rpcbind");
    map.insert(135, "msrpc");
    map.insert(139, "netbios-ssn");
    map.insert(143, "imap");
    map.insert(443, "https");
    map.insert(445, "microsoft-ds");
    map.insert(993, "imaps");
    map.insert(995, "pop3s");
    map.insert(3306, "mysql");
    map.insert(3389, "ms-wbt-server");
    map.insert(5432, "postgresql");
    map.insert(8080, "http-proxy");
    map.insert(8443, "https-alt");

    // Add more services
    map
});

/// Get the service name for a given port number.
pub fn get_service_name(port: u16) -> &'static str {
    PORT_SERVICES.get(&port).copied().unwrap_or("unknown")
}

/// Common protocol detection patterns
pub static PROTOCOL_SIGNATURES: Lazy<Vec<(String, &'static str)>> = Lazy::new(|| {
    vec![
        // HTTP signatures
        ("HTTP/1.1".to_string(), "HTTP/1.1"),
        ("HTTP/2.0".to_string(), "HTTP/2.0"),
        ("HTTP/1.0".to_string(), "HTTP/1.0"),
        // SSH signatures
        ("SSH-2.0".to_string(), "SSH v2"),
        ("SSH-1.99".to_string(), "SSH v2 (compatibility)"),
        ("SSH-1.5".to_string(), "SSH v1.5"),
        // SMTP signatures
        ("220 ".to_string(), "SMTP"),
        ("220-".to_string(), "SMTP"),
        // FTP signatures
        ("220 FTP".to_string(), "FTP"),
        // TLS/SSL signatures
        ("\x16\x03".to_string(), "TLS/SSL"),
        // MySQL
        ("\x0a\x00\x00\x00\x0a".to_string(), "MySQL"),
        // PostgreSQL
        ("SFTP".to_string(), "SFTP"),
        // Redis
        ("-ERR".to_string(), "Redis"),
        ("+PONG".to_string(), "Redis"),
        // MongoDB
        ("\x00\x00\x00\x00\x00\x00\x00\x00".to_string(), "MongoDB"),
        // Elasticsearch
        ("{\"error\":".to_string(), "Elasticsearch"),
        // Add more signatures
    ]
});

/// Service probes for active service detection
#[derive(Debug, Clone)]
pub struct ServiceProbe {
    pub name: &'static str,
    pub probe_data: &'static [u8],
    pub signature: &'static str,
}

/// List of probes for service detection
pub static SERVICE_PROBES: Lazy<Vec<ServiceProbe>> = Lazy::new(|| {
    vec![
        ServiceProbe {
            name: "HTTP",
            probe_data: b"HEAD / HTTP/1.0\r\n\r\n",
            signature: "HTTP",
        },
        ServiceProbe {
            name: "SSH",
            probe_data: b"SSH-2.0-ntrace\r\n",
            signature: "SSH",
        },
        ServiceProbe {
            name: "SMTP",
            probe_data: b"EHLO ntrace\r\n",
            signature: "220",
        },
        ServiceProbe {
            name: "FTP",
            probe_data: b"HELP\r\n",
            signature: "220",
        },
        ServiceProbe {
            name: "POP3",
            probe_data: b"CAPA\r\n",
            signature: "+OK",
        },
        ServiceProbe {
            name: "IMAP",
            probe_data: b"A1 CAPABILITY\r\n",
            signature: "* CAPABILITY",
        },
        // Add more probes
    ]
});
