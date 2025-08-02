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
    map.insert(67, "dhcp-server");
    map.insert(68, "dhcp-client");
    map.insert(69, "tftp");
    map.insert(79, "finger");
    map.insert(80, "http");
    map.insert(88, "kerberos");
    map.insert(110, "pop3");
    map.insert(111, "rpcbind");
    map.insert(119, "nntp");
    map.insert(123, "ntp");
    map.insert(135, "msrpc");
    map.insert(137, "netbios-ns");
    map.insert(138, "netbios-dgm");
    map.insert(139, "netbios-ssn");
    map.insert(143, "imap");
    map.insert(161, "snmp");
    map.insert(162, "snmptrap");
    map.insert(179, "bgp");
    map.insert(194, "irc");
    map.insert(389, "ldap");
    map.insert(443, "https");
    map.insert(445, "microsoft-ds");
    map.insert(465, "smtps");
    map.insert(554, "rtsp");
    map.insert(500, "isakmp");
    map.insert(514, "syslog");
    map.insert(520, "rip");
    map.insert(546, "dhcpv6-client");
    map.insert(547, "dhcpv6-server");
    map.insert(587, "submission");
    map.insert(631, "ipp");
    map.insert(636, "ldaps");
    map.insert(993, "imaps");
    map.insert(995, "pop3s");

    // Registered ports (1024-49151)
    map.insert(1080, "socks");
    map.insert(1194, "openvpn");
    map.insert(1433, "ms-sql-s");
    map.insert(1434, "ms-sql-m");
    map.insert(1521, "oracle");
    map.insert(1723, "pptp");
    map.insert(1812, "radius");
    map.insert(1813, "radius-acct");
    map.insert(2049, "nfs");
    map.insert(2082, "cpanel");
    map.insert(2083, "cpanel-ssl");
    map.insert(2086, "whm");
    map.insert(2087, "whm-ssl");
    map.insert(2181, "zookeeper");
    map.insert(2375, "docker");
    map.insert(2376, "docker-ssl");
    map.insert(3128, "squid");
    map.insert(3306, "mysql");
    map.insert(3389, "ms-wbt-server");
    map.insert(3690, "svn");
    map.insert(4369, "epmd");
    map.insert(5000, "upnp");
    map.insert(5222, "xmpp-client");
    map.insert(5269, "xmpp-server");
    map.insert(5353, "mdns");
    map.insert(5432, "postgresql");
    map.insert(5555, "freeciv");
    map.insert(5672, "amqp");
    map.insert(5900, "vnc");
    map.insert(5984, "couchdb");
    map.insert(6379, "redis");
    map.insert(6443, "kubernetes");
    map.insert(6667, "irc");
    map.insert(8000, "http-alt");
    map.insert(8080, "http-proxy");
    map.insert(8086, "influxdb");
    map.insert(8088, "radan-http");
    map.insert(8333, "bitcoin");
    map.insert(8443, "https-alt");
    map.insert(8888, "http-alt");
    map.insert(9000, "cslistener");
    map.insert(9042, "cassandra");
    map.insert(9092, "kafka");
    map.insert(9200, "elasticsearch");
    map.insert(9300, "elasticsearch-cluster");
    map.insert(9418, "git");
    map.insert(10000, "webmin");
    map.insert(11211, "memcached");
    map.insert(27017, "mongodb");
    map.insert(27018, "mongodb-shard");
    map.insert(27019, "mongodb-config");
    map.insert(28017, "mongodb-web");
    map.insert(49152, "dynamic-first");
    map.insert(49153, "dynamic");
    map.insert(49154, "dynamic");
    map.insert(49155, "dynamic");
    map.insert(49156, "dynamic");
    map.insert(49157, "dynamic");
    map.insert(49158, "dynamic");
    map.insert(49159, "dynamic");
    map.insert(49160, "dynamic");
    map.insert(49161, "dynamic");
    map.insert(49162, "dynamic");
    map.insert(49163, "dynamic");
    map.insert(49164, "dynamic");
    map.insert(49165, "dynamic");
    map.insert(49166, "dynamic");
    map.insert(49167, "dynamic");
    map.insert(49168, "dynamic");
    map.insert(49169, "dynamic");
    map.insert(49170, "dynamic");
    map.insert(49171, "dynamic");
    map.insert(49172, "dynamic");
    map.insert(49173, "dynamic");
    map.insert(49174, "dynamic");
    map.insert(49175, "dynamic");
    map.insert(49176, "dynamic");
    map.insert(49177, "dynamic");
    map.insert(49178, "dynamic");
    map.insert(49179, "dynamic");
    map.insert(49180, "dynamic");
    map.insert(49181, "dynamic");
    map.insert(49182, "dynamic");
    map.insert(49183, "dynamic");
    map.insert(49184, "dynamic");
    map.insert(49185, "dynamic");
    map.insert(49186, "dynamic");
    map.insert(49187, "dynamic");
    map.insert(49188, "dynamic");
    map.insert(49189, "dynamic");
    map.insert(49190, "dynamic");
    map.insert(49191, "dynamic");
    map.insert(49192, "dynamic");
    map.insert(49193, "dynamic");
    map.insert(49194, "dynamic");
    map.insert(49195, "dynamic");
    map.insert(49196, "dynamic");
    map.insert(49197, "dynamic");
    map.insert(49198, "dynamic");
    map.insert(49199, "dynamic");
    map.insert(49200, "dynamic");
    map.insert(65535, "dynamic-last");

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
        ("<html".to_string(), "HTTP"),
        ("<HTML".to_string(), "HTTP"),
        ("<!DOCTYPE html".to_string(), "HTTP"),
        ("<!doctype html".to_string(), "HTTP"),
        // SSH signatures
        ("SSH-2.0".to_string(), "SSH v2"),
        ("SSH-1.99".to_string(), "SSH v2 (compatibility)"),
        ("SSH-1.5".to_string(), "SSH v1.5"),
        // SMTP signatures
        ("220 ".to_string(), "SMTP"),
        ("220-".to_string(), "SMTP"),
        ("ESMTP".to_string(), "SMTP"),
        ("Postfix".to_string(), "SMTP (Postfix)"),
        ("Sendmail".to_string(), "SMTP (Sendmail)"),
        ("Exim".to_string(), "SMTP (Exim)"),
        // FTP signatures
        ("220 FTP".to_string(), "FTP"),
        ("220 FileZilla".to_string(), "FTP (FileZilla)"),
        ("220 ProFTPD".to_string(), "FTP (ProFTPD)"),
        ("220 Pure-FTPd".to_string(), "FTP (Pure-FTPd)"),
        ("220 vsFTPd".to_string(), "FTP (vsFTPd)"),
        // TLS/SSL signatures
        ("\x16\x03\x01".to_string(), "TLS/SSL (TLS 1.0)"),
        ("\x16\x03\x02".to_string(), "TLS/SSL (TLS 1.1)"),
        ("\x16\x03\x03".to_string(), "TLS/SSL (TLS 1.2)"),
        ("\x16\x03\x04".to_string(), "TLS/SSL (TLS 1.3)"),
        // Database signatures
        ("\x0a\x00\x00\x00\x0a".to_string(), "MySQL"),
        ("\x4e\x00\x00\x00".to_string(), "MySQL"),
        ("\x45\x00\x00\x00\x0a".to_string(), "MySQL"),
        ("PostgreSQL".to_string(), "PostgreSQL"),
        ("PGSQL".to_string(), "PostgreSQL"),
        // File transfer protocols
        ("SFTP".to_string(), "SFTP"),
        ("\x00\x00\x00\x13sftp-server".to_string(), "SFTP"),
        (
            "150 Opening BINARY mode data connection".to_string(),
            "FTP-Data",
        ),
        // NoSQL databases
        ("-ERR".to_string(), "Redis"),
        ("+PONG".to_string(), "Redis"),
        ("+OK".to_string(), "Redis"),
        ("\x00\x00\x00\x00\x00\x00\x00\x00".to_string(), "MongoDB"),
        ("MongoDB".to_string(), "MongoDB"),
        ("{\"error\":".to_string(), "Elasticsearch"),
        ("CouchDB".to_string(), "CouchDB"),
        ("couchdb".to_string(), "CouchDB"),
        // Message queues
        ("AMQP".to_string(), "AMQP"),
        ("RabbitMQ".to_string(), "AMQP (RabbitMQ)"),
        ("Kafka".to_string(), "Kafka"),
        // Remote access protocols
        ("RFB 003.".to_string(), "VNC"),
        ("RDP".to_string(), "RDP"),
        // Web servers
        ("Server: Apache".to_string(), "HTTP (Apache)"),
        ("Server: nginx".to_string(), "HTTP (Nginx)"),
        ("Server: Microsoft-IIS".to_string(), "HTTP (IIS)"),
        ("Server: lighttpd".to_string(), "HTTP (Lighttpd)"),
        ("Server: Caddy".to_string(), "HTTP (Caddy)"),
        // Mail protocols
        ("+OK POP3".to_string(), "POP3"),
        ("* OK IMAP4".to_string(), "IMAP"),
        ("* OK Dovecot".to_string(), "IMAP (Dovecot)"),
        // Directory services
        ("LDAP".to_string(), "LDAP"),
        ("OpenLDAP".to_string(), "LDAP (OpenLDAP)"),
        ("Active Directory".to_string(), "LDAP (Active Directory)"),
        // Version control
        ("git".to_string(), "Git"),
        ("SVN".to_string(), "Subversion"),
        // DNS
        ("BIND".to_string(), "DNS (BIND)"),
        ("DiG".to_string(), "DNS"),
        // Proxy servers
        ("Squid".to_string(), "Squid Proxy"),
        ("HAProxy".to_string(), "HAProxy"),
        ("nginx-proxy".to_string(), "Nginx Proxy"),
        // Telnet
        ("telnet".to_string(), "Telnet"),
        // Container platforms
        ("Docker".to_string(), "Docker"),
        ("Kubernetes".to_string(), "Kubernetes"),
        // Monitoring
        ("Prometheus".to_string(), "Prometheus"),
        ("Grafana".to_string(), "Grafana"),
        ("Zabbix".to_string(), "Zabbix"),
        ("Nagios".to_string(), "Nagios"),
        // Network Time Protocol
        ("NTP".to_string(), "NTP"),
        // DHCP
        ("DHCP".to_string(), "DHCP"),
        // SNMP
        ("SNMP".to_string(), "SNMP"),
        // Distributed systems
        ("ZooKeeper".to_string(), "ZooKeeper"),
        ("etcd".to_string(), "etcd"),
        ("Consul".to_string(), "Consul"),
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
        // Web protocols
        ServiceProbe {
            name: "HTTP",
            probe_data: b"HEAD / HTTP/1.0\r\n\r\n",
            signature: "HTTP",
        },
        ServiceProbe {
            name: "HTTP",
            probe_data: b"GET / HTTP/1.0\r\n\r\n",
            signature: "HTTP",
        },
        ServiceProbe {
            name: "HTTP",
            probe_data: b"OPTIONS * HTTP/1.0\r\n\r\n",
            signature: "HTTP",
        },
        // Secure Shell
        ServiceProbe {
            name: "SSH",
            probe_data: b"SSH-2.0-ntrace\r\n",
            signature: "SSH",
        },
        // Mail protocols
        ServiceProbe {
            name: "SMTP",
            probe_data: b"EHLO ntrace\r\n",
            signature: "220",
        },
        ServiceProbe {
            name: "SMTP",
            probe_data: b"HELO ntrace\r\n",
            signature: "250",
        },
        ServiceProbe {
            name: "POP3",
            probe_data: b"CAPA\r\n",
            signature: "+OK",
        },
        ServiceProbe {
            name: "POP3",
            probe_data: b"QUIT\r\n",
            signature: "+OK",
        },
        ServiceProbe {
            name: "IMAP",
            probe_data: b"A1 CAPABILITY\r\n",
            signature: "* CAPABILITY",
        },
        ServiceProbe {
            name: "IMAP",
            probe_data: b"A2 LOGOUT\r\n",
            signature: "* BYE",
        },
        // File transfer
        ServiceProbe {
            name: "FTP",
            probe_data: b"HELP\r\n",
            signature: "214",
        },
        ServiceProbe {
            name: "FTP",
            probe_data: b"SYST\r\n",
            signature: "215",
        },
        ServiceProbe {
            name: "SFTP",
            probe_data: b"SSH-2.0-ntrace\r\n",
            signature: "SSH",
        },
        // Databases
        ServiceProbe {
            name: "MySQL",
            // MySQL protocol handshake
            probe_data: &[0x00, 0x00, 0x01, 0x85, 0x04, 0x00, 0x00, 0x00, 0x00],
            signature: "mysql",
        },
        ServiceProbe {
            name: "PostgreSQL",
            // PostgreSQL protocol handshake
            probe_data: &[0x00, 0x00, 0x00, 0x08, 0x04, 0xd2, 0x16, 0x2f],
            signature: "PostgreSQL",
        },
        ServiceProbe {
            name: "Redis",
            probe_data: b"PING\r\n",
            signature: "PONG",
        },
        ServiceProbe {
            name: "Redis",
            probe_data: b"INFO\r\n",
            signature: "redis_version",
        },
        ServiceProbe {
            name: "MongoDB",
            // MongoDB ismaster command
            probe_data: &[
                0x3a, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xd4, 0x07,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x61, 0x64, 0x6d, 0x69, 0x6e, 0x2e, 0x24, 0x63,
                0x6d, 0x64, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0x13, 0x00, 0x00,
                0x00, 0x10, 0x69, 0x73, 0x6d, 0x61, 0x73, 0x74, 0x65, 0x72, 0x00, 0x01, 0x00, 0x00,
                0x00, 0x00,
            ],
            signature: "ismaster",
        },
        // Remote access
        ServiceProbe {
            name: "Telnet",
            probe_data: b"\xff\xfb\x01\xff\xfb\x03\xff\xfd\x18\xff\xfd\x1f",
            signature: "Telnet",
        },
        ServiceProbe {
            name: "RDP",
            // RDP connection request
            probe_data: &[
                0x03, 0x00, 0x00, 0x13, 0x0e, 0xe0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x08,
                0x00, 0x03, 0x00, 0x00, 0x00,
            ],
            signature: "RDP",
        },
        ServiceProbe {
            name: "VNC",
            probe_data: b"RFB 003.008\n",
            signature: "RFB",
        },
        // Directory services
        ServiceProbe {
            name: "LDAP",
            // LDAP bind request
            probe_data: &[
                0x30, 0x0c, 0x02, 0x01, 0x01, 0x60, 0x07, 0x02, 0x01, 0x03, 0x04, 0x00, 0x80, 0x00,
            ],
            signature: "LDAP",
        },
        // DNS
        ServiceProbe {
            name: "DNS",
            // DNS standard query for www.example.com
            probe_data: &[
                0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x77,
                0x77, 0x77, 0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d,
                0x00, 0x00, 0x01, 0x00, 0x01,
            ],
            signature: "DNS",
        },
        // SNMP
        ServiceProbe {
            name: "SNMP",
            // SNMP get request
            probe_data: &[
                0x30, 0x26, 0x02, 0x01, 0x01, 0x04, 0x06, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63, 0xa0,
                0x19, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x30, 0x0e, 0x30, 0x0c,
                0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00, 0x05, 0x00,
            ],
            signature: "SNMP",
        },
        // NTP
        ServiceProbe {
            name: "NTP",
            // NTP version 3 request
            probe_data: &[
                0x1b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            ],
            signature: "NTP",
        },
        // Message queues
        ServiceProbe {
            name: "AMQP",
            // AMQP protocol header
            probe_data: b"AMQP\x00\x00\x09\x01",
            signature: "AMQP",
        },
        // Memcached
        ServiceProbe {
            name: "Memcached",
            probe_data: b"stats\r\n",
            signature: "STAT",
        },
        // Elasticsearch
        ServiceProbe {
            name: "Elasticsearch",
            probe_data: b"GET / HTTP/1.0\r\nUser-Agent: ntrace\r\n\r\n",
            signature: "elasticsearch",
        },
        // Kubernetes API
        ServiceProbe {
            name: "Kubernetes",
            probe_data: b"GET /api HTTP/1.0\r\nUser-Agent: ntrace\r\n\r\n",
            signature: "kubernetes",
        },
        // Docker API
        ServiceProbe {
            name: "Docker",
            probe_data: b"GET /version HTTP/1.0\r\nUser-Agent: ntrace\r\n\r\n",
            signature: "Docker",
        },
    ]
});
