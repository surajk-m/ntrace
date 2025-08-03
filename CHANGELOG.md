# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.4] - 2025-08-04

### What's Changed
- Traceroute functionality with support for multiple protocols:
  - ICMP traceroute (requires sudo/root privileges)
  - TCP traceroute 
  - UDP traceroute
- Route path visualization with hop by hop analysis
- Hostname resolution for each hop in the path
- Multiple output formats for traceroute results (text, JSON)

## [0.1.0] - 2025-08-02

### Added
- Initial release of ntrace
- Advanced port scanning with TCP protocol support
- Service detection for common protocols
- Support for scanning IP addresses and domain names
- Flexible port selection (specific ports, ranges, or predefined groups)
- Multiple output formats (JSON and CSV)
- Command line interface with various configuration options
- Library API for integration with other Rust projects