# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2025-10-27

### What's Changed
- Major improvements and fixes to traceroute functionality:
  - Fix BSD/macOS socket structure compatibility 
  - Add parallel traceroute for faster results (up to 5x faster)
  - Add path MTU discovery
  - Add path asymmetry detection
  - Add detailed latency statistics (min, max, average, standard deviation)
  - Add packet loss calculation
  - Add support for custom source IP and port
  - Add support for ToS/DSCP values
  - Add adaptive timing for more reliable results
  - Add MPLS tunnel detection
  - Add support for starting from specific TTL (min_ttl)
  - Add support for interface selection

## [0.1.5] - 2025-08-05

### What's Changed
- Add automatic capability handling for ICMP and UDP traceroute
- No longer requires manual `sudo setcap` commands or sudo privileges
- Add build script for setting capabilities during installation

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