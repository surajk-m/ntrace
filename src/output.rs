use crate::scanner::PortResult;
use crate::traceroute::TraceResult;
use colored::Colorize;
use serde::Serialize;
use std::fs::File;
use std::io::Write;
use std::time::Duration;

#[derive(Debug, Serialize)]
pub struct ScanResult {
    pub host: String,
    pub results: Vec<PortResult>,
    pub scan_duration: Option<Duration>,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

impl ScanResult {
    pub fn new(host: String, results: Vec<PortResult>, scan_duration: Option<Duration>) -> Self {
        ScanResult {
            host,
            results,
            scan_duration,
            timestamp: chrono::Utc::now(),
        }
    }

    pub fn to_json_file(&self, path: &str) -> Result<(), std::io::Error> {
        let json = serde_json::to_string_pretty(self)?;
        let mut file = File::create(path)?;
        file.write_all(json.as_bytes())?;
        println!("Scan results saved to {}", path);
        Ok(())
    }

    pub fn to_csv_file(&self, path: &str) -> Result<(), std::io::Error> {
        let mut wtr = csv::Writer::from_path(path)?;

        // Write header
        wtr.write_record(&[
            "Port",
            "Status",
            "Service",
            "Protocol",
            "Latency (ms)",
            "Scan Time",
        ])?;

        // Write data
        for result in &self.results {
            let is_open_filtered = result
                .protocol_info
                .as_ref()
                .map_or(false, |p| p.contains("open|filtered"));

            let status = if result.is_open {
                "Open"
            } else if is_open_filtered {
                "Open|Filtered"
            } else {
                "Closed"
            };
            let unknown = "Unknown".to_string();
            let service = result.service.as_ref().unwrap_or(&unknown);
            let none_str = "None".to_string();
            let protocol = result.protocol_info.as_ref().unwrap_or(&none_str);
            let latency = match result.latency {
                Some(duration) => format!("{:.2}", duration.as_secs_f64() * 1000.0),
                None => "-".to_string(),
            };
            let scan_time = result.scan_time.to_rfc3339();

            wtr.write_record(&[
                result.port.to_string(),
                status.to_string(),
                service.to_string(),
                protocol.to_string(),
                latency,
                scan_time,
            ])?;
        }

        wtr.flush()?;
        println!("Scan results saved to {}", path);
        Ok(())
    }

    pub fn print(&self) {
        // Print header
        let box_width = 70;
        println!(
            "\n{}",
            format!("╔{}╗", "═".repeat(box_width - 2)).blue().bold()
        );
        println!(
            "{} {} {}",
            "║".blue().bold(),
            " SCAN RESULTS ".on_bright_blue().white().bold(),
            "║".blue().bold()
        );
        println!(
            "{}",
            format!("╠{}╣", "═".repeat(box_width - 2)).blue().bold()
        );

        // Target info in a nice format
        println!(
            "{} {}: {} {}",
            "║".blue().bold(),
            "Target".bold(),
            self.host.bright_white(),
            "║".blue().bold()
        );

        if let Some(duration) = self.scan_duration {
            println!(
                "{} {}: {:.2} seconds {} ",
                "║".blue().bold(),
                "Duration".bold(),
                duration.as_secs_f64(),
                "║".blue().bold()
            );
        }

        println!(
            "{} {}: {} {}",
            "║".blue().bold(),
            "Timestamp".bold(),
            self.timestamp.to_rfc3339(),
            "║".blue().bold()
        );

        println!(
            "{} {}: {} {}",
            "║".blue().bold(),
            "Ports Scanned".bold(),
            self.results.len().to_string().bright_white(),
            "║".blue().bold()
        );

        // Count open ports and handle UDP open|filtered ports
        let open_ports = self.results.iter().filter(|r| r.is_open).count();
        let open_filtered_ports = self
            .results
            .iter()
            .filter(|r| {
                !r.is_open
                    && r.protocol_info
                        .as_ref()
                        .map_or(false, |p| p.contains("open|filtered"))
            })
            .count();

        println!(
            "{} {}: {} {}",
            "║".blue().bold(),
            "Open Ports".bold(),
            open_ports.to_string().green().bold(),
            "║".blue().bold()
        );

        if open_filtered_ports > 0 {
            println!(
                "{} {}: {} {}",
                "║".blue().bold(),
                "Open|Filtered Ports".bold(),
                open_filtered_ports.to_string().yellow().bold(),
                "║".blue().bold()
            );
        }

        println!(
            "{}",
            format!("╠{}╣", "═".repeat(box_width - 2)).blue().bold()
        );

        // Print table header
        println!(
            "{} {:6} {:10} {:20} {:20} {:10} {}",
            "║".blue().bold(),
            "PORT".bold(),
            "STATE".bold(),
            "SERVICE".bold(),
            "PROTOCOL".bold(),
            "LATENCY".bold(),
            "║".blue().bold()
        );

        println!(
            "{}",
            format!("╠{}╣", "═".repeat(box_width - 2)).blue().bold()
        );

        // Print results
        for result in &self.results {
            // Show open ports and UDP open|filtered ports
            let is_open_filtered = result
                .protocol_info
                .as_ref()
                .map_or(false, |p| p.contains("open|filtered"));

            if !result.is_open && !is_open_filtered {
                // Skip closed ports in the detailed output
                continue;
            }

            let state = if result.is_open {
                "open".green().bold()
            } else if is_open_filtered {
                "open|filtered".yellow().bold()
            } else {
                "closed".red().bold()
            };

            let unknown = "unknown".to_string();
            let service = result.service.as_ref().unwrap_or(&unknown);
            let dash = "-".to_string();
            let protocol = result.protocol_info.as_ref().unwrap_or(&dash);

            let latency = match result.latency {
                Some(duration) => format!("{:.2}ms", duration.as_secs_f64() * 1000.0),
                None => "-".to_string(),
            };

            // Display port number clearly without background color
            let port_display = result.port.to_string().bold();

            println!(
                "{} {:^6} {:10} {:20} {:20} {:10} {}",
                "║".blue().bold(),
                port_display,
                state,
                service.bright_white(),
                protocol,
                latency,
                "║".blue().bold()
            );
        }

        // Close the box
        println!(
            "{}",
            format!("╚{}╝", "═".repeat(box_width - 2)).blue().bold()
        );
        println!();
    }

    /// Print a verbose version including closed ports
    pub fn print_verbose(&self) {
        // Print header
        let box_width = 70;
        println!(
            "\n{}",
            format!("╔{}╗", "═".repeat(box_width - 2)).blue().bold()
        );
        println!(
            "{} {} {}",
            "║".blue().bold(),
            " DETAILED SCAN RESULTS ".on_bright_blue().white().bold(),
            "║".blue().bold()
        );
        println!(
            "{}",
            format!("╠{}╣", "═".repeat(box_width - 2)).blue().bold()
        );

        // Target info
        println!(
            "{} {}: {} {}",
            "║".blue().bold(),
            "Target".bold(),
            self.host.bright_white(),
            "║".blue().bold()
        );

        if let Some(duration) = self.scan_duration {
            println!(
                "{} {}: {:.2} seconds {} ",
                "║".blue().bold(),
                "Duration".bold(),
                duration.as_secs_f64(),
                "║".blue().bold()
            );
        }

        println!(
            "{} {}: {} {}",
            "║".blue().bold(),
            "Timestamp".bold(),
            self.timestamp.to_rfc3339(),
            "║".blue().bold()
        );

        println!(
            "{} {}: {} {}",
            "║".blue().bold(),
            "Ports Scanned".bold(),
            self.results.len().to_string().bright_white(),
            "║".blue().bold()
        );

        // Count open ports and handle UDP open|filtered ports
        let open_ports = self.results.iter().filter(|r| r.is_open).count();
        let open_filtered_ports = self
            .results
            .iter()
            .filter(|r| {
                !r.is_open
                    && r.protocol_info
                        .as_ref()
                        .map_or(false, |p| p.contains("open|filtered"))
            })
            .count();
        let closed_ports = self.results.len() - open_ports - open_filtered_ports;

        println!(
            "{} {}: {} {}",
            "║".blue().bold(),
            "Open Ports".bold(),
            open_ports.to_string().green().bold(),
            "║".blue().bold()
        );

        if open_filtered_ports > 0 {
            println!(
                "{} {}: {} {}",
                "║".blue().bold(),
                "Open|Filtered Ports".bold(),
                open_filtered_ports.to_string().yellow().bold(),
                "║".blue().bold()
            );
        }

        println!(
            "{} {}: {} {}",
            "║".blue().bold(),
            "Closed Ports".bold(),
            closed_ports.to_string().red().bold(),
            "║".blue().bold()
        );

        println!(
            "{}",
            format!("╠{}╣", "═".repeat(box_width - 2)).blue().bold()
        );

        // Print table header with fancy formatting
        println!(
            "{} {:6} {:10} {:20} {:20} {:10} {}",
            "║".blue().bold(),
            "PORT".bold(),
            "STATE".bold(),
            "SERVICE".bold(),
            "PROTOCOL".bold(),
            "LATENCY".bold(),
            "║".blue().bold()
        );

        println!(
            "{}",
            format!("╠{}╣", "═".repeat(box_width - 2)).blue().bold()
        );

        // Print all results
        for result in &self.results {
            let is_open_filtered = result
                .protocol_info
                .as_ref()
                .map_or(false, |p| p.contains("open|filtered"));

            let state = if result.is_open {
                "open".green().bold()
            } else if is_open_filtered {
                "open|filtered".yellow().bold()
            } else {
                "closed".red().bold()
            };

            let unknown = "unknown".to_string();
            let service = result.service.as_ref().unwrap_or(&unknown);
            let dash = "-".to_string();
            let protocol = result.protocol_info.as_ref().unwrap_or(&dash);

            let latency = match result.latency {
                Some(duration) => format!("{:.2}ms", duration.as_secs_f64() * 1000.0),
                None => "-".to_string(),
            };

            // Apply custom styling based on port state
            let port_display = if result.is_open {
                result.port.to_string().on_green().black().bold()
            } else if is_open_filtered {
                result.port.to_string().on_yellow().black().bold()
            } else {
                result.port.to_string().on_red().black()
            };

            // Apply custom styling to service based on state
            let service_display = if result.is_open {
                service.bright_white()
            } else if is_open_filtered {
                service.bright_white()
            } else {
                service.normal()
            };

            println!(
                "{} {:^6} {:10} {:20} {:20} {:10} {}",
                "║".blue().bold(),
                port_display,
                state,
                service_display,
                protocol,
                latency,
                "║".blue().bold()
            );
        }

        println!(
            "{}",
            format!("╚{}╝", "═".repeat(box_width - 2)).blue().bold()
        );
        println!();
    }
}

/// Extension methods for TraceResult to handle output formatting
pub trait TraceResultOutput {
    /// Print the trace result in standard format
    fn print(&self);

    /// Print the trace result in table format
    fn print_table(&self);

    /// Print the trace result with route path information
    fn print_route_path(&self);

    /// Save the trace result to a JSON file
    fn to_json_file(&self, path: &str) -> Result<(), std::io::Error>;

    /// Save the trace result to a text file
    fn to_text_file(&self, path: &str) -> Result<(), std::io::Error>;
}

impl TraceResultOutput for TraceResult {
    fn print(&self) {
        // Classic traceroute output format
        let max_hops = self.hops.last().map_or(0, |hop| hop.hop);

        // Print header
        println!(
            "traceroute to {}, {} hops max",
            self.target.bright_white(),
            max_hops
        );

        // Print hops
        for hop in &self.hops {
            // Format hop number with 3 spaces
            let hop_num = format!("{:2}", hop.hop);

            // Get the IP or asterisk for timeout
            let ip_display = match &hop.ip {
                Some(ip) => {
                    // If we have a hostname, display it instead of IP
                    if let Some(hostname) = &hop.hostname {
                        hostname.bright_green()
                    } else {
                        ip.bright_white()
                    }
                }
                None => "*".red().bold(),
            };

            // Format latencies
            let latencies = hop
                .latencies
                .iter()
                .map(|latency| match latency {
                    Some(duration) => format!("{:.3}ms", duration.as_secs_f64() * 1000.0).normal(),
                    None => "*".red().bold(),
                })
                .collect::<Vec<_>>();

            // Ensure we have exactly 3 latencies (padding with * if needed)
            let mut formatted_latencies = Vec::new();
            for i in 0..3 {
                if i < latencies.len() {
                    formatted_latencies.push(latencies[i].clone());
                } else {
                    formatted_latencies.push("*".red().bold());
                }
            }

            // Print the line
            println!(
                "  {}   {}  {}  {}  {}",
                hop_num.bold(),
                ip_display,
                formatted_latencies[0],
                formatted_latencies[1],
                formatted_latencies[2]
            );
        }

        println!();
    }

    fn print_table(&self) {
        let box_width = 80;
        println!(
            "\n{}",
            format!("╔{}╗", "═".repeat(box_width - 2)).blue().bold()
        );
        println!(
            "{} {} {}",
            "║".blue().bold(),
            " TRACEROUTE TABLE ".on_bright_blue().white().bold(),
            "║".blue().bold()
        );
        println!(
            "{}",
            format!("╠{}╣", "═".repeat(box_width - 2)).blue().bold()
        );

        // Target info
        println!(
            "{} {}: {} | {}: {} | {}: {}{}",
            "║".blue().bold(),
            "Target".bold(),
            self.target.bright_white(),
            "Protocol".bold(),
            self.protocol.bright_white(),
            "Duration".bold(),
            format!("{:.2}s", self.duration.as_secs_f64()).bright_white(),
            "║".blue().bold()
        );

        println!(
            "{}",
            format!("╠{}╣", "═".repeat(box_width - 2)).blue().bold()
        );

        // Print header
        println!(
            "{} {:^4} {:^15} {:^25} {:^30} {}",
            "║".blue().bold(),
            "HOP".bold(),
            "IP".bold(),
            "HOSTNAME".bold(),
            "LATENCY (ms)".bold(),
            "║".blue().bold()
        );

        println!(
            "{}",
            format!("╠{}╣", "═".repeat(box_width - 2)).blue().bold()
        );

        // Print hops
        for hop in &self.hops {
            let hop_num = hop.hop.to_string().bold();

            let ip = match &hop.ip {
                Some(ip) => ip.bright_white(),
                None => "*".red().bold(),
            };

            let hostname = match &hop.hostname {
                Some(hostname) => hostname.bright_green(),
                None => "-".normal(),
            };

            // Format latencies in a table like structure
            let mut latency_str = String::new();
            for (i, latency) in hop.latencies.iter().enumerate() {
                if i > 0 {
                    latency_str.push_str("  ");
                }
                match latency {
                    Some(duration) => {
                        latency_str.push_str(&format!("{:.2}", duration.as_secs_f64() * 1000.0));
                    }
                    None => {
                        latency_str.push_str("*");
                    }
                }
            }
            let latency_display = latency_str.normal();

            // Highlight the destination
            let (prefix, suffix) = if hop.is_destination {
                (
                    format!("{} ", "→".bright_green().bold()),
                    format!(" {}", "←".bright_green().bold()),
                )
            } else {
                ("  ".to_string(), "  ".to_string())
            };

            println!(
                "{} {:>4} {}{:^15}{} {:^25} {:^30} {}",
                "║".blue().bold(),
                hop_num,
                prefix,
                ip,
                suffix,
                hostname,
                latency_display,
                "║".blue().bold()
            );
        }

        println!(
            "{}",
            format!("╚{}╝", "═".repeat(box_width - 2)).blue().bold()
        );
        println!();
    }

    fn print_route_path(&self) {
        let box_width = 80;
        println!(
            "\n{}",
            format!("╔{}╗", "═".repeat(box_width - 2)).blue().bold()
        );
        println!(
            "{} {} {}",
            "║".blue().bold(),
            " ROUTE PATH ".on_bright_blue().white().bold(),
            "║".blue().bold()
        );
        println!(
            "{}",
            format!("╠{}╣", "═".repeat(box_width - 2)).blue().bold()
        );

        // Target info
        println!(
            "{} {}: {} | {}: {} {}",
            "║".blue().bold(),
            "Target".bold(),
            self.target.bright_white(),
            "Protocol".bold(),
            self.protocol.bright_white(),
            "║".blue().bold()
        );

        println!(
            "{}",
            format!("╠{}╣", "═".repeat(box_width - 2)).blue().bold()
        );

        // Print header
        println!(
            "{} {:^4} {:^15} {:^20} {:^15} {:^15} {}",
            "║".blue().bold(),
            "HOP".bold(),
            "IP".bold(),
            "HOSTNAME".bold(),
            "ASN".bold(),
            "LOCATION".bold(),
            "║".blue().bold()
        );

        println!(
            "{}",
            format!("╠{}╣", "═".repeat(box_width - 2)).blue().bold()
        );

        // Print hops with route path info
        for hop in &self.hops {
            let hop_num = hop.hop.to_string().bold();

            let ip = match &hop.ip {
                Some(ip) => ip.bright_white(),
                None => "*".red().bold(),
            };

            let hostname = match &hop.hostname {
                Some(hostname) => {
                    if hostname.len() > 20 {
                        format!("{}...", &hostname[0..17]).bright_green()
                    } else {
                        hostname.bright_green()
                    }
                }
                None => "-".normal(),
            };

            let asn = match &hop.asn {
                Some(asn) => asn.yellow().bold(),
                None => "-".normal(),
            };

            let location = match &hop.location {
                Some(location) => location.cyan().bold(),
                None => "-".normal(),
            };

            // Highlight the destination
            let (prefix, suffix) = if hop.is_destination {
                (
                    format!("{} ", "→".bright_green().bold()),
                    format!(" {}", "←".bright_green().bold()),
                )
            } else {
                ("  ".to_string(), "  ".to_string())
            };

            println!(
                "{} {:>4} {}{:^15}{} {:^20} {:^15} {:^15} {}",
                "║".blue().bold(),
                hop_num,
                prefix,
                ip,
                suffix,
                hostname,
                asn,
                location,
                "║".blue().bold()
            );
        }

        println!(
            "{}",
            format!("╚{}╝", "═".repeat(box_width - 2)).blue().bold()
        );
        println!();
    }

    fn to_json_file(&self, path: &str) -> Result<(), std::io::Error> {
        let json = serde_json::to_string_pretty(self)?;
        let mut file = File::create(path)?;
        file.write_all(json.as_bytes())?;
        println!("Trace results saved to {}", path);
        Ok(())
    }

    fn to_text_file(&self, path: &str) -> Result<(), std::io::Error> {
        let mut file = File::create(path)?;

        // Write header
        writeln!(file, "Traceroute to {} ({})", self.target, self.protocol)?;
        if let Some(port) = self.port {
            writeln!(file, "Port: {}", port)?;
        }
        writeln!(file, "Duration: {:.2} seconds", self.duration.as_secs_f64())?;
        writeln!(file, "Destination reached: {}", self.reached_destination)?;
        writeln!(file)?;

        // Write hop information
        writeln!(
            file,
            "{:<4} {:<15} {:<25} {:<10}",
            "HOP", "IP", "HOSTNAME", "LATENCY"
        )?;
        writeln!(file, "{}", "-".repeat(60))?;

        for hop in &self.hops {
            let ip = hop.ip.as_deref().unwrap_or("*");
            let hostname = hop.hostname.as_deref().unwrap_or("-");

            let latency = match hop.avg_latency {
                Some(duration) => format!("{:.2}ms", duration.as_secs_f64() * 1000.0),
                None => "*".to_string(),
            };

            let destination_marker = if hop.is_destination {
                " (destination)"
            } else {
                ""
            };

            writeln!(
                file,
                "{:<4} {:<15} {:<25} {:<10}{}",
                hop.hop, ip, hostname, latency, destination_marker
            )?;
        }

        println!("Trace results saved to {}", path);
        Ok(())
    }
}
