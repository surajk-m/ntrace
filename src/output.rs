use crate::scanner::PortResult;
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
