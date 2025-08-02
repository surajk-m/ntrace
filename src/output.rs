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
            let status = if result.is_open { "Open" } else { "Closed" };
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
        println!("{}", "\nScan Results".bold());
        println!("{}: {}", "Target".bold(), self.host);

        if let Some(duration) = self.scan_duration {
            println!(
                "{}: {:.2} seconds",
                "Duration".bold(),
                duration.as_secs_f64()
            );
        }

        println!("{}: {}", "Timestamp".bold(), self.timestamp.to_rfc3339());
        println!("{}: {}", "Ports Scanned".bold(), self.results.len());

        // Count open ports
        let open_ports = self.results.iter().filter(|r| r.is_open).count();
        println!("{}: {}", "Open Ports".bold(), open_ports);
        println!();

        // Print table header
        println!(
            "{:6} {:10} {:20} {:20} {:10}",
            "PORT".bold(),
            "STATE".bold(),
            "SERVICE".bold(),
            "PROTOCOL".bold(),
            "LATENCY".bold()
        );
        println!("{}", "-".repeat(70));

        // Print results
        for result in &self.results {
            if !result.is_open {
                // Skip closed ports in the detailed output
                continue;
            }

            let state = if result.is_open {
                "open".green()
            } else {
                "closed".red()
            };
            let unknown = "unknown".to_string();
            let service = result.service.as_ref().unwrap_or(&unknown);
            let dash = "-".to_string();
            let protocol = result.protocol_info.as_ref().unwrap_or(&dash);

            let latency = match result.latency {
                Some(duration) => format!("{:.2}ms", duration.as_secs_f64() * 1000.0),
                None => "-".to_string(),
            };

            println!(
                "{:6} {:10} {:20} {:20} {:10}",
                result.port.to_string(),
                state,
                service,
                protocol,
                latency
            );
        }

        println!();
    }

    /// Print a verbose version including closed ports
    pub fn print_verbose(&self) {
        // Print header
        println!("{}", "\nDetailed Scan Results".bold());
        println!("{}: {}", "Target".bold(), self.host);

        if let Some(duration) = self.scan_duration {
            println!(
                "{}: {:.2} seconds",
                "Duration".bold(),
                duration.as_secs_f64()
            );
        }

        println!("{}: {}", "Timestamp".bold(), self.timestamp.to_rfc3339());
        println!("{}: {}", "Ports Scanned".bold(), self.results.len());

        // Count open ports
        let open_ports = self.results.iter().filter(|r| r.is_open).count();
        println!("{}: {}", "Open Ports".bold(), open_ports);
        println!();

        // Print table header
        println!(
            "{:6} {:10} {:20} {:20} {:10}",
            "PORT".bold(),
            "STATE".bold(),
            "SERVICE".bold(),
            "PROTOCOL".bold(),
            "LATENCY".bold()
        );
        println!("{}", "-".repeat(70));

        // Print all results
        for result in &self.results {
            let state = if result.is_open {
                "open".green()
            } else {
                "closed".red()
            };
            let unknown = "unknown".to_string();
            let service = result.service.as_ref().unwrap_or(&unknown);
            let dash = "-".to_string();
            let protocol = result.protocol_info.as_ref().unwrap_or(&dash);

            let latency = match result.latency {
                Some(duration) => format!("{:.2}ms", duration.as_secs_f64() * 1000.0),
                None => "-".to_string(),
            };

            println!(
                "{:6} {:10} {:20} {:20} {:10}",
                result.port.to_string(),
                state,
                service,
                protocol,
                latency
            );
        }

        println!();
    }
}
