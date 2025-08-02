use crate::scanner::PortResult;
use serde::Serialize;
use std::fs::File;
use std::io::Write;

#[derive(Debug, Serialize)]
pub struct ScanResult {
    pub host: String,
    pub results: Vec<PortResult>,
}

impl ScanResult {
    pub fn new(host: String, results: Vec<PortResult>) -> Self {
        ScanResult { host, results }
    }

    pub fn to_json_file(&self, path: &str) -> Result<(), std::io::Error> {
        let json = serde_json::to_string_pretty(self)?;
        let mut file = File::create(path)?;
        file.write_all(json.as_bytes())?;
        Ok(())
    }

    pub fn print(&self) {
        for result in &self.results {
            println!(
                "Port {}: {} (Service: {}, Protocol: {})",
                result.port,
                if result.is_open { "Open" } else { "Closed" },
                result.service.as_ref().unwrap_or(&"Unknown".to_string()),
                result.protocol_info.as_ref().unwrap_or(&"None".to_string())
            );
        }
    }
}
