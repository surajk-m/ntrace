use anyhow::Result;
use clap_builder::Parser;
use env_logger::Env;
use ntrace::cli::Cli;
use ntrace::output::ScanResult;
use ntrace::scanner::Scanner;

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::Builder::from_env(Env::default().default_filter_or("info")).init();

    let cli = Cli::parse();
    let config = cli.to_config()?;

    let scanner = Scanner::new(config);
    let results = scanner.scan().await?;

    let scan_result = ScanResult::new(cli.host, results);
    scan_result.print();
    if let Some(output_path) = cli.output.as_ref() {
        scan_result.to_json_file(output_path)?;
    }

    Ok(())
}
