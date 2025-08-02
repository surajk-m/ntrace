use anyhow::Result;
use clap_builder::Parser;
use env_logger::Env;
use indicatif::{ProgressBar, ProgressStyle};
use log::{info, warn};
use ntrace::cli::Cli;
use ntrace::output::ScanResult;
use ntrace::protocol::Target;
use ntrace::scanner::Scanner;
use std::time::Instant;

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logger
    env_logger::Builder::from_env(Env::default().default_filter_or("info")).init();

    // Parse command line arguments
    let cli = Cli::parse();
    let config = cli.to_config()?;

    // Display banner
    print_banner();

    // Check if host is reachable (unless skipped)
    let mut scanner = Scanner::new(config.clone());

    if !cli.skip_discovery {
        let target_display = match &config.target {
            Target::Ip(ip) => ip.to_string(),
            Target::Domain(domain) => domain.clone(),
        };

        info!("Checking if target {} is reachable...", target_display);

        if !scanner.ping_host().await? {
            warn!(
                "Target {} appears to be down or blocking ping requests",
                target_display
            );
            println!(
                "Warning: Target {} may be down or blocking ping requests",
                target_display
            );
            println!("Continuing with scan anyway...");
        }
    }

    // Create progress bar
    let pb = ProgressBar::new(config.ports.len() as u64);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ports ({eta})")
            .unwrap()
            .progress_chars("#>-")
    );

    // Start the scan
    let start_time = Instant::now();
    let target_display = match &config.target {
        Target::Ip(ip) => ip.to_string(),
        Target::Domain(domain) => domain.clone(),
    };
    println!(
        "Starting scan of {} ports on {}...",
        config.ports.len(),
        target_display
    );

    // Configure scanner with CLI options
    scanner = Scanner::new(config)
        .with_rate_limit(cli.rate_limit)
        .with_concurrency_limit(cli.batch_size);

    // Run the scan
    let results = scanner.scan().await?;
    let scan_duration = start_time.elapsed();

    // Finish progress bar
    pb.finish_with_message(format!(
        "Scan completed in {:.2}s",
        scan_duration.as_secs_f64()
    ));

    // Create and display results
    let scan_result = ScanResult::new(target_display, results, Some(scan_duration));

    // Print results based on verbosity
    if cli.verbose {
        scan_result.print_verbose();
    } else {
        scan_result.print();
    }

    // Save results if output path provided
    if let Some(output_path) = cli.output.as_ref() {
        if output_path.ends_with(".json") {
            scan_result.to_json_file(output_path)?;
        } else if output_path.ends_with(".csv") {
            scan_result.to_csv_file(output_path)?;
        } else {
            // Default to JSON
            scan_result.to_json_file(output_path)?;
        }
    }

    Ok(())
}

fn print_banner() {
    println!("\n{}", "=".repeat(60));
    println!("  _   _ _____                    ");
    println!(" | \\ | |_   _| __ __ _  ___ ___ ");
    println!(" |  \\| | | || '__/ _` |/ __/ _ \\");
    println!(" | |\\  | | || | | (_| | (_|  __/");
    println!(" |_| \\_| |_||_|  \\__,_|\\___\\___|");
    println!("                                 ");
    println!(" Network Port Scanner & Protocol Analyzer v0.1.0");
    println!("{}\n", "=".repeat(60));
}
