use anyhow::Result;
use clap_builder::Parser;
use colored::Colorize;
use env_logger::Env;
use log::{info, warn};
use ntrace::cli::{Cli, Command};
use ntrace::output::{ScanResult, TraceResultOutput};
use ntrace::protocol::Target;
use ntrace::scanner::Scanner;
use ntrace::traceroute::Tracer;
use std::time::Instant;

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logger
    env_logger::Builder::from_env(Env::default().default_filter_or("info")).init();

    // Parse command line arguments
    let cli = Cli::parse();

    // Handle commands
    match &cli.command {
        Some(Command::Trace {
            table,
            route_path,
            json,
            output,
            ..
        }) => {
            // Create trace configuration from CLI options
            let trace_config = cli.to_trace_config()?;

            // Create tracer
            let mut tracer = Tracer::new(trace_config.clone());

            // Display banner
            print_trace_banner();

            // Run the trace
            let target_display = match &trace_config.target {
                Target::Ip(ip) => ip.to_string(),
                Target::Domain(domain) => domain.clone(),
            };

            println!(
                "Starting traceroute to {} using {:?}...",
                target_display, trace_config.protocol
            );

            let trace_result = tracer.trace().await?;

            // Display results based on options
            if *table {
                trace_result.print_table();
            } else if *route_path {
                trace_result.print_route_path();
            } else {
                trace_result.print();
            }

            // Save results if output path provided
            if let Some(output_path) = output {
                if *json || output_path.ends_with(".json") {
                    trace_result.to_json_file(output_path)?;
                } else {
                    trace_result.to_text_file(output_path)?;
                }
            }

            Ok(())
        }
        None => {
            // Traditional port scanning mode
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
    }
}

fn print_banner() {
    let box_width = 60;
    println!(
        "\n{}",
        format!("╔{}╗", "═".repeat(box_width - 2)).blue().bold()
    );
    println!(
        "{} {} {}",
        "║".blue().bold(),
        " ".repeat((box_width - 4) / 2),
        "║".blue().bold()
    );
    println!(
        "{} {} {}",
        "║".blue().bold(),
        "  _   _ _____                    ".bright_green().bold(),
        "║".blue().bold()
    );
    println!(
        "{} {} {}",
        "║".blue().bold(),
        " | \\ | |_   _| __ __ _  ___ ___ ".bright_green().bold(),
        "║".blue().bold()
    );
    println!(
        "{} {} {}",
        "║".blue().bold(),
        " |  \\| | | || '__/ _` |/ __/ _ \\".bright_green().bold(),
        "║".blue().bold()
    );
    println!(
        "{} {} {}",
        "║".blue().bold(),
        " | |\\  | | || | | (_| | (_|  __/".bright_green().bold(),
        "║".blue().bold()
    );
    println!(
        "{} {} {}",
        "║".blue().bold(),
        " |_| \\_| |_||_|  \\__,_|\\___\\___|".bright_green().bold(),
        "║".blue().bold()
    );
    println!(
        "{} {} {}",
        "║".blue().bold(),
        " ".repeat((box_width - 4) / 2),
        "║".blue().bold()
    );
    println!(
        "{} {} {}",
        "║".blue().bold(),
        " Network Port Scanner & Protocol Analyzer v0.1.3 "
            .on_bright_blue()
            .white()
            .bold(),
        "║".blue().bold()
    );
    println!(
        "{} {} {}",
        "║".blue().bold(),
        " ".repeat((box_width - 4) / 2),
        "║".blue().bold()
    );
    println!(
        "{}",
        format!("╚{}╝", "═".repeat(box_width - 2)).blue().bold()
    );
    println!();
}

fn print_trace_banner() {
    let box_width = 60;
    println!(
        "\n{}",
        format!("╔{}╗", "═".repeat(box_width - 2)).blue().bold()
    );
    println!(
        "{} {} {}",
        "║".blue().bold(),
        " ".repeat((box_width - 4) / 2),
        "║".blue().bold()
    );
    println!(
        "{} {} {}",
        "║".blue().bold(),
        "  _   _ _____                    ".bright_green().bold(),
        "║".blue().bold()
    );
    println!(
        "{} {} {}",
        "║".blue().bold(),
        " | \\ | |_   _| __ __ _  ___ ___ ".bright_green().bold(),
        "║".blue().bold()
    );
    println!(
        "{} {} {}",
        "║".blue().bold(),
        " |  \\| | | || '__/ _` |/ __/ _ \\".bright_green().bold(),
        "║".blue().bold()
    );
    println!(
        "{} {} {}",
        "║".blue().bold(),
        " | |\\  | | || | | (_| | (_|  __/".bright_green().bold(),
        "║".blue().bold()
    );
    println!(
        "{} {} {}",
        "║".blue().bold(),
        " |_| \\_| |_||_|  \\__,_|\\___\\___|".bright_green().bold(),
        "║".blue().bold()
    );
    println!(
        "{} {} {}",
        "║".blue().bold(),
        " ".repeat((box_width - 4) / 2),
        "║".blue().bold()
    );
    println!(
        "{} {} {}",
        "║".blue().bold(),
        " Traceroute & Network Path Analyzer v0.1.3 "
            .on_bright_blue()
            .white()
            .bold(),
        "║".blue().bold()
    );
    println!(
        "{} {} {}",
        "║".blue().bold(),
        " ".repeat((box_width - 4) / 2),
        "║".blue().bold()
    );
    println!(
        "{}",
        format!("╚{}╝", "═".repeat(box_width - 2)).blue().bold()
    );
    println!();
}
