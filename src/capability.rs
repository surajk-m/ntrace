//! Capability handling module.
//!
//! This module provides functions to check for and set capabilities on Unix systems,
//! specifically for handling the CAP_NET_RAW capability needed for ICMP traceroute.

use log::{debug, info, warn};
use std::process::Command;

/// Checks if the current binary has the CAP_NET_RAW capability.
///
/// This function only works on Unix like systems. On other platforms,
/// it always returns false.
pub fn has_cap_net_raw() -> bool {
    #[cfg(target_family = "unix")]
    {
        // Get the path to the current executable
        if let Ok(exe_path) = std::env::current_exe() {
            // Check if the executable has CAP_NET_RAW capability
            if let Ok(output) = Command::new("getcap").arg(exe_path).output() {
                if output.status.success() {
                    let output_str = String::from_utf8_lossy(&output.stdout);
                    return output_str.contains("cap_net_raw");
                }
            }
        }
        false
    }

    #[cfg(not(target_family = "unix"))]
    {
        // On non Unix platforms, capabilities don't apply
        false
    }
}

/// Attempts to set the CAP_NET_RAW capability on the current binary.
///
/// This function tries to use sudo to set the capability. It will prompt
/// the user for their password if necessary.
///
/// Returns true if the capability was successfully set, false otherwise.
pub fn try_set_cap_net_raw() -> bool {
    #[cfg(target_family = "unix")]
    {
        // Get the path to the current executable
        if let Ok(exe_path) = std::env::current_exe() {
            info!(
                "Attempting to set CAP_NET_RAW capability on {}",
                exe_path.display()
            );

            // Try to set the capability using sudo
            let status = Command::new("sudo")
                .arg("setcap")
                .arg("cap_net_raw+ep")
                .arg(&exe_path)
                .status();

            match status {
                Ok(exit_status) if exit_status.success() => {
                    info!("Successfully set CAP_NET_RAW capability");
                    return true;
                }
                Ok(_) => {
                    warn!("Failed to set CAP_NET_RAW capability");
                }
                Err(e) => {
                    warn!("Error executing sudo command: {}", e);
                }
            }
        } else {
            warn!("Could not determine path to executable");
        }
        false
    }

    #[cfg(not(target_family = "unix"))]
    {
        // On non Unix platforms, capabilities don't apply
        false
    }
}

/// Checks if the binary needs CAP_NET_RAW capability and tries to set it if needed.
///
/// This function is meant to be called when an operation requires the CAP_NET_RAW
/// capability but the current process doesn't have it.
///
/// Returns true if the capability was successfully set or if it's not needed,
/// false otherwise.
pub fn ensure_cap_net_raw() -> bool {
    #[cfg(target_family = "unix")]
    {
        // Check if we already have the capability
        if has_cap_net_raw() {
            debug!("Binary already has CAP_NET_RAW capability");
            return true;
        }

        // Check if we're running as root
        if unsafe { libc::geteuid() == 0 } {
            debug!("Running as root, no need to set capability");
            return true;
        }

        // We need the capability and don't have it, try to set it
        info!("ICMP traceroute requires CAP_NET_RAW capability");
        info!("Attempting to set capability (may prompt for sudo password)...");

        if try_set_cap_net_raw() {
            // Capability was set, but we need to re-execute ourselves to use it
            if let Ok(exe_path) = std::env::current_exe() {
                info!("Re-executing with new capabilities: {}", exe_path.display());

                // Get the current arguments
                let args: Vec<String> = std::env::args().collect();

                // Execute the same binary with the same arguments
                let err = Command::new(&exe_path).args(&args[1..]).status();

                match err {
                    Ok(status) => {
                        // Exit with the same status as the child process
                        std::process::exit(status.code().unwrap_or(0));
                    }
                    Err(e) => {
                        warn!("Failed to re-execute binary: {}", e);
                    }
                }
            }
        }

        false
    }

    #[cfg(not(target_family = "unix"))]
    {
        // On non Unix platforms, capabilities don't apply
        true
    }
}
