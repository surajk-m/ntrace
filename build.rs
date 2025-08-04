//! Build script for ntrace
//! This script provides information about capabilities required for ntrace.

use std::env;

fn main() {
    // Only run the capability messaging on Unix like systems
    #[cfg(target_family = "unix")]
    {
        // Check if this is being run during installation
        // Just to acknowledge we're in a build context
        let _ = env::var("OUT_DIR");
        println!("cargo:rerun-if-changed=build.rs");

        // Print a message about capabilities
        println!(
            "cargo:warning=ntrace requires CAP_NET_RAW capability for ICMP traceroute without sudo"
        );
        println!(
            "cargo:warning=The binary will attempt to set this capability during installation"
        );
    }
}
