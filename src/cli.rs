use std::net::Ipv4Addr;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "vuln-pkg")]
#[command(
    author,
    version,
    about = "A package manager for deliberately-vulnerable applications"
)]
pub struct Cli {
    /// Output in JSON format for automation
    #[arg(long, global = true)]
    pub json: bool,

    /// Manifest URL to fetch apps from
    #[arg(long, global = true, default_value = "https://raw.githubusercontent.com/neutrno2211/vuln-pkg/main/manifest.yml")]
    pub manifest_url: String,

    /// Address that hostnames resolve to (useful if /etc/hosts uses different IP)
    #[arg(long, global = true, default_value = "127.0.0.1")]
    pub resolve_address: Ipv4Addr,

    /// Domain suffix for app hostnames (e.g., "lab.local" -> app.lab.local)
    /// If not specified, uses sslip.io for zero-config DNS resolution
    #[arg(long, global = true)]
    pub domain: Option<String>,

    /// Enable HTTPS with self-signed certificates
    #[arg(long, global = true)]
    pub https: bool,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// List available vulnerable applications
    List,

    /// Install a vulnerable application (pull image, create config)
    Install {
        /// Name of the application to install
        app: String,
    },

    /// Run a vulnerable application (start container with Traefik routing)
    Run {
        /// Name of the application to run
        app: String,
    },

    /// Stop a running vulnerable application
    Stop {
        /// Name of the application to stop
        app: String,
    },

    /// Stop and remove a vulnerable application
    Remove {
        /// Name of the application to remove
        app: String,

        /// Also remove the Docker image
        #[arg(long)]
        purge: bool,
    },

    /// Rebuild a custom application (dockerfile or git type)
    Rebuild {
        /// Name of the application to rebuild
        app: String,
    },

    /// Show status of running applications
    Status,
}
