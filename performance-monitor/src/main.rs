use anyhow::Result;
use clap::Parser;
use std::path::PathBuf;
use tokio::signal;
use tracing::{info, warn};

mod config;
mod metrics;
mod monitor;
mod benchmarks;
mod exporters;
mod system;

use crate::config::Config;
use crate::monitor::PerformanceMonitor;

#[derive(Parser)]
#[command(name = "performance-monitor")]
#[command(about = "BlocksenseOS Performance Monitoring and Benchmarking Suite")]
struct Cli {
    #[arg(short, long, default_value = "config.toml")]
    config: PathBuf,
    
    #[arg(short, long)]
    verbose: bool,
    
    #[command(subcommand)]
    command: Commands,
}

#[derive(Parser)]
enum Commands {
    /// Run continuous monitoring
    Monitor {
        #[arg(short, long, default_value = "60")]
        interval: u64,
    },
    /// Run benchmark suite
    Benchmark {
        #[arg(short, long)]
        suite: Option<String>,
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Start metrics server
    Serve {
        #[arg(short, long, default_value = "9090")]
        port: u16,
        #[arg(short, long, default_value = "0.0.0.0")]
        host: String,
    },
    /// Generate performance report
    Report {
        #[arg(short, long)]
        input: PathBuf,
        #[arg(short, long)]
        output: PathBuf,
        #[arg(long)]
        format: Option<String>,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    
    // Initialize tracing
    let filter = if cli.verbose {
        "debug"
    } else {
        "info"
    };
    
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .init();

    info!("BlocksenseOS Performance Monitor v{}", env!("CARGO_PKG_VERSION"));
    
    // Load configuration
    let config = Config::load(&cli.config)?;
    let monitor = PerformanceMonitor::new(config).await?;
    
    match cli.command {
        Commands::Monitor { interval } => {
            info!("Starting continuous monitoring with {} second intervals", interval);
            run_monitoring(monitor, interval).await?;
        }
        Commands::Benchmark { suite, output } => {
            info!("Running benchmark suite: {:?}", suite.as_deref().unwrap_or("all"));
            monitor.run_benchmarks(suite.as_deref(), output.as_deref()).await?;
        }
        Commands::Serve { port, host } => {
            info!("Starting metrics server on {}:{}", host, port);
            monitor.start_metrics_server(&host, port).await?;
        }
        Commands::Report { input, output, format } => {
            info!("Generating report from {:?} to {:?}", input, output);
            monitor.generate_report(&input, &output, format.as_deref()).await?;
        }
    }
    
    Ok(())
}

async fn run_monitoring(monitor: PerformanceMonitor, interval_secs: u64) -> Result<()> {
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(interval_secs));
    
    // Setup graceful shutdown
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };
    
    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("failed to install signal handler")
            .recv()
            .await;
    };
    
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();
    
    tokio::select! {
        _ = async {
            loop {
                interval.tick().await;
                if let Err(e) = monitor.collect_metrics().await {
                    warn!("Failed to collect metrics: {}", e);
                }
            }
        } => {},
        _ = ctrl_c => {
            info!("Received Ctrl+C, shutting down...");
        },
        _ = terminate => {
            info!("Received terminate signal, shutting down...");
        },
    }
    
    monitor.shutdown().await?;
    info!("Performance monitor shutdown complete");
    Ok(())
}