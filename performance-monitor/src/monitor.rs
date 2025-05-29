use anyhow::{Context, Result};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tracing::{debug, info, warn, error};

use crate::config::Config;
use crate::metrics::{MetricsCollector, SystemMetrics, ServiceMetrics};
use crate::benchmarks::{BenchmarkSuite, BenchmarkResult};
use crate::exporters::{PrometheusExporter, JsonExporter, ReportGenerator};
use crate::system::SystemMonitor;

/// Main performance monitoring coordinator
pub struct PerformanceMonitor {
    config: Config,
    metrics_collector: Arc<MetricsCollector>,
    system_monitor: Arc<SystemMonitor>,
    benchmark_suite: BenchmarkSuite,
    prometheus_exporter: Option<Arc<PrometheusExporter>>,
    baseline_results: Arc<RwLock<Option<Vec<BenchmarkResult>>>>,
}

impl PerformanceMonitor {
    pub async fn new(config: Config) -> Result<Self> {
        info!("Initializing performance monitor with config: {:?}", config.name);
        
        let metrics_collector = Arc::new(MetricsCollector::new(&config).await?);
        let system_monitor = Arc::new(SystemMonitor::new(&config)?);
        let benchmark_suite = BenchmarkSuite::new(&config)?;
        
        let prometheus_exporter = if config.exporters.prometheus.enabled {
            Some(Arc::new(PrometheusExporter::new(&config.exporters.prometheus)?))
        } else {
            None
        };
        
        // Load baseline if exists
        let baseline_results = Arc::new(RwLock::new(Self::load_baseline(&config.baseline_path).await?));
        
        Ok(Self {
            config,
            metrics_collector,
            system_monitor,
            benchmark_suite,
            prometheus_exporter,
            baseline_results,
        })
    }
    
    /// Collect current system and service metrics
    pub async fn collect_metrics(&self) -> Result<()> {
        let start_time = Instant::now();
        
        // Collect system metrics
        let system_metrics = self.system_monitor.collect_system_metrics().await
            .context("Failed to collect system metrics")?;
        
        // Collect service metrics for all configured services
        let mut service_metrics = Vec::new();
        for service_config in &self.config.services {
            match self.metrics_collector.collect_service_metrics(service_config).await {
                Ok(metrics) => service_metrics.push(metrics),
                Err(e) => {
                    warn!("Failed to collect metrics for service {}: {}", service_config.name, e);
                }
            }
        }
        
        // Export to Prometheus if enabled
        if let Some(ref exporter) = self.prometheus_exporter {
            exporter.export_system_metrics(&system_metrics).await?;
            for metrics in &service_metrics {
                exporter.export_service_metrics(metrics).await?;
            }
        }
        
        let collection_duration = start_time.elapsed();
        debug!("Metrics collection completed in {:?}", collection_duration);
        
        // Record collection performance
        self.metrics_collector.record_collection_time(collection_duration).await;
        
        Ok(())
    }
    
    /// Run benchmark suite
    pub async fn run_benchmarks(
        &self, 
        suite_name: Option<&str>, 
        output_path: Option<&Path>
    ) -> Result<Vec<BenchmarkResult>> {
        info!("Starting benchmark suite: {}", suite_name.unwrap_or("all"));
        
        let results = match suite_name {
            Some("attestation") => self.benchmark_suite.run_attestation_benchmarks().await?,
            Some("echo-services") => self.benchmark_suite.run_echo_service_benchmarks().await?,
            Some("throughput") => self.benchmark_suite.run_throughput_benchmarks().await?,
            Some("memory") => self.benchmark_suite.run_memory_benchmarks().await?,
            Some("stress") => self.benchmark_suite.run_stress_tests().await?,
            None | Some("all") => self.benchmark_suite.run_all_benchmarks().await?,
            _ => return Err(anyhow::anyhow!("Unknown benchmark suite: {}", suite_name.unwrap())),
        };
        
        // Check for performance regressions
        let regressions = self.detect_regressions(&results).await?;
        if !regressions.is_empty() {
            warn!("Performance regressions detected: {} issues", regressions.len());
            for regression in &regressions {
                warn!("Regression in {}: {:.2}% change", regression.metric_name, regression.change_percent);
            }
        }
        
        // Save results if output path specified
        if let Some(path) = output_path {
            let json_exporter = JsonExporter::new();
            json_exporter.export_benchmark_results(&results, path).await
                .context("Failed to save benchmark results")?;
            info!("Benchmark results saved to: {}", path.display());
        }
        
        info!("Benchmark suite completed: {} tests, {} regressions", 
              results.len(), regressions.len());
        
        Ok(results)
    }
    
    /// Start Prometheus metrics server
    pub async fn start_metrics_server(&self, host: &str, port: u16) -> Result<()> {
        if let Some(ref exporter) = self.prometheus_exporter {
            exporter.start_server(host, port).await
                .context("Failed to start Prometheus metrics server")?;
            info!("Metrics server started on http://{}:{}/metrics", host, port);
        } else {
            return Err(anyhow::anyhow!("Prometheus exporter not enabled"));
        }
        Ok(())
    }
    
    /// Generate performance report
    pub async fn generate_report(
        &self,
        input_path: &Path,
        output_path: &Path,
        format: Option<&str>
    ) -> Result<()> {
        let report_generator = ReportGenerator::new(&self.config);
        
        match format.unwrap_or("html") {
            "html" => {
                report_generator.generate_html_report(input_path, output_path).await?;
            }
            "markdown" => {
                report_generator.generate_markdown_report(input_path, output_path).await?;
            }
            "pdf" => {
                report_generator.generate_pdf_report(input_path, output_path).await?;
            }
            _ => {
                return Err(anyhow::anyhow!("Unsupported report format"));
            }
        }
        
        info!("Performance report generated: {}", output_path.display());
        Ok(())
    }
    
    /// Save current benchmark results as baseline
    pub async fn save_baseline(&self, results: &[BenchmarkResult]) -> Result<()> {
        let json_exporter = JsonExporter::new();
        json_exporter.export_benchmark_results(results, &self.config.baseline_path).await?;
        
        // Update in-memory baseline
        let mut baseline = self.baseline_results.write().await;
        *baseline = Some(results.to_vec());
        
        info!("Baseline saved to: {}", self.config.baseline_path.display());
        Ok(())
    }
    
    /// Detect performance regressions compared to baseline
    async fn detect_regressions(&self, current_results: &[BenchmarkResult]) -> Result<Vec<RegressionAlert>> {
        let baseline_guard = self.baseline_results.read().await;
        let baseline_results = match baseline_guard.as_ref() {
            Some(baseline) => baseline,
            None => {
                debug!("No baseline available for regression detection");
                return Ok(Vec::new());
            }
        };
        
        let mut regressions = Vec::new();
        
        for current in current_results {
            if let Some(baseline) = baseline_results.iter()
                .find(|b| b.test_name == current.test_name && b.metric_name == current.metric_name) 
            {
                let change_percent = calculate_change_percent(baseline.value, current.value);
                
                // Determine if this is a regression based on metric type
                let is_regression = match current.metric_type.as_str() {
                    "latency" | "time" | "duration" => {
                        // Higher values are worse for timing metrics
                        change_percent > self.config.regression_threshold_percent
                    }
                    "throughput" | "rate" | "ops_per_sec" => {
                        // Lower values are worse for throughput metrics
                        change_percent < -self.config.regression_threshold_percent
                    }
                    "memory" | "cpu" => {
                        // Higher resource usage might be a regression
                        change_percent > self.config.regression_threshold_percent * 1.5 // More lenient for resource metrics
                    }
                    _ => false,
                };
                
                if is_regression {
                    regressions.push(RegressionAlert {
                        test_name: current.test_name.clone(),
                        metric_name: current.metric_name.clone(),
                        baseline_value: baseline.value,
                        current_value: current.value,
                        change_percent,
                        severity: if change_percent.abs() > self.config.regression_threshold_percent * 2.0 {
                            RegressionSeverity::Critical
                        } else {
                            RegressionSeverity::Warning
                        },
                    });
                }
            }
        }
        
        Ok(regressions)
    }
    
    /// Load baseline from file if exists
    async fn load_baseline(path: &Path) -> Result<Option<Vec<BenchmarkResult>>> {
        if !path.exists() {
            debug!("No baseline file found at: {}", path.display());
            return Ok(None);
        }
        
        let json_exporter = JsonExporter::new();
        match json_exporter.load_benchmark_results(path).await {
            Ok(results) => {
                info!("Loaded baseline with {} results from: {}", results.len(), path.display());
                Ok(Some(results))
            }
            Err(e) => {
                warn!("Failed to load baseline from {}: {}", path.display(), e);
                Ok(None)
            }
        }
    }
    
    /// Graceful shutdown
    pub async fn shutdown(&self) -> Result<()> {
        info!("Shutting down performance monitor...");
        
        // Stop Prometheus exporter if running
        if let Some(ref exporter) = self.prometheus_exporter {
            exporter.shutdown().await?;
        }
        
        // Final metrics collection
        if let Err(e) = self.collect_metrics().await {
            warn!("Final metrics collection failed: {}", e);
        }
        
        info!("Performance monitor shutdown complete");
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct RegressionAlert {
    pub test_name: String,
    pub metric_name: String,
    pub baseline_value: f64,
    pub current_value: f64,
    pub change_percent: f64,
    pub severity: RegressionSeverity,
}

#[derive(Debug, Clone)]
pub enum RegressionSeverity {
    Warning,
    Critical,
}

fn calculate_change_percent(baseline: f64, current: f64) -> f64 {
    if baseline == 0.0 {
        return if current == 0.0 { 0.0 } else { 100.0 };
    }
    ((current - baseline) / baseline) * 100.0
}