use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use std::time::Duration;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub monitoring: MonitoringConfig,
    pub services: HashMap<String, ServiceConfig>,
    pub benchmarks: BenchmarkConfig,
    pub exporters: ExporterConfig,
    pub thresholds: ThresholdConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonitoringConfig {
    pub interval_secs: u64,
    pub metrics_retention_hours: u64,
    pub system_monitoring: bool,
    pub process_monitoring: bool,
    pub network_monitoring: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceConfig {
    pub name: String,
    pub port: u16,
    pub health_endpoint: Option<String>,
    pub protocol: ServiceProtocol,
    pub expected_response_time_ms: Option<u64>,
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ServiceProtocol {
    #[serde(rename = "tcp")]
    Tcp,
    #[serde(rename = "http")]
    Http,
    #[serde(rename = "grpc")]
    Grpc,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchmarkConfig {
    pub suites: HashMap<String, BenchmarkSuite>,
    pub output_dir: String,
    pub concurrent_limit: usize,
    pub timeout_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchmarkSuite {
    pub name: String,
    pub tests: Vec<BenchmarkTest>,
    pub warmup_iterations: usize,
    pub measurement_iterations: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchmarkTest {
    pub name: String,
    pub test_type: TestType,
    pub target: String,
    pub parameters: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TestType {
    #[serde(rename = "latency")]
    Latency,
    #[serde(rename = "throughput")]
    Throughput,
    #[serde(rename = "concurrent")]
    Concurrent,
    #[serde(rename = "memory")]
    Memory,
    #[serde(rename = "cpu")]
    Cpu,
    #[serde(rename = "custom")]
    Custom,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExporterConfig {
    pub prometheus: Option<PrometheusConfig>,
    pub json: Option<JsonConfig>,
    pub csv: Option<CsvConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrometheusConfig {
    pub enabled: bool,
    pub port: u16,
    pub path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonConfig {
    pub enabled: bool,
    pub output_file: String,
    pub pretty: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CsvConfig {
    pub enabled: bool,
    pub output_file: String,
    pub include_headers: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThresholdConfig {
    pub cpu_usage_percent: f64,
    pub memory_usage_percent: f64,
    pub response_time_ms: u64,
    pub error_rate_percent: f64,
    pub disk_usage_percent: f64,
}

impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        if path.exists() {
            let content = std::fs::read_to_string(path)?;
            let config: Config = toml::from_str(&content)?;
            Ok(config)
        } else {
            // Return default configuration
            Ok(Self::default())
        }
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        let content = toml::to_string_pretty(self)?;
        std::fs::write(path, content)?;
        Ok(())
    }
}

impl Default for Config {
    fn default() -> Self {
        let mut services = HashMap::new();
        
        // BlocksenseOS services
        services.insert("rust-echo".to_string(), ServiceConfig {
            name: "Rust Echo Service".to_string(),
            port: 8081,
            health_endpoint: None,
            protocol: ServiceProtocol::Tcp,
            expected_response_time_ms: Some(100),
            enabled: true,
        });
        
        services.insert("cpp-echo".to_string(), ServiceConfig {
            name: "C++ Echo Service".to_string(),
            port: 8080,
            health_endpoint: None,
            protocol: ServiceProtocol::Tcp,
            expected_response_time_ms: Some(100),
            enabled: true,
        });
        
        services.insert("attestation-agent".to_string(), ServiceConfig {
            name: "Attestation Agent".to_string(),
            port: 3000,
            health_endpoint: Some("/health".to_string()),
            protocol: ServiceProtocol::Http,
            expected_response_time_ms: Some(200),
            enabled: true,
        });

        let mut benchmark_suites = HashMap::new();
        
        // Core performance suite
        let core_tests = vec![
            BenchmarkTest {
                name: "echo_latency".to_string(),
                test_type: TestType::Latency,
                target: "rust-echo".to_string(),
                parameters: [
                    ("message_size".to_string(), serde_json::Value::Number(1024.into())),
                    ("iterations".to_string(), serde_json::Value::Number(1000.into())),
                ].into_iter().collect(),
            },
            BenchmarkTest {
                name: "echo_throughput".to_string(),
                test_type: TestType::Throughput,
                target: "rust-echo".to_string(),
                parameters: [
                    ("concurrent_connections".to_string(), serde_json::Value::Number(50.into())),
                    ("duration_secs".to_string(), serde_json::Value::Number(30.into())),
                ].into_iter().collect(),
            },
            BenchmarkTest {
                name: "attestation_latency".to_string(),
                test_type: TestType::Latency,
                target: "attestation-agent".to_string(),
                parameters: [
                    ("iterations".to_string(), serde_json::Value::Number(100.into())),
                ].into_iter().collect(),
            },
        ];
        
        benchmark_suites.insert("core".to_string(), BenchmarkSuite {
            name: "Core Performance Suite".to_string(),
            tests: core_tests,
            warmup_iterations: 10,
            measurement_iterations: 100,
        });

        Self {
            monitoring: MonitoringConfig {
                interval_secs: 60,
                metrics_retention_hours: 24,
                system_monitoring: true,
                process_monitoring: true,
                network_monitoring: true,
            },
            services,
            benchmarks: BenchmarkConfig {
                suites: benchmark_suites,
                output_dir: "./benchmark_results".to_string(),
                concurrent_limit: 100,
                timeout_secs: 300,
            },
            exporters: ExporterConfig {
                prometheus: Some(PrometheusConfig {
                    enabled: true,
                    port: 9090,
                    path: "/metrics".to_string(),
                }),
                json: Some(JsonConfig {
                    enabled: true,
                    output_file: "./metrics.json".to_string(),
                    pretty: true,
                }),
                csv: Some(CsvConfig {
                    enabled: false,
                    output_file: "./metrics.csv".to_string(),
                    include_headers: true,
                }),
            },
            thresholds: ThresholdConfig {
                cpu_usage_percent: 80.0,
                memory_usage_percent: 85.0,
                response_time_ms: 1000,
                error_rate_percent: 5.0,
                disk_usage_percent: 90.0,
            },
        }
    }
}