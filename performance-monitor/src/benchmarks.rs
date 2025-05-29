use anyhow::{Context, Result};
use criterion::{BenchmarkId, Criterion, Throughput, measurement::WallTime};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::time::timeout;
use serde::{Deserialize, Serialize};
use tracing::{info, warn, debug};

use crate::config::Config;

/// Benchmark suite using Criterion for professional benchmarking
pub struct BenchmarkSuite {
    config: Config,
    criterion: Criterion<WallTime>,
    client: reqwest::Client,
}

impl BenchmarkSuite {
    pub fn new(config: &Config) -> Result<Self> {
        let criterion = Criterion::default()
            .warm_up_time(Duration::from_secs(3))
            .measurement_time(Duration::from_secs(10))
            .sample_size(100)
            .output_directory(&config.benchmark_output_dir);

        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .context("Failed to create HTTP client")?;

        Ok(Self {
            config: config.clone(),
            criterion,
            client,
        })
    }

    /// Run all benchmark suites
    pub async fn run_all_benchmarks(&self) -> Result<Vec<BenchmarkResult>> {
        info!("Running comprehensive benchmark suite");
        
        let mut all_results = Vec::new();
        
        // Run individual benchmark suites
        all_results.extend(self.run_attestation_benchmarks().await?);
        all_results.extend(self.run_echo_service_benchmarks().await?);
        all_results.extend(self.run_throughput_benchmarks().await?);
        all_results.extend(self.run_memory_benchmarks().await?);
        
        info!("Completed all benchmarks: {} total tests", all_results.len());
        Ok(all_results)
    }

    /// Benchmark attestation generation and validation
    pub async fn run_attestation_benchmarks(&self) -> Result<Vec<BenchmarkResult>> {
        info!("Running attestation benchmarks");
        let mut results = Vec::new();

        // Find attestation agent endpoint
        let attestation_url = format!("http://{}:{}", 
            self.config.services.iter()
                .find(|s| s.name == "attestation-agent")
                .map(|s| s.host.as_str())
                .unwrap_or("127.0.0.1"),
            self.config.services.iter()
                .find(|s| s.name == "attestation-agent")
                .map(|s| s.port)
                .unwrap_or(8080)
        );

        // Attestation generation latency
        let mut group = self.criterion.benchmark_group("attestation_latency");
        group.throughput(Throughput::Elements(1));
        
        let attestation_times = self.measure_attestation_latency(&attestation_url, 50).await?;
        let avg_latency = attestation_times.iter().sum::<Duration>().as_nanos() as f64 / attestation_times.len() as f64;
        
        results.push(BenchmarkResult {
            test_name: "attestation_generation".to_string(),
            metric_name: "average_latency_ns".to_string(),
            metric_type: "latency".to_string(),
            value: avg_latency,
            unit: "nanoseconds".to_string(),
            timestamp: chrono::Utc::now(),
        });

        // Attestation validation throughput
        let validation_rate = self.measure_attestation_validation_rate(&attestation_url, 100).await?;
        results.push(BenchmarkResult {
            test_name: "attestation_validation".to_string(),
            metric_name: "validations_per_second".to_string(),
            metric_type: "throughput".to_string(),
            value: validation_rate,
            unit: "ops/sec".to_string(),
            timestamp: chrono::Utc::now(),
        });

        group.finish();
        info!("Attestation benchmarks completed: {} tests", results.len());
        Ok(results)
    }

    /// Benchmark echo services performance
    pub async fn run_echo_service_benchmarks(&self) -> Result<Vec<BenchmarkResult>> {
        info!("Running echo service benchmarks");
        let mut results = Vec::new();

        // Test both Rust and C++ echo services
        for service in &self.config.services {
            if service.name.contains("echo") {
                let service_url = format!("http://{}:{}", service.host, service.port);
                
                // Latency benchmark
                let latencies = self.measure_echo_latency(&service_url, 100).await?;
                let avg_latency = latencies.iter().sum::<Duration>().as_nanos() as f64 / latencies.len() as f64;
                
                results.push(BenchmarkResult {
                    test_name: format!("{}_echo", service.name),
                    metric_name: "average_latency_ns".to_string(),
                    metric_type: "latency".to_string(),
                    value: avg_latency,
                    unit: "nanoseconds".to_string(),
                    timestamp: chrono::Utc::now(),
                });

                // Throughput benchmark
                let throughput = self.measure_echo_throughput(&service_url, 1000).await?;
                results.push(BenchmarkResult {
                    test_name: format!("{}_echo", service.name),
                    metric_name: "requests_per_second".to_string(),
                    metric_type: "throughput".to_string(),
                    value: throughput,
                    unit: "ops/sec".to_string(),
                    timestamp: chrono::Utc::now(),
                });
            }
        }

        info!("Echo service benchmarks completed: {} tests", results.len());
        Ok(results)
    }

    /// Benchmark system throughput under load
    pub async fn run_throughput_benchmarks(&self) -> Result<Vec<BenchmarkResult>> {
        info!("Running throughput benchmarks");
        let mut results = Vec::new();

        // Concurrent connection benchmark
        for concurrency in [10, 50, 100, 200] {
            let throughput = self.measure_concurrent_throughput(concurrency).await?;
            
            results.push(BenchmarkResult {
                test_name: "concurrent_connections".to_string(),
                metric_name: format!("throughput_{}_concurrent", concurrency),
                metric_type: "throughput".to_string(),
                value: throughput,
                unit: "ops/sec".to_string(),
                timestamp: chrono::Utc::now(),
            });
        }

        // Mixed workload benchmark
        let mixed_throughput = self.measure_mixed_workload_throughput().await?;
        results.push(BenchmarkResult {
            test_name: "mixed_workload".to_string(),
            metric_name: "combined_throughput".to_string(),
            metric_type: "throughput".to_string(),
            value: mixed_throughput,
            unit: "ops/sec".to_string(),
            timestamp: chrono::Utc::now(),
        });

        info!("Throughput benchmarks completed: {} tests", results.len());
        Ok(results)
    }

    /// Benchmark memory usage patterns
    pub async fn run_memory_benchmarks(&self) -> Result<Vec<BenchmarkResult>> {
        info!("Running memory benchmarks");
        let mut results = Vec::new();

        // Memory usage under different loads
        for load_level in ["light", "medium", "heavy"] {
            let memory_usage = self.measure_memory_usage_under_load(load_level).await?;
            
            results.push(BenchmarkResult {
                test_name: format!("memory_usage_{}", load_level),
                metric_name: "peak_memory_mb".to_string(),
                metric_type: "memory".to_string(),
                value: memory_usage,
                unit: "megabytes".to_string(),
                timestamp: chrono::Utc::now(),
            });
        }

        info!("Memory benchmarks completed: {} tests", results.len());
        Ok(results)
    }

    /// Run stress tests to find breaking points
    pub async fn run_stress_tests(&self) -> Result<Vec<BenchmarkResult>> {
        info!("Running stress tests");
        let mut results = Vec::new();

        // Find maximum sustainable throughput
        let max_throughput = self.find_maximum_throughput().await?;
        results.push(BenchmarkResult {
            test_name: "stress_test".to_string(),
            metric_name: "maximum_throughput".to_string(),
            metric_type: "throughput".to_string(),
            value: max_throughput,
            unit: "ops/sec".to_string(),
            timestamp: chrono::Utc::now(),
        });

        // Connection limit test
        let max_connections = self.find_connection_limit().await?;
        results.push(BenchmarkResult {
            test_name: "stress_test".to_string(),
            metric_name: "maximum_connections".to_string(),
            metric_type: "capacity".to_string(),
            value: max_connections as f64,
            unit: "connections".to_string(),
            timestamp: chrono::Utc::now(),
        });

        info!("Stress tests completed: {} tests", results.len());
        Ok(results)
    }

    // Helper methods for specific benchmarks

    async fn measure_attestation_latency(&self, url: &str, samples: usize) -> Result<Vec<Duration>> {
        let mut times = Vec::with_capacity(samples);
        
        for _ in 0..samples {
            let start = Instant::now();
            
            let response = timeout(
                Duration::from_secs(10),
                self.client.post(&format!("{}/generate", url))
                    .json(&serde_json::json!({"nonce": "test_nonce"}))
                    .send()
            ).await??;
            
            if response.status().is_success() {
                times.push(start.elapsed());
            } else {
                warn!("Attestation request failed: {}", response.status());
            }
        }
        
        Ok(times)
    }

    async fn measure_attestation_validation_rate(&self, url: &str, samples: usize) -> Result<f64> {
        // First generate an attestation to validate
        let attestation = self.client
            .post(&format!("{}/generate", url))
            .json(&serde_json::json!({"nonce": "validation_test"}))
            .send()
            .await?
            .text()
            .await?;

        let start = Instant::now();
        let mut successful_validations = 0;

        for _ in 0..samples {
            let response = self.client
                .post(&format!("{}/validate", url))
                .json(&serde_json::json!({"attestation": attestation}))
                .send()
                .await?;
            
            if response.status().is_success() {
                successful_validations += 1;
            }
        }

        let elapsed = start.elapsed();
        Ok(successful_validations as f64 / elapsed.as_secs_f64())
    }

    async fn measure_echo_latency(&self, url: &str, samples: usize) -> Result<Vec<Duration>> {
        let mut times = Vec::with_capacity(samples);
        let test_message = "benchmark_test_message";
        
        for _ in 0..samples {
            let start = Instant::now();
            
            let response = self.client
                .post(&format!("{}/echo", url))
                .json(&serde_json::json!({"message": test_message}))
                .send()
                .await?;
            
            if response.status().is_success() {
                times.push(start.elapsed());
            }
        }
        
        Ok(times)
    }

    async fn measure_echo_throughput(&self, url: &str, requests: usize) -> Result<f64> {
        let start = Instant::now();
        let mut successful_requests = 0;
        let test_message = "throughput_test";

        // Use semaphore to control concurrency
        let semaphore = Arc::new(tokio::sync::Semaphore::new(50));
        let mut handles = Vec::new();

        for _ in 0..requests {
            let client = self.client.clone();
            let url = url.to_string();
            let semaphore = semaphore.clone();
            let message = test_message.to_string();

            let handle = tokio::spawn(async move {
                let _permit = semaphore.acquire().await.unwrap();
                client
                    .post(&format!("{}/echo", url))
                    .json(&serde_json::json!({"message": message}))
                    .send()
                    .await
                    .map(|r| r.status().is_success())
                    .unwrap_or(false)
            });
            
            handles.push(handle);
        }

        for handle in handles {
            if handle.await.unwrap_or(false) {
                successful_requests += 1;
            }
        }

        let elapsed = start.elapsed();
        Ok(successful_requests as f64 / elapsed.as_secs_f64())
    }

    async fn measure_concurrent_throughput(&self, concurrency: usize) -> Result<f64> {
        let duration = Duration::from_secs(30);
        let start = Instant::now();
        let mut total_requests = 0;

        let semaphore = Arc::new(tokio::sync::Semaphore::new(concurrency));
        let mut handles = Vec::new();

        // Find a working service endpoint
        let service_url = self.config.services.iter()
            .find(|s| s.name.contains("echo"))
            .map(|s| format!("http://{}:{}", s.host, s.port))
            .unwrap_or_else(|| "http://127.0.0.1:8081".to_string());

        while start.elapsed() < duration {
            let client = self.client.clone();
            let url = service_url.clone();
            let semaphore = semaphore.clone();

            let handle = tokio::spawn(async move {
                let _permit = semaphore.acquire().await.unwrap();
                client
                    .post(&format!("{}/echo", url))
                    .json(&serde_json::json!({"message": "concurrent_test"}))
                    .send()
                    .await
                    .map(|r| r.status().is_success())
                    .unwrap_or(false)
            });
            
            handles.push(handle);
            total_requests += 1;

            // Small delay to prevent overwhelming
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        let mut successful_requests = 0;
        for handle in handles {
            if handle.await.unwrap_or(false) {
                successful_requests += 1;
            }
        }

        Ok(successful_requests as f64 / duration.as_secs_f64())
    }

    async fn measure_mixed_workload_throughput(&self) -> Result<f64> {
        // Simulate mixed workload: 60% echo, 40% attestation
        let duration = Duration::from_secs(60);
        let start = Instant::now();
        let mut total_operations = 0;

        let echo_url = self.config.services.iter()
            .find(|s| s.name.contains("echo"))
            .map(|s| format!("http://{}:{}", s.host, s.port))
            .unwrap_or_else(|| "http://127.0.0.1:8081".to_string());

        let attestation_url = self.config.services.iter()
            .find(|s| s.name == "attestation-agent")
            .map(|s| format!("http://{}:{}", s.host, s.port))
            .unwrap_or_else(|| "http://127.0.0.1:8080".to_string());

        while start.elapsed() < duration {
            let operation_type = if total_operations % 10 < 6 { "echo" } else { "attestation" };
            
            match operation_type {
                "echo" => {
                    let _ = self.client
                        .post(&format!("{}/echo", echo_url))
                        .json(&serde_json::json!({"message": "mixed_workload"}))
                        .send()
                        .await;
                }
                "attestation" => {
                    let _ = self.client
                        .post(&format!("{}/generate", attestation_url))
                        .json(&serde_json::json!({"nonce": format!("mixed_{}", total_operations)}))
                        .send()
                        .await;
                }
                _ => unreachable!(),
            }
            
            total_operations += 1;
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        Ok(total_operations as f64 / duration.as_secs_f64())
    }

    async fn measure_memory_usage_under_load(&self, load_level: &str) -> Result<f64> {
        use sysinfo::{System, SystemExt, ProcessExt};
        
        let mut system = System::new_all();
        system.refresh_all();
        
        let initial_memory = system.used_memory();
        
        // Generate load based on level
        let (requests, concurrency) = match load_level {
            "light" => (100, 10),
            "medium" => (500, 25),
            "heavy" => (1000, 50),
            _ => (100, 10),
        };

        // Run load test
        let _ = self.measure_concurrent_throughput(concurrency).await;
        
        // Measure peak memory
        system.refresh_memory();
        let peak_memory = system.used_memory();
        
        Ok((peak_memory - initial_memory) as f64 / 1_048_576.0) // Convert to MB
    }

    async fn find_maximum_throughput(&self) -> Result<f64> {
        let mut max_throughput = 0.0;
        
        // Binary search for maximum sustainable throughput
        for concurrency in [10, 25, 50, 100, 200, 500] {
            let throughput = self.measure_concurrent_throughput(concurrency).await?;
            if throughput > max_throughput {
                max_throughput = throughput;
            } else {
                // Throughput is decreasing, we've likely hit the limit
                break;
            }
        }
        
        Ok(max_throughput)
    }

    async fn find_connection_limit(&self) -> Result<usize> {
        // Test increasing connection counts until failure
        for connections in [100, 500, 1000, 2000, 5000] {
            let success_rate = self.test_connection_limit(connections).await?;
            if success_rate < 0.95 {
                return Ok(connections / 2); // Return last successful level
            }
        }
        
        Ok(5000) // If we get here, limit is above 5000
    }

    async fn test_connection_limit(&self, target_connections: usize) -> Result<f64> {
        let service_url = self.config.services.iter()
            .find(|s| s.name.contains("echo"))
            .map(|s| format!("http://{}:{}", s.host, s.port))
            .unwrap_or_else(|| "http://127.0.0.1:8081".to_string());

        let mut handles = Vec::new();
        let start = Instant::now();

        for _ in 0..target_connections {
            let client = self.client.clone();
            let url = service_url.clone();

            let handle = tokio::spawn(async move {
                client
                    .post(&format!("{}/echo", url))
                    .json(&serde_json::json!({"message": "connection_test"}))
                    .send()
                    .await
                    .map(|r| r.status().is_success())
                    .unwrap_or(false)
            });
            
            handles.push(handle);
        }

        let mut successful = 0;
        for handle in handles {
            if handle.await.unwrap_or(false) {
                successful += 1;
            }
        }

        Ok(successful as f64 / target_connections as f64)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchmarkResult {
    pub test_name: String,
    pub metric_name: String,
    pub metric_type: String,
    pub value: f64,
    pub unit: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}