use crate::metrics::MetricsCollector;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use sysinfo::{CpuExt, DiskExt, NetworkExt, ProcessExt, System, SystemExt};
use tokio::time::{interval, Duration};
use tracing::{debug, error, info};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemMetrics {
    pub cpu_usage: f64,
    pub memory_usage: f64,
    pub memory_total: u64,
    pub memory_used: u64,
    pub disk_usage: HashMap<String, DiskMetrics>,
    pub network_stats: NetworkMetrics,
    pub load_average: LoadAverage,
    pub process_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiskMetrics {
    pub usage_percent: f64,
    pub total_space: u64,
    pub used_space: u64,
    pub available_space: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkMetrics {
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub packets_sent: u64,
    pub packets_received: u64,
    pub errors_on_sent: u64,
    pub errors_on_received: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoadAverage {
    pub one_minute: f64,
    pub five_minutes: f64,
    pub fifteen_minutes: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessMetrics {
    pub pid: u32,
    pub name: String,
    pub cpu_usage: f32,
    pub memory_usage: u64,
    pub virtual_memory: u64,
    pub status: String,
    pub start_time: u64,
}

pub struct SystemMonitor {
    system: System,
    metrics_collector: Arc<MetricsCollector>,
    monitoring_interval: Duration,
}

impl SystemMonitor {
    pub fn new(
        metrics_collector: Arc<MetricsCollector>,
        monitoring_interval: Duration,
    ) -> Self {
        let mut system = System::new_all();
        system.refresh_all();

        Self {
            system,
            metrics_collector,
            monitoring_interval,
        }
    }

    pub async fn start_monitoring(&mut self) -> Result<()> {
        info!("Starting system monitoring");
        let mut interval = interval(self.monitoring_interval);

        loop {
            interval.tick().await;

            if let Err(e) = self.collect_system_metrics().await {
                error!("Failed to collect system metrics: {}", e);
            }

            if let Err(e) = self.collect_process_metrics().await {
                error!("Failed to collect process metrics: {}", e);
            }

            // Cleanup old metrics periodically
            self.metrics_collector.cleanup_old_metrics().await;
        }
    }

    async fn collect_system_metrics(&mut self) -> Result<()> {
        self.system.refresh_all();

        // CPU metrics
        let cpu_usage = self.system.global_cpu_info().cpu_usage() as f64;
        self.metrics_collector
            .record_gauge("system_cpu_usage_percent", cpu_usage, HashMap::new())
            .await;

        debug!("CPU usage: {:.2}%", cpu_usage);

        // Memory metrics
        let total_memory = self.system.total_memory();
        let used_memory = self.system.used_memory();
        let memory_usage_percent = (used_memory as f64 / total_memory as f64) * 100.0;

        self.metrics_collector
            .record_gauge("system_memory_usage_percent", memory_usage_percent, HashMap::new())
            .await;

        self.metrics_collector
            .record_gauge("system_memory_total_bytes", total_memory as f64, HashMap::new())
            .await;

        self.metrics_collector
            .record_gauge("system_memory_used_bytes", used_memory as f64, HashMap::new())
            .await;

        debug!("Memory usage: {:.2}% ({} MB / {} MB)", 
               memory_usage_percent, 
               used_memory / 1024 / 1024, 
               total_memory / 1024 / 1024);

        // Disk metrics
        for disk in self.system.disks() {
            let disk_name = disk.name().to_string_lossy().to_string();
            let total_space = disk.total_space();
            let available_space = disk.available_space();
            let used_space = total_space - available_space;
            let usage_percent = if total_space > 0 {
                (used_space as f64 / total_space as f64) * 100.0
            } else {
                0.0
            };

            let mut labels = HashMap::new();
            labels.insert("disk".to_string(), disk_name.clone());

            self.metrics_collector
                .record_gauge("system_disk_usage_percent", usage_percent, labels.clone())
                .await;

            self.metrics_collector
                .record_gauge("system_disk_total_bytes", total_space as f64, labels.clone())
                .await;

            self.metrics_collector
                .record_gauge("system_disk_used_bytes", used_space as f64, labels.clone())
                .await;

            debug!("Disk {} usage: {:.2}% ({} GB / {} GB)", 
                   disk_name, usage_percent, 
                   used_space / 1024 / 1024 / 1024, 
                   total_space / 1024 / 1024 / 1024);
        }

        // Load average
        let load_avg = self.system.load_average();
        self.metrics_collector
            .record_gauge("system_load_average_1m", load_avg.one, HashMap::new())
            .await;

        self.metrics_collector
            .record_gauge("system_load_average_5m", load_avg.five, HashMap::new())
            .await;

        self.metrics_collector
            .record_gauge("system_load_average_15m", load_avg.fifteen, HashMap::new())
            .await;

        debug!("Load average: {:.2} {:.2} {:.2}", load_avg.one, load_avg.five, load_avg.fifteen);

        // Network metrics
        let mut total_bytes_sent = 0u64;
        let mut total_bytes_received = 0u64;
        let mut total_packets_sent = 0u64;
        let mut total_packets_received = 0u64;
        let mut total_errors_sent = 0u64;
        let mut total_errors_received = 0u64;

        for (interface_name, network) in self.system.networks() {
            let mut labels = HashMap::new();
            labels.insert("interface".to_string(), interface_name.clone());

            self.metrics_collector
                .record_counter("network_bytes_sent_total", network.total_transmitted() as f64, labels.clone())
                .await;

            self.metrics_collector
                .record_counter("network_bytes_received_total", network.total_received() as f64, labels.clone())
                .await;

            self.metrics_collector
                .record_counter("network_packets_sent_total", network.total_packets_transmitted() as f64, labels.clone())
                .await;

            self.metrics_collector
                .record_counter("network_packets_received_total", network.total_packets_received() as f64, labels.clone())
                .await;

            self.metrics_collector
                .record_counter("network_errors_sent_total", network.total_errors_on_transmitted() as f64, labels.clone())
                .await;

            self.metrics_collector
                .record_counter("network_errors_received_total", network.total_errors_on_received() as f64, labels)
                .await;

            total_bytes_sent += network.total_transmitted();
            total_bytes_received += network.total_received();
            total_packets_sent += network.total_packets_transmitted();
            total_packets_received += network.total_packets_received();
            total_errors_sent += network.total_errors_on_transmitted();
            total_errors_received += network.total_errors_on_received();
        }

        // Total network metrics
        self.metrics_collector
            .record_counter("network_total_bytes_sent", total_bytes_sent as f64, HashMap::new())
            .await;

        self.metrics_collector
            .record_counter("network_total_bytes_received", total_bytes_received as f64, HashMap::new())
            .await;

        debug!("Network total: sent {} MB, received {} MB", 
               total_bytes_sent / 1024 / 1024, 
               total_bytes_received / 1024 / 1024);

        Ok(())
    }

    async fn collect_process_metrics(&mut self) -> Result<()> {
        self.system.refresh_processes();

        let process_count = self.system.processes().len();
        self.metrics_collector
            .record_gauge("system_process_count", process_count as f64, HashMap::new())
            .await;

        // Track specific BlocksenseOS processes
        let blocksense_processes = [
            "rust-echo-service",
            "cpp-echo-service", 
            "attestation-agent",
            "derivation-hasher",
            "performance-monitor",
        ];

        for process_name in &blocksense_processes {
            if let Some(process) = self.find_process_by_name(process_name) {
                let mut labels = HashMap::new();
                labels.insert("process".to_string(), process_name.to_string());
                labels.insert("pid".to_string(), process.pid().to_string());

                self.metrics_collector
                    .record_gauge("process_cpu_usage_percent", process.cpu_usage() as f64, labels.clone())
                    .await;

                self.metrics_collector
                    .record_gauge("process_memory_usage_bytes", process.memory() as f64, labels.clone())
                    .await;

                self.metrics_collector
                    .record_gauge("process_virtual_memory_bytes", process.virtual_memory() as f64, labels.clone())
                    .await;

                debug!("Process {}: CPU {:.2}%, Memory {} MB", 
                       process_name, 
                       process.cpu_usage(), 
                       process.memory() / 1024 / 1024);
            }
        }

        Ok(())
    }

    fn find_process_by_name(&self, name: &str) -> Option<&sysinfo::Process> {
        self.system
            .processes()
            .values()
            .find(|process| process.name().contains(name))
    }

    pub fn get_current_metrics(&mut self) -> SystemMetrics {
        self.system.refresh_all();

        let cpu_usage = self.system.global_cpu_info().cpu_usage() as f64;
        let total_memory = self.system.total_memory();
        let used_memory = self.system.used_memory();
        let memory_usage = (used_memory as f64 / total_memory as f64) * 100.0;

        let mut disk_usage = HashMap::new();
        for disk in self.system.disks() {
            let disk_name = disk.name().to_string_lossy().to_string();
            let total_space = disk.total_space();
            let available_space = disk.available_space();
            let used_space = total_space - available_space;
            let usage_percent = if total_space > 0 {
                (used_space as f64 / total_space as f64) * 100.0
            } else {
                0.0
            };

            disk_usage.insert(disk_name, DiskMetrics {
                usage_percent,
                total_space,
                used_space,
                available_space,
            });
        }

        let mut total_bytes_sent = 0u64;
        let mut total_bytes_received = 0u64;
        let mut total_packets_sent = 0u64;
        let mut total_packets_received = 0u64;
        let mut total_errors_sent = 0u64;
        let mut total_errors_received = 0u64;

        for (_, network) in self.system.networks() {
            total_bytes_sent += network.total_transmitted();
            total_bytes_received += network.total_received();
            total_packets_sent += network.total_packets_transmitted();
            total_packets_received += network.total_packets_received();
            total_errors_sent += network.total_errors_on_transmitted();
            total_errors_received += network.total_errors_on_received();
        }

        let load_avg = self.system.load_average();

        SystemMetrics {
            cpu_usage,
            memory_usage,
            memory_total: total_memory,
            memory_used: used_memory,
            disk_usage,
            network_stats: NetworkMetrics {
                bytes_sent: total_bytes_sent,
                bytes_received: total_bytes_received,
                packets_sent: total_packets_sent,
                packets_received: total_packets_received,
                errors_on_sent: total_errors_sent,
                errors_on_received: total_errors_received,
            },
            load_average: LoadAverage {
                one_minute: load_avg.one,
                five_minutes: load_avg.five,
                fifteen_minutes: load_avg.fifteen,
            },
            process_count: self.system.processes().len(),
        }
    }

    pub fn get_process_metrics(&self, process_name: &str) -> Option<ProcessMetrics> {
        if let Some(process) = self.find_process_by_name(process_name) {
            Some(ProcessMetrics {
                pid: process.pid().as_u32(),
                name: process.name().to_string(),
                cpu_usage: process.cpu_usage(),
                memory_usage: process.memory(),
                virtual_memory: process.virtual_memory(),
                status: format!("{:?}", process.status()),
                start_time: process.start_time(),
            })
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::Duration;

    #[tokio::test]
    async fn test_system_metrics_collection() {
        let collector = Arc::new(MetricsCollector::new(24));
        let mut monitor = SystemMonitor::new(collector.clone(), Duration::from_secs(1));

        // Test single collection
        assert!(monitor.collect_system_metrics().await.is_ok());

        // Verify some metrics were collected
        let metrics = collector.get_metrics().await;
        assert!(!metrics.is_empty());

        // Check for expected metric names
        let metric_names: Vec<String> = metrics.iter().map(|m| m.name.clone()).collect();
        assert!(metric_names.contains(&"system_cpu_usage_percent".to_string()));
        assert!(metric_names.contains(&"system_memory_usage_percent".to_string()));
    }

    #[test]
    fn test_get_current_metrics() {
        let collector = Arc::new(MetricsCollector::new(24));
        let mut monitor = SystemMonitor::new(collector, Duration::from_secs(1));

        let metrics = monitor.get_current_metrics();
        
        assert!(metrics.cpu_usage >= 0.0);
        assert!(metrics.memory_usage >= 0.0);
        assert!(metrics.memory_total > 0);
        assert!(metrics.process_count > 0);
    }
}