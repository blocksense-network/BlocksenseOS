use anyhow::Result;
use chrono::{DateTime, Utc};
use metrics::{counter, gauge, histogram, register_counter, register_gauge, register_histogram};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricPoint {
    pub timestamp: DateTime<Utc>,
    pub name: String,
    pub value: f64,
    pub labels: HashMap<String, String>,
    pub metric_type: MetricType,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MetricType {
    Counter,
    Gauge,
    Histogram,
}

#[derive(Debug, Default)]
pub struct MetricsCollector {
    metrics: Arc<RwLock<Vec<MetricPoint>>>,
    retention_hours: u64,
}

impl MetricsCollector {
    pub fn new(retention_hours: u64) -> Self {
        Self {
            metrics: Arc::new(RwLock::new(Vec::new())),
            retention_hours,
        }
    }

    pub async fn record_counter(&self, name: &str, value: f64, labels: HashMap<String, String>) {
        let metric = MetricPoint {
            timestamp: Utc::now(),
            name: name.to_string(),
            value,
            labels: labels.clone(),
            metric_type: MetricType::Counter,
        };

        self.metrics.write().await.push(metric);
        
        // Record to metrics registry
        let label_str = format_labels(&labels);
        counter!(name, value, &label_str);
    }

    pub async fn record_gauge(&self, name: &str, value: f64, labels: HashMap<String, String>) {
        let metric = MetricPoint {
            timestamp: Utc::now(),
            name: name.to_string(),
            value,
            labels: labels.clone(),
            metric_type: MetricType::Gauge,
        };

        self.metrics.write().await.push(metric);
        
        // Record to metrics registry
        let label_str = format_labels(&labels);
        gauge!(name, value, &label_str);
    }

    pub async fn record_histogram(&self, name: &str, value: f64, labels: HashMap<String, String>) {
        let metric = MetricPoint {
            timestamp: Utc::now(),
            name: name.to_string(),
            value,
            labels: labels.clone(),
            metric_type: MetricType::Histogram,
        };

        self.metrics.write().await.push(metric);
        
        // Record to metrics registry
        let label_str = format_labels(&labels);
        histogram!(name, value, &label_str);
    }

    pub async fn get_metrics(&self) -> Vec<MetricPoint> {
        self.metrics.read().await.clone()
    }

    pub async fn get_metrics_by_name(&self, name: &str) -> Vec<MetricPoint> {
        self.metrics
            .read()
            .await
            .iter()
            .filter(|m| m.name == name)
            .cloned()
            .collect()
    }

    pub async fn cleanup_old_metrics(&self) {
        let cutoff = Utc::now() - chrono::Duration::hours(self.retention_hours as i64);
        
        let mut metrics = self.metrics.write().await;
        metrics.retain(|m| m.timestamp > cutoff);
    }

    pub async fn get_latest_by_name(&self, name: &str) -> Option<MetricPoint> {
        self.metrics
            .read()
            .await
            .iter()
            .filter(|m| m.name == name)
            .max_by_key(|m| m.timestamp)
            .cloned()
    }

    pub async fn get_statistics(&self, name: &str) -> Option<MetricStatistics> {
        let metrics = self.get_metrics_by_name(name).await;
        if metrics.is_empty() {
            return None;
        }

        let values: Vec<f64> = metrics.iter().map(|m| m.value).collect();
        let len = values.len() as f64;
        let sum: f64 = values.iter().sum();
        let mean = sum / len;

        let mut sorted_values = values.clone();
        sorted_values.sort_by(|a, b| a.partial_cmp(b).unwrap());

        let median = if sorted_values.len() % 2 == 0 {
            let mid = sorted_values.len() / 2;
            (sorted_values[mid - 1] + sorted_values[mid]) / 2.0
        } else {
            sorted_values[sorted_values.len() / 2]
        };

        let variance = values.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / len;
        let std_dev = variance.sqrt();

        let min = sorted_values.first().copied().unwrap_or(0.0);
        let max = sorted_values.last().copied().unwrap_or(0.0);

        // Percentiles
        let p95_idx = ((sorted_values.len() as f64) * 0.95) as usize;
        let p99_idx = ((sorted_values.len() as f64) * 0.99) as usize;
        let p95 = sorted_values.get(p95_idx.saturating_sub(1)).copied().unwrap_or(max);
        let p99 = sorted_values.get(p99_idx.saturating_sub(1)).copied().unwrap_or(max);

        Some(MetricStatistics {
            count: metrics.len(),
            sum,
            mean,
            median,
            std_dev,
            min,
            max,
            p95,
            p99,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricStatistics {
    pub count: usize,
    pub sum: f64,
    pub mean: f64,
    pub median: f64,
    pub std_dev: f64,
    pub min: f64,
    pub max: f64,
    pub p95: f64,
    pub p99: f64,
}

pub fn register_metrics() {
    // System metrics
    register_gauge!("system_cpu_usage_percent", "CPU usage percentage");
    register_gauge!("system_memory_usage_percent", "Memory usage percentage");
    register_gauge!("system_disk_usage_percent", "Disk usage percentage");
    register_gauge!("system_load_average_1m", "1-minute load average");
    register_gauge!("system_load_average_5m", "5-minute load average");
    register_gauge!("system_load_average_15m", "15-minute load average");

    // Network metrics
    register_counter!("network_bytes_sent_total", "Total bytes sent");
    register_counter!("network_bytes_received_total", "Total bytes received");
    register_counter!("network_packets_sent_total", "Total packets sent");
    register_counter!("network_packets_received_total", "Total packets received");

    // Service metrics
    register_histogram!("service_response_time_ms", "Service response time in milliseconds");
    register_counter!("service_requests_total", "Total service requests");
    register_counter!("service_errors_total", "Total service errors");
    register_gauge!("service_active_connections", "Active service connections");

    // Process metrics
    register_gauge!("process_cpu_usage_percent", "Process CPU usage percentage");
    register_gauge!("process_memory_usage_bytes", "Process memory usage in bytes");
    register_gauge!("process_open_file_descriptors", "Process open file descriptors");
    register_gauge!("process_threads", "Process thread count");
}

fn format_labels(labels: &HashMap<String, String>) -> Vec<String> {
    labels
        .iter()
        .map(|(k, v)| format!("{}={}", k, v))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::{sleep, Duration};

    #[tokio::test]
    async fn test_metrics_collection() {
        let collector = MetricsCollector::new(24);
        let mut labels = HashMap::new();
        labels.insert("service".to_string(), "test".to_string());

        collector.record_gauge("test_metric", 42.0, labels.clone()).await;
        collector.record_counter("test_counter", 1.0, labels.clone()).await;

        let metrics = collector.get_metrics().await;
        assert_eq!(metrics.len(), 2);

        let gauge_metrics = collector.get_metrics_by_name("test_metric").await;
        assert_eq!(gauge_metrics.len(), 1);
        assert_eq!(gauge_metrics[0].value, 42.0);
    }

    #[tokio::test]
    async fn test_metrics_statistics() {
        let collector = MetricsCollector::new(24);
        let labels = HashMap::new();

        // Add some test data
        for i in 1..=10 {
            collector.record_gauge("test_stats", i as f64, labels.clone()).await;
        }

        let stats = collector.get_statistics("test_stats").await.unwrap();
        assert_eq!(stats.count, 10);
        assert_eq!(stats.min, 1.0);
        assert_eq!(stats.max, 10.0);
        assert_eq!(stats.mean, 5.5);
    }

    #[tokio::test]
    async fn test_metrics_cleanup() {
        let collector = MetricsCollector::new(0); // 0 hours retention
        let labels = HashMap::new();

        collector.record_gauge("test_cleanup", 1.0, labels).await;
        assert_eq!(collector.get_metrics().await.len(), 1);

        // Sleep a bit to ensure timestamp difference
        sleep(Duration::from_millis(10)).await;
        
        collector.cleanup_old_metrics().await;
        assert_eq!(collector.get_metrics().await.len(), 0);
    }
}