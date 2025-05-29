use chrono::{DateTime, Utc};
use log::{debug, error, info, warn};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;
use tokio::time::{timeout, Duration};

#[derive(Serialize, Deserialize, Debug)]
struct EchoMessage {
    content: String,
    timestamp: DateTime<Utc>,
    service_id: String,
    request_id: String,
    client_addr: String,
}

#[derive(Error, Debug)]
pub enum EchoServiceError {
    #[error("Network error: {0}")]
    NetworkError(String),

    #[error("Invalid input: {0}")]
    InvalidInput(String),

    #[error("Rate limit exceeded for client: {0}")]
    RateLimitExceeded(String),

    #[error("Service unavailable: {0}")]
    ServiceUnavailable(String),

    #[error("Timeout error: {0}")]
    Timeout(String),

    #[error("Internal error: {0}")]
    Internal(String),
}

#[derive(Clone)]
struct RateLimiter {
    requests: Arc<Mutex<HashMap<String, Vec<u64>>>>,
    max_requests: usize,
    window_seconds: u64,
}

impl RateLimiter {
    fn new(max_requests: usize, window_seconds: u64) -> Self {
        Self {
            requests: Arc::new(Mutex::new(HashMap::new())),
            max_requests,
            window_seconds,
        }
    }

    async fn check_rate_limit(&self, client_ip: &str) -> Result<(), EchoServiceError> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| EchoServiceError::Internal(format!("System time error: {}", e)))?
            .as_secs();

        let mut requests = self.requests.lock().await;

        // SECURITY FIX: Periodic garbage collection to prevent memory leaks
        // Clean up old entries for ALL clients, not just current one
        let cutoff_time = now.saturating_sub(self.window_seconds);
        requests.retain(|_, timestamps| {
            timestamps.retain(|&timestamp| timestamp >= cutoff_time);
            !timestamps.is_empty() // Remove clients with no recent requests
        });

        let client_requests = requests
            .entry(client_ip.to_string())
            .or_insert_with(Vec::new);

        // Additional cleanup for current client (should be redundant after above, but safe)
        client_requests.retain(|&timestamp| now - timestamp < self.window_seconds);

        if client_requests.len() >= self.max_requests {
            warn!("Rate limit exceeded for client: {}", client_ip);
            return Err(EchoServiceError::RateLimitExceeded(client_ip.to_string()));
        }

        client_requests.push(now);

        // Log memory usage periodically for monitoring
        if client_requests.len() == 1 && requests.len() % 100 == 0 {
            debug!("Rate limiter tracking {} clients", requests.len());
        }

        Ok(())
    }

    // Add periodic cleanup method for external use
    #[allow(dead_code)] // Will be used when periodic cleanup is implemented
    async fn cleanup_expired_entries(&self) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_else(|_| Duration::from_secs(0))
            .as_secs();

        let mut requests = self.requests.lock().await;
        let initial_count = requests.len();

        let cutoff_time = now.saturating_sub(self.window_seconds);
        requests.retain(|_, timestamps| {
            timestamps.retain(|&timestamp| timestamp >= cutoff_time);
            !timestamps.is_empty()
        });

        let cleaned_count = initial_count - requests.len();
        if cleaned_count > 0 {
            info!(
                "Rate limiter cleaned up {} expired client entries",
                cleaned_count
            );
        }
    }
}

struct RustTcpEchoServer {
    service_id: String,
    port: u16,
    rate_limiter: RateLimiter,
    max_message_size: usize,
    connection_timeout: Duration,
}

impl RustTcpEchoServer {
    fn new(port: u16) -> Self {
        Self {
            service_id: "rust-echo-v0.1.0".to_string(),
            port,
            rate_limiter: RateLimiter::new(100, 60), // 100 requests per minute
            max_message_size: 8192,                  // 8KB max message size
            connection_timeout: Duration::from_secs(30),
        }
    }

    #[allow(dead_code)] // Will be used when instance-based validation is needed
    fn validate_input(&self, input: &[u8]) -> Result<(), EchoServiceError> {
        // Check message size
        if input.len() > self.max_message_size {
            return Err(EchoServiceError::InvalidInput(format!(
                "Message too large: {} bytes (max: {})",
                input.len(),
                self.max_message_size
            )));
        }

        // Check for null bytes (potential binary attacks)
        if input.contains(&0) {
            return Err(EchoServiceError::InvalidInput(
                "Null bytes not allowed".to_string(),
            ));
        }

        // Validate UTF-8 encoding
        if std::str::from_utf8(input).is_err() {
            return Err(EchoServiceError::InvalidInput(
                "Invalid UTF-8 encoding".to_string(),
            ));
        }

        Ok(())
    }

    async fn start(&self) -> Result<(), Box<dyn std::error::Error>> {
        let addr = SocketAddr::from(([0, 0, 0, 0], self.port));
        let listener = TcpListener::bind(addr).await?;

        info!(
            "[{}] Rust TCP Echo Server started on port {}",
            Utc::now().format("%Y-%m-%d %H:%M:%S"),
            self.port
        );
        info!("Security settings:");
        info!("  Max message size: {} bytes", self.max_message_size);
        info!("  Rate limit: {} requests per minute", 100);
        info!("  Connection timeout: {:?}", self.connection_timeout);

        loop {
            match listener.accept().await {
                Ok((stream, addr)) => {
                    info!(
                        "[{}] New connection from {}",
                        Utc::now().format("%Y-%m-%d %H:%M:%S"),
                        addr
                    );

                    let service_id = self.service_id.clone();
                    let rate_limiter = self.rate_limiter.clone();
                    let max_message_size = self.max_message_size;
                    let connection_timeout = self.connection_timeout;

                    tokio::spawn(async move {
                        let client_ip = addr.ip().to_string();

                        // Check rate limit before processing
                        if let Err(e) = rate_limiter.check_rate_limit(&client_ip).await {
                            error!("Rate limit check failed for {}: {}", client_ip, e);
                            return;
                        }

                        let result = timeout(
                            connection_timeout,
                            Self::handle_client(stream, service_id, addr, max_message_size),
                        )
                        .await;

                        match result {
                            Ok(Ok(())) => debug!("Connection from {} completed successfully", addr),
                            Ok(Err(e)) => error!("Error handling client {}: {}", addr, e),
                            Err(_) => warn!("Connection from {} timed out", addr),
                        }
                    });
                }
                Err(e) => {
                    error!("Failed to accept connection: {}", e);
                    // Add backoff to prevent tight error loops
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            }
        }
    }

    async fn handle_client(
        mut stream: TcpStream,
        service_id: String,
        client_addr: SocketAddr,
        max_message_size: usize,
    ) -> Result<(), EchoServiceError> {
        let mut buffer = vec![0; max_message_size];
        let mut total_messages = 0;
        const MAX_MESSAGES_PER_CONNECTION: usize = 1000;

        loop {
            if total_messages >= MAX_MESSAGES_PER_CONNECTION {
                warn!(
                    "Maximum messages per connection reached for {}",
                    client_addr
                );
                break;
            }

            match stream.read(&mut buffer).await {
                Ok(0) => {
                    debug!("Connection from {} closed by client", client_addr);
                    break;
                }
                Ok(n) => {
                    let received_data = &buffer[..n];

                    // Validate input
                    if let Err(e) = Self::validate_input_static(received_data, max_message_size) {
                        error!("Input validation failed for {}: {}", client_addr, e);
                        // Send error response but don't close connection immediately
                        let error_msg = format!("ERROR: {}\n", e);
                        if let Err(write_err) = stream.write_all(error_msg.as_bytes()).await {
                            error!(
                                "Failed to send error response to {}: {}",
                                client_addr, write_err
                            );
                        }
                        continue;
                    }

                    let message = String::from_utf8_lossy(received_data);
                    let request_id = uuid::Uuid::new_v4().to_string();

                    let echo_msg = EchoMessage {
                        content: message.to_string(),
                        timestamp: Utc::now(),
                        service_id: service_id.clone(),
                        request_id: request_id.clone(),
                        client_addr: client_addr.to_string(),
                    };

                    debug!(
                        "[{}] Received message from {}: {} (request_id: {})",
                        echo_msg.timestamp.format("%Y-%m-%d %H:%M:%S"),
                        client_addr,
                        echo_msg.content.trim(),
                        request_id
                    );

                    // Echo back the original received data, not the re-encoded string
                    match stream.write_all(received_data).await {
                        Ok(()) => {
                            debug!(
                                "Response sent to {} (request_id: {})",
                                client_addr, request_id
                            );
                            total_messages += 1;
                        }
                        Err(e) => {
                            error!("Failed to send response to {}: {}", client_addr, e);
                            return Err(EchoServiceError::NetworkError(e.to_string()));
                        }
                    }
                }
                Err(e) => {
                    error!("Error reading from socket {}: {}", client_addr, e);
                    return Err(EchoServiceError::NetworkError(e.to_string()));
                }
            }
        }

        info!(
            "Connection from {} handled {} messages",
            client_addr, total_messages
        );
        Ok(())
    }

    fn validate_input_static(input: &[u8], max_size: usize) -> Result<(), EchoServiceError> {
        if input.len() > max_size {
            return Err(EchoServiceError::InvalidInput(format!(
                "Message too large: {} bytes (max: {})",
                input.len(),
                max_size
            )));
        }

        if input.contains(&0) {
            return Err(EchoServiceError::InvalidInput(
                "Null bytes not allowed".to_string(),
            ));
        }

        if std::str::from_utf8(input).is_err() {
            return Err(EchoServiceError::InvalidInput(
                "Invalid UTF-8 encoding".to_string(),
            ));
        }

        Ok(())
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    info!("BlocksenseOS Rust TCP Echo Service v0.1.0");
    info!("Async TCP echo service for TEE environment");
    info!("Security features enabled: input validation, rate limiting, timeouts");

    let server = RustTcpEchoServer::new(8081);

    // Graceful shutdown handling
    let shutdown_signal = async {
        tokio::signal::ctrl_c()
            .await
            .expect("Failed to install CTRL+C signal handler");
        info!("Shutdown signal received, stopping server...");
    };

    tokio::select! {
        result = server.start() => {
            if let Err(e) = result {
                error!("Server error: {}", e);
                return Err(e);
            }
        }
        _ = shutdown_signal => {
            info!("Server shutdown completed");
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use rstest::*;
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;
    use tokio::time::{timeout, Duration};

    #[fixture]
    fn test_server() -> RustTcpEchoServer {
        RustTcpEchoServer::new(0) // Use port 0 for testing (OS assigns available port)
    }

    #[fixture]
    async fn running_server() -> (RustTcpEchoServer, u16) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("Failed to bind test listener to available port");
        let port = listener
            .local_addr()
            .expect("Failed to get bound port for test listener")
            .port();

        // Start server in background
        let server_clone = RustTcpEchoServer::new(port);
        tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((stream, addr)) => {
                        let service_id = server_clone.service_id.clone();
                        let max_size = server_clone.max_message_size;
                        tokio::spawn(async move {
                            let _ = RustTcpEchoServer::handle_client(
                                stream, service_id, addr, max_size,
                            )
                            .await;
                        });
                    }
                    Err(_) => break,
                }
            }
        });

        // Give server time to start
        tokio::time::sleep(Duration::from_millis(100)).await;

        (RustTcpEchoServer::new(port), port)
    }

    #[tokio::test]
    async fn test_server_creation() {
        let server = test_server();
        assert_eq!(server.service_id, "rust-echo-v0.1.0");
        assert_eq!(server.max_message_size, 8192);
        assert_eq!(server.connection_timeout, Duration::from_secs(30));
    }

    #[tokio::test]
    async fn test_input_validation_valid() {
        let server = test_server();
        let large_message = vec![b'a'; 1000]; // Large but within limit
        let valid_inputs = vec![
            b"Hello, world!".as_slice(),
            b"Test message 123".as_slice(),
            b"UTF-8: \xc3\xa9\xc3\xa1\xc3\xad".as_slice(),
            &large_message,
        ];

        for input in valid_inputs {
            assert!(server.validate_input(input).is_ok());
        }
    }

    #[tokio::test]
    async fn test_input_validation_invalid() {
        let server = test_server();

        // Test oversized message
        let oversized = vec![b'a'; server.max_message_size + 1];
        assert!(matches!(
            server.validate_input(&oversized),
            Err(EchoServiceError::InvalidInput(_))
        ));

        // Test null bytes
        let with_null = b"hello\x00world";
        assert!(matches!(
            server.validate_input(with_null),
            Err(EchoServiceError::InvalidInput(_))
        ));

        // Test invalid UTF-8
        let invalid_utf8 = &[0xff, 0xfe, 0xfd];
        assert!(matches!(
            server.validate_input(invalid_utf8),
            Err(EchoServiceError::InvalidInput(_))
        ));
    }

    #[tokio::test]
    async fn test_rate_limiter() {
        let rate_limiter = RateLimiter::new(2, 60); // 2 requests per minute
        let client_ip = "127.0.0.1";

        // First two requests should succeed
        assert!(rate_limiter.check_rate_limit(client_ip).await.is_ok());
        assert!(rate_limiter.check_rate_limit(client_ip).await.is_ok());

        // Third request should fail
        assert!(matches!(
            rate_limiter.check_rate_limit(client_ip).await,
            Err(EchoServiceError::RateLimitExceeded(_))
        ));
    }

    #[tokio::test]
    async fn test_rate_limiter_different_clients() {
        let rate_limiter = RateLimiter::new(1, 60);

        // Different clients should have separate rate limits
        assert!(rate_limiter.check_rate_limit("127.0.0.1").await.is_ok());
        assert!(rate_limiter.check_rate_limit("127.0.0.2").await.is_ok());

        // But same client should be rate limited
        assert!(matches!(
            rate_limiter.check_rate_limit("127.0.0.1").await,
            Err(EchoServiceError::RateLimitExceeded(_))
        ));
    }

    #[tokio::test]
    async fn test_echo_functionality() {
        let (_server, port) = running_server().await;

        // Test basic echo functionality
        let mut stream = tokio::net::TcpStream::connect(format!("127.0.0.1:{}", port))
            .await
            .expect("Failed to connect to test service");

        let test_message = b"Hello, World!\n";
        stream
            .write_all(test_message)
            .await
            .expect("Failed to write test message");

        let mut buffer = [0; 1024];
        let n = stream
            .read(&mut buffer)
            .await
            .expect("Failed to read response from test service");

        let response = std::str::from_utf8(&buffer[..n]).expect("Response should be valid UTF-8");
        assert_eq!(response, "Hello, World!\n"); // Direct echo, not prefixed

        // Test that the connection is still alive for multiple messages
        let test_message2 = b"Second message";
        stream
            .write_all(test_message2)
            .await
            .expect("Failed to write second test message");

        let n2 = stream
            .read(&mut buffer)
            .await
            .expect("Failed to read second response from test service");

        let response2 =
            std::str::from_utf8(&buffer[..n2]).expect("Second response should be valid UTF-8");
        assert_eq!(response2, "Second message");
    }

    #[tokio::test]
    async fn test_multiple_messages() {
        let (_server, port) = running_server().await;

        let mut stream = TcpStream::connect(format!("127.0.0.1:{}", port))
            .await
            .expect("Failed to connect to test server for multiple messages test");

        let messages = vec!["Message 1", "Message 2", "Message 3"];

        for message in &messages {
            stream
                .write_all(message.as_bytes())
                .await
                .expect("Failed to write test message to stream");

            let mut buffer = vec![0; 1024];
            let n = timeout(Duration::from_secs(5), stream.read(&mut buffer))
                .await
                .expect("Test read operation should not timeout")
                .expect("Failed to read response from test stream");

            let response = String::from_utf8_lossy(&buffer[..n]);
            assert!(response.contains(message));
        }
    }

    #[tokio::test]
    async fn test_concurrent_connections() {
        let (_server, port) = running_server().await;

        let mut handles = vec![];

        for i in 0..10 {
            let handle = tokio::spawn(async move {
                let mut stream = TcpStream::connect(format!("127.0.0.1:{}", port))
                    .await
                    .expect("Failed to connect to test server for concurrent connection test");
                let message = format!("Message from connection {}", i);

                stream
                    .write_all(message.as_bytes())
                    .await
                    .expect("Failed to write concurrent test message");

                let mut buffer = vec![0; 1024];
                let n = timeout(Duration::from_secs(5), stream.read(&mut buffer))
                    .await
                    .expect("Concurrent test read should not timeout")
                    .expect("Failed to read concurrent test response");

                let response = String::from_utf8_lossy(&buffer[..n]);
                assert!(response.contains(&message));
            });
            handles.push(handle);
        }

        for handle in handles {
            handle
                .await
                .expect("Concurrent connection test task should complete successfully");
        }
    }

    #[tokio::test]
    async fn test_large_message_handling() {
        let (_server, port) = running_server().await;

        let mut stream = TcpStream::connect(format!("127.0.0.1:{}", port))
            .await
            .expect("Failed to connect to test server for large message test");

        // Send a large but valid message
        let large_message = "A".repeat(4096);
        stream
            .write_all(large_message.as_bytes())
            .await
            .expect("Failed to write large test message");

        let mut buffer = vec![0; 8192];
        let n = timeout(Duration::from_secs(5), stream.read(&mut buffer))
            .await
            .expect("Large message test read should not timeout")
            .expect("Failed to read large message test response");

        let response = String::from_utf8_lossy(&buffer[..n]);
        assert!(response.contains(&large_message));
    }

    #[tokio::test]
    async fn test_invalid_message_handling() {
        let (_server, port) = running_server().await;

        let mut stream = TcpStream::connect(format!("127.0.0.1:{}", port))
            .await
            .expect("Failed to connect to test server for invalid message test");

        // Send message with null bytes
        let invalid_message = b"Hello\x00World";
        stream
            .write_all(invalid_message)
            .await
            .expect("Failed to write invalid test message");

        let mut buffer = vec![0; 1024];
        let n = timeout(Duration::from_secs(5), stream.read(&mut buffer))
            .await
            .expect("Invalid message test read should not timeout")
            .expect("Failed to read invalid message test response");

        let response = String::from_utf8_lossy(&buffer[..n]);
        assert!(response.contains("ERROR"));
    }

    #[tokio::test]
    async fn test_connection_timeout() {
        let (_server, port) = running_server().await;

        let stream = TcpStream::connect(format!("127.0.0.1:{}", port))
            .await
            .expect("Failed to connect to test server for timeout test");

        // Don't send anything, just hold the connection
        // The server should handle this gracefully
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Connection should still be valid for a short time
        drop(stream);
    }

    #[rstest]
    #[case(b"simple message")]
    #[case(b"message with numbers 12345")]
    #[case(b"UTF-8: hello world")]
    #[tokio::test]
    async fn test_echo_with_different_inputs(#[case] input: &[u8]) {
        let (_server, port) = running_server().await;

        let mut stream = TcpStream::connect(format!("127.0.0.1:{}", port))
            .await
            .expect("Failed to connect to test server for input variation test");

        stream
            .write_all(input)
            .await
            .expect("Failed to write test input variation");

        let mut buffer = vec![0; 1024];
        let n = timeout(Duration::from_secs(5), stream.read(&mut buffer))
            .await
            .expect("Input variation test read should not timeout")
            .expect("Failed to read input variation test response");

        let response = String::from_utf8_lossy(&buffer[..n]);
        let input_str = String::from_utf8_lossy(input);
        assert!(response.contains(input_str.as_ref()));
    }

    // Property-based tests
    proptest! {
        #[test]
        fn test_input_validation_properties(
            message_len in 1usize..4096,
            use_valid_utf8 in any::<bool>()
        ) {
            let server = RustTcpEchoServer::new(8081);

            let message = if use_valid_utf8 {
                "a".repeat(message_len).into_bytes()
            } else {
                vec![b'a'; message_len]
            };

            let result = server.validate_input(&message);

            if message_len <= server.max_message_size && !message.contains(&0) {
                if use_valid_utf8 {
                    prop_assert!(result.is_ok());
                }
            }
        }

        #[test]
        fn test_rate_limiter_properties(
            max_requests in 1usize..10,
            window_seconds in 1u64..60
        ) {
            tokio_test::block_on(async {
                let rate_limiter = RateLimiter::new(max_requests, window_seconds);
                let client_ip = "127.0.0.1";

                // Should allow up to max_requests
                for _ in 0..max_requests {
                    prop_assert!(rate_limiter.check_rate_limit(client_ip).await.is_ok());
                }

                // Next request should fail
                prop_assert!(rate_limiter.check_rate_limit(client_ip).await.is_err());

                Ok(())
            })?;
        }
    }

    #[tokio::test]
    async fn test_error_display() {
        let errors = vec![
            EchoServiceError::NetworkError("test".to_string()),
            EchoServiceError::InvalidInput("test".to_string()),
            EchoServiceError::RateLimitExceeded("127.0.0.1".to_string()),
            EchoServiceError::ServiceUnavailable("test".to_string()),
            EchoServiceError::Timeout("test".to_string()),
            EchoServiceError::Internal("test".to_string()),
        ];

        for error in errors {
            let error_string = format!("{}", error);
            assert!(!error_string.is_empty());
            assert!(error_string.len() > 5); // Ensure meaningful error messages
        }
    }

    #[tokio::test]
    async fn test_message_structure() {
        let message = EchoMessage {
            content: "test".to_string(),
            timestamp: Utc::now(),
            service_id: "test-service".to_string(),
            request_id: "test-id".to_string(),
            client_addr: "127.0.0.1:12345".to_string(),
        };

        // Test serialization
        let json =
            serde_json::to_string(&message).expect("Test message serialization should never fail");
        assert!(json.contains("test"));
        assert!(json.contains("test-service"));

        // Test deserialization
        let deserialized: EchoMessage = serde_json::from_str(&json)
            .expect("Test message deserialization should never fail with valid JSON");
        assert_eq!(deserialized.content, message.content);
        assert_eq!(deserialized.service_id, message.service_id);
    }

    #[tokio::test]
    async fn test_static_validation_function() {
        // Test the static validation function directly
        assert!(RustTcpEchoServer::validate_input_static(b"valid message", 8192).is_ok());
        assert!(RustTcpEchoServer::validate_input_static(&vec![b'a'; 10000], 8192).is_err());
        assert!(RustTcpEchoServer::validate_input_static(b"invalid\x00message", 8192).is_err());
    }

    #[tokio::test]
    async fn test_rate_limiter_garbage_collection() {
        let rate_limiter = RateLimiter::new(1, 1); // 1 request per second for quick testing

        // Add some requests
        assert!(rate_limiter.check_rate_limit("client1").await.is_ok());
        assert!(rate_limiter.check_rate_limit("client2").await.is_ok());

        // Wait a bit and add more requests to trigger cleanup
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Should still work for new clients
        assert!(rate_limiter.check_rate_limit("client3").await.is_ok());
    }
}
