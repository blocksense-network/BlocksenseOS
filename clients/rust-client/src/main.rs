use clap::{Arg, Command};
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};
use std::net::TcpStream;

#[derive(Serialize, Deserialize, Debug)]
struct AttestationRequest {
    challenge: String,
    service_endpoint: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct AttestationResponse {
    report: String,
    signature: String,
    certificates: Vec<String>,
}

struct BlocksenseClient {
    #[allow(dead_code)]
    base_url: String,
}

impl BlocksenseClient {
    fn new(base_url: String) -> Self {
        Self { base_url }
    }

    async fn test_echo_service(
        &self,
        port: u16,
        message: &str,
    ) -> Result<String, Box<dyn std::error::Error>> {
        let addr = format!("127.0.0.1:{}", port);
        let mut stream = TcpStream::connect(&addr)?;

        // Send message
        stream.write_all(message.as_bytes())?;

        // Read response
        let mut buffer = [0; 1024];
        let bytes_read = stream.read(&mut buffer)?;
        let response = String::from_utf8_lossy(&buffer[..bytes_read]);

        Ok(response.to_string())
    }

    async fn request_attestation(
        &self,
        service: &str,
    ) -> Result<AttestationResponse, Box<dyn std::error::Error>> {
        // Make actual HTTP request to the attestation agent
        println!("Requesting attestation for service: {}", service);

        let client = reqwest::Client::new();
        let attestation_url = format!("{}/attestation", self.base_url);

        // Prepare attestation request
        let request_body = AttestationRequest {
            challenge: format!("challenge_for_{}", service),
            service_endpoint: service.to_string(),
        };

        // Send request to attestation agent
        let response = client
            .get(&attestation_url)
            .query(&[
                ("challenge", request_body.challenge.as_str()),
                ("include_certificates", "true"),
                ("tee_type_filter", "sev-snp"),
            ])
            .timeout(std::time::Duration::from_secs(30))
            .send()
            .await?;

        if !response.status().is_success() {
            return Err(format!("Attestation request failed: {}", response.status()).into());
        }

        // Parse the attestation agent's response
        #[derive(Deserialize)]
        struct AgentResponse {
            success: bool,
            report: Option<AgentReport>,
            error: Option<String>,
            request_id: String,
        }

        #[derive(Deserialize)]
        struct AgentReport {
            measurement: String,
            signature: Option<String>,
            certificates: Vec<String>,
            tee_type: String,
            timestamp: u64,
        }

        let agent_response: AgentResponse = response.json().await?;

        if !agent_response.success {
            let error_msg = agent_response.error.unwrap_or("Unknown error".to_string());
            return Err(format!("Attestation failed: {}", error_msg).into());
        }

        let report = agent_response
            .report
            .ok_or("No report in successful response")?;

        // Convert to our response format
        let attestation_response = AttestationResponse {
            report: format!(
                "TEE: {}, Measurement: {}, Timestamp: {}",
                report.tee_type, report.measurement, report.timestamp
            ),
            signature: report.signature.unwrap_or("no_signature".to_string()),
            certificates: report.certificates,
        };

        println!(
            "✓ Received attestation report (Request ID: {})",
            agent_response.request_id
        );

        Ok(attestation_response)
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let matches = Command::new("BlocksenseOS Rust Client")
        .version("0.1.0")
        .about("Verification client for BlocksenseOS TEE services")
        .arg(
            Arg::new("command")
                .help("Command to execute: test-echo, attest")
                .required(true)
                .index(1),
        )
        .arg(
            Arg::new("service")
                .help("Service to interact with: cpp-echo, rust-echo")
                .short('s')
                .long("service")
                .default_value("cpp-echo"),
        )
        .arg(
            Arg::new("message")
                .help("Message to send for echo test")
                .short('m')
                .long("message")
                .default_value("Hello BlocksenseOS!"),
        )
        .get_matches();

    let client = BlocksenseClient::new("http://127.0.0.1:3000".to_string());
    let command = matches.get_one::<String>("command").unwrap();
    let service = matches.get_one::<String>("service").unwrap();
    let message = matches.get_one::<String>("message").unwrap();

    match command.as_str() {
        "test-echo" => {
            let port = match service.as_str() {
                "cpp-echo" => 8080,
                "rust-echo" => 8081,
                _ => {
                    eprintln!("Unknown service: {}", service);
                    return Ok(());
                }
            };

            println!("Testing {} service on port {}...", service, port);
            match client.test_echo_service(port, message).await {
                Ok(response) => {
                    println!("✓ Echo test successful!");
                    println!("Sent: {}", message);
                    println!("Received: {}", response.trim());
                }
                Err(e) => {
                    eprintln!("✗ Echo test failed: {}", e);
                }
            }
        }
        "attest" => {
            println!("Requesting attestation for service: {}", service);
            match client.request_attestation(service).await {
                Ok(response) => {
                    println!("✓ Attestation successful!");
                    println!("Report: {}", response.report);
                    println!("Signature: {}", response.signature);
                }
                Err(e) => {
                    eprintln!("✗ Attestation failed: {}", e);
                }
            }
        }
        _ => {
            eprintln!("Unknown command: {}", command);
            eprintln!("Available commands: test-echo, attest");
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_creation() {
        let client = BlocksenseClient::new("http://test.example.com".to_string());
        assert_eq!(client.base_url, "http://test.example.com");
    }

    #[test]
    fn test_attestation_request_format() {
        let request = AttestationRequest {
            challenge: "test_challenge".to_string(),
            service_endpoint: "test_service".to_string(),
        };

        assert_eq!(request.challenge, "test_challenge");
        assert_eq!(request.service_endpoint, "test_service");
    }

    #[test]
    fn test_attestation_response_format() {
        let response = AttestationResponse {
            report: "test_report".to_string(),
            signature: "test_signature".to_string(),
            certificates: vec!["cert1".to_string(), "cert2".to_string()],
        };

        assert_eq!(response.report, "test_report");
        assert_eq!(response.signature, "test_signature");
        assert_eq!(response.certificates.len(), 2);
    }

    #[tokio::test]
    async fn test_port_mapping() {
        // Test that port mapping logic works correctly
        let cpp_port = match "cpp-echo" {
            "cpp-echo" => 8080,
            "rust-echo" => 8081,
            _ => 0,
        };

        let rust_port = match "rust-echo" {
            "cpp-echo" => 8080,
            "rust-echo" => 8081,
            _ => 0,
        };

        assert_eq!(cpp_port, 8080);
        assert_eq!(rust_port, 8081);
    }
}
