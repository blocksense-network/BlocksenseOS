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
        // For demonstration purposes, return a mock response
        // In a real implementation, this would make HTTP requests to the attestation service
        println!("Mock attestation request for service: {}", service);

        let mock_response = AttestationResponse {
            report: format!("mock_report_for_{}", service),
            signature: "mock_signature_12345".to_string(),
            certificates: vec!["mock_cert_1".to_string(), "mock_cert_2".to_string()],
        };

        Ok(mock_response)
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
