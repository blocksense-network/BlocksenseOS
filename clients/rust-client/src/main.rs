use clap::{Arg, Command};
use hex;
use reqwest;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::net::TcpStream;
use std::io::{Read, Write};
use tokio;

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
    base_url: String,
}

impl BlocksenseClient {
    fn new(base_url: String) -> Self {
        Self { base_url }
    }

    async fn test_echo_service(&self, port: u16, message: &str) -> Result<String, Box<dyn std::error::Error>> {
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

    fn verify_measurement(&self, expected: &str, actual: &str) -> bool {
        // Simple hash comparison for demonstration
        let mut hasher = Sha256::new();
        hasher.update(actual.as_bytes());
        let hash = hex::encode(hasher.finalize());
        
        hash == expected
    }

    async fn request_attestation(&self, service: &str) -> Result<AttestationResponse, Box<dyn std::error::Error>> {
        let client = reqwest::Client::new();
        let url = format!("{}/attest/{}", self.base_url, service);
        
        let request = AttestationRequest {
            challenge: hex::encode("test_challenge_123"),
            service_endpoint: service.to_string(),
        };

        let response = client
            .post(&url)
            .json(&request)
            .send()
            .await?
            .json::<AttestationResponse>()
            .await?;

        Ok(response)
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