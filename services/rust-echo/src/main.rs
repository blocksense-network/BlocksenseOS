use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::io::{self, Write};
use tokio::time::{sleep, Duration};

#[derive(Serialize, Deserialize, Debug)]
struct EchoMessage {
    content: String,
    timestamp: DateTime<Utc>,
    service_id: String,
}

struct RustEchoService {
    service_id: String,
    running: bool,
}

impl RustEchoService {
    fn new() -> Self {
        Self {
            service_id: "rust-echo-v0.1.0".to_string(),
            running: false,
        }
    }

    async fn start(&mut self) -> io::Result<()> {
        self.running = true;
        println!("[{}] Rust Echo Service started", Utc::now().format("%Y-%m-%d %H:%M:%S"));
        
        loop {
            print!("Enter message (or 'quit' to exit): ");
            io::stdout().flush()?;
            
            let mut input = String::new();
            io::stdin().read_line(&mut input)?;
            let input = input.trim();
            
            if input == "quit" {
                self.stop().await;
                break;
            }
            
            let echo_msg = EchoMessage {
                content: input.to_string(),
                timestamp: Utc::now(),
                service_id: self.service_id.clone(),
            };
            
            println!("[{}] Echo: {}", 
                echo_msg.timestamp.format("%Y-%m-%d %H:%M:%S"),
                echo_msg.content
            );
            
            // Simulate async processing
            sleep(Duration::from_millis(10)).await;
        }
        
        Ok(())
    }
    
    async fn stop(&mut self) {
        self.running = false;
        println!("[{}] Rust Echo Service stopped", Utc::now().format("%Y-%m-%d %H:%M:%S"));
    }
}

#[tokio::main]
async fn main() -> io::Result<()> {
    println!("BlocksenseOS Rust Echo Service v0.1.0");
    println!("Async echo service for TEE environment");
    
    let mut service = RustEchoService::new();
    service.start().await?;
    
    Ok(())
}