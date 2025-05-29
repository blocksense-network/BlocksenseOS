use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

#[derive(Serialize, Deserialize, Debug)]
struct EchoMessage {
    content: String,
    timestamp: DateTime<Utc>,
    service_id: String,
}

struct RustTcpEchoServer {
    service_id: String,
    port: u16,
}

impl RustTcpEchoServer {
    fn new(port: u16) -> Self {
        Self {
            service_id: "rust-echo-v0.1.0".to_string(),
            port,
        }
    }

    async fn start(&self) -> Result<(), Box<dyn std::error::Error>> {
        let addr = SocketAddr::from(([0, 0, 0, 0], self.port));
        let listener = TcpListener::bind(addr).await?;
        
        println!("[{}] Rust TCP Echo Server started on port {}", 
            Utc::now().format("%Y-%m-%d %H:%M:%S"), 
            self.port
        );
        
        loop {
            let (stream, addr) = listener.accept().await?;
            println!("[{}] New connection from {}", 
                Utc::now().format("%Y-%m-%d %H:%M:%S"), 
                addr
            );
            
            let service_id = self.service_id.clone();
            tokio::spawn(async move {
                if let Err(e) = Self::handle_client(stream, service_id).await {
                    eprintln!("Error handling client: {}", e);
                }
            });
        }
    }
    
    async fn handle_client(
        mut stream: TcpStream, 
        service_id: String
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut buffer = [0; 1024];
        
        loop {
            match stream.read(&mut buffer).await {
                Ok(0) => {
                    // Connection closed
                    break;
                }
                Ok(n) => {
                    let message = String::from_utf8_lossy(&buffer[..n]);
                    
                    let echo_msg = EchoMessage {
                        content: message.to_string(),
                        timestamp: Utc::now(),
                        service_id: service_id.clone(),
                    };
                    
                    println!("[{}] Received: {}", 
                        echo_msg.timestamp.format("%Y-%m-%d %H:%M:%S"),
                        echo_msg.content.trim()
                    );
                    
                    // Echo back the message
                    stream.write_all(&buffer[..n]).await?;
                }
                Err(e) => {
                    eprintln!("Error reading from socket: {}", e);
                    break;
                }
            }
        }
        
        Ok(())
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("BlocksenseOS Rust TCP Echo Service v0.1.0");
    println!("Async TCP echo service for TEE environment");
    
    let server = RustTcpEchoServer::new(8081);
    server.start().await?;
    
    Ok(())
}