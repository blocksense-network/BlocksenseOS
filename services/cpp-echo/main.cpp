#include <iostream>
#include <string>
#include <cstring>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <chrono>
#include <iomanip>
#include <sstream>

class TCPEchoServer {
private:
    int server_fd;
    int port;
    bool running;
    
    std::string getCurrentTimestamp() {
        auto now = std::chrono::system_clock::now();
        auto time_t = std::chrono::system_clock::to_time_t(now);
        auto tm = *std::localtime(&time_t);
        std::ostringstream oss;
        oss << std::put_time(&tm, "%Y-%m-%d %H:%M:%S");
        return oss.str();
    }

public:
    TCPEchoServer(int port) : port(port), running(false), server_fd(-1) {}
    
    ~TCPEchoServer() {
        stop();
    }
    
    bool start() {
        server_fd = socket(AF_INET, SOCK_STREAM, 0);
        if (server_fd == -1) {
            std::cerr << "Failed to create socket" << std::endl;
            return false;
        }
        
        int opt = 1;
        if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt))) {
            std::cerr << "Failed to set socket options" << std::endl;
            close(server_fd);
            return false;
        }
        
        struct sockaddr_in address;
        address.sin_family = AF_INET;
        address.sin_addr.s_addr = INADDR_ANY;
        address.sin_port = htons(port);
        
        if (bind(server_fd, (struct sockaddr*)&address, sizeof(address)) < 0) {
            std::cerr << "Failed to bind to port " << port << std::endl;
            close(server_fd);
            return false;
        }
        
        if (listen(server_fd, 3) < 0) {
            std::cerr << "Failed to listen on socket" << std::endl;
            close(server_fd);
            return false;
        }
        
        running = true;
        std::cout << "[" << getCurrentTimestamp() << "] C++ TCP Echo Server started on port " << port << std::endl;
        
        while (running) {
            struct sockaddr_in client_addr;
            socklen_t client_len = sizeof(client_addr);
            int client_fd = accept(server_fd, (struct sockaddr*)&client_addr, &client_len);
            
            if (client_fd < 0) {
                if (running) {
                    std::cerr << "Failed to accept connection" << std::endl;
                }
                continue;
            }
            
            handleClient(client_fd);
        }
        
        return true;
    }
    
    void handleClient(int client_fd) {
        char buffer[1024] = {0};
        
        while (true) {
            int bytes_read = read(client_fd, buffer, sizeof(buffer) - 1);
            if (bytes_read <= 0) {
                break;
            }
            
            buffer[bytes_read] = '\0';
            std::string message(buffer);
            
            std::cout << "[" << getCurrentTimestamp() << "] Received: " << message;
            
            // Echo back the message
            send(client_fd, buffer, bytes_read, 0);
        }
        
        close(client_fd);
    }
    
    void stop() {
        running = false;
        if (server_fd != -1) {
            close(server_fd);
            server_fd = -1;
        }
        std::cout << "[" << getCurrentTimestamp() << "] C++ TCP Echo Server stopped" << std::endl;
    }
};

int main() {
    std::cout << "BlocksenseOS C++ TCP Echo Service v0.1.0" << std::endl;
    std::cout << "Secure TCP echo service for TEE environment" << std::endl;
    
    TCPEchoServer server(8080);
    if (!server.start()) {
        return 1;
    }
    
    return 0;
}