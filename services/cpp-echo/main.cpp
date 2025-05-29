#include <iostream>
#include <string>
#include <thread>
#include <chrono>
#include <ctime>
#include <iomanip>

class EchoService {
private:
    bool running;
    
    std::string getCurrentTimestamp() {
        auto now = std::time(nullptr);
        auto tm = *std::localtime(&now);
        std::ostringstream oss;
        oss << std::put_time(&tm, "%Y-%m-%d %H:%M:%S");
        return oss.str();
    }

public:
    EchoService() : running(false) {}
    
    void start() {
        running = true;
        std::cout << "[" << getCurrentTimestamp() << "] C++ Echo Service started" << std::endl;
        
        while (running) {
            std::string input;
            std::cout << "Enter message (or 'quit' to exit): ";
            std::getline(std::cin, input);
            
            if (input == "quit") {
                stop();
                break;
            }
            
            // Echo the message with timestamp
            std::cout << "[" << getCurrentTimestamp() << "] Echo: " << input << std::endl;
        }
    }
    
    void stop() {
        running = false;
        std::cout << "[" << getCurrentTimestamp() << "] C++ Echo Service stopped" << std::endl;
    }
};

int main() {
    std::cout << "BlocksenseOS C++ Echo Service v0.1.0" << std::endl;
    std::cout << "Secure echo service for TEE environment" << std::endl;
    
    EchoService service;
    service.start();
    
    return 0;
}