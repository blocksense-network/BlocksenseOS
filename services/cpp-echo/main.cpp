#include <asio.hpp>
#include <asio/awaitable.hpp>
#include <asio/co_spawn.hpp>
#include <asio/detached.hpp>
#include <asio/signal_set.hpp>
#include <asio/use_awaitable.hpp>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <exception>
#include <iomanip>
#include <iostream>
#include <memory>
#include <sstream>
#include <string>
#include <vector>

using asio::awaitable;
using asio::co_spawn;
using asio::detached;
using asio::use_awaitable;
using asio::ip::tcp;

class AsyncEchoServer {
private:
  static constexpr size_t MAX_MESSAGE_SIZE = 8192;
  static constexpr std::chrono::seconds CLIENT_TIMEOUT{30};

  asio::io_context &io_context_;
  tcp::acceptor acceptor_;
  std::atomic<size_t> active_connections_{0};

  std::string getCurrentTimestamp() {
    auto now = std::chrono::system_clock::now();
    auto time_t = std::chrono::system_clock::to_time_t(now);
    auto tm = *std::localtime(&time_t);
    std::ostringstream oss;
    oss << std::put_time(&tm, "%Y-%m-%d %H:%M:%S");
    return oss.str();
  }

  bool validateInput(const std::vector<uint8_t> &buffer, size_t length) {
    // Check message size
    if (length > MAX_MESSAGE_SIZE) {
      std::cerr << "[" << getCurrentTimestamp()
                << "] Invalid input: message too large (" << length << " > "
                << MAX_MESSAGE_SIZE << ")" << std::endl;
      return false;
    }

    // Check for null bytes using modern C++ algorithms
    if (std::find(buffer.begin(), buffer.begin() + length, 0) !=
        buffer.begin() + length) {
      std::cerr << "[" << getCurrentTimestamp()
                << "] Invalid input: contains null bytes" << std::endl;
      return false;
    }

    return true;
  }

  // Modern C++20 coroutine for handling individual client sessions
  awaitable<void> handleClient(tcp::socket socket) {
    auto remote_endpoint = socket.remote_endpoint();
    std::cout << "[" << getCurrentTimestamp() << "] New client connected from "
              << remote_endpoint.address().to_string() << ":"
              << remote_endpoint.port() << std::endl;

    active_connections_++;

    try {
      // Set socket options for performance and security
      socket.set_option(tcp::no_delay(true));

      std::vector<uint8_t> buffer(MAX_MESSAGE_SIZE + 1);

      while (true) {
        size_t bytes_read;
        try {
          // Use socket's async_read_some method with co_await
          bytes_read = co_await socket.async_read_some(
              asio::buffer(buffer, MAX_MESSAGE_SIZE), use_awaitable);
        } catch (const std::exception &) {
          // Connection closed or error occurred
          break;
        }

        if (bytes_read == 0) {
          break; // Client disconnected
        }

        // Validate input before processing
        if (!validateInput(buffer, bytes_read)) {
          const std::string error_msg = "ERROR: Invalid input\n";
          co_await asio::async_write(socket, asio::buffer(error_msg),
                                     use_awaitable);
          break;
        }

        // Log received message (truncate for security)
        std::string message(reinterpret_cast<const char *>(buffer.data()),
                            bytes_read);
        std::cout << "[" << getCurrentTimestamp() << "] Client "
                  << remote_endpoint.address().to_string() << ":"
                  << remote_endpoint.port() << " sent " << bytes_read
                  << " bytes: "
                  << message.substr(0, 100); // Log only first 100 chars
        if (message.length() > 100) {
          std::cout << "... (truncated)";
        }
        std::cout << std::endl;

        // Echo back the message using coroutine
        try {
          co_await asio::async_write(
              socket, asio::buffer(buffer.data(), bytes_read), use_awaitable);
        } catch (const std::exception &e) {
          std::cerr << "[" << getCurrentTimestamp()
                    << "] Write error: " << e.what() << std::endl;
          break;
        }
      }
    } catch (const std::exception &e) {
      std::cerr << "[" << getCurrentTimestamp()
                << "] Client session error: " << e.what() << std::endl;
    }

    active_connections_--;
    std::cout << "[" << getCurrentTimestamp() << "] Client "
              << remote_endpoint.address().to_string() << ":"
              << remote_endpoint.port() << " disconnected. Active connections: "
              << active_connections_.load() << std::endl;
  }

  // Modern C++20 coroutine for accepting connections
  awaitable<void> acceptConnections() {
    while (true) {
      try {
        // Accept new connection using coroutine
        auto socket = co_await acceptor_.async_accept(use_awaitable);

        // Spawn a new coroutine to handle this client
        co_spawn(socket.get_executor(), handleClient(std::move(socket)),
                 detached);
      } catch (const std::exception &e) {
        std::cerr << "[" << getCurrentTimestamp()
                  << "] Accept error: " << e.what() << std::endl;
        break;
      }
    }
  }

public:
  AsyncEchoServer(asio::io_context &io_context, unsigned short port)
      : io_context_(io_context),
        acceptor_(io_context, tcp::endpoint(tcp::v4(), port)) {

    // Set acceptor options
    acceptor_.set_option(tcp::acceptor::reuse_address(true));

    std::cout << "[" << getCurrentTimestamp()
              << "] Modern C++20 ASIO Echo Server v0.2.0 started on port "
              << port << std::endl;
    std::cout
        << "Features: C++20 coroutines, ASIO async I/O, memory-safe validation"
        << std::endl;
  }

  // Start the server using coroutines
  awaitable<void> start() {
    std::cout << "[" << getCurrentTimestamp()
              << "] Server accepting connections..." << std::endl;
    co_await acceptConnections();
  }

  void stop() {
    std::cout << "[" << getCurrentTimestamp() << "] Stopping server..."
              << std::endl;
    acceptor_.close();
    std::cout << "[" << getCurrentTimestamp()
              << "] Server stopped. Final active connections: "
              << active_connections_.load() << std::endl;
  }

  size_t getActiveConnections() const { return active_connections_.load(); }
};

int main() {
  std::cout << "BlocksenseOS Modern C++ TCP Echo Service v0.2.0" << std::endl;
  std::cout
      << "High-performance async echo service using C++20 coroutines and ASIO"
      << std::endl;
  std::cout
      << "Addressing security review: eliminated thread-per-connection model"
      << std::endl
      << std::endl;

  try {
    asio::io_context io_context;

    // Create the server
    AsyncEchoServer server(io_context, 8080);

    // Set up graceful shutdown signal handling
    asio::signal_set signals(io_context, SIGINT, SIGTERM);
    signals.async_wait([&](const std::error_code &, int signal) {
      std::cout << "\nShutdown signal " << signal << " received" << std::endl;
      server.stop();
      io_context.stop();
    });

    // Start the server using coroutines
    co_spawn(io_context, server.start(), detached);

    // Run the I/O context (event loop)
    std::cout << "Server running... Press Ctrl+C to stop." << std::endl;
    io_context.run();

    std::cout << "Server shutdown complete." << std::endl;

  } catch (const std::exception &e) {
    std::cerr << "Server exception: " << e.what() << std::endl;
    return 1;
  }

  return 0;
}