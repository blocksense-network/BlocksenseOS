#!/usr/bin/env ruby
# frozen_string_literal: true

# BlocksenseOS Testing Script
# Tests the echo services and attestation functionality

require 'socket'
require 'timeout'
require 'fileutils'
require 'open3'

class BlocksenseOSTest
  # ANSI color codes
  RED = "\e[31m"
  GREEN = "\e[32m"
  YELLOW = "\e[33m"
  RESET = "\e[0m"

  def initialize
    @script_dir = File.dirname(File.expand_path(__FILE__))
    @project_root = File.dirname(@script_dir)
    @cpp_service_pid = nil
    @rust_service_pid = nil
    
    # Set up signal handlers for cleanup
    setup_signal_handlers
  end

  def log_info(message)
    puts "#{GREEN}[INFO]#{RESET} #{message}"
  end

  def log_warn(message)
    puts "#{YELLOW}[WARN]#{RESET} #{message}"
  end

  def log_error(message)
    puts "#{RED}[ERROR]#{RESET} #{message}"
  end

  def setup_signal_handlers
    %w[INT TERM].each do |signal|
      Signal.trap(signal) do
        cleanup_services
        exit(1)
      end
    end
    
    at_exit { cleanup_services }
  end

  def cleanup_services
    log_info "Cleaning up services..."
    
    [@cpp_service_pid, @rust_service_pid].each do |pid|
      next unless pid && process_running?(pid)
      
      begin
        log_info "Stopping service (PID: #{pid})"
        Process.kill('TERM', pid)
        Process.wait(pid)
      rescue Errno::ESRCH, Errno::ECHILD
        # Process already dead
      end
    end
    
    # Clean up any remaining processes on test ports
    system('pkill -f "cpp-echo" 2>/dev/null || true')
    system('pkill -f "rust-echo" 2>/dev/null || true')
    
    log_info "Service cleanup completed"
  end

  def process_running?(pid)
    return false unless pid
    
    begin
      Process.kill(0, pid)
      true
    rescue Errno::ESRCH
      false
    end
  end

  def port_in_use?(port)
    begin
      socket = TCPSocket.new('127.0.0.1', port)
      socket.close
      true
    rescue Errno::ECONNREFUSED
      false
    end
  end

  def start_service(service_name, service_path, port, timeout: 15)
    log_info "Starting #{service_name}..."
    
    # Check if port is already in use
    if port_in_use?(port)
      log_warn "Port #{port} is already in use, attempting to free it"
      system("pkill -f ':#{port}' 2>/dev/null || true")
      sleep 2
    end
    
    # Start the service in background
    pid = spawn(service_path)
    
    log_info "Service started with PID: #{pid}, waiting for it to listen on port #{port}..."
    
    # Wait for service to start listening
    timeout.times do |count|
      if port_in_use?(port)
        log_info "✓ #{service_name} started successfully on port #{port} (PID: #{pid})"
        return pid
      end
      
      sleep 1
      
      # Check if process is still running
      unless process_running?(pid)
        log_error "✗ #{service_name} process died unexpectedly (PID: #{pid})"
        return nil
      end
      
      log_info "Waiting... (#{count + 1}/#{timeout})"
    end
    
    log_error "✗ #{service_name} failed to start within #{timeout} seconds"
    begin
      Process.kill('TERM', pid)
    rescue Errno::ESRCH
      # Process already dead
    end
    nil
  end

  def test_tcp_service(service_name, port)
    test_message = "Hello BlocksenseOS!"
    
    log_info "Testing #{service_name} on port #{port}..."
    
    # Check if port is listening
    unless port_in_use?(port)
      log_error "#{service_name} is not listening on port #{port}"
      return false
    end
    
    # Send test message and check response
    begin
      response = nil
      Timeout.timeout(5) do
        socket = TCPSocket.new('127.0.0.1', port)
        socket.write(test_message + "\n")
        response = socket.gets&.chomp
        socket.close
      end
      
      if response == test_message
        log_info "✓ #{service_name} echo test passed"
        true
      else
        log_error "✗ #{service_name} echo test failed. Expected: '#{test_message}', Got: '#{response}'"
        false
      end
    rescue Timeout::Error, Errno::ECONNREFUSED => e
      log_error "✗ #{service_name} test failed: #{e.message}"
      false
    end
  end

  def run_command(command, description = nil)
    log_info description if description
    
    stdout, stderr, status = Open3.capture3(command, chdir: @project_root)
    
    if status.success?
      log_info "✓ Command succeeded" if description
      true
    else
      log_error "✗ Command failed: #{stderr.strip}" if description
      false
    end
  end

  def build_services
    log_info "Building BlocksenseOS services..."
    
    Dir.chdir(@project_root)
    
    # Create build directory
    FileUtils.mkdir_p('build')
    
    # Build each service with specific output names in build directory
    builds = [
      ['.#cpp-echo-service', 'build/cpp-echo-service'],
      ['.#rust-echo-service', 'build/rust-echo-service'], 
      ['.#attestation-agent', 'build/attestation-agent']
    ]
    
    builds.each do |service, output|
      unless run_command("nix build #{service} -o #{output}")
        log_error "✗ Failed to build #{service}"
        return false
      end
    end
    
    log_info "✓ Core services built successfully"
    
    # Try to build rust-client separately (optional)
    if run_command('nix build .#rust-client -o build/rust-client')
      log_info "✓ Rust client also built successfully"
    else
      log_warn "Rust client build failed, but continuing with core services"
    end
    
    true
  end

  def test_vm_build
    log_info "Testing VM image build..."
    
    Dir.chdir(@project_root)
    
    if run_command('nix build .#blocksenseOS-vm --dry-run')
      log_info "✓ VM build configuration is valid"
      true
    else
      log_error "✗ VM build configuration has errors"
      false
    end
  end

  def find_service_binary(service_name)
    # Map service names to their expected build directory names
    service_map = {
      'cpp-echo-service' => 'build/cpp-echo-service',
      'rust-echo-service' => 'build/rust-echo-service',
      'attestation-agent' => 'build/attestation-agent',
      'rust-client' => 'build/rust-client'
    }
    
    # First try the specific named build directory
    if service_map[service_name]
      build_dir = service_map[service_name]
      binary_path = File.join(build_dir, 'bin', service_name)
      return binary_path if File.exist?(binary_path)
    end
    
    # Fallback: search through all build subdirectories
    Dir.glob('build/*').each do |build_dir|
      binary_path = File.join(build_dir, 'bin', service_name)
      return binary_path if File.exist?(binary_path)
    end
    
    # Legacy fallback: search through result* directories for backwards compatibility
    Dir.glob('result*').each do |result_dir|
      binary_path = File.join(result_dir, 'bin', service_name)
      return binary_path if File.exist?(binary_path)
    end
    
    nil
  end

  def start_test_services
    log_info "Starting test services..."
    
    # Find C++ service binary dynamically
    cpp_binary = find_service_binary('cpp-echo-service')
    unless cpp_binary
      log_error "C++ echo service binary not found in any result directory"
      return false
    end
    
    @cpp_service_pid = start_service("C++ Echo Service", cpp_binary, 8080)
    unless @cpp_service_pid
      log_error "Failed to start C++ service"
      return false
    end
    log_info "C++ service started with PID: #{@cpp_service_pid}"
    
    # Find Rust service binary dynamically
    rust_binary = find_service_binary('rust-echo-service')
    unless rust_binary
      log_error "Rust echo service binary not found in any result directory"
      return false
    end
    
    @rust_service_pid = start_service("Rust Echo Service", rust_binary, 8081)
    unless @rust_service_pid
      log_error "Failed to start Rust service"
      cleanup_services
      return false
    end
    log_info "Rust service started with PID: #{@rust_service_pid}"
    
    log_info "All test services started successfully"
    true
  end

  def run_integration_tests
    log_info "Running integration tests..."
    
    # First, make sure services are built - check dynamically
    cpp_binary = find_service_binary('cpp-echo-service')
    rust_binary = find_service_binary('rust-echo-service')
    
    unless cpp_binary && rust_binary
      log_warn "Service binaries not found, rebuilding..."
      return false unless build_services
      
      # Re-check after building
      cpp_binary = find_service_binary('cpp-echo-service')
      rust_binary = find_service_binary('rust-echo-service')
      
      unless cpp_binary && rust_binary
        log_error "Service binaries still not found after rebuilding"
        return false
      end
    end
    
    # Start services for testing
    return false unless start_test_services
    
    cpp_result = test_tcp_service("C++ Echo Service", 8080)
    rust_result = test_tcp_service("Rust Echo Service", 8081)
    
    puts "  C++ service: #{cpp_result ? 'PASS' : 'FAIL'}"
    puts "  Rust service: #{rust_result ? 'PASS' : 'FAIL'}"
    
    # Test using rust client if available
    client_binary = find_service_binary('rust-client')
    if client_binary
      log_info "Testing with Rust client..."
      if run_command("#{client_binary} --help >/dev/null 2>&1")
        log_info "✓ Rust client is functional"
      else
        log_warn "Rust client found but not responding correctly"
      end
    else
      log_warn "Rust client not found, skipping client tests"
    end
    
    # Return overall result
    if cpp_result && rust_result
      log_info "✓ All integration tests passed"
      true
    else
      log_error "✗ Some integration tests failed"
      false
    end
  end

  def show_usage
    puts "Usage: #{$0} [build|vm|integration|all]"
    puts "  build       - Build all services"
    puts "  vm          - Test VM configuration"
    puts "  integration - Run integration tests"
    puts "  all         - Run all tests (default)"
  end

  def run(args)
    puts "======================================"
    puts "    BlocksenseOS Test Suite"
    puts "======================================"
    
    command = args.first || 'all'
    
    success = case command
              when 'build'
                build_services
              when 'vm'
                test_vm_build
              when 'integration'
                run_integration_tests
              when 'all'
                build_services && test_vm_build && run_integration_tests
              else
                show_usage
                exit 1
              end
    
    log_info "Test suite completed!"
    exit(success ? 0 : 1)
  end
end

# Run the test suite if this file is executed directly
if __FILE__ == $0
  BlocksenseOSTest.new.run(ARGV)
end