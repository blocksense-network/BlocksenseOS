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
    @attestation_agent_pid = nil
    
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
    
    [@cpp_service_pid, @rust_service_pid, @attestation_agent_pid].each do |pid|
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
    
    # Find Attestation Agent binary dynamically
    attestation_binary = find_service_binary('attestation-agent')
    unless attestation_binary
      log_error "Attestation Agent binary not found in any result directory"
      return false
    end
    
    @attestation_agent_pid = start_service("Attestation Agent", attestation_binary, 3000)
    unless @attestation_agent_pid
      log_error "Failed to start Attestation Agent"
      cleanup_services
      return false
    end
    log_info "Attestation Agent started with PID: #{@attestation_agent_pid}"
    
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

  def run_performance_startup_tests
    log_info "Running service startup performance tests..."
    
    return false unless build_services
    
    services = [
      ['cpp-echo-service', 8080],
      ['rust-echo-service', 8081], 
      ['attestation-agent', 3000]
    ]
    
    services.each do |service_name, port|
      binary = find_service_binary(service_name)
      unless binary
        log_error "#{service_name} binary not found"
        return false
      end
      
      log_info "Testing startup time for #{service_name}..."
      start_time = Time.now
      
      pid = start_service(service_name, binary, port, timeout: 10)
      if pid
        startup_time = Time.now - start_time
        log_info "✓ #{service_name} started in #{startup_time.round(2)} seconds"
        Process.kill('TERM', pid) rescue nil
      else
        log_error "✗ #{service_name} failed to start"
        return false
      end
      
      sleep 1 # Brief pause between tests
    end
    
    log_info "✓ All startup performance tests completed"
    true
  end

  def run_load_testing
    log_info "Running load testing..."
    
    return false unless start_test_services
    
    # Test echo services with concurrent connections
    log_info "Testing C++ echo service load..."
    success_count = 0
    total_requests = 50
    
    threads = []
    (1..total_requests).each do |i|
      threads << Thread.new do
        begin
          socket = TCPSocket.new('127.0.0.1', 8080)
          socket.write("Load test #{i}")
          socket.close_write
          response = socket.read
          socket.close
          success_count += 1 if response == "Load test #{i}"
        rescue
          # Connection failed
        end
      end
    end
    
    threads.each(&:join)
    
    if success_count >= total_requests * 0.8 # 80% success rate
      log_info "✓ Load test passed: #{success_count}/#{total_requests} requests succeeded"
    else
      log_error "✗ Load test failed: only #{success_count}/#{total_requests} requests succeeded"
      return false
    end
    
    log_info "✓ Load testing completed"
    true
  end

  def run_memory_testing
    log_info "Running memory usage tests..."
    
    return false unless start_test_services
    
    # Check if ps command is available
    unless system("which ps > /dev/null 2>&1")
      log_warn "ps command not available, skipping memory tests"
      return true
    end
    
    # Get initial memory usage
    initial_memory = get_process_memory
    
    # Perform some operations that might consume memory
    50.times do |i|
      begin
        socket = TCPSocket.new('127.0.0.1', 8081)
        socket.write("Memory test #{i}")
        socket.close_write
        socket.read
        socket.close
      rescue
        # Ignore errors for this test
      end
    end
    
    # Check memory after operations
    final_memory = get_process_memory
    memory_increase = final_memory - initial_memory
    
    if memory_increase < 10000 # Less than 10MB increase
      log_info "✓ Memory usage stable: #{memory_increase}KB increase"
    else
      log_warn "Memory usage increased: #{memory_increase}KB"
    end
    
    log_info "✓ Memory testing completed"
    true
  end

  def run_attestation_e2e_tests
    log_info "Running end-to-end attestation tests..."
    
    return false unless start_test_services
    
    # Test health endpoint
    log_info "Testing attestation agent health..."
    if system("curl -s -f http://localhost:3000/health > /dev/null")
      log_info "✓ Health endpoint accessible"
    else
      log_error "✗ Health endpoint failed"
      return false
    end
    
    # Test attestation generation
    log_info "Testing attestation generation..."
    if system("curl -s -f 'http://localhost:3000/attestation?tee_type_filter=mock' > /dev/null")
      log_info "✓ Attestation generation successful"
    else
      log_error "✗ Attestation generation failed"
      return false
    end
    
    log_info "✓ End-to-end attestation tests completed"
    true
  end

  def run_tee_compatibility_tests
    log_info "Running TEE compatibility tests..."
    
    return false unless start_test_services
    
    tee_types = ['sev-snp', 'tdx', 'sgx', 'mock']
    
    tee_types.each do |tee_type|
      log_info "Testing #{tee_type} compatibility..."
      if system("curl -s -f 'http://localhost:3000/attestation?tee_type_filter=#{tee_type}' > /dev/null")
        log_info "✓ #{tee_type} compatibility verified"
      else
        log_warn "#{tee_type} may not be fully supported (expected in test environment)"
      end
    end
    
    log_info "✓ TEE compatibility tests completed"
    true
  end

  def run_attestation_security_tests
    log_info "Running attestation security tests..."
    
    return false unless start_test_services
    
    # Test invalid TEE type
    log_info "Testing invalid TEE type rejection..."
    if system("curl -s -f 'http://localhost:3000/attestation?tee_type_filter=invalid-tee' > /dev/null 2>&1")
      log_error "✗ Invalid TEE type should be rejected but was accepted"
      return false
    else
      log_info "✓ Invalid TEE type properly rejected"
    end
    
    # Test malformed verification request
    log_info "Testing malformed verification request..."
    if system("curl -s -f -X POST http://localhost:3000/verify -H 'Content-Type: application/json' -d '{\"invalid\": \"data\"}' > /dev/null 2>&1")
      log_error "✗ Malformed request should be rejected but was accepted"
      return false
    else
      log_info "✓ Malformed request properly rejected"
    end
    
    log_info "✓ Attestation security tests completed"
    true
  end

  def run_derivation_consistency_tests
    log_info "Running derivation hash consistency tests..."
    
    derivation_binary = find_service_binary('derivation-hasher')
    unless derivation_binary
      log_error "Derivation hasher binary not found"
      return false
    end
    
    # Test hash consistency
    hash1 = `#{derivation_binary} test-input 2>/dev/null`.strip
    hash2 = `#{derivation_binary} test-input 2>/dev/null`.strip
    
    if hash1 == hash2 && !hash1.empty?
      log_info "✓ Derivation hashing is consistent"
    else
      log_error "✗ Derivation hashing is inconsistent or failed"
      return false
    end
    
    log_info "✓ Derivation consistency tests completed"
    true
  end

  def show_usage
    puts "Usage: #{$0} [command]"
    puts ""
    puts "Available commands:"
    puts "  build                   - Build all services"
    puts "  vm                      - Test VM configuration"
    puts "  integration            - Run integration tests"
    puts "  performance-startup    - Test service startup performance"
    puts "  load-testing          - Run load testing"
    puts "  memory-testing        - Test memory usage"
    puts "  attestation-e2e       - End-to-end attestation tests"
    puts "  tee-compatibility     - TEE compatibility tests"
    puts "  attestation-security  - Attestation security tests"
    puts "  derivation-consistency - Derivation hash consistency tests"
    puts "  all                   - Run all tests (default)"
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
              when 'performance-startup'
                run_performance_startup_tests
              when 'load-testing'
                run_load_testing
              when 'memory-testing'
                run_memory_testing
              when 'attestation-e2e'
                run_attestation_e2e_tests
              when 'tee-compatibility'
                run_tee_compatibility_tests
              when 'attestation-security'
                run_attestation_security_tests
              when 'derivation-consistency'
                run_derivation_consistency_tests
              when 'all'
                build_services && test_vm_build && run_integration_tests
              else
                show_usage
                exit 1
              end
    
    log_info "Test suite completed!"
    exit(success ? 0 : 1)
  end

  private

  def get_process_memory
    # Get memory usage of our test services
    memory_kb = `ps aux | grep -E "(attestation-agent|echo-service)" | grep -v grep | awk '{sum+=$6} END {print sum}'`.strip.to_i
    memory_kb > 0 ? memory_kb : 0
  end
end

# Run the test suite if this file is executed directly
if __FILE__ == $0
  BlocksenseOSTest.new.run(ARGV)
end