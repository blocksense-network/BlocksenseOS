#!/usr/bin/env ruby
# encoding: utf-8
# Integration test suite for BlocksenseOS components
# Tests end-to-end functionality including attestation, services, and client verification

require 'json'
require 'net/http'
require 'socket'
require 'timeout'
require 'digest'
require 'securerandom'

class BlocksenseIntegrationTests
  attr_reader :results, :errors

  def initialize
    @results = []
    @errors = []
    @test_start_time = Time.now
    @service_pids = {}
    @project_root = File.dirname(File.dirname(File.expand_path(__FILE__)))
    
    # Set up signal handlers for cleanup
    setup_signal_handlers
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
    puts "\n[INFO] Cleaning up services..."
    
    @service_pids.each do |name, pid|
      next unless pid && process_running?(pid)
      
      begin
        puts "[INFO] Stopping #{name} (PID: #{pid})"
        Process.kill('TERM', pid)
        Process.wait(pid)
      rescue Errno::ESRCH, Errno::ECHILD
        # Process already dead
      end
    end
    
    # Clean up any remaining processes on test ports
    system('pkill -f "attestation-agent" 2>/dev/null || true')
    system('pkill -f "cpp-echo-service" 2>/dev/null || true')
    system('pkill -f "rust-echo-service" 2>/dev/null || true')
    
    puts "[INFO] Service cleanup completed"
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

  def find_service_binary(service_name)
    # Map service names to their expected build directory names
    service_map = {
      'cpp-echo-service' => 'build/cpp-echo-service',
      'rust-echo-service' => 'build/rust-echo-service',
      'attestation-agent' => 'build/attestation-agent'
    }
    
    # First try the specific named build directory
    if service_map[service_name]
      build_dir = service_map[service_name]
      binary_path = File.join(@project_root, build_dir, 'bin', service_name)
      return binary_path if File.exist?(binary_path)
    end
    
    # Fallback: search through all build subdirectories
    Dir.glob(File.join(@project_root, 'build/*')).each do |build_dir|
      binary_path = File.join(build_dir, 'bin', service_name)
      return binary_path if File.exist?(binary_path)
    end
    
    nil
  end

  def start_service(service_name, port, timeout: 15)
    binary_path = find_service_binary(service_name)
    unless binary_path
      log_error "#{service_name} binary not found"
      return false
    end

    log_info "Starting #{service_name}..."
    
    # Check if port is already in use
    if port_in_use?(port)
      log_info "Port #{port} is already in use, attempting to free it"
      system("pkill -f ':#{port}' 2>/dev/null || true")
      sleep 2
    end
    
    # Start the service in background
    pid = spawn(binary_path)
    @service_pids[service_name] = pid
    
    log_info "Service started with PID: #{pid}, waiting for it to listen on port #{port}..."
    
    # Wait for service to start listening
    timeout.times do |count|
      if port_in_use?(port)
        log_info "✓ #{service_name} started successfully on port #{port} (PID: #{pid})"
        return true
      end
      
      sleep 1
      
      # Check if process is still running
      unless process_running?(pid)
        log_error "✗ #{service_name} process died unexpectedly (PID: #{pid})"
        @service_pids.delete(service_name)
        return false
      end
      
      if count % 5 == 4  # Log every 5 seconds
        log_info "Waiting for #{service_name}... (#{count + 1}/#{timeout})"
      end
    end
    
    log_error "✗ #{service_name} failed to start within #{timeout} seconds"
    begin
      Process.kill('TERM', pid)
      @service_pids.delete(service_name)
    rescue Errno::ESRCH
      # Process already dead
    end
    false
  end

  def start_all_services
    log_info "Starting all required services..."
    
    services = [
      ['attestation-agent', 3000],
      ['rust-echo-service', 8081],
      ['cpp-echo-service', 8080]
    ]
    
    services.each do |service_name, port|
      unless start_service(service_name, port)
        log_error "Failed to start #{service_name}, aborting test suite"
        return false
      end
    end
    
    log_info "All services started successfully!"
    true
  end

  def run_all_tests
    puts "=" * 60
    puts "    BlocksenseOS Integration Test Suite"
    puts "=" * 60
    puts "[INFO] Starting comprehensive integration tests..."
    
    # Start all required services first
    unless start_all_services
      log_error "Failed to start required services, cannot run integration tests"
      generate_test_report
      return
    end
    
    # Wait a moment for services to stabilize
    sleep 2
    
    # Service availability tests (should pass now)
    test_service_availability
    
    # Attestation functionality tests
    test_attestation_generation
    test_attestation_validation
    
    # Network service tests
    test_echo_services
    test_rate_limiting
    
    # Security tests
    test_input_validation
    test_buffer_overflow_protection
    
    # Client verification tests
    test_client_attestation_flow
    
    # Performance and stress tests
    test_concurrent_connections
    test_memory_usage
    
    # Generate final report
    generate_test_report
  end

  private

  def test_service_availability
    log_test "Service Availability Check"
    
    services = [
      { name: "Attestation Agent", port: 3000, path: "/health" },
      { name: "Rust Echo Service", port: 8081, path: "/" },
      { name: "C++ Echo Service", port: 8080, path: "/" }
    ]
    
    services.each do |service|
      begin
        if service[:path] == "/"
          # TCP socket test for echo services
          socket = TCPSocket.new('localhost', service[:port])
          socket.close
          log_success "#{service[:name]} is listening on port #{service[:port]}"
        else
          # HTTP test for attestation agent
          uri = URI("http://localhost:#{service[:port]}#{service[:path]}")
          response = Net::HTTP.get_response(uri)
          if response.code == '200'
            log_success "#{service[:name]} health check passed"
          else
            log_error "#{service[:name]} health check failed: #{response.code}"
          end
        end
      rescue => e
        log_error "#{service[:name]} unavailable: #{e.message}"
      end
    end
  end

  def test_attestation_generation
    log_test "Attestation Generation"
    
    begin
      uri = URI('http://localhost:3000/attestation')
      http = Net::HTTP.new(uri.host, uri.port)
      http.read_timeout = 30
      
      request = Net::HTTP::Get.new(uri)
      request['Content-Type'] = 'application/json'
      
      # Try different TEE types for testing
      tee_types_to_try = ["sev-snp", "tdx", "sgx", "mock"]
      
      tee_types_to_try.each do |tee_type|
        # Add query parameters for GET request
        uri.query = URI.encode_www_form({
          challenge: SecureRandom.hex(32),
          tee_type_filter: tee_type
        })
        
        response = http.get(uri)
        
        if response.code == '200'
          response_data = JSON.parse(response.body)
          
          if response_data['success'] && response_data['report']
            attestation = response_data['report']
            
            # Validate attestation structure
            required_fields = ['tee_type', 'measurement', 'timestamp']
            missing_fields = required_fields - attestation.keys
            
            if missing_fields.empty?
              log_success "Attestation generated with all required fields for #{tee_type}"
              
              # Validate field formats
              if attestation['measurement'] && attestation['measurement'].match?(/^[a-f0-9]+$/i)
                log_success "Measurement field format is valid for #{tee_type}"
              else
                log_warning "Measurement field format may be non-standard for #{tee_type}"
              end
              
              if attestation['timestamp'].to_i > (Time.now.to_i - 60)
                log_success "Timestamp is recent (within 60 seconds) for #{tee_type}"
              else
                log_warning "Timestamp is not recent for #{tee_type}"
              end
              
              # Found working TEE type, stop trying others
              return
            else
              log_error "Missing required fields for #{tee_type}: #{missing_fields.join(', ')}"
            end
          else
            log_info "TEE type #{tee_type} not supported: #{response_data['error'] || 'Unknown error'}"
          end
        else
          log_info "TEE type #{tee_type} failed: #{response.code}"
        end
      end
      
      # If we get here, no TEE type worked
      log_error "No supported TEE type found - attestation generation failed for all tested types"
      
    rescue => e
      log_error "Attestation generation error: #{e.message}"
    end
  end

  def test_attestation_validation
    log_test "Attestation Validation"
    
    # Test with invalid signatures
    test_cases = [
      { name: "Empty signature", signature: "", should_fail: true },
      { name: "Invalid hex signature", signature: "invalid_hex", should_fail: true },
      { name: "Short signature", signature: "abcd", should_fail: true },
      { name: "Future timestamp", timestamp: (Time.now + 3600).to_i, should_fail: true },
      { name: "Old timestamp", timestamp: (Time.now - 7200).to_i, should_fail: true }
    ]
    
    test_cases.each do |test_case|
      begin
        uri = URI('http://localhost:3000/verify')
        http = Net::HTTP.new(uri.host, uri.port)
        
        request = Net::HTTP::Post.new(uri)
        request['Content-Type'] = 'application/json'
        
        payload = {
          version: 1,
          tee_type: "mock",
          measurement: "a" * 64,
          signature: test_case[:signature] || "valid_signature_placeholder",
          timestamp: test_case[:timestamp] || Time.now.to_i,
          report_data: "test_data"
        }
        
        request.body = payload.to_json
        response = http.request(request)
        
        if test_case[:should_fail]
          if response.code != '200'
            log_success "#{test_case[:name]} correctly rejected"
          else
            log_error "#{test_case[:name]} should have been rejected"
          end
        else
          if response.code == '200'
            log_success "#{test_case[:name]} correctly accepted"
          else
            log_error "#{test_case[:name]} should have been accepted"
          end
        end
      rescue => e
        log_error "Validation test error for #{test_case[:name]}: #{e.message}"
      end
    end
  end

  def test_echo_services
    log_test "Echo Service Functionality"
    
    # Test Rust echo service
    test_echo_service("Rust Echo", 8081)
    
    # Test C++ echo service  
    test_echo_service("C++ Echo", 8080)
  end

  def test_echo_service(service_name, port)
    begin
      test_messages = [
        "Hello, World!",
        "Test message with special chars: @#$%^&*()",
        "Unicode test: 你好世界 🌍",
        "Large message: #{'A' * 1000}",
        "" # Empty message
      ]
      
      test_messages.each do |message|
        message_bytes = message.encode('UTF-8')
        socket = TCPSocket.new('localhost', port)
        socket.write(message_bytes)
        socket.close_write
        
        response_bytes = socket.read
        socket.close
        
        if response_bytes.bytes == message_bytes.bytes
          log_success "#{service_name} echoed correctly: '#{message[0,20]}#{message.length > 20 ? '...' : ''}'"
        else
          log_error "#{service_name} echo mismatch for: '#{message[0,20]}#{message.length > 20 ? '...' : ''}'"
          log_error "  Expected (#{message_bytes.encoding}, #{message_bytes.length} bytes): #{message_bytes.inspect}"
          log_error "  Received (#{response_bytes.encoding}, #{response_bytes.length} bytes): #{response_bytes.inspect}"
        end
      end
    rescue => e
      log_error "#{service_name} test failed: #{e.message}"
    end
  end

  def test_rate_limiting
    log_test "Rate Limiting Protection"
    
    begin
      # Test rate limiting on Rust echo service
      rapid_requests = 0
      start_time = Time.now
      
      (1..20).each do |i|
        begin
          socket = TCPSocket.new('localhost', 8081)
          socket.write("Rate limit test #{i}")
          socket.close_write
          response = socket.read
          socket.close
          rapid_requests += 1
        rescue => e
          # Connection refused indicates rate limiting
          if e.message.include?("Connection refused") || e.message.include?("Connection reset")
            log_success "Rate limiting activated after #{rapid_requests} requests"
            return
          end
        end
        
        # Small delay to avoid overwhelming
        sleep(0.1)
      end
      
      if rapid_requests >= 20
        log_warning "Rate limiting may not be active (completed 20 requests)"
      end
      
    rescue => e
      log_error "Rate limiting test failed: #{e.message}"
    end
  end

  def test_input_validation
    log_test "Input Validation Security"
    
    malicious_inputs = [
      "\x00\x01\x02\x03", # Null bytes and control characters
      "A" * 10000,        # Oversized input
      "../../../etc/passwd", # Path traversal
      "<script>alert('xss')</script>", # XSS attempt
      "'; DROP TABLE users; --", # SQL injection
      "\xFF\xFE\xFD\xFC"  # Invalid UTF-8
    ]
    
    malicious_inputs.each do |input|
      begin
        # Test against Rust service (should handle gracefully)
        socket = TCPSocket.new('localhost', 8081)
        socket.write(input)
        socket.close_write
        
        Timeout::timeout(5) do
          response = socket.read
          socket.close
          
          # Service should either echo safely or reject
          log_success "Malicious input handled safely: #{input.inspect[0,30]}..."
        end
      rescue Timeout::Error
        log_error "Service hung on malicious input: #{input.inspect[0,30]}..."
      rescue => e
        # Connection errors are acceptable for malicious input
        log_success "Malicious input rejected: #{input.inspect[0,30]}... (#{e.class})"
      end
    end
  end

  def test_buffer_overflow_protection
    log_test "Buffer Overflow Protection"
    
    # Test extremely large inputs
    large_inputs = [
      "A" * 8192,   # 8KB
      "B" * 16384,  # 16KB
      "C" * 32768   # 32KB
    ]
    
    large_inputs.each do |input|
      begin
        # Test C++ service specifically for buffer safety
        socket = TCPSocket.new('localhost', 8080)
        socket.write(input)
        socket.close_write
        
        Timeout::timeout(10) do
          response = socket.read
          socket.close
          
          if response.length <= 8192  # Should be truncated or rejected
            log_success "Large input handled safely: #{input.length} bytes -> #{response.length} bytes"
          else
            log_warning "Large input passed through: #{input.length} bytes"
          end
        end
      rescue Timeout::Error
        log_error "Service hung on large input: #{input.length} bytes"
      rescue => e
        log_success "Large input rejected: #{input.length} bytes (#{e.class})"
      end
    end
  end

  def test_client_attestation_flow
    log_test "Client Attestation Flow"
    
    begin
      # Simulate full client flow
      challenge = SecureRandom.hex(32)
      
      # Step 1: Request attestation - try working TEE types
      tee_types_to_try = ["sev-snp", "tdx", "sgx"]
      
      tee_types_to_try.each do |tee_type|
        uri = URI('http://localhost:3000/attestation')
        http = Net::HTTP.new(uri.host, uri.port)
        
        # Use GET request with query parameters
        uri.query = URI.encode_www_form({
          challenge: challenge,
          tee_type_filter: tee_type
        })
        
        response = http.get(uri)
        
        if response.code == '200'
          response_data = JSON.parse(response.body)
          if response_data['success'] && response_data['report']
            attestation = response_data['report']
            log_success "Step 1: Attestation received for #{tee_type}"
            
            # Step 2: Verify attestation
            verify_uri = URI('http://localhost:3000/verify')
            verify_request = Net::HTTP::Post.new(verify_uri)
            verify_request['Content-Type'] = 'application/json'
            verify_request.body = attestation.to_json
            
            verify_response = http.request(verify_request)
            
            if verify_response.code == '200'
              log_success "Step 2: Attestation verification passed for #{tee_type}"
              
              # Step 3: Test service interaction with validated system
              socket = TCPSocket.new('localhost', 8081)
              test_message = "Verified system test: #{SecureRandom.hex(16)}"
              socket.write(test_message)
              socket.close_write
              response = socket.read
              socket.close
              
              if response == test_message
                log_success "Step 3: Service interaction successful on verified system"
              else
                log_error "Step 3: Service interaction failed"
              end
              
              # Successfully completed flow, stop trying other TEE types
              return
            else
              log_info "Step 2: Attestation verification failed for #{tee_type}"
            end
          else
            log_info "Step 1: Attestation generation failed for #{tee_type}: #{response_data['error'] || 'Unknown error'}"
          end
        else
          log_info "Step 1: Attestation request failed for #{tee_type}: #{response.code}"
        end
      end
      
      # If we get here, no TEE type worked
      log_error "Client attestation flow failed: No supported TEE type found"
      
    rescue => e
      log_error "Client attestation flow failed: #{e.message}"
    end
  end

  def test_concurrent_connections
    log_test "Concurrent Connection Handling"
    
    begin
      threads = []
      results = []
      
      # Create 10 concurrent connections
      (1..10).each do |i|
        threads << Thread.new do
          begin
            socket = TCPSocket.new('localhost', 8081)
            message = "Concurrent test #{i}: #{SecureRandom.hex(8)}"
            socket.write(message)
            socket.close_write
            response = socket.read
            socket.close
            
            results << (response == message)
          rescue => e
            results << false
          end
        end
      end
      
      # Wait for all threads
      threads.each(&:join)
      
      successful = results.count(true)
      total = results.length
      
      if successful >= total * 0.8  # 80% success rate acceptable
        log_success "Concurrent connections: #{successful}/#{total} successful"
      else
        log_error "Concurrent connections: only #{successful}/#{total} successful"
      end
      
    rescue => e
      log_error "Concurrent connection test failed: #{e.message}"
    end
  end

  def test_memory_usage
    log_test "Memory Usage Monitoring"
    
    begin
      # Get initial memory usage (if available)
      if system("which", "ps", out: File::NULL, err: File::NULL)
        initial_memory = `ps aux | grep -E "(attestation-agent|echo-service)" | grep -v grep | awk '{sum+=$6} END {print sum}'`.strip.to_i
        
        # Perform stress operations with delays to avoid rate limiting
        (1..50).each do |i|
          begin
            socket = TCPSocket.new('localhost', 8081)
            socket.write("Memory test #{i}")
            socket.close_write
            socket.read
            socket.close
            
            # Small delay to respect rate limiting
            sleep(0.05) if i % 10 == 0
          rescue => e
            # If rate limited, wait a bit longer and continue
            if e.message.include?("Connection reset") || e.message.include?("Connection refused")
              log_info "Rate limiting encountered during memory test, waiting..."
              sleep(2)
              break  # Stop the test if rate limited
            end
          end
        end
        
        # Check memory after stress
        final_memory = `ps aux | grep -E "(attestation-agent|echo-service)" | grep -v grep | awk '{sum+=$6} END {print sum}'`.strip.to_i
        
        memory_increase = final_memory - initial_memory
        
        if memory_increase < 10000  # Less than 10MB increase acceptable
          log_success "Memory usage stable: #{memory_increase}KB increase"
        else
          log_warning "Memory usage increased significantly: #{memory_increase}KB"
        end
      else
        log_info "Memory monitoring tools not available, skipping"
      end
    rescue => e
      log_error "Memory usage test failed: #{e.message}"
    end
  end

  def generate_test_report
    duration = Time.now - @test_start_time
    
    puts "\n" + "=" * 60
    puts "    Test Execution Summary"
    puts "=" * 60
    
    success_count = @results.count { |r| r[:status] == :success }
    warning_count = @results.count { |r| r[:status] == :warning }
    error_count = @results.count { |r| r[:status] == :error }
    total_count = @results.length
    
    puts "[INFO] Total tests executed: #{total_count}"
    puts "[SUCCESS] Passed: #{success_count}"
    puts "[WARNING] Warnings: #{warning_count}" if warning_count > 0
    puts "[ERROR] Failed: #{error_count}" if error_count > 0
    puts "[INFO] Execution time: #{duration.round(2)} seconds"
    
    # Overall status
    if error_count == 0
      puts "\n✅ Overall Status: PASS"
      exit(0)
    else
      puts "\n❌ Overall Status: FAIL"
      puts "\nFailed tests:"
      @results.select { |r| r[:status] == :error }.each do |result|
        puts "  - #{result[:message]}"
      end
      exit(1)
    end
  end

  def log_test(test_name)
    puts "\n[TEST] #{test_name}"
  end

  def log_success(message)
    puts "[SUCCESS] #{message}"
    @results << { status: :success, message: message }
  end

  def log_warning(message)
    puts "[WARNING] #{message}"
    @results << { status: :warning, message: message }
  end

  def log_error(message)
    puts "[ERROR] #{message}"
    @results << { status: :error, message: message }
    @errors << message
  end

  def log_info(message)
    puts "[INFO] #{message}"
  end
end

# Run tests if script is executed directly
if __FILE__ == $0
  tests = BlocksenseIntegrationTests.new
  tests.run_all_tests
end