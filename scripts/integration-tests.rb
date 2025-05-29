#!/usr/bin/env ruby
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
  end

  def run_all_tests
    puts "=" * 60
    puts "    BlocksenseOS Integration Test Suite"
    puts "=" * 60
    puts "[INFO] Starting comprehensive integration tests..."
    
    # Service availability tests
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
      
      # Add query parameters for GET request
      uri.query = URI.encode_www_form({
        challenge: SecureRandom.hex(32),
        tee_type_filter: "mock"
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
            log_success "Attestation generated with all required fields"
            
            # Validate field formats
            if attestation['measurement'].match?(/^[a-f0-9]{64}$/i)
              log_success "Measurement field format is valid (64-char hex)"
            else
              log_error "Measurement field format is invalid"
            end
            
            if attestation['timestamp'].to_i > (Time.now.to_i - 60)
              log_success "Timestamp is recent (within 60 seconds)"
            else
              log_error "Timestamp is not recent"
            end
            
          else
            log_error "Missing required fields: #{missing_fields.join(', ')}"
          end
        else
          log_error "Attestation generation failed: #{response_data['error'] || 'Unknown error'}"
        end
      else
        log_error "Attestation generation failed: #{response.code} - #{response.body}"
      end
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
        socket = TCPSocket.new('localhost', port)
        socket.write(message)
        socket.close_write
        
        response = socket.read
        socket.close
        
        if response == message
          log_success "#{service_name} echoed correctly: '#{message[0,20]}#{message.length > 20 ? '...' : ''}'"
        else
          log_error "#{service_name} echo mismatch for: '#{message[0,20]}#{message.length > 20 ? '...' : ''}'"
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
      
      # Step 1: Request attestation
      uri = URI('http://localhost:3000/attestation')
      http = Net::HTTP.new(uri.host, uri.port)
      
      # Use GET request with query parameters
      uri.query = URI.encode_www_form({
        challenge: challenge,
        tee_type_filter: "mock"
      })
      
      response = http.get(uri)
      
      if response.code == '200'
        response_data = JSON.parse(response.body)
        if response_data['success'] && response_data['report']
          attestation = response_data['report']
          log_success "Step 1: Attestation received"
          
          # Step 2: Verify attestation
          verify_uri = URI('http://localhost:3000/verify')
          verify_request = Net::HTTP::Post.new(verify_uri)
          verify_request['Content-Type'] = 'application/json'
          verify_request.body = attestation.to_json
          
          verify_response = http.request(verify_request)
          
          if verify_response.code == '200'
            log_success "Step 2: Attestation verification passed"
            
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
          else
            log_error "Step 2: Attestation verification failed"
          end
        else
          log_error "Step 1: Attestation generation failed: #{response_data['error'] || 'Unknown error'}"
        end
      else
        log_error "Step 1: Attestation request failed: #{response.code}"
      end
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
        
        # Perform stress operations
        (1..100).each do |i|
          socket = TCPSocket.new('localhost', 8081)
          socket.write("Memory test #{i}")
          socket.close_write
          socket.read
          socket.close
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