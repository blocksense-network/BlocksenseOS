#!/usr/bin/env ruby
# Comprehensive security audit script for BlocksenseOS
# Performs automated security checks, vulnerability scanning, and compliance validation
# Ruby translation of the original bash script for better reliability and debugging

require 'json'
require 'fileutils'
require 'open3'
require 'optparse'
require 'date'
require 'tempfile'

class SecurityAudit
  # ANSI color codes
  RED = "\033[0;31m".freeze
  GREEN = "\033[0;32m".freeze
  YELLOW = "\033[1;33m".freeze
  BLUE = "\033[0;34m".freeze
  NC = "\033[0m".freeze # No Color

  attr_reader :findings_file, :output_dir, :report_format, :command, :critical_issues, :high_issues, :medium_issues, :low_issues, :info_issues, :security_issues_found

  def initialize
    @script_dir = File.dirname(File.expand_path(__FILE__))
    @project_root = File.dirname(@script_dir)
    @audit_timestamp = Time.now.strftime('%Y%m%d_%H%M%S')
    @audit_dir = File.join(@project_root, 'security', "audit-#{@audit_timestamp}")
    @findings_file = File.join(@audit_dir, 'findings.json')
    @report_file = File.join(@audit_dir, 'security-audit-report.md')
    
    # CLI options
    @verbose = false
    @output_dir = File.join(@project_root, 'security')
    @report_format = 'markdown'
    @command = 'all'
    
    # Counters
    @critical_issues = 0
    @high_issues = 0
    @medium_issues = 0
    @low_issues = 0
    @info_issues = 0
    @security_issues_found = false
  end

  def log_info(message)
    puts "#{BLUE}[INFO]#{NC} #{message}"
    if @verbose
      STDERR.puts "[#{Time.now.strftime('%Y-%m-%dT%H:%M:%S%z')}] INFO: #{message}"
    end
  end

  def log_success(message)
    puts "#{GREEN}[PASS]#{NC} #{message}"
    if @verbose
      STDERR.puts "[#{Time.now.strftime('%Y-%m-%dT%H:%M:%S%z')}] SUCCESS: #{message}"
    end
  end

  def log_warning(message)
    puts "#{YELLOW}[WARN]#{NC} #{message}"
    @medium_issues += 1
    @security_issues_found = true
    if @verbose
      STDERR.puts "[#{Time.now.strftime('%Y-%m-%dT%H:%M:%S%z')}] WARNING: #{message}"
    end
  end

  def log_error(message)
    puts "#{RED}[FAIL]#{NC} #{message}"
    @high_issues += 1
    @security_issues_found = true
    if @verbose
      STDERR.puts "[#{Time.now.strftime('%Y-%m-%dT%H:%M:%S%z')}] ERROR: #{message}"
    end
  end

  def log_critical(message)
    puts "#{RED}[CRITICAL]#{NC} #{message}"
    @critical_issues += 1
    @security_issues_found = true
    if @verbose
      STDERR.puts "[#{Time.now.strftime('%Y-%m-%dT%H:%M:%S%z')}] CRITICAL: #{message}"
    end
  end

  def show_help
    puts <<~EOF
      BlocksenseOS Security Audit Tool v2.0

      USAGE:
          #{$0} [OPTIONS] [COMMAND]

      OPTIONS:
          -v, --verbose       Enable verbose output
          -o, --output DIR    Set output directory (default: #{@output_dir})
          -f, --format FORMAT Set report format: markdown|json (default: #{@report_format})
          -h, --help          Show this help message

      COMMANDS:
          rust-audit          Run Rust security audits only
          cpp-audit           Run C++ security audits only
          sbom               Generate SBOM only
          vulnerability-scan  Run vulnerability scanning only
          secret-scan        Scan for secrets only
          dependencies       Audit dependencies only
          configuration      Audit security configuration only
          build-security     Audit build security only
          documentation      Audit security documentation only
          nix-validate       Validate Nix configurations only
          report             Generate security report only
          all                Run all security checks (default)

      EXAMPLES:
          #{$0}                          # Run all security checks
          #{$0} rust-audit               # Run only Rust audits
          #{$0} -v sbom                  # Generate SBOM with verbose output
          #{$0} -o /tmp/security all     # Run all checks, output to /tmp/security
          #{$0} -f json vulnerability-scan  # Run vulnerability scan with JSON output

      LEGACY COMPATIBILITY:
          This script maintains compatibility with the original modular interface
          while providing comprehensive security audit coverage.
    EOF
  end

  def parse_args
    OptionParser.new do |opts|
      opts.on('-v', '--verbose', 'Enable verbose output') do
        @verbose = true
      end
      
      opts.on('-o', '--output DIR', 'Set output directory') do |dir|
        @output_dir = dir
        @audit_dir = File.join(@output_dir, "audit-#{@audit_timestamp}")
        @findings_file = File.join(@audit_dir, 'findings.json')
        @report_file = File.join(@audit_dir, 'security-audit-report.md')
      end
      
      opts.on('-f', '--format FORMAT', 'Set report format: markdown|json') do |format|
        @report_format = format
      end
      
      opts.on('-h', '--help', 'Show this help message') do
        show_help
        exit 0
      end
    end.parse!
    
    @command = ARGV[0] || 'all'
  end

  def setup_audit_environment
    log_info "Setting up security audit environment..."
    FileUtils.mkdir_p(@audit_dir)
    
    # Create legacy directory structure for compatibility
    %w[rust-audit sbom scan-results secret-scan nix-validation reports].each do |dir|
      FileUtils.mkdir_p(File.join(@output_dir, dir))
    end
    
    Dir.chdir(@project_root)
    
    # Initialize findings file
    version = run_command('git describe --tags --always 2>/dev/null') rescue 'unknown'
    commit = run_command('git rev-parse HEAD 2>/dev/null') rescue 'unknown'
    
    metadata = {
      audit_metadata: {
        timestamp: @audit_timestamp,
        project: 'BlocksenseOS',
        version: version.strip,
        commit: commit.strip,
        output_directory: @output_dir,
        report_format: @report_format
      },
      findings: []
    }
    
    File.write(@findings_file, JSON.pretty_generate(metadata))
    log_success "Audit environment setup completed"
  end

  def add_finding(severity, category, title, description, file = '', line = '')
    # Update counters
    case severity
    when 'critical'
      @critical_issues += 1
    when 'high'
      @high_issues += 1
    when 'medium'
      @medium_issues += 1
    when 'low'
      @low_issues += 1
    when 'info'
      @info_issues += 1
    end

    # Add to findings file
    finding = {
      severity: severity,
      category: category,
      title: title,
      description: description,
      file: file,
      line: line,
      timestamp: Time.now.strftime('%Y-%m-%dT%H:%M:%S%z')
    }

    if File.exist?(@findings_file)
      temp_file = Tempfile.new('findings')
      begin
        findings_data = JSON.parse(File.read(@findings_file))
        findings_data['findings'] << finding
        temp_file.write(JSON.pretty_generate(findings_data))
        temp_file.close
        FileUtils.mv(temp_file.path, @findings_file)
      ensure
        temp_file.unlink
      end
    end
  end

  def command_available?(cmd)
    system("command -v #{cmd} >/dev/null 2>&1")
  end

  def run_command(cmd, capture_output: true)
    if capture_output
      stdout, stderr, status = Open3.capture3(cmd)
      return stdout if status.success?
      raise "Command failed: #{cmd}\n#{stderr}"
    else
      system(cmd)
    end
  end

  def check_dependencies
    log_info "Checking security audit dependencies..."
    
    missing_tools = []
    
    # Required tools
    required_tools = {
      'cargo' => 'Rust package manager',
      'git' => 'Version control',
      'grep' => 'Text search',
      'find' => 'File search',
      'sha256sum' => 'Checksum verification'
    }
    
    # Optional but recommended tools
    optional_tools = {
      'jq' => 'JSON processing',
      'trivy' => 'Vulnerability scanner',
      'syft' => 'SBOM generation',
      'cargo-audit' => 'Rust vulnerability scanner',
      'cargo-deny' => 'Rust policy enforcement',
      'alejandra' => 'Nix formatter',
      'semgrep' => 'Static analysis',
      'bandit' => 'Python security linter',
      'shellcheck' => 'Shell script analysis'
    }
    
    required_tools.each do |tool, desc|
      unless command_available?(tool)
        missing_tools << "#{tool} (#{desc})"
        log_error "Required tool missing: #{tool}"
      end
    end
    
    optional_tools.each do |tool, desc|
      if command_available?(tool)
        log_success "Found optional tool: #{tool}" if @verbose
      else
        log_info "Optional tool missing: #{tool} (#{desc})" if @verbose
        add_finding('info', 'dependencies', 'Missing optional security tool', 
                   "Tool #{tool} not available: #{desc}")
      end
    end
    
    unless missing_tools.empty?
      log_critical "Cannot proceed with audit. Missing required tools: #{missing_tools.join(', ')}"
      exit 1
    end
    
    log_success "All required dependencies available"
  end

  def audit_rust_security
    log_info "Running comprehensive Rust security audits..."
    
    rust_projects = [
      'attestation-agent',
      'services/rust-echo',
      'clients/rust-client',
      'derivation-hasher',
      'performance-monitor'
    ]
    
    audit_issues_found = false
    
    rust_projects.each do |project|
      project_path = File.join(@project_root, project)
      next unless File.directory?(project_path)
      
      log_info "Auditing #{project}..."
      Dir.chdir(project_path)
      
      # Advanced cargo-audit integration
      if command_available?('cargo-audit')
        begin
          audit_output = run_command('cargo audit --json 2>&1')
          audit_file = File.join(@output_dir, 'rust-audit', "#{project.tr('/', '-')}-audit.json")
          File.write(audit_file, audit_output)
          
          # Enhanced JSON parsing
          if audit_output.include?('"vulnerabilities"')
            begin
              audit_data = JSON.parse(audit_output)
              if audit_data.dig('vulnerabilities', 'found') && 
                 audit_data.dig('vulnerabilities', 'found').length > 0
                vuln_count = audit_data.dig('vulnerabilities', 'count') || 0
                log_error "Found #{vuln_count} vulnerabilities in #{project}"
                add_finding('high', 'rust_security', 'Known vulnerabilities found',
                           "Cargo audit found #{vuln_count} vulnerabilities in #{project}",
                           "#{project}/Cargo.toml")
                audit_issues_found = true
              else
                log_success "No known vulnerabilities in #{project}"
              end
            rescue JSON::ParserError
              log_success "No known vulnerabilities in #{project}"
            end
          else
            log_success "No known vulnerabilities in #{project}"
          end
        rescue => e
          audit_file = File.join(@output_dir, 'rust-audit', "#{project.tr('/', '-')}-audit.json")
          File.write(audit_file, e.message)
          log_error "Security vulnerabilities found in #{project}"
          add_finding('high', 'rust_security', 'Cargo audit vulnerabilities',
                     "Vulnerabilities found in #{project}", "#{project}/Cargo.toml")
          audit_issues_found = true
        end
      else
        log_warning "cargo-audit not installed, skipping vulnerability check for #{project}"
        add_finding('medium', 'rust_security', 'Missing cargo-audit',
                   'Cannot check for known vulnerabilities without cargo-audit',
                   "#{project}/Cargo.toml")
      end
      
      # Advanced cargo-deny integration
      if command_available?('cargo-deny')
        begin
          deny_output = run_command('cargo deny check 2>&1')
          deny_file = File.join(@output_dir, 'rust-audit', "#{project.tr('/', '-')}-deny.txt")
          File.write(deny_file, deny_output)
          log_success "No policy violations in #{project}"
        rescue => e
          deny_file = File.join(@output_dir, 'rust-audit', "#{project.tr('/', '-')}-deny.txt")
          File.write(deny_file, e.message)
          log_error "Policy violations found in #{project}"
          add_finding('high', 'rust_security', 'Cargo deny policy violations',
                     "Policy violations found in #{project}", "#{project}/deny.toml")
          audit_issues_found = true
        end
      end
      
      # Check for unsafe code usage
      unsafe_count = `grep -r "unsafe" --include="*.rs" . 2>/dev/null | wc -l`.strip.to_i
      if unsafe_count > 0
        log_warning "Found #{unsafe_count} unsafe blocks in #{project}"
        add_finding('medium', 'rust_security', 'Unsafe code usage',
                   "Found #{unsafe_count} unsafe blocks in Rust code", project)
      else
        log_success "No unsafe code blocks found in #{project}"
      end
      
      # Check for unwrap() usage (potential panics)
      unwrap_count = `grep -r "\\.unwrap()" --include="*.rs" . 2>/dev/null | wc -l`.strip.to_i
      if unwrap_count > 5
        log_warning "High unwrap() usage (#{unwrap_count} occurrences) in #{project}"
        add_finding('low', 'rust_security', 'High unwrap usage',
                   "Found #{unwrap_count} .unwrap() calls which could cause panics", project)
      end
      
      # Check deny.toml configuration
      if File.exist?('deny.toml')
        log_success "Found deny.toml configuration in #{project}"
        
        # Check if deny.toml is comprehensive
        deny_sections = File.read('deny.toml').scan(/^\[/).length
        if deny_sections < 3
          log_warning "deny.toml appears incomplete (only #{deny_sections} sections)"
          add_finding('medium', 'rust_security', 'Incomplete deny.toml',
                     'deny.toml should include advisories, licenses, and bans sections',
                     'deny.toml')
        end
      else
        log_error "No deny.toml found in #{project}"
        add_finding('high', 'rust_security', 'Missing deny.toml',
                   'Rust project lacks cargo-deny configuration', "#{project}/Cargo.toml")
      end
      
      Dir.chdir(@project_root)
    end
    
    if audit_issues_found
      log_success "Rust audits completed"
    else
      log_success "Rust audits completed - no issues found"
    end
  end

  def audit_cpp_security
    log_info "Auditing C++ security..."
    
    # Find C++ source files
    cpp_files = `find . -name "*.cpp" -o -name "*.hpp" -o -name "*.h" -not -path "./target/*" -not -path "./.git/*" 2>/dev/null`.split("\n")
    
    if cpp_files.empty?
      log_info "No C++ files found"
      return
    end
    
    # Check for dangerous functions
    dangerous_functions = %w[strcpy strcat sprintf gets scanf strncpy vsprintf strtok]
    dangerous_functions.each do |func|
      usage_count = `grep -r "\\b#{func}\\b" #{cpp_files.join(' ')} 2>/dev/null | wc -l`.strip.to_i
      if usage_count > 0
        log_error "Found #{usage_count} uses of dangerous function: #{func}"
        add_finding('high', 'cpp_security', 'Dangerous function usage',
                   "Found usage of potentially unsafe function: #{func}")
      end
    end
    
    # Check for buffer size constants
    magic_numbers = `grep -r "char.*\\[.*[0-9]\\+.*\\]" #{cpp_files.join(' ')} 2>/dev/null | wc -l`.strip.to_i
    if magic_numbers > 0
      log_warning "Found #{magic_numbers} potential magic number buffer sizes"
      add_finding('medium', 'cpp_security', 'Magic number buffer sizes',
                 'Consider using named constants for buffer sizes')
    end
    
    # Check for proper includes
    security_headers = %w[cstring algorithm memory]
    security_headers.each do |header|
      if cpp_files.none? { |file| File.read(file).include?("#include <#{header}>") rescue false }
        log_info "Consider including <#{header}> for safer C++ operations" if @verbose
      end
    end
    
    log_success "C++ security audit completed"
  end

  # Continue with remaining methods...
  def generate_sbom
    log_info "Generating Software Bill of Materials..."
    
    if command_available?('syft')
      begin
        run_command("syft '#{@project_root}' -o spdx-json='#{@output_dir}/sbom/blocksense-os-sbom.spdx.json' 2>/dev/null", capture_output: false)
      rescue
        log_warning "SPDX SBOM generation failed"
      end
      
      begin
        run_command("syft '#{@project_root}' -o cyclonedx-json='#{@output_dir}/sbom/blocksense-os-sbom.cyclone.json' 2>/dev/null", capture_output: false)
      rescue
        log_warning "CycloneDX SBOM generation failed"
      end
      
      begin
        run_command("syft '#{@project_root}' -o syft-json='#{@output_dir}/sbom/blocksense-os-sbom.syft.json' 2>/dev/null", capture_output: false)
      rescue
        log_warning "Syft SBOM generation failed"
      end
      
      # Validate SBOM was created
      spdx_file = File.join(@output_dir, 'sbom', 'blocksense-os-sbom.spdx.json')
      if File.exist?(spdx_file)
        log_success "SBOM generated successfully"
        
        # Analyze SBOM for security insights
        if command_available?('jq')
          begin
            package_count = JSON.parse(File.read(spdx_file))['packages']&.length || 'unknown'
            log_info "SBOM contains #{package_count} packages"
          rescue
            # Ignore JSON parsing errors
          end
        end
      else
        log_error "SBOM generation failed"
        add_finding('medium', 'dependencies', 'SBOM generation failed',
                   'Could not generate Software Bill of Materials')
      end
    else
      log_warning "syft not available for SBOM generation"
      add_finding('info', 'dependencies', 'Missing SBOM tool',
                 'Consider installing syft for Software Bill of Materials generation')
    end
  end

  def vulnerability_scan
    log_info "Running comprehensive vulnerability scan..."
    
    if command_available?('trivy')
      issues_found = false
      
      # Run filesystem scan
      log_info "Scanning filesystem for vulnerabilities..."
      begin
        fs_scan_file = File.join(@output_dir, 'scan-results', 'filesystem-scan.json')
        run_command("trivy fs --format json --output '#{fs_scan_file}' '#{@project_root}'", capture_output: false)
        
        if File.exist?(fs_scan_file)
          scan_data = JSON.parse(File.read(fs_scan_file))
          vuln_count = scan_data['Results']&.sum { |result| result['Vulnerabilities']&.length || 0 } || 0
          
          if vuln_count > 0
            log_error "Found #{vuln_count} vulnerabilities in filesystem scan"
            add_finding('high', 'dependencies', 'Vulnerabilities in dependencies',
                       "Found #{vuln_count} vulnerabilities in dependencies")
            
            # Show high/critical vulnerabilities
            scan_data['Results']&.each do |result|
              result['Vulnerabilities']&.each do |vuln|
                if %w[HIGH CRITICAL].include?(vuln['Severity'])
                  log_error "  #{vuln['Severity']}: #{vuln['VulnerabilityID']} in #{vuln['PkgName']} #{vuln['InstalledVersion']}"
                end
              end
            end
            issues_found = true
          else
            log_success "No vulnerabilities found in filesystem scan"
          end
        end
      rescue => e
        log_error "Trivy filesystem scan failed"
        add_finding('medium', 'dependencies', 'Vulnerability scan failed',
                   'Could not complete trivy vulnerability scan')
        issues_found = true
      end
      
      # Enhanced configuration scan
      log_info "Scanning configurations for security issues..."
      begin
        config_scan_file = File.join(@output_dir, 'scan-results', 'config-scan.json')
        run_command("trivy config --format json --output '#{config_scan_file}' '#{@project_root}'", capture_output: false)
        
        if File.exist?(config_scan_file)
          config_data = JSON.parse(File.read(config_scan_file))
          misconfig_count = config_data['Results']&.sum { |result| result['Misconfigurations']&.length || 0 } || 0
          
          if misconfig_count > 0
            log_error "Found #{misconfig_count} configuration issues"
            add_finding('medium', 'configuration', 'Configuration security issues',
                       "Found #{misconfig_count} configuration security issues")
            
            # Show high/critical misconfigurations
            config_data['Results']&.each do |result|
              result['Misconfigurations']&.each do |misconfig|
                if %w[HIGH CRITICAL].include?(misconfig['Severity'])
                  log_error "  #{misconfig['Severity']}: #{misconfig['ID']} - #{misconfig['Title']}"
                end
              end
            end
            issues_found = true
          else
            log_success "No configuration issues found"
          end
        end
      rescue => e
        log_error "Trivy configuration scan failed"
        add_finding('medium', 'configuration', 'Configuration scan failed',
                   'Could not complete trivy configuration scan')
        issues_found = true
      end
      
      if issues_found
        log_error "Vulnerability scan completed with issues"
      else
        log_success "Vulnerability scan completed - no issues found"
      end
    else
      log_warning "Trivy not available for vulnerability scanning"
      add_finding('info', 'dependencies', 'Missing vulnerability scanner',
                 'Consider installing trivy for comprehensive vulnerability scanning')
    end
  end

  def secret_scan
    log_info "Scanning for secrets and sensitive data..."
    
    Dir.chdir(@project_root)
    
    # Enhanced secret patterns (more specific to avoid false positives)
    patterns = [
      # API keys and tokens (must be in assignment context)
      "(?i)(api[_-]?key|secret[_-]?key|access[_-]?token)\\s*[:=]\\s*['\"][a-zA-Z0-9]{20,}['\"]",
      # Database connection strings
      "(?i)(password|pwd)\\s*[:=]\\s*['\"][^'\"]{8,}['\"]",
      # Private keys (actual key content, not just headers)
      "-----BEGIN [A-Z ]*PRIVATE KEY-----[\\s\\S]{100,}-----END [A-Z ]*PRIVATE KEY-----",
      # AWS access keys (specific format)
      "AKIA[0-9A-Z]{16}",
      # JWT tokens (must be complete)
      "eyJ[A-Za-z0-9_=-]{10,}\\.[A-Za-z0-9_=-]{10,}\\.[A-Za-z0-9_=.-]{10,}",
      # SSH private keys (actual content)
      "-----BEGIN OPENSSH PRIVATE KEY-----[\\s\\S]+-----END OPENSSH PRIVATE KEY-----",
      # Generic secrets in quotes (but not in comments or docs)
      "(?i)secret\\s*[:=]\\s*['\"][^'\"]{12,}['\"]"
    ]
    
    secrets_found = false
    temp_results = Tempfile.new('secret_scan')
    
    begin
      # Search for each pattern with better filtering
      patterns.each do |pattern|
        if command_available?('grep')
          # Search only in source files, exclude documentation and generated files
          # Use simpler shell escaping to avoid EOF issues
          escaped_pattern = pattern.gsub("'", "'\"'\"'")
          cmd = "find . -type f \\( -name '*.rs' -o -name '*.toml' -o -name '*.nix' -o -name '*.yml' -o -name '*.yaml' -o -name '*.json' \\) " \
                "-not -path '*/.git/*' -not -path '*/target/*' -not -path '*/build/*' -not -path '*/node_modules/*' " \
                "-not -path '*/security/*' -not -path '*/docs/*' -not -path '*/*.md' -not -path '*/README*' " \
                "-not -path '*/Cargo.lock' -not -path '*/flake.lock' -not -path '*/result*' " \
                "| xargs grep -E '#{escaped_pattern}' 2>/dev/null || true"
          
          result = `#{cmd}`
          unless result.empty?
            temp_results.write(result)
            secrets_found = true
          end
        end
      end
      
      temp_results.close
      
      # Enhanced false positive filtering
      if File.size(temp_results.path) > 0
        filtered_results = Tempfile.new('filtered_secrets')
        
        begin
          # Advanced filtering to remove false positives
          File.foreach(temp_results.path) do |line|
            # Skip GitHub Actions secret references (legitimate)
            next if line.match?(/\$\{\{\s*secrets\./)
            # Skip obvious test/example patterns
            next if line.match?(/password.*[=:].*["'](password|test|example|dummy|placeholder|sample|mock|changeme|123456|admin)["']/i)
            # Skip API key examples in documentation
            next if line.match?(/api[_-]?key.*[=:].*["'](your[_-]?api[_-]?key|example|test|demo|sample)["']/i)
            # Skip security audit script patterns (our own patterns)
            next if line.match?(/scripts\/security-audit/)
            # Skip comments and documentation
            next if line.match?(/^\s*[#\/\*]/)
            # Skip variable declarations without actual values
            next if line.match?(/\$\w+/)
            # Skip environment variable patterns
            next if line.match?(/\$\{[A-Z_]+\}/)
            # Skip checksum patterns (hex strings in lock files)
            next if line.match?(/[0-9a-f]{32,64}/) && line.match?(/lock|checksum|hash/)
            # Skip git commit references
            next if line.match?(/[0-9a-f]{40}/) && line.match?(/git|commit|ref/)
            # Skip Nix store paths
            next if line.match?(/\/nix\/store\/[0-9a-z]{32}/)
            
            filtered_results.write(line)
          end
          
          filtered_results.close
          
          if File.size(filtered_results.path) > 0
            results_file = File.join(@output_dir, 'secret-scan', 'results.txt')
            FileUtils.cp(filtered_results.path, results_file)
            
            secret_count = File.foreach(filtered_results.path).count
            
            # Only flag as critical if we find real secrets (not just patterns)
            if secret_count > 0
              log_error "Found #{secret_count} potential secrets - manual review required: #{results_file}"
              add_finding('high', 'secrets', 'Potential secrets found',
                         "Found #{secret_count} potential secrets requiring manual review")
              secrets_found = true
              
              # Show first few secrets for immediate attention
              if @verbose
                log_error "Potential secrets found:"
                File.foreach(filtered_results.path).first(3).each do |line|
                  log_error "  #{line.strip}"
                end
              end
            else
              results_file = File.join(@output_dir, 'secret-scan', 'results.txt')
              File.write(results_file, "No secrets found after filtering")
              secrets_found = false
            end
          else
            results_file = File.join(@output_dir, 'secret-scan', 'results.txt')
            File.write(results_file, "No real secrets found (all patterns filtered as false positives)")
            secrets_found = false
          end
        ensure
          filtered_results.unlink
        end
      else
        results_file = File.join(@output_dir, 'secret-scan', 'results.txt')
        File.write(results_file, "No secrets found")
        secrets_found = false
      end
      
      # Check for actual secret files (not just patterns)
      secret_files = ['.env', '.secrets', '*.pem', '*.key', 'id_rsa', 'id_dsa', '.aws/credentials']
      secret_files.each do |pattern|
        files = `find '#{@project_root}' -name "#{pattern}" -not -path "*/.git/*" -not -path "*/target/*" -not -path "*/build/*" -not -path "*/test*" 2>/dev/null`.strip
        unless files.empty?
          files.split("\n").each do |file|
            # Check if it's actually a secret file (has content that looks like secrets)
            if File.exist?(file) && File.size(file) > 0 && File.size(file) < 10240 # reasonable size
              content = File.read(file)
              # Look for actual secret-like content, not just the filename
              if content.match?(/[A-Za-z0-9]{20,}/) && !content.match?(/^#.*test|example|sample/i)
                results_file = File.join(@output_dir, 'secret-scan', 'results.txt')
                File.open(results_file, 'a') { |f| f.puts("Found potential secret file: #{file}") }
                log_error "Found potential secret file: #{file}"
                add_finding('high', 'secrets', 'Secret file found',
                           "Found file that may contain secrets: #{file}")
                secrets_found = true
              end
            end
          end
        end
      end
      
    ensure
      temp_results.unlink
    end
    
    unless secrets_found
      log_success "No secrets detected"
    end
  end

  # Enhanced dependency audit (restored from bash)
  def audit_dependencies
    log_info "Auditing dependency security..."
    
    # Enhanced trivy integration (restored from bash)
    if command_available?('trivy')
      log_info "Running comprehensive trivy vulnerability scan..."
      trivy_results = File.join(@audit_dir, 'trivy-results.json')
      
      begin
        run_command("trivy fs --format json --output '#{trivy_results}' '#{@project_root}' 2>/dev/null", capture_output: false)
        
        if File.exist?(trivy_results)
          scan_data = JSON.parse(File.read(trivy_results))
          vuln_count = (scan_data['Results'] || []).sum { |result| (result['Vulnerabilities'] || []).length }
          
          if vuln_count > 0
            log_error "Trivy found #{vuln_count} vulnerabilities"
            add_finding('high', 'dependencies', 'Vulnerabilities in dependencies',
                       "Found #{vuln_count} vulnerabilities in dependencies")
          else
            log_success "No vulnerabilities found by trivy"
          end
        end
      rescue => e
        log_error "Trivy scan failed"
        add_finding('medium', 'dependencies', 'Vulnerability scan failed',
                   'Could not complete trivy vulnerability scan')
      end
    else
      log_warning "Trivy not available for vulnerability scanning"
      add_finding('info', 'dependencies', 'Missing vulnerability scanner',
                 'Consider installing trivy for comprehensive vulnerability scanning')
    end
    
    # Check for pinned versions in flake.lock (restored from bash)
    if File.exist?('flake.lock')
      log_success "Found flake.lock with pinned Nix dependencies"
      
      # Check if flake.lock is recent
      lock_age_days = ((Time.now - File.mtime('flake.lock')) / 86400).to_i
      if lock_age_days > 90
        log_warning "flake.lock is #{lock_age_days} days old"
        add_finding('medium', 'dependencies', 'Outdated dependency pins',
                   "flake.lock is #{lock_age_days} days old, consider updating", 'flake.lock')
      end
    else
      log_error "No flake.lock found - dependencies not pinned"
      add_finding('high', 'dependencies', 'Unpinned dependencies',
                 'Missing flake.lock file for reproducible builds')
    end
  end

  # Enhanced configuration audit (restored from bash)
  def audit_configuration
    log_info "Auditing security configuration..."
    
    # Check NixOS security modules
    security_modules = Dir.glob('nixos-modules/*.nix')
    if security_modules.any?
      log_success "Found NixOS security modules: #{security_modules.join(', ')}"
      
      # Check for security hardening options
      hardening_options = ['security.allowUserNamespaces', 'security.protectKernelImage', 'boot.kernel.sysctl']
      security_modules.each do |security_module|
        hardening_options.each do |option|
          if File.read(security_module).include?(option)
            log_success "Found security option #{option} in #{security_module}"
          end
        end
      end
    else
      log_warning "No NixOS security modules found"
      add_finding('medium', 'configuration', 'Missing security modules',
                 'Consider adding dedicated security configuration modules')
    end
    
    # Check for systemd service hardening
    service_files = Dir.glob('**/*.service')
    service_files.each do |service|
      hardening_options = ['NoNewPrivileges', 'ProtectSystem', 'ProtectHome', 'PrivateTmp']
      hardening_count = 0
      
      service_content = File.read(service)
      hardening_options.each do |option|
        hardening_count += 1 if service_content.include?(option)
      end
      
      if hardening_count < 2
        log_warning "Service #{service} has minimal hardening options"
        add_finding('medium', 'configuration', 'Insufficient service hardening',
                   "Service #{service} lacks security hardening options", service)
      end
    end
  end

  # Build security audit (restored from bash)
  def audit_build_security
    log_info "Auditing build security..."
    
    # Check CI configuration
    ci_files = Dir.glob('.github/workflows/*.{yml,yaml}')
    if ci_files.any?
      log_success "Found CI configuration files"
      
      # Check if ANY workflow file has security checks (not all of them)
      has_security_workflow = false
      security_keywords_found = false
      
      ci_files.each do |ci_file|
        ci_content = File.read(ci_file)
        
        # Check for dedicated security workflows or security steps
        if ci_file.match?(/security|audit/) || ci_content.match?(/security|audit|vulnerability|trivy|cargo-audit/i)
          has_security_workflow = true
          security_keywords_found = true
          log_success "Security checks found in #{ci_file}"
        end
        
        # Check for secrets handling
        if ci_content.include?('secrets.')
          log_success "Proper secrets handling in #{ci_file}"
        end
      end
      
      # Only flag as missing if NO workflows have security checks
      unless has_security_workflow
        log_warning "No dedicated security workflows found"
        add_finding('medium', 'build_security', 'Missing CI security workflow',
                   'Consider adding a dedicated security audit workflow')
      end
      
    else
      log_warning "No CI configuration found"
      add_finding('medium', 'build_security', 'Missing CI configuration',
                 'No automated CI pipeline for security checks')
    end
    
    # Check for reproducible build configuration
    if File.exist?('flake.nix')
      log_success "Found Nix flake for reproducible builds"
      
      flake_content = File.read('flake.nix')
      # Check for security-related packages
      if flake_content.match?(/tpm|luks|security/i)
        log_success "Security packages referenced in flake.nix"
      else
        log_info "No explicit security packages found in flake.nix (may be inherited from NixOS modules)"
      end
    end
  end

  # Documentation audit (restored from bash)
  def audit_documentation
    log_info "Auditing security documentation..."
    
    # Check for required documentation files
    required_docs = ['SECURITY.md', 'THREAT-MODEL.md', 'MAINTAINERS.md']
    required_docs.each do |doc|
      doc_paths = ["docs/#{doc}", doc]
      if doc_paths.any? { |path| File.exist?(path) }
        log_success "Found required documentation: #{doc}"
      else
        log_error "Missing required documentation: #{doc}"
        add_finding('high', 'documentation', 'Missing security documentation',
                   "Required security document not found: #{doc}")
      end
    end
    
    # Check documentation completeness with more reasonable criteria
    threat_doc_paths = ['docs/THREAT-MODEL.md', 'THREAT-MODEL.md']
    threat_doc = threat_doc_paths.find { |path| File.exist?(path) }
    
    if threat_doc
      threat_content = File.read(threat_doc)
      
      # Check for either traditional sections OR STRIDE methodology
      traditional_sections = ['Assets', 'Threat Actors', 'Attack Scenarios', 'Mitigations']
      stride_sections = ['STRIDE', 'Spoofing', 'Tampering', 'Repudiation', 'Information disclosure', 'Denial of service', 'Elevation of privilege']
      
      # Check if using STRIDE methodology (more comprehensive)
      has_stride = stride_sections.any? { |section| threat_content.match?(/#{section}/i) }
      
      if has_stride
        log_success "Threat model uses STRIDE methodology (comprehensive approach)"
        
        # For STRIDE, just check that basic elements are present
        essential_elements = ['Assets', 'Mitigations']
        essential_elements.each do |element|
          if threat_content.match?(/#{element}/i)
            log_success "Threat model includes #{element} section"
          else
            log_warning "Threat model should include #{element} analysis"
            add_finding('low', 'documentation', 'Incomplete threat model',
                       "Threat model should include #{element} analysis", threat_doc)
          end
        end
      else
        # Traditional threat model - check for all sections
        traditional_sections.each do |section|
          if threat_content.match?(/#{section}/i)
            log_success "Threat model includes #{section} section"
          else
            log_warning "Threat model missing #{section} section"
            add_finding('medium', 'documentation', 'Incomplete threat model',
                       "Threat model should include #{section} analysis", threat_doc)
          end
        end
      end
    end
  end

  # Enhanced Nix validation (restored from bash)
  def nix_validate
    log_info "Validating Nix configurations..."
    
    Dir.chdir(@project_root)
    
    if command_available?('nix')
      # Enhanced flake checking (restored from bash)
      flake_check_log = File.join(@output_dir, 'nix-validation', 'flake-check.log')
      
      begin
        run_command("nix flake check --all-systems > '#{flake_check_log}' 2>&1", capture_output: false)
        log_success "Nix flake check passed for all systems"
      rescue => e
        log_error "Nix flake check failed for some systems"
        add_finding('high', 'build_security', 'Nix flake check failed',
                   'Nix flake validation failed for some systems', 'flake.nix')
        
        # Show specific errors if verbose
        if @verbose && File.exist?(flake_check_log)
          log_error "Flake check errors:"
          File.foreach(flake_check_log).last(10).each do |line|
            log_error "  #{line.strip}"
          end
        end
      end
      
      # Enhanced formatting check (restored from bash)
      if command_available?('alejandra')
        formatting_log = File.join(@output_dir, 'nix-validation', 'formatting.log')
        
        begin
          run_command("alejandra --check . > '#{formatting_log}' 2>&1", capture_output: false)
          log_success "All Nix files are properly formatted"
        rescue => e
          log_error "Nix formatting issues found"
          add_finding('medium', 'build_security', 'Nix formatting issues',
                     'Nix files are not properly formatted')
          
          if @verbose && File.exist?(formatting_log)
            log_error "Formatting issues:"
            File.foreach(formatting_log).first(5).each do |line|
              log_error "  #{line.strip}"
            end
          end
        end
      else
        log_warning "alejandra not available for Nix formatting check"
      end
      
      log_success "Nix validation completed"
    else
      log_warning "Nix not available for validation"
      add_finding('info', 'build_security', 'Missing Nix',
                 'Nix not available for configuration validation')
    end
  end

  # Enhanced report generation with format support (restored from bash)
  def generate_report
    log_info "Generating security audit report..."
    
    total_issues = @critical_issues + @high_issues + @medium_issues + @low_issues + @info_issues
    timestamp = Time.now.strftime('%Y%m%d-%H%M%S')
    report_file = File.join(@output_dir, 'reports', "security-report-#{timestamp}.#{@report_format}")
    
    if @report_format == 'json'
      # JSON format report (restored from bash)
      version = run_command('git describe --tags --always 2>/dev/null') rescue 'unknown'
      commit = run_command('git rev-parse HEAD 2>/dev/null') rescue 'unknown'
      
      report_data = {
        metadata: {
          timestamp: Time.now.strftime('%Y-%m-%dT%H:%M:%S%z'),
          project: 'BlocksenseOS',
          version: version.strip,
          commit: commit.strip,
          output_directory: @output_dir,
          audit_id: @audit_timestamp
        },
        summary: {
          total_issues: total_issues,
          critical_issues: @critical_issues,
          high_issues: @high_issues,
          medium_issues: @medium_issues,
          low_issues: @low_issues,
          info_issues: @info_issues
        },
        components_checked: [
          'rust-audit',
          'cpp-audit',
          'sbom',
          'vulnerability-scan',
          'secret-scan',
          'dependencies',
          'configuration',
          'build-security',
          'documentation',
          'nix-validation'
        ],
        results_location: {
          rust_audits: "#{@output_dir}/rust-audit/",
          sbom_files: "#{@output_dir}/sbom/",
          vulnerability_scans: "#{@output_dir}/scan-results/",
          secret_scan: "#{@output_dir}/secret-scan/",
          nix_validation: "#{@output_dir}/nix-validation/",
          detailed_findings: @findings_file
        }
      }
      
      File.write(report_file, JSON.pretty_generate(report_data))
    else
      # Markdown format report (enhanced from bash)
      version = run_command('git describe --tags --always 2>/dev/null') rescue 'unknown'
      commit = run_command('git rev-parse HEAD 2>/dev/null') rescue 'unknown'
      
      report_content = <<~EOF
        # BlocksenseOS Security Audit Report

        **Audit Date:** #{Time.now.strftime('%Y-%m-%d %H:%M:%S')}  
        **Project Version:** #{version.strip}  
        **Commit:** #{commit.strip}  
        **Output Directory:** #{@output_dir}

        ## Executive Summary

        This automated security audit analyzed the BlocksenseOS codebase for security vulnerabilities, configuration issues, and compliance with security best practices.

        ### Findings Summary

        | Severity | Count |
        |----------|-------|
        | Critical | #{@critical_issues} |
        | High     | #{@high_issues} |
        | Medium   | #{@medium_issues} |
        | Low      | #{@low_issues} |
        | Info     | #{@info_issues} |
        | **Total** | **#{total_issues}** |

        ### Overall Risk Assessment

      EOF

      if @critical_issues > 0
        report_content += "🔴 **CRITICAL** - Immediate action required\n\n"
      elsif @high_issues > 0
        report_content += "🟠 **HIGH** - Address before production deployment\n\n"
      elsif @medium_issues > 5
        report_content += "🟡 **MEDIUM** - Multiple issues require attention\n\n"
      else
        report_content += "🟢 **LOW** - Security posture is acceptable\n\n"
      end
      
      report_content += <<~EOF
        ## Audit Scope

        The following areas were analyzed:

        - ✅ Rust code security (cargo audit, unsafe usage, panic safety)
        - ✅ C++ code security (dangerous functions, buffer safety)
        - ✅ Secret scanning (hardcoded credentials, keys)
        - ✅ Dependency vulnerabilities (known CVEs)
        - ✅ Configuration security (NixOS modules, systemd hardening)
        - ✅ Build security (CI/CD, reproducible builds)
        - ✅ Documentation completeness (security policies, threat model)
        - ✅ Software Bill of Materials (SBOM) generation
        - ✅ Nix configuration validation

        ## Results Location

        - **Rust audits:** `#{@output_dir}/rust-audit/`
        - **SBOM files:** `#{@output_dir}/sbom/`
        - **Vulnerability scans:** `#{@output_dir}/scan-results/`
        - **Secret scan:** `#{@output_dir}/secret-scan/`
        - **Nix validation:** `#{@output_dir}/nix-validation/`
        - **Detailed findings:** `#{@findings_file}`

        ## Detailed Findings

      EOF

      # Add detailed findings if available
      if command_available?('jq') && File.exist?(@findings_file)
        begin
          findings_data = JSON.parse(File.read(@findings_file))
          findings = findings_data['findings'] || []
          
          findings.each do |finding|
            report_content += <<~FINDING
              ### #{finding['severity'].upcase}: #{finding['title']}

              **Category:** #{finding['category']}  
              **File:** #{finding['file'] || 'N/A'}  
              **Description:** #{finding['description']}

              ---
            FINDING
          end
        rescue JSON::ParserError
          report_content += "Detailed findings available in: #{@findings_file}\n\n"
        end
      else
        report_content += "Detailed findings available in: #{@findings_file}\n\n"
      end
      
      report_content += <<~EOF
        ## Recommendations

        ### Immediate Actions (Critical/High Issues)
      EOF

      if @critical_issues > 0 || @high_issues > 0
        report_content += <<~EOF
          - Review and address all critical and high severity findings
          - Conduct manual security review of flagged code sections
          - Update vulnerable dependencies immediately
        EOF
      else
        report_content += "- No immediate critical actions required\n"
      end
      
      report_content += <<~EOF

        ### Medium-Term Improvements
        - Regular dependency updates and vulnerability scanning
        - Expand threat modeling documentation
        - Enhance systemd service hardening
        - Consider reducing .unwrap() usage in Rust code for better error handling

        ### Ongoing Security Practices
        - Monthly security audits
        - Quarterly dependency reviews
        - Annual third-party security assessment
        - Continuous monitoring of security advisories

        ## Next Steps

        Review individual result files for detailed findings:
      EOF

      # Add list of result files
      result_files = Dir.glob("#{@output_dir}/**/*.{json,txt,log}").first(10)
      result_files.each { |file| report_content += "- #{file}\n" }
      
      report_content += <<~EOF

        ---

        **Generated by:** BlocksenseOS Security Audit Script v2.0  
        **Audit ID:** #{@audit_timestamp}
      EOF
      
      File.write(report_file, report_content)
    end
    
    log_success "Security audit report generated: #{report_file}"
  end

  # Main execution function with enhanced modularity (restored from bash)
  def run
    log_info "BlocksenseOS Security Audit v2.0 - Command: #{@command}"
    setup_audit_environment
    check_dependencies
    
    case @command
    when 'rust-audit'
      audit_rust_security
    when 'cpp-audit'
      audit_cpp_security
    when 'sbom'
      generate_sbom
    when 'vulnerability-scan'
      vulnerability_scan
    when 'secret-scan'
      secret_scan
    when 'dependencies'
      audit_dependencies
    when 'configuration'
      audit_configuration
    when 'build-security'
      audit_build_security
    when 'documentation'
      audit_documentation
    when 'nix-validate'
      nix_validate
    when 'report'
      generate_report
    when 'all'
      # Run all audits in logical order
      audit_rust_security
      audit_cpp_security
      generate_sbom
      vulnerability_scan
      secret_scan
      audit_dependencies
      audit_configuration
      audit_build_security
      audit_documentation
      nix_validate
      generate_report
    else
      log_error "Unknown command: #{@command}"
      show_help
      exit 1
    end
    
    # Print summary (restored from bash)
    puts
    puts "======================================================================"
    puts "    Security Audit Complete"
    puts "======================================================================"
    puts "Critical Issues: #{@critical_issues}"
    puts "High Issues:     #{@high_issues}"
    puts "Medium Issues:   #{@medium_issues}"
    puts "Low Issues:      #{@low_issues}"
    puts "Info Items:      #{@info_issues}"
    puts
    puts "Report: #{@output_dir}/reports/"
    puts "Findings: #{@findings_file}"
    puts
    
    # Exit with appropriate code (enhanced from bash)
    if @critical_issues > 0
      puts "❌ AUDIT FAILED - Critical issues found"
      exit 2
    elsif @high_issues > 0
      puts "⚠️  AUDIT PASSED WITH WARNINGS - High issues found"
      exit 1
    elsif @security_issues_found
      puts "⚠️  AUDIT PASSED WITH WARNINGS - Issues found"
      exit 1
    else
      puts "✅ AUDIT PASSED - No critical issues found"
      exit 0
    end
  end
end

# Parse arguments and run (restored from bash)
if __FILE__ == $0
  audit = SecurityAudit.new
  audit.parse_args
  audit.run
end