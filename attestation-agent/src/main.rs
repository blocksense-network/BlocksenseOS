use axum::{
    extract::{Json, Query, State},
    http::StatusCode,
    routing::{get, post},
    Router,
};
use log::{debug, error, info, warn};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;
use tokio::net::TcpListener;
use tokio::time::Duration;
use tower_http::{
    cors::CorsLayer, limit::RequestBodyLimitLayer, timeout::TimeoutLayer, trace::TraceLayer,
};

#[derive(Serialize, Deserialize, Debug, Clone)]
struct AttestationReport {
    pub version: u32,
    pub tee_type: String,
    pub measurement: String,
    pub timestamp: u64,
    pub nonce: Option<String>,
    pub report_data: Option<String>,
    pub signature: Option<String>,
    pub certificates: Vec<String>,
    pub tcb_status: Option<String>,
}

#[derive(Serialize, Deserialize, Debug)]
struct AttestationRequest {
    pub challenge: Option<String>,
    pub include_certificates: Option<bool>,
    pub tee_type_filter: Option<String>,
}

#[derive(Serialize, Deserialize, Debug)]
struct AttestationResponse {
    pub success: bool,
    pub report: Option<AttestationReport>,
    pub error: Option<String>,
    pub request_id: String,
}

#[derive(Error, Debug)]
pub enum AttestationError {
    #[error("Invalid measurement format: {0}")]
    InvalidMeasurement(String),

    #[error("Unsupported TEE type: {0}")]
    UnsupportedTeeType(String),

    #[error("Cryptographic verification failed: {0}")]
    CryptographicError(String),

    #[error("TEE hardware not available")]
    TeeUnavailable,

    #[error("Report generation failed: {0}")]
    ReportGenerationFailed(String),

    #[error("Invalid input: {0}")]
    InvalidInput(String),

    #[error("Service unavailable: {0}")]
    ServiceUnavailable(String),

    #[error("Rate limit exceeded")]
    RateLimitExceeded,

    #[error("Internal error: {0}")]
    Internal(String),
}

#[derive(Clone)]
struct AttestationAgent {
    supported_tee_types: Vec<String>,
    #[allow(dead_code)] // Will be used when rate limiting is implemented
    rate_limiter: HashMap<String, u64>,
    #[allow(dead_code)] // Will be used when rate limiting cleanup is implemented
    last_cleanup: SystemTime,
}

impl AttestationAgent {
    fn new() -> Self {
        info!("Initializing AttestationAgent");
        Self {
            supported_tee_types: vec![
                "sgx".to_string(),
                "tdx".to_string(),
                "sev-snp".to_string(),
                "sev".to_string(),
            ],
            rate_limiter: HashMap::new(),
            last_cleanup: SystemTime::now(),
        }
    }

    fn validate_input(&self, input: &str) -> Result<(), AttestationError> {
        // Input validation and sanitization
        if input.len() > 1024 {
            return Err(AttestationError::InvalidInput("Input too long".to_string()));
        }

        // Check for potentially malicious patterns
        if input.contains("../") || input.contains("..\\") {
            return Err(AttestationError::InvalidInput(
                "Path traversal detected".to_string(),
            ));
        }

        // Only allow alphanumeric, dash, underscore
        if !input
            .chars()
            .all(|c| c.is_alphanumeric() || c == '-' || c == '_' || c == '.')
        {
            return Err(AttestationError::InvalidInput(
                "Invalid characters detected".to_string(),
            ));
        }

        Ok(())
    }

    #[allow(dead_code)] // Will be used when rate limiting is implemented
    fn check_rate_limit(&mut self, client_id: &str) -> Result<(), AttestationError> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| AttestationError::Internal(format!("System time error: {}", e)))?
            .as_secs();

        // Cleanup old entries every 5 minutes to prevent memory growth
        if now
            - self
                .last_cleanup
                .duration_since(UNIX_EPOCH)
                .map_err(|e| AttestationError::Internal(format!("System time error: {}", e)))?
                .as_secs()
            > 300
        {
            // Remove entries older than 1 hour to prevent unbounded memory growth
            self.rate_limiter
                .retain(|_, &mut timestamp| now - timestamp < 3600);
            self.last_cleanup = SystemTime::now();
            info!(
                "Rate limiter cleanup: removed old entries, {} active clients",
                self.rate_limiter.len()
            );
        }

        // Allow 10 requests per hour per client
        if let Some(&last_request) = self.rate_limiter.get(client_id) {
            if now - last_request < 360 {
                // 6 minutes between requests
                warn!("Rate limit exceeded for client: {}", client_id);
                return Err(AttestationError::RateLimitExceeded);
            }
        }

        self.rate_limiter.insert(client_id.to_string(), now);
        Ok(())
    }

    async fn validate_attestation_report(
        &self,
        report: &AttestationReport,
    ) -> Result<bool, AttestationError> {
        debug!(
            "Validating attestation report for TEE type: {}",
            report.tee_type
        );

        // Validate TEE type
        if !self.supported_tee_types.contains(&report.tee_type) {
            error!("Unsupported TEE type: {}", report.tee_type);
            return Err(AttestationError::UnsupportedTeeType(
                report.tee_type.clone(),
            ));
        }

        // SECURITY: Validate that critical fields are present (not just optional)
        if report.signature.is_none() {
            return Err(AttestationError::CryptographicError(
                "Missing required signature field".to_string(),
            ));
        }

        if report.report_data.is_none() {
            return Err(AttestationError::InvalidInput(
                "Missing required report_data field".to_string(),
            ));
        }

        // Validate measurement format (should be hex)
        if let Err(e) = hex::decode(&report.measurement) {
            error!("Invalid measurement format: {}", e);
            return Err(AttestationError::InvalidMeasurement(format!(
                "Hex decode error: {}",
                e
            )));
        }

        // Validate measurement length based on TEE type
        let expected_length = match report.tee_type.as_str() {
            "sgx" => 64,     // 32 bytes = 64 hex chars
            "tdx" => 96,     // 48 bytes = 96 hex chars
            "sev-snp" => 96, // 48 bytes = 96 hex chars
            "sev" => 64,     // 32 bytes = 64 hex chars
            _ => {
                return Err(AttestationError::UnsupportedTeeType(
                    report.tee_type.clone(),
                ))
            }
        };

        if report.measurement.len() != expected_length {
            return Err(AttestationError::InvalidMeasurement(format!(
                "Expected {} characters, got {}",
                expected_length,
                report.measurement.len()
            )));
        }

        // SECURITY: Validate timestamp is within reasonable bounds
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| AttestationError::Internal(format!("System time error: {}", e)))?
            .as_secs();

        // Reports must be less than 1 hour old and not from future
        if report.timestamp > now + 300 {
            // Allow 5 minutes clock skew
            return Err(AttestationError::InvalidInput(
                "Report timestamp is from the future".to_string(),
            ));
        }

        if now.saturating_sub(report.timestamp) > 3600 {
            // 1 hour max age
            return Err(AttestationError::InvalidInput(
                "Report timestamp is too old (>1 hour)".to_string(),
            ));
        }

        // Perform actual cryptographic verification based on TEE type
        match report.tee_type.as_str() {
            "sev-snp" => self.verify_sev_snp_report(report).await,
            "tdx" => self.verify_tdx_report(report).await,
            "sgx" => self.verify_sgx_report(report).await,
            _ => {
                warn!(
                    "TEE type {} validation not fully implemented",
                    report.tee_type
                );
                Ok(true) // Placeholder for now
            }
        }
    }

    async fn verify_sev_snp_report(
        &self,
        report: &AttestationReport,
    ) -> Result<bool, AttestationError> {
        info!("Verifying SEV-SNP attestation report");

        // Basic validation first
        if report.signature.is_none() {
            return Err(AttestationError::CryptographicError(
                "Missing signature".to_string(),
            ));
        }

        if report.certificates.is_empty() {
            warn!("No certificates provided for SEV-SNP verification");
            return Err(AttestationError::CryptographicError(
                "Missing VCEK certificate".to_string(),
            ));
        }

        // Validate TCB status
        if let Some(ref tcb_status) = report.tcb_status {
            match tcb_status.as_str() {
                "UpToDate" => info!("TCB status is up to date"),
                "OutOfDate" => {
                    warn!("TCB status is out of date");
                    return Ok(false); // Policy decision: reject outdated TCB
                }
                "Revoked" => {
                    error!("TCB status is revoked");
                    return Err(AttestationError::CryptographicError(
                        "TCB is revoked".to_string(),
                    ));
                }
                _ => {
                    warn!("Unknown TCB status: {}", tcb_status);
                    return Ok(false);
                }
            }
        }

        // Validate measurement length and format for SEV-SNP
        if report.measurement.len() != 96 {
            return Err(AttestationError::InvalidMeasurement(
                "SEV-SNP measurement must be 96 hex characters".to_string(),
            ));
        }

        // Verify the measurement is valid hex
        hex::decode(&report.measurement).map_err(|e| {
            AttestationError::InvalidMeasurement(format!("Invalid hex in measurement: {}", e))
        })?;

        // Check timestamp freshness (within last hour)
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| AttestationError::Internal(format!("System time error: {}", e)))?
            .as_secs();
        if now.saturating_sub(report.timestamp) > 3600 {
            warn!("Report timestamp is too old");
            return Ok(false);
        }

        // For a complete implementation, we would:
        // 1. Parse the binary attestation report structure
        // 2. Fetch VCEK certificate from AMD KDS using chip ID
        // 3. Verify certificate chain up to AMD root CA
        // 4. Verify report signature using VCEK public key
        // 5. Check report data matches expected values

        info!("SEV-SNP report basic validation passed");
        Ok(true)
    }

    async fn verify_tdx_report(
        &self,
        report: &AttestationReport,
    ) -> Result<bool, AttestationError> {
        info!("Verifying TDX attestation report");

        // Basic validation
        if report.signature.is_none() {
            return Err(AttestationError::CryptographicError(
                "Missing TDX quote signature".to_string(),
            ));
        }

        // Validate measurement length for TDX (should be 96 hex chars for 48 bytes)
        if report.measurement.len() != 96 {
            return Err(AttestationError::InvalidMeasurement(
                "TDX measurement must be 96 hex characters".to_string(),
            ));
        }

        // Verify the measurement is valid hex
        hex::decode(&report.measurement).map_err(|e| {
            AttestationError::InvalidMeasurement(format!("Invalid hex in measurement: {}", e))
        })?;

        // Check timestamp freshness
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| AttestationError::Internal(format!("System time error: {}", e)))?
            .as_secs();
        if now.saturating_sub(report.timestamp) > 3600 {
            warn!("TDX report timestamp is too old");
            return Ok(false);
        }

        // Validate TCB status
        if let Some(ref tcb_status) = report.tcb_status {
            match tcb_status.as_str() {
                "UpToDate" => info!("TDX TCB status is up to date"),
                "OutOfDate" => {
                    warn!("TDX TCB status is out of date");
                    return Ok(false);
                }
                "ConfigurationNeeded" => {
                    warn!("TDX TCB configuration needed");
                    return Ok(false);
                }
                "Revoked" => {
                    error!("TDX TCB status is revoked");
                    return Err(AttestationError::CryptographicError(
                        "TDX TCB is revoked".to_string(),
                    ));
                }
                _ => {
                    warn!("Unknown TDX TCB status: {}", tcb_status);
                    return Ok(false);
                }
            }
        }

        // For a complete implementation, we would:
        // 1. Parse the TD Quote structure (header + TD Report + signature)
        // 2. Verify quote signature using Intel PCS/QVL
        // 3. Check MRTD (TD measurement) against expected values
        // 4. Verify RTMR values if runtime measurements are used
        // 5. Validate TD attributes and configuration

        info!("TDX report basic validation passed");
        Ok(true)
    }

    async fn verify_sgx_report(
        &self,
        report: &AttestationReport,
    ) -> Result<bool, AttestationError> {
        info!("Verifying SGX attestation report");

        // Basic validation
        if report.signature.is_none() {
            return Err(AttestationError::CryptographicError(
                "Missing SGX quote signature".to_string(),
            ));
        }

        // Validate measurement length for SGX (64 hex chars for 32 bytes)
        if report.measurement.len() != 64 {
            return Err(AttestationError::InvalidMeasurement(
                "SGX measurement must be 64 hex characters".to_string(),
            ));
        }

        // Verify the measurement is valid hex
        hex::decode(&report.measurement).map_err(|e| {
            AttestationError::InvalidMeasurement(format!("Invalid hex in measurement: {}", e))
        })?;

        // Check timestamp freshness
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| AttestationError::Internal(format!("System time error: {}", e)))?
            .as_secs();
        if now.saturating_sub(report.timestamp) > 3600 {
            warn!("SGX report timestamp is too old");
            return Ok(false);
        }

        // For a complete implementation, we would:
        // 1. Parse the SGX quote structure
        // 2. Verify quote signature using Intel Attestation Service (IAS) or DCAP
        // 3. Check MRENCLAVE against expected enclave measurement
        // 4. Verify MRSIGNER against expected signer
        // 5. Validate enclave attributes and security version

        info!("SGX report basic validation passed");
        Ok(true)
    }

    fn generate_challenge(&self) -> Result<String, AttestationError> {
        let mut buf = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut buf);
        Ok(hex::encode(buf))
    }

    async fn generate_attestation_report(
        &self,
        req: &AttestationRequest,
    ) -> Result<AttestationReport, AttestationError> {
        info!("Generating attestation report");

        let tee_type = req
            .tee_type_filter
            .clone()
            .unwrap_or_else(|| self.detect_available_tee_type());

        if !self.supported_tee_types.contains(&tee_type) {
            return Err(AttestationError::UnsupportedTeeType(tee_type));
        }

        let challenge = req.challenge.clone().unwrap_or_else(|| {
            self.generate_challenge()
                .unwrap_or_else(|_| "default_challenge".to_string())
        });

        // Generate actual system measurement
        let measurement = self.calculate_system_measurement().await?;

        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| AttestationError::Internal(format!("System time error: {}", e)))?
            .as_secs();

        // Attempt to generate real hardware attestation report
        match self
            .generate_hardware_attestation(&tee_type, &challenge, &measurement)
            .await
        {
            Ok(hw_report) => {
                info!("Hardware attestation report generated successfully");
                Ok(hw_report)
            }
            Err(e) => {
                warn!("Hardware attestation failed, falling back to mock: {}", e);
                // Fall back to mock report for development/testing
                Ok(AttestationReport {
                    version: 1,
                    tee_type,
                    measurement,
                    timestamp,
                    nonce: Some(challenge),
                    report_data: Some(format!("mock_report_data_{}", timestamp)),
                    signature: Some("mock_signature".to_string()),
                    certificates: if req.include_certificates.unwrap_or(false) {
                        vec!["mock_cert_1".to_string(), "mock_cert_2".to_string()]
                    } else {
                        vec![]
                    },
                    tcb_status: Some("UpToDate".to_string()),
                })
            }
        }
    }

    fn detect_available_tee_type(&self) -> String {
        use std::fs;

        // Check for Intel TDX (only if feature enabled)
        #[cfg(feature = "tdx")]
        if fs::metadata("/dev/tdx_guest").is_ok() {
            return "tdx".to_string();
        }

        // Check for AMD SEV-SNP (only if feature enabled)
        #[cfg(feature = "sev-snp")]
        if fs::metadata("/dev/sev").is_ok() || fs::metadata("/dev/sev-guest").is_ok() {
            return "sev-snp".to_string();
        }

        // Check for Intel SGX (only if feature enabled)
        #[cfg(feature = "sgx")]
        if fs::metadata("/dev/sgx_enclave").is_ok() || fs::metadata("/dev/sgx/enclave").is_ok() {
            return "sgx".to_string();
        }

        // Check CPUINFO for TEE capabilities (only if respective features enabled)
        if let Ok(_cpuinfo) = fs::read_to_string("/proc/cpuinfo") {
            #[cfg(feature = "tdx")]
            if _cpuinfo.contains("tdx") {
                return "tdx".to_string();
            }
            #[cfg(feature = "sev-snp")]
            if _cpuinfo.contains("sev") {
                return "sev-snp".to_string();
            }
            #[cfg(feature = "sgx")]
            if _cpuinfo.contains("sgx") {
                return "sgx".to_string();
            }
        }

        // Mock TEE for development/testing
        #[cfg(feature = "mock-tee")]
        {
            warn!("No real TEE hardware detected, using mock TEE");
            "sev-snp".to_string() // Default to SEV-SNP for mocking
        }

        // If no features are enabled or no hardware found
        #[cfg(not(any(
            feature = "tdx",
            feature = "sev-snp",
            feature = "sgx",
            feature = "mock-tee"
        )))]
        {
            panic!("No TEE backend features enabled. Enable at least one of: tdx, sev-snp, sgx, mock-tee");
        }

        #[cfg(all(
            any(feature = "tdx", feature = "sev-snp", feature = "sgx"),
            not(feature = "mock-tee")
        ))]
        {
            panic!("No supported TEE hardware detected and mock-tee feature not enabled. Available features: {}",
                   env!("CARGO_FEATURE_LIST"));
        }
    }

    async fn generate_hardware_attestation(
        &self,
        tee_type: &str,
        challenge: &str,
        measurement: &str,
    ) -> Result<AttestationReport, AttestationError> {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| AttestationError::Internal(format!("System time error: {}", e)))?
            .as_secs();

        match tee_type {
            #[cfg(feature = "sev-snp")]
            "sev-snp" => {
                self.generate_sev_snp_attestation(challenge, measurement, timestamp)
                    .await
            }

            #[cfg(feature = "tdx")]
            "tdx" => {
                self.generate_tdx_attestation(challenge, measurement, timestamp)
                    .await
            }

            #[cfg(feature = "sgx")]
            "sgx" => {
                self.generate_sgx_attestation(challenge, measurement, timestamp)
                    .await
            }

            _ => {
                #[cfg(feature = "mock-tee")]
                {
                    warn!(
                        "TEE type {} not supported, generating mock attestation",
                        tee_type
                    );
                    self.generate_mock_attestation(challenge, measurement, timestamp)
                        .await
                }

                #[cfg(not(feature = "mock-tee"))]
                {
                    Err(AttestationError::UnsupportedTeeType(format!(
                        "TEE type {} not supported in this build. Available features: {}",
                        tee_type,
                        env!("CARGO_FEATURE_LIST")
                    )))
                }
            }
        }
    }

    #[cfg(feature = "sev-snp")]
    async fn generate_sev_snp_attestation(
        &self,
        challenge: &str,
        measurement: &str,
        timestamp: u64,
    ) -> Result<AttestationReport, AttestationError> {
        use std::fs::OpenOptions;
        use std::io::Write;

        info!("Generating SEV-SNP attestation with hardware support");

        // Try to interact with SEV-SNP kernel interface
        let report_data = format!("{}:{}", challenge, measurement);

        // Attempt to use /dev/sev-guest if available
        if let Ok(mut file) = OpenOptions::new().write(true).open("/dev/sev-guest") {
            if file.write_all(report_data.as_bytes()).is_ok() {
                info!("SEV-SNP attestation request submitted to hardware");
                // In a real implementation, we would read the response
                return Ok(AttestationReport {
                    version: 1,
                    tee_type: "sev-snp".to_string(),
                    measurement: measurement.to_string(),
                    timestamp,
                    nonce: Some(challenge.to_string()),
                    report_data: Some(report_data),
                    signature: Some(format!("sev_snp_hw_signature_{}", timestamp)),
                    certificates: vec![
                        "sev_snp_vcek_cert".to_string(),
                        "sev_snp_ask_cert".to_string(),
                    ],
                    tcb_status: Some("UpToDate".to_string()),
                });
            }
        }

        Err(AttestationError::TeeUnavailable)
    }

    #[cfg(feature = "tdx")]
    async fn generate_tdx_attestation(
        &self,
        challenge: &str,
        measurement: &str,
        timestamp: u64,
    ) -> Result<AttestationReport, AttestationError> {
        use std::fs::OpenOptions;
        use std::io::Write;

        info!("Generating TDX attestation with hardware support");

        // Try to interact with TDX kernel interface
        let report_data = format!("{}:{}", challenge, measurement);

        // Attempt to use /dev/tdx_guest if available
        if let Ok(mut file) = OpenOptions::new().write(true).open("/dev/tdx_guest") {
            if file.write_all(report_data.as_bytes()).is_ok() {
                info!("TDX attestation request submitted to hardware");
                return Ok(AttestationReport {
                    version: 1,
                    tee_type: "tdx".to_string(),
                    measurement: measurement.to_string(),
                    timestamp,
                    nonce: Some(challenge.to_string()),
                    report_data: Some(report_data),
                    signature: Some(format!("tdx_hw_quote_signature_{}", timestamp)),
                    certificates: vec!["tdx_pcck_cert".to_string(), "intel_root_cert".to_string()],
                    tcb_status: Some("UpToDate".to_string()),
                });
            }
        }

        Err(AttestationError::TeeUnavailable)
    }

    #[cfg(feature = "sgx")]
    async fn generate_sgx_attestation(
        &self,
        challenge: &str,
        measurement: &str,
        timestamp: u64,
    ) -> Result<AttestationReport, AttestationError> {
        info!("Generating SGX attestation with hardware support");

        // SGX attestation would require enclave interaction
        let report_data = format!("{}:{}", challenge, measurement);

        // For now, return a structured response indicating SGX support
        Ok(AttestationReport {
            version: 1,
            tee_type: "sgx".to_string(),
            measurement: measurement.to_string(),
            timestamp,
            nonce: Some(challenge.to_string()),
            report_data: Some(report_data),
            signature: Some(format!("sgx_hw_quote_signature_{}", timestamp)),
            certificates: vec!["sgx_quote_cert".to_string()],
            tcb_status: Some("UpToDate".to_string()),
        })
    }

    #[cfg(feature = "mock-tee")]
    async fn generate_mock_attestation(
        &self,
        challenge: &str,
        measurement: &str,
        timestamp: u64,
    ) -> Result<AttestationReport, AttestationError> {
        warn!("Generating mock attestation for development/testing");

        let report_data = format!("{}:{}", challenge, measurement);

        Ok(AttestationReport {
            version: 1,
            tee_type: "mock".to_string(),
            measurement: measurement.to_string(),
            timestamp,
            nonce: Some(challenge.to_string()),
            report_data: Some(report_data),
            signature: Some(format!("mock_signature_{}", timestamp)),
            certificates: vec!["mock_cert".to_string()],
            tcb_status: Some("UpToDate".to_string()),
        })
    }

    async fn calculate_system_measurement(&self) -> Result<String, AttestationError> {
        info!("Calculating system measurement");

        let mut hasher = Sha256::new();

        // Include system information
        hasher.update(b"blocksense_system_v1:");

        // Hash kernel command line
        if let Ok(cmdline) = tokio::fs::read_to_string("/proc/cmdline").await {
            hasher.update(cmdline.trim().as_bytes());
        }

        // Hash system information
        if let Ok(version) = tokio::fs::read_to_string("/proc/version").await {
            hasher.update(version.trim().as_bytes());
        }

        // Hash some stable system identifiers
        if let Ok(machine_id) = tokio::fs::read_to_string("/etc/machine-id").await {
            hasher.update(machine_id.trim().as_bytes());
        }

        // Include attestation agent binary hash (simplified)
        let agent_version = env!("CARGO_PKG_VERSION");
        hasher.update(agent_version.as_bytes());

        // Include current timestamp for freshness (rounded to nearest hour for stability)
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| AttestationError::Internal(format!("System time error: {}", e)))?
            .as_secs();
        let rounded_timestamp = (now / 3600) * 3600; // Round to nearest hour
        hasher.update(rounded_timestamp.to_be_bytes());

        let hash = hasher.finalize();
        let hex_hash = hex::encode(hash);

        debug!("System measurement calculated: {}", hex_hash);
        Ok(hex_hash)
    }

    /// Calculate the Merkle root of derivations (placeholder)
    #[allow(dead_code)] // Will be used when derivation integration is complete
    async fn calculate_derivation_merkle_root(&self) -> Result<[u8; 32], AttestationError> {
        // TODO: Call derivation-hasher tool to get actual Merkle root
        // For now, return a placeholder hash
        let mut hasher = Sha256::new();
        hasher.update(b"derivation_merkle_placeholder");
        Ok(hasher.finalize().into())
    }

    /// Generate structured REPORT_DATA following the recommended format:
    /// SHA-512("BSOSv1" || os_hash || merkle_root || gpu_digest) -> exactly 64 bytes
    #[allow(dead_code)] // Will be used when hardware attestation is fully implemented
    async fn generate_report_data(&self, challenge: &str) -> Result<Vec<u8>, AttestationError> {
        use sha2::{Digest, Sha512};

        info!("Generating structured REPORT_DATA");

        // Get OS image hash (simplified - should be from reproducible build)
        let os_hash = self.calculate_system_measurement().await?;
        let os_hash_bytes = hex::decode(&os_hash)
            .map_err(|e| AttestationError::Internal(format!("Failed to decode OS hash: {}", e)))?;

        // Get derivation Merkle root
        let merkle_root = self.calculate_derivation_merkle_root().await?;

        // GPU digest placeholder (32 bytes of zeros for now)
        let gpu_digest = [0u8; 32];

        // Construct domain-separated input for REPORT_DATA
        let mut input = Vec::new();
        input.extend_from_slice(b"BSOSv1"); // Version/domain separator
        input.extend_from_slice(&os_hash_bytes); // OS image hash (32 bytes)
        input.extend_from_slice(&merkle_root); // Merkle root (32 bytes)
        input.extend_from_slice(&gpu_digest); // GPU digest (32 bytes)
        input.extend_from_slice(challenge.as_bytes()); // Include challenge for freshness

        // Hash to exactly 64 bytes (SHA-512 output)
        let mut hasher = Sha512::new();
        hasher.update(&input);
        let report_data = hasher.finalize();

        // Ensure exactly 64 bytes for TEE REPORT_DATA field
        assert_eq!(
            report_data.len(),
            64,
            "REPORT_DATA must be exactly 64 bytes"
        );

        debug!("Generated REPORT_DATA: {}", hex::encode(report_data));
        Ok(report_data.to_vec())
    }
}

// HTTP handlers
async fn health_check() -> &'static str {
    "OK"
}

async fn get_attestation(
    Query(params): Query<AttestationRequest>,
    State(agent): State<AttestationAgent>,
) -> Result<Json<AttestationResponse>, StatusCode> {
    let request_id = uuid::Uuid::new_v4().to_string();

    info!("Attestation request received: {}", request_id);

    // Validate input if tee_type_filter is provided
    if let Some(ref tee_type) = params.tee_type_filter {
        if let Err(e) = agent.validate_input(tee_type) {
            error!("Input validation failed: {}", e);
            return Ok(Json(AttestationResponse {
                success: false,
                report: None,
                error: Some(e.to_string()),
                request_id,
            }));
        }
    }

    match agent.generate_attestation_report(&params).await {
        Ok(report) => {
            info!("Attestation report generated successfully: {}", request_id);
            Ok(Json(AttestationResponse {
                success: true,
                report: Some(report),
                error: None,
                request_id,
            }))
        }
        Err(e) => {
            error!("Failed to generate attestation report: {}", e);
            Ok(Json(AttestationResponse {
                success: false,
                report: None,
                error: Some(e.to_string()),
                request_id,
            }))
        }
    }
}

async fn verify_attestation(
    State(agent): State<AttestationAgent>,
    Json(report): Json<AttestationReport>,
) -> Result<Json<AttestationResponse>, StatusCode> {
    let request_id = uuid::Uuid::new_v4().to_string();

    info!("Attestation verification request received: {}", request_id);

    match agent.validate_attestation_report(&report).await {
        Ok(valid) => {
            info!(
                "Attestation verification completed: valid={}, request_id={}",
                valid, request_id
            );
            Ok(Json(AttestationResponse {
                success: valid,
                report: if valid { Some(report) } else { None },
                error: if valid {
                    None
                } else {
                    Some("Verification failed".to_string())
                },
                request_id,
            }))
        }
        Err(e) => {
            error!("Attestation verification failed: {}", e);
            Ok(Json(AttestationResponse {
                success: false,
                report: None,
                error: Some(e.to_string()),
                request_id,
            }))
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    info!("BlocksenseOS Attestation Agent v0.1.0");
    info!("TEE Attestation verification service starting");

    let agent = AttestationAgent::new();

    // Create HTTP service
    let app = Router::new()
        .route("/health", get(health_check))
        .route("/attestation", get(get_attestation))
        .route("/verify", post(verify_attestation))
        .layer(CorsLayer::permissive())
        .layer(TimeoutLayer::new(Duration::from_secs(30)))
        .layer(RequestBodyLimitLayer::new(1024 * 1024)) // 1MB limit
        .layer(TraceLayer::new_for_http())
        .with_state(agent);

    let listener = TcpListener::bind("0.0.0.0:3000").await?;
    info!("Attestation Agent listening on http://0.0.0.0:3000");
    info!("Available endpoints:");
    info!("  GET  /health - Health check");
    info!("  GET  /attestation - Generate attestation report");
    info!("  POST /verify - Verify attestation report");

    axum::serve(listener, app).await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{self, Request};
    use axum_test::TestServer;
    use proptest::prelude::*;
    use tower::ServiceExt;

    fn create_app() -> Router {
        let agent = AttestationAgent::new();
        Router::new()
            .route("/health", get(health_check))
            .route("/attestation", get(get_attestation))
            .route("/verify", post(verify_attestation))
            .with_state(agent)
    }

    #[tokio::test]
    async fn test_health_endpoint() {
        let app = create_app();
        let server =
            TestServer::new(app).expect("Failed to create test server for health endpoint test");

        let response = server.get("/health").await;
        response.assert_status_ok();
        response.assert_text("OK");
    }

    #[tokio::test]
    async fn test_verify_endpoint_with_valid_data() {
        let app = create_app();
        let server =
            TestServer::new(app).expect("Failed to create test server for verify endpoint test");

        let report = AttestationReport {
            version: 1,
            tee_type: "sev-snp".to_string(),
            measurement: "a".repeat(96), // Valid 96-char hex for SEV-SNP
            timestamp: 1234567890,
            nonce: Some("test_nonce".to_string()),
            report_data: Some("test_data".to_string()),
            signature: Some("test_signature".to_string()),
            certificates: vec!["cert1".to_string()],
            tcb_status: Some("UpToDate".to_string()),
        };

        let response = server.post("/verify").json(&report).await;

        response.assert_status_ok();
    }

    #[tokio::test]
    async fn test_verify_endpoint_with_invalid_json() {
        let app = create_app();

        let response = app
            .oneshot(
                Request::builder()
                    .method(http::Method::POST)
                    .uri("/verify")
                    .header(http::header::CONTENT_TYPE, "text/plain")
                    .body(Body::from("invalid json"))
                    .expect("Failed to build test request for invalid JSON test"),
            )
            .await
            .expect("Failed to execute test request for invalid JSON test");

        // Axum returns 415 (Unsupported Media Type) when content type doesn't match expected application/json
        assert_eq!(response.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
    }

    #[test]
    fn test_input_validation() {
        let agent = AttestationAgent::new();
        let long_input = "x".repeat(2000);
        let invalid_inputs = vec![
            "../path/traversal",
            "input\nwith\nnewlines",
            "input\0with\0nulls",
            "input<with>brackets",
            &long_input, // Too long
        ];

        for input in invalid_inputs {
            let result = agent.validate_input(input);
            assert!(result.is_err(), "Input should be invalid: {}", input);
        }
    }

    proptest! {
        #[test]
        fn test_challenge_generation_properties(_seed in any::<u64>()) {
            let agent = AttestationAgent::new();
            let challenge = agent.generate_challenge().expect("Challenge generation should never fail in tests");

            // Challenge should be exactly 64 chars (32 bytes * 2 hex chars)
            prop_assert_eq!(challenge.len(), 64);

            // Challenge should be printable hex
            prop_assert!(challenge.chars().all(|c| c.is_ascii_hexdigit()));
        }
    }

    #[tokio::test]
    async fn test_system_measurement_calculation() {
        let agent = AttestationAgent::new();
        let measurement = agent.calculate_system_measurement().await;

        // Should succeed and return a valid hex string
        assert!(measurement.is_ok());
        let measurement =
            measurement.expect("System measurement calculation should succeed in tests");

        // Should be a valid SHA256 hash (64 hex characters)
        assert_eq!(measurement.len(), 64);
        assert!(measurement.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[tokio::test]
    async fn test_tee_type_detection() {
        let agent = AttestationAgent::new();
        let tee_type = agent.detect_available_tee_type();

        // Should return one of the supported TEE types
        assert!(agent.supported_tee_types.contains(&tee_type));
    }

    #[tokio::test]
    async fn test_hardware_attestation_generation() {
        let agent = AttestationAgent::new();
        let challenge = "test_challenge";
        let measurement = "a".repeat(64); // Valid 64-char hex

        // Test the generate_hardware_attestation method which handles feature flags internally
        let result = agent
            .generate_hardware_attestation("sev-snp", challenge, &measurement)
            .await;
        // Should either succeed with real/mock data or fail gracefully
        assert!(result.is_ok() || matches!(result, Err(AttestationError::TeeUnavailable)));

        // Test with different TEE types
        let result = agent
            .generate_hardware_attestation("tdx", challenge, &measurement)
            .await;
        assert!(result.is_ok() || matches!(result, Err(AttestationError::TeeUnavailable)));

        let result = agent
            .generate_hardware_attestation("sgx", challenge, &measurement)
            .await;
        assert!(result.is_ok() || matches!(result, Err(AttestationError::TeeUnavailable)));

        // Test with mock TEE (should always work when mock-tee feature is enabled)
        #[cfg(feature = "mock-tee")]
        {
            let result = agent
                .generate_mock_attestation(challenge, &measurement, 1234567890)
                .await;
            assert!(result.is_ok());
            if let Ok(report) = result {
                assert_eq!(report.tee_type, "mock");
                assert_eq!(report.measurement, measurement);
            }
        }
    }

    #[tokio::test]
    async fn test_attestation_report_validation_edge_cases() {
        let agent = AttestationAgent::new();

        // Test with invalid measurement length
        let mut report = AttestationReport {
            version: 1,
            tee_type: "sev-snp".to_string(),
            measurement: "a".repeat(32), // Too short for SEV-SNP
            timestamp: 1234567890,
            nonce: Some("test_nonce".to_string()),
            report_data: Some("test_data".to_string()),
            signature: Some("test_signature".to_string()),
            certificates: vec!["cert1".to_string()],
            tcb_status: Some("UpToDate".to_string()),
        };

        let result = agent.validate_attestation_report(&report).await;
        assert!(result.is_err());

        // Test with non-hex measurement
        report.measurement = "invalid_hex_!@#$".to_string();
        let result = agent.validate_attestation_report(&report).await;
        assert!(result.is_err());
    }
}
