# Detailed Development Blueprint

This blueprint expands on the phases outlined in the original project document, focusing on dependencies and logical build order.

## 1. Foundation (Nix Environment & Base VM)

* **1.1:** Establish [Nix Flake](https://nixos.wiki/wiki/Flakes): Define basic structure (`flake.nix`), inputs (`nixpkgs`), and standard dev shell.
* **1.2:** Basic NixOS VM Configuration: Create a minimal `nixosConfiguration` in the flake. Define basic networking.
* **1.3:** Build & Run Base VM: Add VM build output (`config.system.build.vm`). Implement script/command to build and run the VM using [QEMU](https://www.qemu.org/documentation/) locally. Test basic boot and SSH access.

## 2. Payload Services (C++ & Rust)

* **2.1:** C++ TCP Echo Service: Write simple C++ echo server code ([CMake](https://cmake.org/documentation/) build).
* **2.2:** C++ Service Nix Derivation: Create `stdenv.mkDerivation` to build the C++ service. Add as a package in the flake.
* **2.3:** Rust TCP Echo Service: Write simple Rust echo server code ([Cargo](https://doc.rust-lang.org/cargo/) build).
* **2.4:** Rust Service Nix Derivation: Create `rustPlatform.buildRustPackage` derivation. Add as a package in the flake.
* **2.5:** NixOS Service Modules: Create NixOS modules (`service-cpp.nix`, `service-rust.nix`) defining [systemd](https://www.freedesktop.org/wiki/Software/systemd/) services for both echo servers.
* **2.6:** Integrate Services into VM: Import service modules into the NixOS VM configuration. Test: Build VM, run, verify both services are running and responding (e.g., using `netcat` from host or within VM).

## 3. Basic Security Layer (TPM Disk Encryption)

* **3.1:** Add TPM Tools: Include [tpm2-tools](https://github.com/tpm2-software/tpm2-tools) and [swtpm](https://github.com/stefanberger/swtpm) packages in the NixOS VM configuration and dev shell. ([TPM - Trusted Platform Module](https://trustedcomputinggroup.org/resource/tpm-library-specification/))
* **3.2:** Configure [LUKS](https://en.wikipedia.org/wiki/Linux_Unified_Key_Setup) Encryption: Modify NixOS configuration to use LUKS for the root filesystem.
* **3.3:** Implement TPM Sealing/Unsealing: Add boot-time scripts (initrd) to: generate a LUKS key, seal it using `tpm2-tools` against [PCRs (Platform Configuration Registers)](https://trustedcomputinggroup.org/resource/pc-client-platform-firmware-profile-specification/), (initially against simulated PCRs), store the sealed blob, and unseal/unlock during subsequent boots. (NixOS has built-in support that simplifies this, see `boot.initrd.luks.devices.<name>.tpm2`).
* **3.4:** Test TPM Encryption (Simulation): Configure the QEMU VM runner (NixOS `run-*-vm` script or custom QEMU command) to use `swtpm`. Test initial boot (key generation/sealing) and subsequent boots (unsealing/unlocking). Verify filesystem is encrypted.

## 4. TEE Integration & Attestation Agent (Phase 1: SEV-SNP Focus)

* **4.1:** Attestation Agent Skeleton (Rust): Create a new Rust package/crate for the Attestation Agent. Define basic structure, dependencies (logging, error handling). Add as a package in the flake.
* **4.2:** Agent NixOS Module: Create a NixOS module to enable and run the Attestation Agent as a systemd service. Integrate into VM. Test: Build VM, verify agent process starts.
* **4.3:** NixOS Image Hash Calculation: Implement logic within the Agent to calculate the hash of the *running* NixOS system (strategy: hash the system derivation store path from `/run/current-system`). Add unit tests.
* **4.4:** Service Derivation Hash Inclusion: Modify Agent's NixOS module to pass the Nix store paths (or pre-computed hashes) of the C++ and Rust service derivations to the running Agent (e.g., via config file).
* **4.5:** [Sparse Merkle Tree (SMT)](https://medium.com/@CarlFarterson/what-are-sparse-merkle-trees-4161693918c4) Calculation: Implement logic in the Agent (using a Rust SMT library) to build an SMT from the provided service derivation hashes (and later, service app public keys). Compute the SMT root. Add unit tests.
* **4.6:** [SEV-SNP](https://www.amd.com/en/processors/sev-snp-strengthening-vm-isolation) Report Generation (Raw): Implement logic in the Agent (using [FFI - Foreign Function Interface](https://doc.rust-lang.org/nomicon/ffi.html) bindings to AMD's `sev-tool` or PSP firmware communication libraries/drivers, or QEMU-SEV simulation) to request a *raw* SEV-SNP attestation report. Focus on getting *any* report first. Test: Agent logs successful report retrieval or errors. (See [AMD SEV-SNP Attestation ABI Specification](https://www.amd.com/system/files/TechDocs/56860.pdf))
* **4.7:** Custom Data Preparation: Implement logic to combine the NixOS image hash and SMT root (and later GPU digest) into a single hash digest suitable for the 64-byte [REPORT_DATA](https://www.amd.com/system/files/TechDocs/56860.pdf) field (e.g., [SHA-512](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf) truncated or another SHA-512 hash). Add unit tests.
* **4.8:** Custom Data Injection (SEV-SNP): Modify the report generation call (Step 4.6) to include the prepared custom data hash in the `REPORT_DATA` field. Test: Mock TEE interaction or inspect report if simulation allows.
* **4.9:** Agent API Endpoint: Add an HTTP endpoint (e.g., using [axum](https://docs.rs/axum/) or [actix-web](https://actix.rs/docs)) to the Agent service (`/attestation`) that generates a fresh attestation report (with custom data) and returns it. Test: `curl` endpoint from within VM or host. (Later, add another endpoint for SMT Merkle proofs).

## 5. Rust Verification Client (Phase 1: SEV-SNP Focus)

* **5.1:** Rust Client Skeleton: Create a new Rust package/crate for the Verification Client. Add dependencies (`tokio`, `reqwest`, crypto libs, `serde`). Add as package in flake.
* **5.2:** Fetch Attestation Report: Implement function in Client to fetch the report from the Agent's API endpoint. Test: Client successfully retrieves report bytes.
* **5.3:** SEV-SNP Report Parsing: Implement logic (using FFI/structs based on AMD specs, or existing crates) to parse the fetched raw report bytes into a structured format. Add unit tests with sample report data.
* **5.4:** Signature & TCB Verification (SEV-SNP): Implement logic to: retrieve the [VCEK (Versioned Chip Endorsement Key)](https://www.amd.com/system/files/TechDocs/SEV-SNP-strengthening-vm-isolation-with-integrity-protection.pdf) certificate (from AMD [KDS - Key Distribution Service](https://www.amd.com/en/developer/sev-key-management.html) or cache), validate the VCEK chain against AMD root CAs ([ASK/ARK - AMD SEV Signing Key / AMD Root Key](https://www.amd.com/system/files/TechDocs/SEV-Key-Management.pdf)), verify the report signature using VCEK, and check TCB version (SVNs) against known good values. Requires trusted AMD root certs. Add unit/integration tests.
* **5.5:** Measurement Verification (SEV-SNP): Implement logic to extract the [MEASUREMENT](https://www.amd.com/system/files/TechDocs/56860.pdf) field (see Section 2.1 Attestation Report Structure of AMD SEV-SNP Attestation ABI Spec) and compare it against a known-good value for the trusted boot configuration. Test with expected and unexpected values.
* **5.6:** Custom Data Verification: Implement logic to: extract the hash from the `REPORT_DATA` field, independently calculate the expected combined hash (using known NixOS hash, SMT root, and later GPU digest), and compare. Test with expected and unexpected data.
* **5.7:** Client CLI: Create a simple CLI for the client that takes the Agent URL, expected NixOS hash, SMT root, etc., and performs the full verification flow.

## 6. TEE Heterogeneity (Phase 2: Add TDX Support)

* **6.1:** Refactor Agent for TEE Abstraction: Introduce traits or enums in the Agent to handle differences between SEV-SNP and [TDX (Trust Domain Extensions)](https://www.intel.com/content/www/us/en/architecture-and-technology/trust-domain-extensions.html) report generation/custom data injection.
* **6.2:** TDX Report Generation: Implement TDX quote generation logic in the Agent (using Intel TDX SDK/libraries/FFI for instructions like `TDG.MR.REPORT`). (See [Intel TDX Module v1.5 ABI Specification](https://cdrdv2.intel.com/v1/dl/getContent/733579), especially Section 5.3.10 `_TDX_TD_REPORT`)
* **6.3:** Custom Data Injection (TDX): Adapt custom data injection for the TDX [REPORTDATA](https://cdrdv2.intel.com/v1/dl/getContent/733579) field (see `TDREPORT_BODY` in Intel TDX Module v1.5 ABI Spec).
* **6.4:** Refactor Client for TEE Abstraction: Add logic to auto-detect TEE type from report or require explicit flag. Introduce traits/enums for parsing and verification.
* **6.5:** TDX Quote Parsing: Implement TDX quote parsing logic (using Intel libraries/SDK/FFI or Rust crates like `tdx-attest-rs`).
* **6.6:** Signature & TCB Verification (TDX): Implement TDX quote signature verification (using Intel [QVL/QvE (Quote Validation Library/Quote Verification Enclave)](https://github.com/intel/SGXDataCenterAttestationPrimitives) or interacting with [Intel PCS (Provisioning Certification Service)](https://www.intel.com/content/www/us/en/security/trust-authority.html)) and TCB status checks.
* **6.7:** Measurement Verification (TDX): Implement comparison of TDX measurements ([MRTD](https://cdrdv2.intel.com/v1/dl/getContent/733579), [MRCONFIGID](https://cdrdv2.intel.com/v1/dl/getContent/733579), [MROWNERCONFIG](https://cdrdv2.intel.com/v1/dl/getContent/733579), etc. from `TDREPORT_BODY` in Intel TDX Module v1.5 ABI Spec) against known-good values.
* **6.8:** Update Client CLI: Allow specifying TEE type or auto-detect. Test against both SEV-SNP and TDX environments.

## 7. Cloud & GPU Integration (Phase 3)

* **7.1:** Cloud vTPM Adaptation Strategy: Research vTPM interfaces ([Azure vTPM](https://docs.microsoft.com/en-us/azure/confidential-computing/confidential-vm-vtpm), [AWS NitroTPM](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/nitro-enclave-concepts.html#nitro-tpm), [GCP vTPM](https://cloud.google.com/compute/confidential-vm/docs/shielded-vtpm)). Plan adaptation of NixOS TPM sealing/unsealing scripts (Step 3.3) for cloud provider vTPMs. Test in target cloud environments.
* **7.2:** Cloud Deployment Testing: Test the full NixOS VM deployment, attestation generation, and Rust client verification flow in Azure, AWS, and GCP confidential VM offerings (TDX/SNP).
* **7.3:** Nvidia Driver Packaging (NixOS): Package the required Nvidia drivers (with [Nvidia Hopper CC - Confidential Computing](https://www.nvidia.com/en-us/data-center/h100/) support) as a Nix derivation.
* **7.4:** Integrate GPU Drivers into VM: Add driver package and necessary kernel module configurations to the NixOS VM.
* **7.5:** GPU Measurement Inclusion (Agent): Extend Attestation Agent to query Nvidia management libraries/drivers (e.g. related to [Nvidia GSP - GPU System Processor](https://developer.nvidia.com/blog/nvidia-open-source-gpu-kernel-modules/)) for GPU attestation measurements. Include these measurements (or a hash of them) within the custom data injected into the CPU TEE report.
* **7.6:** GPU Measurement Verification (Client): Extend Rust Client to extract and verify the GPU measurements from the custom data field against expected values.
* **7.7:** Secure Data Transfer Test ([CUDA](https://developer.nvidia.com/cuda-toolkit) Sample): Implement a simple test case using CUDA (e.g., `cudaMemcpy`, basic kernel) within the VM to ensure basic CPU-GPU communication works in the CC environment. Add as a package and to the VM.

## 8. Noir ZKP Client (Phase 4)

* **8.1:** Modify Rust Echo Service to Sign Responses: The service signs its responses with a ([secp256k1](https://www.secg.org/sec2-v2.pdf)) key. The public part of this key will be part of the SMT leaf.
* **8.2:** Agent API for SMT Merkle Proofs: Extend agent to provide Merkle proofs for service SMT entries on demand.
* **8.3:** [Noir](https://noir-lang.org/) Project Setup: Create a new Noir project ([Nargo.toml](https://noir-lang.org/docs/reference/nargo_toml_manifest), `src/main.nr`). Define circuit structure and initial dependencies (`noir_stdlib`, signature libraries).
* **8.4:** Define Circuit Inputs & Witnesses: Specify public inputs (commitments to NixOS hash, SMT root, service hash, response hash, TEE vendor key hash) and private inputs (full attestation elements, SMT proof, service key, signature, response).
* **8.5:** Implement Custom Data Verification (Noir): Verify `zkp_custom_data_commitment` (derived from NixOS hash, SMT root) matches expected values.
* **8.6:** Implement SMT Verification (Noir): Verify the service's leaf (derivation hash + app signing public key hash) is part of the SMT root using the Merkle proof.
* **8.7:** Implement Service Response Signature Verification (Noir): Verify the application signature on the service response using the service's public signing key (from SMT leaf) within the circuit (e.g., [ECDSA](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-5.pdf) secp256k1).
* **8.8:** Implement TEE Attestation Report Linkage (Noir): Placeholder/simplified check (e.g., assert prover-supplied hash of TEE vendor key against expected, ensure ZKP custom data corresponds to TEE report's custom data field).
* **8.9:** Develop Prover Tooling (Rust/TS): Write host code using Noir Rust/JS bindings to: gather inputs, prepare witness data, generate the proof using `nargo prove` or backend API. This becomes the "Alice" application.
* **8.10:** Develop Verifier Tooling (Rust/TS): Write host code to: take public inputs and proof, call `nargo verify` or backend API. This becomes the "Bob" application.
* **8.11:** End-to-End ZKP Test: Create a test scenario: Alice interacts with service, gets response & attestation data, generates ZKP, Bob verifies ZKP.

## 9. Finalization (Phase 5)

* **9.1:** Testing & QA: Comprehensive integration testing, cross-platform testing (Clouds, On-Prem, different CPU gens), security review/testing, performance testing (especially ZKP generation).
* **9.2:** Documentation: Write detailed setup, usage, architecture, and security documentation. ([X.509](https://datatracker.ietf.org/doc/html/rfc5280) for certificate structures if relevant)
* **9.3:** Refinement & Packaging: Code cleanup, error handling, logging improvements, build optimization. Package for easier deployment/use.
