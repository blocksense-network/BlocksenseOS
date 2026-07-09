# BlocksenseOS Threat Model

**Version:** 0.3-draft (re-scoped 2026-07-08 for the ReproOS re-founding)
**Scope:** the Blocksense-specific layer described in
[BlocksenseOS-Design.md](./BlocksenseOS-Design.md) v0.2.0.

## 1. Split of analysis

BlocksenseOS is a downstream attested configuration of ReproOS.
Platform-level threats — boot/measurement-chain tampering, TEE
hardware and vendor-key compromise, TCB rollback, sealed-storage
attacks, attestation-agent hardening, verifier fail-open bugs,
report replay/freshness, side channels — are analyzed in the
platform threat model:
[ReproOS-Remote-Attestation.md §11–12](https://github.com/metacraft-labs/reprobuild-specs/blob/latest/ReproOS-Remote-Attestation.md).
Supply-chain threats (Trusting Trust, build-cache amplification) are
analyzed in
[ReproOS.md](https://github.com/metacraft-labs/reprobuild-specs/blob/latest/ReproOS.md).

This document analyzes only what BlocksenseOS adds on top: service
identity and signed responses, the ZK verification pipeline, the
watcher committee, and measurement governance. Re-analyzing platform
threats here would drift out of date; when a Blocksense feature
changes a platform assumption, the platform model is updated
upstream instead.

## 2. Assets (Blocksense layer)

- Per-service in-enclave signing keys and the service-identity
  record/root.
- Response transcripts (request/response commitments + signatures).
- Watcher-committee keys and their signed verification facts.
- The approved-measurement set (policy file + on-chain set) and its
  governance path.
- ZK circuits, proving/verifying keys, and the on-chain verifier
  contract.

## 3. Trust assumptions

- The ReproOS platform guarantees hold (verified launch measurement
  ⇒ exact configuration; report-data binding discipline; fail-closed
  verification). Attacks that require breaking those are platform
  scope.
- TEE vendor cryptography is sound at the attested TCB level.
- For the v1 ZK stage: at most K−1 of N watchers are compromised.
- Blocksense release governance (who may approve a measurement) is
  performed by the parties named in the M6 governance record.

## 4. STRIDE analysis — Blocksense layer

| Category | Representative threats | Controls | Residual risk / actions |
| --- | --- | --- | --- |
| **S — Spoofing** | Fake service key presented as attested; foreign instance's identity root replayed against fresh evidence; watcher impersonation | Identity root bound into challenge-bound `report_data`; per-service Merkle proofs; watcher keys pinned + K-of-N | Watcher key custody procedures; rotate on personnel change |
| **T — Tampering** | Response modified after signing; identity record mutated between attestation and use; approved-set edited outside governance | Signatures over `domain_tag ‖ request ‖ response ‖ counter`; root re-bound per attestation epoch; approved-set changes only via signed governance actions with audit trail | Counter/epoch semantics must be property-tested (replay-window edges) |
| **R — Repudiation** | Operator denies an instance served a response; governance denies an approval | Offline-verifiable transcripts; signed, logged policy updates; on-chain approved-set history | Define transcript retention expectations for disputes |
| **I — Information disclosure** | ZK proof leaks transcript details; identity record enumerates internal topology; provisioned secrets exposed by a compromised workload | Commitments/blinding in circuit inputs; identity record contains only public keys + package hashes; secrets tmpfs-only, session-scoped (platform §8) | A compromised *service* can still leak what it can read — application-level compartmentalization guidance needed |
| **D — Denial of service** | Attestation-verification flooding of watchers; governance stall bricks releases; committee unavailability blocks v1 proofs | Watcher rate limits; N sized for liveness (K < N with margin); governance has a documented emergency-revocation and quorum-recovery path | Availability analysis for the committee is an M7 deliverable |
| **E — Elevation of privilege** | Circuit soundness bug proves false statements on-chain; unaudited crypto library in the proof stack; verifier-contract upgrade path abused | Staged verification (committee v1 before in-circuit v2); per-dependency audit log; negative/property tests for every soundness claim; contract upgrade behind governance | Budget external audit of circuits before mainnet reliance |

## 5. Abuse cases worth explicit tests

1. **Replayed identity root:** evidence fresh, root stale (from an
   earlier boot session) — must fail (root is inside the
   challenge-bound hash).
2. **Cross-instance splice:** valid evidence from instance A + valid
   identity proof from instance B — must fail.
3. **Approved-set race:** response produced under a measurement
   revoked mid-session — verifiers must reject at their policy
   epoch; document the accepted staleness window.
4. **Committee equivocation:** watchers sign conflicting facts for
   the same epoch — must be detectable from the signed-fact log and
   slashable/actionable under governance.
5. **Mock leakage:** any mock/TPM-tier artifact accepted by a
   production verifier — must be impossible by policy construction
   (platform rule; asserted again here because the cost is
   catastrophic on-chain).

## 6. Review cadence

Re-run this analysis at every migration milestone that changes the
security surface (M3, M4, M5, M7 of
[ReproOS-Migration.milestones.org](./ReproOS-Migration.milestones.org)),
and whenever the upstream platform model records a change that
alters an assumption in §3.
