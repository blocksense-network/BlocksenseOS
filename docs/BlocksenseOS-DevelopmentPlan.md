# Development Plan (superseded)

> **Status:** Superseded on 2026-07-08. This file previously
> contained the v0.1.0 blueprint for building a bespoke NixOS-based
> confidential-computing OS (TEE attestation agent, sparse Merkle
> derivation hashing, TPM/LUKS sealing, cloud/GPU integration, Noir
> client — phases 1–9).
>
> That plan is retired. BlocksenseOS is now developed as a
> downstream **attested configuration of ReproOS**; the
> platform-level phases of the old plan (TEE report generation and
> verification, measured boot, disk sealing, cloud CVM support, GPU
> attestation) are delivered upstream by the ReproOS
> Remote-Attestation campaign, and the Blocksense-specific work is
> re-planned with verification gates in:
>
> - [BlocksenseOS-Design.md](./BlocksenseOS-Design.md) — v0.2.0
>   architecture and division of responsibilities.
> - [ReproOS-Migration.milestones.org](./ReproOS-Migration.milestones.org)
>   — the active, ordered development plan for this repository.
> - `ReproOS-Remote-Attestation.md` /
>   `ReproOS-Remote-Attestation.milestones.org` in
>   [metacraft-labs/reprobuild-specs](https://github.com/metacraft-labs/reprobuild-specs)
>   — the upstream platform design and campaign.
>
> The old blueprint remains available in git history
> (`git log -- docs/BlocksenseOS-DevelopmentPlan.md`).
