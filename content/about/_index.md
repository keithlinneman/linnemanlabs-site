---
title: "About"
description: "LinnemanLabs - an infrastructure lab running multiple projects across a multi-account platform, documenting security-first design and software supply chain integrity."
---

## LinnemanLabs

LinnemanLabs is my working infrastructure lab, a multi-account platform running several projects across 200+ nodes. This site is one tenant on that platform, and serves as a public window into how it's built.

This site is largely my public workbench focused on secure-by-default infrastructure, platform engineering, software supply chain security, and red teaming. I publish notes, prototypes, and reference implementations as I learn and build. The goal is to document my process, open-sourcing what I can along the way so others can reuse the same ideas without starting from scratch.

Learn more [about me](/about/me/) or [how it's built](/about/infrastructure/).


### Mission

To demonstrate that security and usability are not mutually exclusive. Projects here prioritize:

- **Verification** — cryptographic proof of what was built and where it came from
- **Transparency** — open-source, auditable implementations and reproducible decisions
- **Integrity** — defense in depth from build -> deploy -> operate

These principles apply equally to traditional software and to ML models. Provenance and integrity matter regardless of what the artifact is

### Principles in practice

This site itself serves as a demonstration of these principles.

- Signed release artifacts and verifiable provenance (SLSA/Sigstore where appropriate)
- Explicit trust roots and verification at deploy time
- Secure update patterns (TUF-style metadata, freshness, and role separation)
- Operability as a security feature (telemetry, rollback, recovery)

---

## Architecture overview

> The exact implementation evolves as the lab evolves. The goal is to keep the design auditable and repeatable.

This site is one project running on the larger LinnemanLabs platform. It's static-first, with dynamic features implemented deliberately and minimally:
- **Static generation:** Hugo + content-first design (Tailwind CSS), minimal JS (HTMX where needed)
- **Serving layer:** a custom Go binary with observability and security as primary concerns
- **CI/CD:** signed/attested releases with vulnerability and policy gates
- **Infrastructure:** AWS, defined as code, deployed across a multi-account Organizations layout
- **Observability:** Grafana stack (metrics/logs/traces/profiles) with OpenTelemetry-based collection

[Learn more about LinnemanLabs infrastructure](/about/infrastructure)

## Content

Posts cover topics including:

- Platform engineering and developer experience
- Security architecture and implementation
- AI/ML security and model supply chain integrity
- Infrastructure automation and infrastructure as code
- Observability and incident response
- Software supply chain security
- Compliance and hardening
- Multi-account AWS architecture patterns