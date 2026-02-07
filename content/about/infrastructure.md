---
title: "LinnemanLabs Infrastructure"
description: "Multi-account AWS platform architecture with supply chain security, TUF-based updates, CIS-hardened images, and a 98-node observability stack."
---

This site runs on the full LinnemanLabs platform - the same multi-account AWS organization, observability stack, supply chain security, and hardened images behind every project. Everything described here applies to what's serving this page.

I build and manage all of this myself. No Terraform modules, no managed platforms, no abstraction layers I don't own. Every CloudFormation template, every Ansible role, every pipeline is hand-written because I want to understand exactly what's running and why.

I stand on plenty of established tools - Ansible, Cosign, Hugo, dozens of others just in producing this site. What I do myself is the architecture and everything that connects it: how accounts are isolated, how signing flows through the pipeline, how the observability stack is distributed, how hardening is applied. The configuration layer is where security-relevant decisions actually live, and that's where I want full understanding. Building it all from the ground up means every layer knows about every other layer - cross-cutting concerns like signing, telemetry, and hardening are woven through the whole stack instead of bolted on per-service.

---

## Static Generation

- **Hugo** generates static HTML with no server-side rendering
- Minimal JavaScript
- Content-first design with **Tailwind CSS**

### Application Server (linnemanlabs-web)

The site is served by a custom Go binary built with observability, security, and performance as first-class concerns:


- **Prometheus metrics** - request latency, error rates, and custom business metrics
- **Pyroscope profiling** - continuous CPU and memory profiling
- **Secure CI/CD** - binary deployed from signed release artifacts with SBOM, vulnerability, license, and attestation gates

---

## Infrastructure

All infrastructure is defined as code using AWS CloudFormation and deployed across a multi-account AWS Organization. Currently running 200+ nodes across 10+ accounts.

### Infrastructure as Code

Everything is defined declaratively, version-controlled, and written from scratch:

- **CloudFormation** - all AWS infrastructure managed through hand-crafted templates
- **Packer** - automated AMI builds with security hardening baked in for Ubuntu 24.04 and RHEL 9
- **Ansible** - system management, application deployment, and configuration management across all EC2 instances
- **Bash** - deployment automation, bootstrap processes, build pipelines, glue across systems
- **Git-based workflows** - all changes reviewed and auditable
- Parameterized templates with extensive SSM Parameter Store integration
- Multi-environment support (prod, dev, qa, staging)

### AWS Architecture

Multi-account Organizations structure with proper isolation:

- **Organizations** - separate accounts for networking/DNS, security, CI builds, observability, and application workloads (separate account per company/project/concern)
- **Transit Gateway** - hub-and-spoke network topology with dedicated route tables per account
- **Ingress/egress isolation** - separate ingress and egress VPCs in the networking account, all traffic routes through central networking
- **Private subnets** - no direct internet access for application workloads
- **DNS automation** - Route53 with automated CNAME management
- **Cross-account resource sharing** - RAM with SSM parameters, cross-account security group references, KMS key policies
- EC2 instances with least-privileged IAM roles, ECR with KMS encryption and immutable tags, S3 for artifacts and TUF metadata, Secrets Manager for credential storage and rotation

### Network Security

- Network isolation via Transit Gateway with per-account route tables
- Security groups with least-privilege access patterns
- VPC flow logs for network visibility
- Private endpoints for AWS service access
- HTTPS/TLS everywhere, including internal traffic

### Golden AMI Pipeline

Automated, security-hardened base images:

- Packer builds for Ubuntu (x86_64, arm64) and RHEL 9
- CIS Level 2 Benchmark hardened using hand-crafted configuration
- Shared across organizational accounts
- Automated SSM parameter updates for latest stable AMIs
- Scheduled automated rebuilds
- Vulnerability scanning and AWS Patch Manager compliance before promotion
- Immutable infrastructure patterns

---

## Security Hardening

All instances are built from hardened golden AMIs and further configured at deployment for their specific role. Controls include:

- CIS Level 2 benchmark compliance validated at AMI build time
- SSH hardening (key-only auth, no root login, restricted groups)
- Filesystem hardening (noexec on /tmp, separate partitions)
- auditd with comprehensive rules for file access, privilege escalation, and kernel module events
- AppArmor profiles
- AIDE file integrity monitoring with SHA-512 checksums
- UFW firewall with default-deny policies
- pam_faillock for brute force protection, pam_pwquality for password complexity
- ASLR, core dump restrictions, automatic security updates, minimal installed packages
- Kernel module blacklisting (USB storage, DCCP, TIPC, RDS, SCTP)
- IPv6 disabled, TCP SYN cookies enabled
- Centralized audit log collection

---

## Supply Chain Security

Securing the full path from source to deployment to operation.

### Artifact Signing and Attestation

All release artifacts are cryptographically signed and attested:

- **Cosign** - container images signed with both keyless (OIDC via Sigstore) and AWS KMS-backed keys
- **SLSA Level 3** provenance attestations
- **SBOM generation** - Syft (SPDX) and cyclonedx-gomod
- **Vulnerability scanning** - Trivy, Grype, and govulncheck
- Signatures and attestations stored as OCI referrers alongside release artifacts
- Separate signing keys per application and environment (canary/stable)
- Cross-account key access via KMS key policies and IAM roles
- SSM parameters store signer URIs for build systems

### Deploy-Time Verification

- Deployment playbooks verify signatures before extracting binaries
- Public keys baked into golden AMIs as the initial trust root anchor
- Every deployment is a verification event, not just a file copy

### TUF (The Update Framework)

Content delivery uses TUF for verified updates:

- S3-based TUF repository for secure update distribution
- Signed metadata with role separation and threshold signatures for critical roles
- Snapshot and timestamp for freshness guarantees
- Automatic verification before content display
- Build roles with write access scoped to specific prefixes only
- Separate TUF paths per application and channel (canary/stable)
- Cross-account read access with bucket policies

### Container Security

- ECR repositories with immutable image tags
- KMS encryption for images at rest
- Lifecycle policies for image retention
- Organization-scoped pull access via service control policies

---

## Observability Stack

The observability platform serves the full LinnemanLabs environment - 98 nodes dedicated to observability alone, supporting the larger multi-account infrastructure across all projects.

This is a full Grafana stack running as distributed microservices across multiple availability zones. Service discovery and per-app configurations drive collection across multiple exporters including custom eBPF collectors and instrumented applications. All communication uses OTLP to stay standards-based and avoid lock-in to any specific vendor implementation.

### Metrics (Prometheus + Mimir)

- **Prometheus** - metric collection in HA configuration
  - node_exporter and ebpf_exporter across all nodes with tailored eBPF collectors
  - blackbox_exporter for custom checks
  - Instrumented applications with full RED metrics and database query metrics
  - Remote write to Mimir with exemplars enabled
  - Service discovery via file_sd and static configs
- **Mimir** - long-term metrics storage with multi-tenancy
  - Distributed architecture (distributor, ingester, querier, query-frontend, query-scheduler, store-gateway, compactor)
  - S3 backend storage with memberlist for cluster coordination
  - External labels for cluster, region, environment, and company
- Memcached caching layer for query results, chunks, metadata, and index

### Logging (Loki)

- **Loki** - log aggregation with label-based indexing
  - Distributed architecture (distributor, ingester, querier, query-frontend, query-scheduler, index-gateway, compactor, ruler)
  - Structured logging with trace correlation
  - Memberlist for cluster coordination, OTLP support for structured metadata
  - S3 backend storage, retention and rate limiting per-tenant
- Memcached caching layer for query results, chunks, deduplication, and index

### Tracing (Tempo)

- **Tempo** - distributed tracing backend
  - vParquet4 block format with S3 storage
  - OTLP receivers on gRPC (4317) and HTTP (4318)
  - Metrics generator producing service-graphs and span-metrics
  - Zone-aware replication (factor of 3)
- Memcached caching for bloom filters and parquet pages

### Profiling (Pyroscope)

- **Pyroscope** - continuous profiling with S3 backend storage
- **Grafana Alloy** - agent running eBPF-based profiling on all hosts
  - System-wide CPU profiling with automatic process discovery
  - Production-safe with minimal overhead
- Instrumented applications for continuous CPU, memory, and goroutine profiling

### Telemetry Collection

- **OpenTelemetry Collector** - unified telemetry pipeline for log and trace shipping
  - Protocol translation (OTLP, Prometheus)
  - Sampling and filtering at collection time
  - journald receiver for system logs, file log receiver for direct logs
  - OTLP receiver for instrumented application telemetry
  - Resource detection (EC2 metadata) and attribute enrichment
- **Alloy** - profile pipeline for OTLP profile schema translation to Pyroscope

### Visualization and Alerting

- **Grafana** - unified dashboards for all telemetry
  - HA with PostgreSQL backend for dashboard and session storage
  - OAuth/OIDC integration with Okta
  - High-level environmental ops dashboards plus custom dashboards per app and service
  - Dedicated memcached clusters per service
- **Alertmanager** - HA cluster with de-duplication
  - Slack and PagerDuty integration for routing and on-call
  - Comprehensive alert rules for all LGTM components
  - Node-level alerts (CPU, disk, memory, network, time sync) and per-application conditions
  - CloudFormation stack event notifications via Slack

---

## Deployment and Automation

### CI/CD

- Hand-crafted pipelines from build to deploy
- **Blue-green deployments** for zero-downtime releases
- **Automated rollback** on health check failures

### Bootstrap System

- S3-hosted bootstrap scripts pulled at instance launch
- Git-based configuration with deploy keys stored in Secrets Manager
- CloudFormation signal-resource for deployment status
- Autoscaling group health reporting
- Post-install hooks for service-specific configuration

### Notifications

- SNS topics for autoscaling events
- Lambda functions for CloudFormation event processing
- Slack webhooks for real-time deployment notifications with AWS Organizations account name resolution for context