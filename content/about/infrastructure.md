---
title: "LinnemanLabs Infrastructure"
description: "Multi-account AWS platform architecture with supply chain security, TUF-based updates, CIS-hardened images, and a 98-node observability stack."
---

> The exact implementation evolves as the lab evolves. The goal is to keep the design auditable and repeatable.

This site runs on LinnemanLabs' multi-account AWS platform - the same infrastructure supporting several internal projects. What follows describes the full platform behind this site not just the blog.

## Static Generation

- **Hugo** generates static HTML with no server-side rendering
- Minimal JavaScript (HTMX where needed)
- Content-first design with **Tailwind CSS**

### Application Server (linnemanlabs-web)

The site is served by a custom Go binary built with observability, security and performance as first-class concerns:

- **Prometheus metrics** - Request latency, error rates, and custom business metrics
- **Pyroscope profiling** - Continuous CPU and memory profiling
- **Secure CI/CD** - Binary deployed from signed release artifacts with sbom, vulnerability, license, and attestation gates

---

## Infrastructure

All infrastructure is defined as code using AWS CloudFormation (CFN) and deployed across a multi-account AWS Organization structure. Currently running 200+ nodes across 10+ accounts.

### Infrastructure as Code

All infrastructure is defined declaratively, version controlled and built by hand from scratch:

- **CloudFormation** - All AWS infrastructure is managed and deployed through hand-crafted templates
- **Packer** - Automated AMI builds with security hardening baked in for Ubuntu 24.04 and RHEL 9
- **Bash Scripting** - Deployment automation, bootstrap processes, build pipelines, misc glue across systems
- **Git-based workflows** - All changes reviewed and auditable
- Parameterized templates with extensive SSM Parameter Store integration
- Multi-environment support (prod, dev, qa, staging)

### AWS Architecture

Multi-account AWS Organizations structure with proper isolation:

- **AWS Organizations** - Multi-account structure with separate accounts for:
  - Networking/DNS
  - Security
  - CI Build
  - Observability
  - Application workloads (separate account per company/project/concern)
- **Transit Gateway** - Hub-and-spoke network topology with dedicated route tables per account
- **Ingress/Egress Isolation** - Separate ingress VPC and egress VPC in the networking account
- **Private subnets** - No direct internet access for application workloads
- **Centralized Egress/Ingress** - All ingress/egress routes through the central networking account
- **DNS Automation** - Route53 with automated CNAME management
- **SSM Parameter Store** - Environment and infrastructure configuration management
- **Secrets Manager** - Credential storage and rotation
- **ECR** - Container image storage with KMS encryption and immutable tags
- **S3** - Artifact storage, TUF metadata, and object storage backends
- **EC2 instances** - Ephemeral instances with least-privileged IAM roles for service access
- **RAM (Resource Access Manager)** - Cross-account resource sharing using SSM Parameters

### Network Security

- Network isolation via Transit Gateway with per-account route tables
- Security groups with least-privilege access patterns
- Cross-account security group referencing support
- VPC flow logs for network visibility
- Private endpoints for AWS service access
- HTTPS/TLS everywhere, including internally

### Golden AMI Pipeline

Automated, secure base images:

- Packer builds for Ubuntu (x86_64, arm64) and RHEL 9
- Shared AMIs across organizational accounts
- CIS Level 2 Benchmark hardened base images using hand-crafted configuration
- Automated SSM parameter updates for latest stable AMIs
- Frequented, scheduled, automated rebuilds
- Vulnerability scanning before promotion
- AWS Patch Manager compliance before promotion
- Immutable infrastructure patterns

---

## Security Hardening

All instances are built from hardened golden AMIs and further configured at deployment for their use-case. Security controls include:

- Full compliance with CIS Level 2 benchmarks validated at AMI build time
- SSH hardening (key-only auth, no root login, restricted groups)
- Filesystem hardening (noexec on /tmp, separate partitions)
- Automatic security updates
- Minimal installed packages
- Audit logging with centralized collection
- auditd with comprehensive rules for file access, privilege escalation, and kernel module events
- AppArmor profiles
- ASLR, core dump restrictions
- pam_faillock for brute force protection
- pam_pwquality for password complexity enforcement
- AIDE for file integrity monitoring with SHA-512 checksums
- UFW firewall with default deny policies
- Kernel module blacklisting (USB storage, DCCP, TIPC, RDS, SCTP)
- IPv6 disabled, TCP SYN cookies enabled

---

## Supply Chain Security

Deep expertise in securing the software supply chain from source to deployment to operation.

### Attestations
- Cosign signatures with keyless (OIDC) signing via Sigstore
- Cosign signatures with KMS signing
- SLSA Level 3 provenance attestations
- SBOM generation with Syft (SPDX format) and cyclonedx-gomod
- Vulnerability scanning with Trivy, Grype and govulnscan
- Stored as referrers to release artifacts in OCI registry

### Artifact Signing with Cosign

All release artifacts are cryptographically signed:

- Container images signed with Cosign
- Signatures stored in OCI registry alongside images
- Keyless signing with Sigstore for transparency
- AWS KMS-backed signing keys for cosign operations
- Separate signing keys per application and environment (canary/stable)
- Cross-account key access via KMS key policies and IAM roles
- SSM parameters store signer URIs for build systems

### Release Verification Pipeline

- SLSA Level 3 provenance for builds
- Software Bill of Materials (SBOM) generation
- Vulnerability scanning with Trivy, Grype and govulnscan
- Deployment playbooks verify signatures before extracting binaries
- Public keys baked into golden AMIs for initial trust root anchor

### TUF (The Update Framework)

Content delivery uses TUF for verified updates:

- S3-based TUF repository for secure update distribution
- Signed metadata with role separation
- Snapshot and timestamp for freshness
- Threshold signatures for critical roles
- Automatic verification before content display
- Build roles with write access to specific prefixes only
- Separate TUF paths per application and channel (canary/stable)
- Cross-account read access with bucket policies

### Container Security

- ECR repositories with immutable image tags
- KMS encryption for images at rest
- Lifecycle policies for image retention
- Organization-scoped pull access via service control policies

---

## Observability Stack

The observability platform serves the full LinnemanLabs environment - 98 nodes dedicated to observability alone, supporting a larger multi-account infrastructure spanning several projects.

A full Grafana stack (plus more) running as distributed microservices across multiple availability zones. Using service discovery and per-app configurations with multiple exporters including custom eBPF collectors and instrumented applications. All communications use OTLP to reduce dependency on any specific tool implementation and stay standards-based.

### Metrics (Prometheus + Mimir)

- **Prometheus** - Metric collection with HA configuration
  - node_exporter and ebpf_exporter across all nodes with tailored ebpf collectors
  - blackbox_exporter custom checks
  - Instrumented applications with full RED metrics and database query metrics
- **Mimir** - Long-term metrics storage with multi-tenancy
  - Distributed architecture (distributor, ingester, querier, query-frontend, query-scheduler, store-gateway, compactor)
  - Multi-tenant support
  - S3 backend storage
  - Memberlist for cluster coordination
  - External labels for cluster, region, environment, and company
  - Remote write to Mimir with exemplars enabled
  - Service discovery via file_sd and static configs
- Memcached caching layer for query results, chunks, metadata, and index caching.

### Logging (Loki)

- **Loki** - Log aggregation with label-based indexing
- Distributed architecture (distributor, ingester, querier, query-frontend, query-scheduler, index-gateway, compactor, ruler)
- Structured logging with trace correlation
- Memberlist for cluster coordination
- OTLP support for structured metadata
- S3 backend storage for retention
- Retention and rate limiting configured per-tenant
- Memcached caching layer for query results, chunks, deduplication, and index caching.

### Tracing (Tempo)

- **Tempo** - Distributed tracing backend
- vParquet4 block format and S3 storage
- OTLP receivers on gRPC (4317) and HTTP (4318)
- Metrics generator producing service-graphs and span-metrics
- Zone-aware replication (factor of 3)
- Memcached caching layer for bloom filters and parquet pages

### Profiling (Pyroscope)

- **Pyroscope** - Profiling storage using S3
- **Grafana Alloy** - Agent running continuous eBPF-based profiling on all hosts
- System-wide CPU profiling with automatic process discovery
- Long-term retention with S3 backend storage
- Instrumented applications for continuous CPU, memory, and goroutines profiling
- Production-safe with minimal overhead

### Telemetry Collection

- **OpenTelemetry Collector** - Unified telemetry pipeline for log and trace shipping
- Protocol translation (OTLP, Prometheus)
- Sampling and filtering at collection time
- journald receiver for system logs
- File log receiver for directly written logs
- OTLP receiver for instrumented application telemetry
- Resource detection (EC2 metadata) and attribute enrichment
- **Alloy** - profile pipeline to allow modern OTLP profile schema translation to Pyroscope over HTTP

### Visualization (grafana)

- **Grafana** - Unified dashboards for all telemetry
- HA design using PostgreSQL backend for dashboards and login session storage
- OAuth/OIDC integration with Okta
- High level environmental ops dashboards
- Custom dashboards for each app and service
- Dedicated memcached clusters per service for performance optimization

### Alerting (alertmanager)

- **Alertmanager** - Alert routing
- HA cluster mode with de-duplication
- Slack integration for notifications using multiple conditions to determine destination channel routing
- PagerDuty integration for on-call
- Comprehensive alert rules for all LGTM components
- Node-level alerts: CPU, disk, memory, network, time sync
- Per-application alert conditions and rules
- Slack integration for CloudFormation stack notifications

---

## Deployment & Automation

- Hand-crafted CI/CD pipelines from build to deploy
- **Blue-green deployments** - Zero-downtime releases
- **Automated rollback** - Health check failures trigger automatic rollback

### Bootstrap System

- S3-hosted bootstrap scripts pulled at instance launch
- Git-based configuration with deploy keys stored in Secrets Manager
- CloudFormation signal-resource for deployment status
- Autoscaling group health status reporting
- Post-install hooks for service-specific configuration
- Ansible roles for all ec2 system management, application deployments and configuration management

### Notifications

- SNS topics for autoscaling events
- Lambda functions for CloudFormation event processing
- Slack webhooks for real-time deployment notifications
- AWS Organizations account name resolution for context
