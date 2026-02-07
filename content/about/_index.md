---
title: "About"
description: "LinnemanLabs - an infrastructure lab and security research platform built on a multi-account AWS organization, documenting offensive and defensive security work across 200+ nodes."
---

## LinnemanLabs

LinnemanLabs is my lab. It's a multi-account AWS platform - 10+ accounts, 200+ nodes, 100+ CloudFormation stacks, all hand-written - where I build things, break things, and write about both. This site is one tenant on that platform, and it's where I make the work public.

I've been building and operating infrastructure for 20+ years. The throughline across all of it is wanting to understand systems completely - every bit, every packet, every syscall. Not because that's efficient, but because that's where the interesting problems live, and it's the only way to know whether something is actually secure or just appears to be.

The work here sits at the intersection of building production systems and studying how they break. I think those are the same discipline and two sides of the same coin. You can't meaningfully defend infrastructure you haven't operated, and you can't find the real attack surface in systems you've only read about. This site documents both sides of that as I go - research, reference implementations, notes on process. I open-source what I can so the ideas are reusable.

Learn more [about me](/about/me/) or [the infrastructure](/about/infrastructure/).

### What I'm working on

**Observability as attack surface** - I'm researching how the monitoring and telemetry infrastructure we rely on can be turned against us. eBPF, collector pipelines, metric/log/trace data paths - these are deeply trusted components that most security models treat as safely internal. I think that's wrong, and I want to demonstrate why.

**Trust and verification** - I care about systems where security properties are provable, not just documented. That means the full chain: hardware roots of trust, signed and attested builds, deploy-time cryptographic verification, runtime integrity, transparency logs. Not as a checklist but as a coherent architecture where each layer actually depends on the one below it. This site is a working implementation of that thinking - every release is signed, attested, and verifiable from source to what's running in production.

**Platform security** - The lab itself is the testbed. 10+ AWS accounts with multi-account isolation, everything defined as code, everything instrumented. I treat operability - telemetry, rollback, recovery - as a security property, not a convenience feature. If you can't understand and observe it, you can't secure it, and if you can't roll it back, your incident response is theoretical.

### What I believe

I'd rather understand one system top to bottom than skim ten. Depth is the thing. First principles over cargo culting, understand the primitives end to end before you abstract or automate. I write my own CloudFormation stacks and Ansible roles because I want to know exactly what's happening and why, and because that's where you find the gaps that matter.

I think offense and defense are the same skillset applied in different directions. The best security work I've seen comes from people who've built the thing they're trying to break. That's what I'm trying to demonstrate here.

Provenance and integrity matter regardless of what the artifact is - application code, container images, ML models, infrastructure definitions, policy, dependencies, firmware. If you can't verify where it came from, what happened to it along the way, and that nothing changed between there and here, you're trusting. I'd rather verify.

---

## Architecture overview

This site is one project on the larger LinnemanLabs platform. It's static-first, with dynamic features added deliberately and minimally:

- **Static generation:** Hugo, content-first design with Tailwind CSS, minimal JS (HTMX where needed)
- **Serving layer:** custom Go binary with observability and security as primary concerns
- **CI/CD:** signed and attested releases with vulnerability scanning and policy gates
- **Infrastructure:** AWS, defined as code, deployed across a multi-account Organizations layout
- **Observability:** Grafana stack (metrics, logs, traces, profiles) with OpenTelemetry-based collection

The implementation evolves as the lab evolves. The design stays auditable and repeatable.

[Learn more about LinnemanLabs infrastructure →](/about/infrastructure)