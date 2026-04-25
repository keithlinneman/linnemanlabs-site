---
title: "About Me"
description: "Keith Linneman - infrastructure and security engineer with 25+ years building, breaking, and securing production systems."
---

## Keith Linneman

I've been doing this since the mid-90s - over 25 years of building, breaking, and operating systems. I started by breaking into them as a kid, living on IRC, learning how networks and operating systems actually worked by taking them apart. That offensive background shaped everything that came after. I moved into infrastructure and operations, bringing an attacker's perspective to how I design, harden, and monitor production systems. Now I'm circling back to offensive security with deep infrastructure and operations experience behind it.

I run LinnemanLabs as a working lab for security research and infrastructure engineering - documenting what I build and learn, and open-sourcing what I can.

My roots are in offensive security, and that's where the work is heading again. The current focus is a purple-team loop in the lab - building offensive tooling, exercising it against my own systems, and writing the detection rules to catch it. I'm researching how production infrastructure (especially observability pipelines) can be subverted from within, and I'm building systems where security properties are cryptographically provable rather than assumed: a self-hosted Sigstore stack with hardware-rooted trust, dual-signing through keyless OIDC and KMS, and deploy-time verification. Detection-coverage tooling that verifies "did we catch it?" as a continuous property across every SIEM and log backend, and deception environments realistic enough that malware behaves naturally rather than recognizing the lab are two areas I plan to push into next.

---

### How I work

I'd rather understand one system completely than be passingly familiar with ten. Full-stack ownership means knowing how the system behaves from protocol to code to infrastructure to operations - not just the layer I'm responsible for on the org chart.

First principles over cargo culting. I understand the primitives end to end before I abstract or automate, and I trust what I can explain. If I can't reason about how something works, I won't trust it in production.

I prefer small, composable systems over big frameworks. When I learn a better model, I refactor and simplify rather than layering on complexity. I'd rather own fewer things well than accumulate technical debt across many.

I think security should be the default path, not a gate at the end. That means building guardrails into CI/CD, treating operability - telemetry, rollback, recovery - as a primary feature, and designing systems where the easy thing and the secure thing are the same thing.

These principles don't change with the artifact. Provenance, integrity, and verification matter whether what you're shipping is application code, a container image, an infrastructure definition, a configuration, an ML model, or firmware.

---

### Get in touch

For the right problem, I go deep.

- GitHub: [keithlinneman](https://github.com/keithlinneman)
- Email: [hello@linnemanlabs.com](mailto:hello@linnemanlabs.com)