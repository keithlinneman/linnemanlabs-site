---
title: "About Me"
description: "Keith Linneman - infrastructure and security engineer with 25+ years building, breaking, and securing production systems."
---

``` text
░▒▓██████████████████████████████████████████████████████████████████████████▓▒░

    ██▓     ██▓ ███▄    █  ███▄    █ ▓█████  ███▄ ▄███▓ ▄▄▄       ███▄    █
   ▓██▒    ▓██▒ ██ ▀█   █  ██ ▀█   █ ▓█   ▀ ▓██▒▀█▀ ██▒▒████▄     ██ ▀█   █
   ▒██░    ▒██▒▓██  ▀█ ██▒▓██  ▀█ ██▒▒███   ▓██    ▓██░▒██  ▀█▄  ▓██  ▀█ ██▒
   ▒██░    ░██░▓██▒  ▐▌██▒▓██▒  ▐▌██▒▒▓█  ▄ ▒██    ▒██ ░██▄▄▄▄██ ▓██▒  ▐▌██▒
   ░██████▒░██░▒██░   ▓██░▒██░   ▓██░░▒████▒▒██▒   ░██▒ ▓█   ▓██▒▒██░   ▓██░
   ░ ▒░▓  ░░▓  ░ ▒░   ▒ ▒ ░ ▒░   ▒ ▒ ░░ ▒░ ░░ ▒░   ░  ░ ▒▒   ▓▒█░░ ▒░   ▒ ▒
   ░ ░ ▒  ░ ▒ ░░ ░░   ░ ▒░░ ░░   ░ ▒░ ░ ░  ░░  ░      ░  ▒   ▒▒ ░░ ░░   ░ ▒░
     ░ ░    ▒ ░   ░   ░ ░    ░   ░ ░    ░   ░      ░     ░   ▒      ░   ░ ░
       ░  ░ ░           ░          ░    ░  ░       ░         ░  ░         ░

                        ██▓    ▄▄▄       ▄▄▄▄     ██████
                       ▓██▒   ▒████▄    ▓█████▄ ▒██    ▒
                       ▒██░   ▒██  ▀█▄  ▒██▒ ▄██░ ▓██▄
                       ▒██░   ░██▄▄▄▄██ ▒██░█▀    ▒   ██▒
                       ░██████▒▓█   ▓██▒░▓█  ▀█▓▒██████▒▒
                       ░ ▒░▓  ░▒▒   ▓▒█░░▒▓███▀▒▒ ▒▓▒ ▒ ░
                       ░ ░ ▒  ░ ▒   ▒▒ ░▒░▒   ░ ░ ░▒  ░ ░
                         ░ ░    ░   ▒    ░    ░ ░  ░  ░
                           ░  ░     ░  ░ ░            ░
                                              ░

░▒▓██████████████████████████████████████████████████████████████████████████▓▒░
┌───────────────────────────────────────────────────────────────────────────────
│
│           ::: presents :::   about · the · operator   [release 2026]
│
└──[ keith@linnemanlabs:~/about$ ]──────────────────────────────────────────────┐
                                                                                │
  $ whoami                                                                      │
  keith linneman                                                                │
                                                                                │
  $ uptime                                                                      │
   09:08:59 up 20+ years, load average: build, operate, attack                  │
                                                                                │
  $ file /etc/localtime                                                         │
  /etc/localtime: symbolic link to ../usr/share/zoneinfo/America/Los_Angeles    │
                                                                                │
  $ id                                                                          │
  uid=1001(keith) gid=1005(operators) groups=1006(research),1007(purple-team)   │
  uid=1001(k) gid=1005(ops) groups=1006(research),1007(blue-team),1008(red-team)│
                                                                                │
  $ history | tail -21 | head -20                                               │
   980 ./build infrastructure --aws --accounts_total=12 --node_count=200+       │
   981 ./build ansible --roles=20+ --zero-lint-failures --handwritten           │
   982 ./deploy observability --prometheus --loki --mimir --pyroscope --tempo   │
   983 ./build go-libraries --observability --instrumentation --http            │
   984 ./build ebpf-exporters --kernel-telemetry --prometheus                   │
   985 ./build pki --yubikey-root --intermediates=3 --p384 --tuf --cosign       │
   986 ./perform key-ceremony --air-gapped --tails --offline-root               │
   987 ./build kms-csr-tool --go --hardware-backed-signing                      │
   988 ./deploy sigstore --rekor --tesseract --tsa --fulcio                     │
   989 ./deploy spiffe-spire --workload-identity --every-service                │
   990 ./build trust.linnemanlabs.com                                           │
   991 ./build app-build-system --github --sigstore --keyless-signing --oidc    │
   992 ./deploy wazuh --agents=164 --ossec --osquery --yara --suricata          │
   993 ./build linnemanlabs.com                                                 │
   994 ./build vigil --alerts --llm-triage --notify=slack                       │
   995 ./build glimmer --c2 --beacon --raw-sockets --af_packet --dbus           │
   996 ./run purple-team-exercises --emulate=adversary --verify=detection       │
   997 ./migrate cloudformation --to=terraform --start=trust-account            │
   998 ./build switchboard --v1 --grpc --spiffe --runbook-proposal              │
   999 ./build hardened-workstation --ebpf --lsm --selinux --secure-boot        │
                                                                                │
  $ ps -u keith                                                                 │
    PID  STAT  COMMAND                                                          │
   0001  R     switchboard --version=1                                          │
   0002  S     vigil --version=1 --deployed                                     │
   0003  R     terraform-migration --account=trust                              │
   0004  R     improve-workstation --research --attack --harden --document      │
   R = Running(building), S = Sleeping(deployed), Z = Zombie(dormant)           │
                                                                                │
  $ goodbye                                                                     │
  goodbye: Command not found.                                                   │
                                                                                │
  ^]                                                                            │
  telnet> q                                                                     │
  Connection closed.                                                            │
                                                                                │
┌───────────────────────────────────────────────────────────────────────────────┘
│
└─[ methodology ]───────────────────────────────────────────────────────────────┐
                                                                                │
   > detect ........... see what is actually happening                          │
   > instrument ....... make it visible to anyone                               │
   > correlate ........ connect signals across layers                           │
   > verify ........... prove the conclusion, end to end                        │
   > document ......... leave the trail for next time                           │
                                                                                │
                   "every bit, every packet, every syscall."                    │
                                                                                │
┌───────────────────────────────────────────────────────────────────────────────┘
│
└─[ now playing ]───────────────────────────────────────────────────────────────┐
                                                                                │
   · vigil ........... AI alert triage engine (go) .......... shipped           │
   · switchboard ..... AI orchestration platform ............ in progress       │
   · trust ........... sigstore + spire chain ............... phase 4 of 6      │
   · clauditor ....... eBPF audit daemon (AI agents) ........ planned           │
   · leash ........... eBPF LSM-based AI containment ........ planned           │
   · glimmer.......... adversary emulation, C2 framework..... in progress       │
   · prism............ detection engineering verifier........ planned           │
                                                                                │
┌───────────────────────────────────────────────────────────────────────────────┘
│
└─[ stack ]─────────────────────────────────────────────────────────────────────┐
                                                                                │
   cloud ............. aws (us-east-2) · 200+ nodes · 12 accounts               │
   config ............ cloudformation → terraform · ansible · zero modules      │
   observability ..... prometheus · mimir · loki · tempo · pyroscope            │
   identity .......... custom pki · spire · sigstore · yubikey root             │
   defense ........... wazuh · ossec · suricata · yara · tetragon · ebpf        │
   languages ......... go · rust · shell · sql                                  │
                                                                                │
┌───────────────────────────────────────────────────────────────────────────────┘
│
└─[ greetz ]────────────────────────────────────────────────────────────────────┐
                                                                                │
   to: the people still reading source 3 layers below the abstractions          │
                                                                                │
┌───────────────────────────────────────────────────────────────────────────────┘
│
└─[ contact ]───────────────────────────────────────────────────────────────────┐
                                                                                │
   www ..........: linnemanlabs.com                                             │
   trust ........: trust.linnemanlabs.com                                       │
   github .......: github.com/linnemanlabs                                      │
   github .......: github.com/keithlinneman                                     │
   email ........: hello@linnemanlabs.com                                       │
┌───────────────────────────────────────────────────────────────────────────────┘
│
└───────────────────────────────────────────────────────────────────────────────
░▒▓██████████████████████████████████████████████████████████████████████████▓▒░
                          · LinnemanLabs · est. 199x ·                          
░▒▓██████████████████████████████████████████████████████████████████████████▓▒░

```
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
- GitHub: [linnemanlabs](https://github.com/linnemanlabs)
- Email: [hello@linnemanlabs.com](mailto:hello@linnemanlabs.com)