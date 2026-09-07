---
title: "About Me"
description: "Keith Linneman - security researcher and infrastructure engineer, building, breaking, and operating systems since the mid-90s. Linux vulnerability research, systems security, and production infrastructure."
---

{{< term >}}
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
   09:08:59 up 25+ years, load average: build, operate, attack                  │
                                                                                │
  $ file /etc/localtime                                                         │
  /etc/localtime: symbolic link to ../usr/share/zoneinfo/America/Los_Angeles    │
                                                                                │
  $ id                                                                          │
  uid=1001(k) gid=1005(ops) groups=1006(research),1007(blue-team),1008(red-team)│
                                                                                │
  $ history | tail -25 | head -24                                               │
   976 ./build infrastructure --aws --accounts_total=12 --node_count=200+       │
   977 ./build ansible --roles=20+ --zero-lint-failures --handwritten           │
   978 ./deploy observability --prometheus --loki --mimir --pyroscope --tempo   │
   979 ./build go-libraries --observability --instrumentation --http            │
   980 ./build ebpf-exporters --kernel-telemetry --prometheus                   │
   981 ./build pki --yubikey-root --intermediates=3 --p384 --tuf --cosign       │
   982 ./perform key-ceremony --air-gapped --tails --offline-root               │
   983 ./build kms-csr-tool --go --hardware-backed-signing                      │
   984 ./deploy sigstore --rekor --tesseract --tsa --fulcio                     │
   985 ./deploy spiffe-spire --workload-identity --every-service                │
   986 ./build trust.linnemanlabs.com                                           │
   987 ./build app-build-system --github --sigstore --keyless-signing --oidc    │
   988 ./deploy wazuh --agents=164 --ossec --osquery --yara --suricata          │
   989 ./build linnemanlabs.com                                                 │
   990 ./build vigil --alerts --llm-triage --notify=slack                       │
   991 ./build glimmer --c2 --beacon --raw-sockets --af_packet --dbus           │
   992 ./run purple-team-exercises --emulate=adversary --verify=detection       │
   993 ./migrate cloudformation --to=terraform --start=trust-account            │
   994 ./build switchboard --v1 --grpc --spiffe --runbook-proposal              │
   995 ./build hardened-workstation --ebpf --lsm --selinux --secure-boot        │
   996 ./audit linux --userspace --ipc --write_poc --cves=15 --projects=9       │
   997 ./disclose --vendor --coordinated --30days --writeup                     │
   998 ./escape confinement --selinux --apparmor --namespaces --sandbox         │
   999 ./exploit portable --rhel --ubuntu --debian --suse --fedora --mac-escape │
                                                                                │
  $ ps -u k                                                                     │
    PID  STAT  COMMAND                                                          │
   0001  R     switchboard --version=1                                          │
   0002  S     vigil --version=1 --deployed                                     │
   0003  S     improve-workstation --research --attack --harden --document      │
   0004  Z     audit --linux --user --ipc --write_exploit                       │
   0005  Z     escape-confinement --selinux --apparmor --namespaces --sandbox   │
   0006  R     document --cves --vulnerabilities --research --hardening         │
   0007  R     migrate --to-fedora --write-selinux-policies --systemd-hardening │
   0008  R     research --k8s --eBPF --LSM --MAC --MCS --bottlerocket           │
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
   > understand ....... learn and know every component under each abstraction   │
   > instrument ....... auditable, inspectable systems to inform decisions      │
   > detect ........... collect data, analyze, see what is actually happening   │
   > correlate ........ connect signals across layers, follow the entire flow   │
   > verify ........... prove the conclusion, end to end, in a real environment │
   > document ......... leave the trail for others, precision and depth are key │
                                                                                │
                   "every bit, every packet, every syscall."                    │
                                                                                │
┌───────────────────────────────────────────────────────────────────────────────┘
│
└─[ now playing ]───────────────────────────────────────────────────────────────┐
                                                                                │
   · vigil ........... AI alert triage engine (Go) .......... shipped           │
   · switchboard ..... AI orchestration platform (Go) ....... in progress       │
   · trust ........... sigstore + spire chain ............... phase 4 of 6      │
   · clauditor ....... eBPF audit daemon (AI agents) ........ planned           │
   · leash ........... eBPF LSM-based AI containment ........ planned           │
   · glimmer.......... adversary emulation, C2 framework .... in progress       │
   · vuln-research.... audit Linux userspace, ipc, devices .. in progress       │
   · prism............ detection engineering verifier ....... planned           │
                                                                                │
┌───────────────────────────────────────────────────────────────────────────────┘
│
└─[ stack ]─────────────────────────────────────────────────────────────────────┐
                                                                                │
   cloud ............. aws (us-east-2) · 200+ nodes · 12 accounts               │
   config ............ cloudformation -> terraform · ansible · handwritten      │
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
{{< /term >}}

## Keith Linneman

I've been doing this since the mid-90s - over 25 years of building, breaking, and operating systems. I started by breaking into them as a kid, living on IRC, learning how networks and operating systems actually worked by taking them apart. That offensive background shaped everything that came after. I moved into infrastructure and operations, bringing an attacker's perspective to how I design, harden, and monitor production systems. Now I'm back to my roots in offensive security with deep infrastructure and operations experience behind it.

I run LinnemanLabs as a working lab for security research and infrastructure engineering - documenting what I build and learn, and open-sourcing what I can.

The recent focus has been a several months-long audit of many Linux userspace daemons and libraries. This resulted in 15 CVEs issued so far across 9 separate projects with more disclosures ongoing. I [write and share exploits](https://github.com/linnemanlabs/advisories) for many as they come out of embargo. I went on to research [escaping SELinux confinement](/posts/confined-root-is-still-root) and documented 10+ methods from a compromised root daemon across the major distros.

Before this vulnerability research I was running a purple-team loop in the lab - building offensive tooling, exercising it against my own systems, writing the detection rules to catch it, then modifying my tooling to evade detection. I'm researching how production infrastructure (especially observability pipelines) can be subverted from within, and I'm building systems where security properties are cryptographically provable rather than assumed: a self-hosted Sigstore stack with hardware-rooted trust, dual-signing through keyless OIDC and KMS, and deploy-time verification. Integrating secure-boot, TPM, and IMA are areas I plan to explore next, with the end goal being cryptographic trust from silicon to running application.

Detection-coverage tooling that tests new techniques I develop and verifies "did we catch it?" as a continuous property across every SIEM and log backend, and deception environments realistic enough that malware behaves naturally rather than recognizing the lab are two areas I plan to push into next.

---

## Highlighted Research

- [nm-l2tp: Newline to Root](/posts/nm-l2tp-newline-to-root/): nm-l2tp local root vulnerability research, post-exploitation analysis, and SELinux/AppArmor confinement escapes. Wrote a portable exploit tested across nine distributions and a supporting IKE responder.

- [Confined Root is Still Root](/posts/confined-root-is-still-root/): SELinux and systemd confinement research. Discovered 10+ escape methods, tested across 6 distributions. 12 PoCs written.

- [Pi-hole: Root with Extra Steps](/posts/pi-hole-root-with-extra-steps/): Vulnerability research leading to 5 CVEs. 4 separate ways to turn a web session to code exec, 2 LPEs to root, 1 arbitrary file disclosure race. 6 PoCs written.

- [Hello, My Name is Orca](/posts/hello-my-name-is-orca/): Linux workstation D-Bus research, discovered unprivileged ability to keylog under Wayland through screenreader accessibility interface. PoC written. 

Selected CVEs:

| CVE              | Project             | Finding / impact                          | Links                     |
| ---------------- | ------------------- | ----------------------------------------- | ------------------------- |
| `CVE-2026-19624` | NetworkManager-l2tp | Newline injection -> root LPE             | [CVE](#) |
| `CVE-2026-44943` | open-iscsi          | Remote arbitrary file write as root       | [CVE](https://www.cve.org/CVERecord?id=CVE-2026-44943) |
| `CVE-2026-44944` | open-iscsi          | Local control-socket authorization bypass | [CVE](https://www.cve.org/CVERecord?id=CVE-2026-44944) |
| `CVE-2026-18724` | open-iscsi          | Stack buffer overflow                     | [CVE](https://access.redhat.com/security/cve/cve-2026-18724) |
| `CVE-2026-18725` | open-iscsi          | OOB read                                  | [CVE](https://access.redhat.com/security/cve/cve-2026-18725) |
| `CVE-2026-55995` | open-isns           | Double-free, DoS                          | [CVE](https://access.redhat.com/security/cve/cve-2026-55995) |
| `CVE-2026-84267` | gvfs                | Heap disclosure / ASLR defeat             | [CVE](https://access.redhat.com/security/cve/cve-2026-84267) |
| `CVE-2026-84268` | gvfs                | SFTP heap buffer overflow                 | [CVE](https://access.redhat.com/security/cve/cve-2026-84268) |
| `CVE-2026-74861` | fprintd             | System authentication bypass              | [CVE](#) |

## How I work

I trust what I can explain. If I can't reason about how something works, I won't trust it in production.

First principles over cargo culting. I understand the primitives end to end before I abstract or automate.

I'd rather understand one system completely than be passingly familiar with ten. Full-stack ownership means knowing how the system behaves from protocol to code to infrastructure to operations - not just the layer I'm responsible for on the org chart.

I prefer small, composable systems over big frameworks. When I learn a better model, I refactor and simplify rather than layering on complexity. I'd rather own fewer things well than accumulate technical debt across many.

I weave security through every component of systems I build rather than tack on a layer at the end. That means building guardrails into CI/CD, treating operability (telemetry, rollback, recovery) as a primary feature, and designing systems where the easy thing and the secure thing are the same thing.

These principles don't change with the artifact. Provenance, integrity, and verification matter whether what you're shipping is application code, a container image, an infrastructure definition, a configuration, a log event, an ML model, or firmware.

---

## Get in touch

Feel free to reach out with related research or questions/thoughts/opinions.

Always open to contracting opportunities and interesting work.

For the right problem, I go deep. 

- GitHub: [keithlinneman](https://github.com/keithlinneman)
- GitHub: [linnemanlabs](https://github.com/linnemanlabs)
- Email: [hello@linnemanlabs.com](mailto:hello@linnemanlabs.com)
