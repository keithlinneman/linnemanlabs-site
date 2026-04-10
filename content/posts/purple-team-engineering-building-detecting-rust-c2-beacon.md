---
date: '2026-04-09T00:00:00Z'
title: "Purple Team Engineering: Building and Detecting a Rust C2 Beacon"
summary: "Building an offensive tool and the detection rules to catch it. The architecture behind Glimmer's dual-layer encryption, binary hardening from 1.4MB to 388K, and real-time YARA detection through Wazuh."
tags: ["Purple Team", "Detection Engineering", "YARA", "Wazuh", "Rust", "C2", "Binary Analysis", "Offensive Security", "SIEM"]
categories: ["Security Research"]
---

[Glimmer](https://github.com/linnemanlabs/glimmer) is a C2 framework I'm building in Rust as a purple team research project. The goal isn't to create another red team tool - it's to build something real enough that writing detection rules against it teaches me things I can't learn from reading about other people's tools. Every design decision on the offensive side creates a detection surface. Every detection rule I write reveals what to harden next. This post covers the first round of that loop.

As I build out my security and observability infrastructure, I needed tooling to attack my own systems - both to test defenses and to understand the detection pipeline end-to-end. There's a gap in how most security engineers learn detection: studying attacker techniques from documentation, writing rules against theoretical patterns, and hoping they hold up. Without building the offensive side yourself, you're pattern-matching against descriptions rather than understanding the mechanics that produce the patterns. Not every threat is a piece of well-studied commodity malware sending obvious signatures.

## Why Rust

The initial prototype was Go. It worked with checkin, beacon, basic encryption, etc. But Go binaries carry the entire runtime and garbage collector. Even stripped, a minimal Go binary with crypto and networking starts around 3-4MB. The GC leaves memory access patterns that are fingerprintable, and the runtime embeds identifiable strings. For a tool where binary analysis resistance matters, Go gives away too much for free.

Rust compiles to native code with no runtime, no garbage collector, and gives you direct access to syscalls. The language's ownership model means memory is managed at compile time, not runtime - there's no GC pause pattern to fingerprint. And the binary size starts small and stays small if you're careful about dependencies.

## Architecture

Glimmer's crypto architecture uses dual-layer encryption for every beacon message.

The **outer layer** is time-based key derivation from a shared root secret. Both the beacon and server derive the same encryption key from the root secret plus the current time bucket. No key material is exchanged on the wire for routine beacons - both sides compute independently. This eliminates the EC point fingerprint that ECIES would leave on every message.

The **inner layer** is per-message ECIES - a fresh ephemeral ECDH keypair for every single message. The ephemeral private key exists in memory briefly before being consumed and zeroized. I haven't measured the lifetime yet, I will when I go deep on memory analysis. Only the server's private key can decrypt the inner layer.

The **bootstrap** phase establishes the root secret through a full ephemeral ECDH exchange during the initial checkin. The server's public key is baked into the beacon at build time. The root secret is derived from `SHA-256(server_pub_bytes || ECDH_shared_secret)`, which both sides compute identically from the same exchange.

The result: an analyst looking at network traffic sees the outer layer - time-encrypted blobs that change every time bucket. They can't see the inner ECIES layer, and even if they break the time-based key, each message has its own ephemeral encryption that requires the server's private key.

## Binary Hardening

This is where the purple team loop gets interesting. Every hardening step is motivated by running detection tools against my own binary and seeing what they find.

### The Starting Point

The first release build with `reqwest` (a popular Rust HTTP client) as the HTTP transport:

- **Binary size:** 1.4MB
- **Total strings:** 10,365
- **Unique strings:** 3,779

Running `strings` against it revealed everything: the project name, HTTP headers including `User-Agent` and `Cookie`, error messages describing exactly what the tool does (`"bootstrap complete, time-based key established"`), compiler versions, my home directory path, source file paths for every dependency, the full HTTP/2 protocol implementation from hyper, proxy configuration strings, TLS library internals, and hundreds of HTTP status codes and header names.

An analyst spending 30 seconds with `strings` would know: this is a Rust binary, it makes HTTP connections, it does ECDH key exchange, it beacons, it was compiled on this specific machine, and the developer's username is `k`.

### Removing reqwest

The single biggest win was replacing `reqwest` with a hand-built HTTP channel using raw TCP sockets. `reqwest` pulls in hyper, tower, h2, tokio, native-tls, url, http, httparse - a massive dependency tree where every crate contributes its own error messages, debug strings, and type names to the binary.

The replacement is ~80 lines of code that builds an HTTP request from byte slices and sends it over a raw socket. No async runtime, no HTTP/2, no proxy support, no TLS library - just the minimum needed to POST encrypted data to an endpoint.

Result after removing reqwest:
- **Binary size:** 464KB (67% reduction)
- **Total strings:** 3,128 (70% reduction)

### Build-Time String Encoding

Sensitive strings - HTTP headers, file paths, protocol elements - are encoded at compile time using rolling XOR with a multi-byte random key that changes every build. A `build.rs` script generates the encoded bytes and the key, which get compiled into the binary as opaque byte arrays. At runtime, strings are decoded only when needed and exist in memory only for the duration of their use before being deallocated by Rust's ownership system. Future hardening will zeroize these as early as possible.

This means `strings` finds nothing recognizable from the HTTP layer. No `POST`, no `Cookie`, no `Content-Type`, no `User-Agent`. Each build produces different encoded bytes, so a signature matching encoded strings from one build won't match the next.

### Compiler and Path Elimination

The Rust compiler embeds source file paths in panic messages. A standard release build contained my full home directory path, every dependency's path in `~/.cargo/registry`, and the rustc version with its git commit hash.

Using nightly Rust with `-Zlocation-detail=none` strips location info from panic messages. Adding `-Zbuild-std=std,panic_abort` rebuilds the standard library from source with the same flags, eliminating paths from stdlib panic messages too. Post-build, `objcopy` removes several ELF sections: `.comment` (GCC/rustc version strings), `.gnu.build.attributes` (annotated build metadata), `.note.gnu.build-id` (unique build identifier), and `.annobin.notes` (GCC annotation metadata).

### Raw Syscalls

The final step was replacing standard library networking with direct syscalls. Instead of Rust's `TcpStream` (which imports `socket`, `connect`, `send`, `recv` from libc), the beacon uses the generic `syscall` entry point for all network operations. The dynamic symbol table no longer shows any network-specific imports - an analyst examining the import table sees standard libc functions but nothing indicating network capability. I am still using libc getaddrinfo(), will write our own resolver soon.

### Final State

After all hardening passes:

- **Binary size:** 388KB
- **Total strings:** ~3,000 (all from dependencies)
- **Identifying strings from our code:** Zero
- **Home directory paths:** Zero
- **Compiler version strings:** Zero
- **Network function imports:** Zero (`socket`, `connect`, `send`, `recv` all absent)
- **Dynamic libraries:** `libc.so.6`, `libgcc_s.so.1`, `libm.so.6`

Running `strings` and grepping for glimmer, beacon, cookie, mozilla, user-agent, localhost, server, endpoint, decrypt, encrypt, rustc, gcc, or the home directory produces no results. Everything remaining is dependency noise - serde's JSON parser errors, crypto crate type names, getrandom's platform-specific messages - that any Rust binary with crypto would contain.

## Detection Engineering

Now to put on the defender hat and try to catch it.

### YARA Rules

I wrote five YARA rules at different confidence levels, each targeting a different aspect of the binary:

**`glimmer_crypto_profile`** (medium confidence) - Matches the combination of P-256 ECDH and AES-GCM string artifacts (`Pkcs8`, `PointEncoding`, `StreamCipherError`) in a small ELF binary. Catches any Rust binary using this specific crypto stack.

**`glimmer_syscall_pattern`** (medium-high confidence) — Matches a binary that imports `syscall` but does NOT import `socket` or `connect`, combined with Rust standard library artifacts. The absence of network-specific imports in a binary that has the generic `syscall` entry point suggests either raw syscall networking or non-network syscall usage. Combined with other indicators, it's a useful signal though on its own it would require additional context like observed network connections to confirm network capability.

**`glimmer_serde_config`** (low confidence) - Matches serde's `struct Config` error messages combined with crypto artifacts in a small binary. Broad but useful as a triage signal.

**`glimmer_stripped_rust_implant`** (high confidence) - The tightest rule. Combines: small ELF (100-500KB) + crypto strings + `syscall` import + no `socket`/`connect` imports + the mysterious `GLTR` string that appears from somewhere in the dependency tree. Extremely specific to this binary's profile.

**`glimmer_high_entropy_small_elf`** (low confidence) - Generic entropy check. Catches any small binary with high rodata entropy, which includes legitimate tools.

### False Positive Testing

Testing against system binaries:

| Binary | crypto_profile | syscall_pattern | serde_config | stripped_implant | high_entropy |
|--------|:---:|:---:|:---:|:---:|:---:|
| Glimmer beacon | x | x | x | x | x |
| curl | | | | | x |
| ssh | | | | | |
| git | | | | | |
| ls | | | | | x |
| python3 | | | | | |
| vim | | | | | |
| systemctl | | | | | x |

The four specific rules have zero false positives across all tested system binaries (tested against every binary in /bin /usr/bin, etc, table above is a summary). Only the generic entropy rule triggers on curl, ls, and systemctl - expected, since that rule is intentionally broad. The `glimmer_stripped_rust_implant` rule is production-deployable: highly specific, zero false positives.

These are designed specifically for testing against Glimmer. What I learn here will inform Yara rules I run across my environment to catch other tools using patterns I identify.

### Wazuh Integration

The YARA rules are deployed through Wazuh's active response pipeline. The detection chain:

1. **File Integrity Monitoring** detects a new or modified binary in a monitored directory (realtime inotify)
2. **Active Response** triggers automatically on the FIM alert
3. **YARA scan** runs against the detected file using all five rules
4. **Alert** fires at level 12 (high severity) in Wazuh with the matching rule names
5. **Dashboard** shows the alert with full context - agent, file path, rule matched, timestamp

{{< imgmodal src="/img/security/glimmer-wazuh-yara-syscall-networking.png" alt="Wazuh Dashboard showing YARA alert" mode="shrink" caption="Wazuh Dashboard showing YARA alert for Glimmer" >}}

This runs automatically with zero analyst intervention. A binary matching the Glimmer profile lands on any monitored system, and within seconds five YARA alerts fire in the SIEM. The entire pipeline - from file creation to indexed alert - takes under 10 seconds.

## Behavioral Analysis

Static detection is one layer. The behavioral profile reveals more.

### strace

Tracing the beacon's syscalls shows its operational fingerprint:

```
openat(AT_FDCWD, "config.json", O_RDONLY|O_CLOEXEC)
openat(AT_FDCWD, "/etc/hostname", O_RDONLY)
openat(AT_FDCWD, "/etc/machine-id", O_RDONLY)
socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)
connect(3, {sa_family=AF_INET, sin_port=htons(8080)...})
setsockopt(3, SOL_SOCKET, SO_RCVTIMEO_OLD, ...)
[repeats: socket → connect → setsockopt]
```

The file access pattern - config file, hostname, machine-id, then network connections - is unremarkable. Those files are read by hundreds of normal applications. Earlier versions read `/proc/cpuinfo`, `/proc/version`, and `/sys/block/dm-0/dm/uuid` for identity generation, which was a much more distinctive and suspicious pattern. Switching to hostname + machine-id eliminated that behavioral fingerprint. The config will be built into the binary soon as well.

### Network Timing

Beacon intervals use an exponential distribution rather than fixed intervals with linear jitter. Most beacons land between 30-50% and 200% of the configured base interval, with occasional long-tail gaps at 3-5x the base. This produces a timing pattern that's statistically consistent with event-driven application traffic rather than timer-driven polling.

With uniform jitter, a histogram of beacon intervals shows a clear rectangular distribution centered on the base interval - trivially identifiable as periodic with jitter. With exponential distribution, the histogram shows a decay curve that's harder to distinguish from legitimate traffic patterns without significantly more samples.


### Syscall Networking

Glimmer intentionally uses syscalls for all networking to bypass anything hooking or monitoring libc network functions. This is a unique fingerprint in itself, inspecting the binary doesn't show it linking to any libc networking libraries, so if it goes on to make any network connections they are from direct syscalls.

I added an auditd rule to log all syscalls for `connect`:
```
sudo auditctl -a always,exit -F arch=b64 -S connect -k network_connect
```

Combining these audit events with the YARA rules from earlier that flag binaries that are not linked against libc networking libraries, I can look for any binary making network connections through direct syscalls.

OpenSearch query:
```
GET wazuh-alerts-*/_search
{
  "size": 0,
  "query": {
    "bool": {
      "must": [
        {"terms": {"rule.id": ["100102", "100103", "100104", "100105", "100106", "100200"]}},
        {"range": {"timestamp": {"gte": "now-7d"}}}
      ]
    }
  },
  "aggs": {
    "by_binary": {
      "terms": {
        "script": "doc.containsKey('data.yara.file') && doc['data.yara.file'].size() > 0 ? doc['data.yara.file'].value : (doc.containsKey('data.audit.exe') && doc['data.audit.exe'].size() > 0 ? doc['data.audit.exe'].value : 'unknown')",
        "size": 50
      },
      "aggs": {
        "detections": {
          "terms": {
            "field": "rule.id",
            "size": 20
          },
          "aggs": {
            "rule_name": {
              "terms": {
                "field": "rule.description",
                "size": 1
              }
            }
          }
        },
        "severity": {
          "terms": {
            "field": "data.yara.severity",
            "size": 5
          }
        },
        "sha256": {
          "terms": {
            "field": "data.yara.sha256",
            "size": 1
          }
        },
        "has_yara_syscall": {
          "filter": {"term": {"rule.id": "100102"}}
        },
        "has_auditd_connect": {
          "filter": {"term": {"rule.id": "100200"}}
        },
        "has_both": {
          "bucket_selector": {
            "buckets_path": {
              "yara": "has_yara_syscall._count",
              "audit": "has_auditd_connect._count"
            },
            "script": "params.yara > 0 && params.audit > 0"
          }
        }
      }
    }
  }
}
```

Our Glimmer binary was flagged by YARA and then went on to make outbound network connections. This would be a high severity alert to dig into. From here, I would send the alert to [Vigil](https://github.com/linnemanlabs/vigil) and let it query Wazuh and our Observability tools for a deeper investigation. In the future, I will have a 'trusted-runner' ebpf program that will expose methods for Vigil to proactively block the execution of that hash in our environment, terminate running instances of it, etc.

{{< imgmodal src="/img/security/glimmer-wazuh-yara-correlation-query.png" alt="Wazuh Dashboard correlating YARA and auditd events" mode="shrink" caption="Wazuh Dashboard correlating YARA and auditd events" >}}


### What's Still Detectable

The HTTP channel has several fingerprintable characteristics that detection rules can target:

- **No User-Agent header** - extremely unusual for legitimate HTTP traffic
- **Bare server response** - `HTTP/1.1 200 OK` with only `Content-Length`, no `Date` or `Server` headers
- **POST body format** - 8 hex characters followed by base64, a very specific pattern
- **Same destination, same path** - every beacon is `POST /` to the same host:port
- **Connection: close** on every request - most modern HTTP clients use keep-alive

A Suricata rule matching `POST` with no `User-Agent` and a cookie containing `sid=` would catch every beacon with near-zero false positives. These network-layer signatures are the focus of the next hardening round.

The DNS query still uses libc and follows normal system resolvers.

The kernel and any eBPF programs/LSM hooks/auditd/etc see all syscalls and network activity with full accurate headers/encrypted payload available.

Upstream network monitoring will see full connection packet flows.

## What's Next

The first purple team loop is complete: build, detect, analyze. The next round focuses on the detection surfaces that remain:

**Network evasion** - fixing the HTTP fingerprint, adding TLS, implementing channel rotation. The beacon should be able to communicate through multiple channels (HTTP, DNS, process proxying) and rotate between them to break timing correlation.

**Process architecture evasion** — the current correlation query works because one binary does everything. YARA flags it for static indicators, auditd catches it making network connections, and the join is trivial. A more sophisticated architecture would separate concerns with a coordinator binary holding crypto state and tasking logic that never touches the network, spawning ephemeral worker processes that make a single connection and exit. YARA would still flag the coordinator, auditd sees the worker make a connection, but they're different binaries with different PIDs and no obvious link. Defeating this would require tracking process lineage to connect parent PPIDs to child PIDs across the detection sources. Even that breaks down when the coordinator uses techniques like `memfd_create` to execute workers from memory without ever writing to disk, bypassing FIM and YARA entirely.

**Network steganography** - encoding data in TCP initial sequence numbers, timing channels, and other protocol fields that aren't typically logged or inspected. These are low-bandwidth but nearly invisible to standard network monitoring.

**Deeper detection** - deploying Suricata for network-level detection, Zeek for traffic analysis, and auditd rules for kernel-level syscall monitoring. Auditd is particularly interesting because it operates at the kernel boundary - there's no userspace evasion for it. The beacon's raw syscalls are visible to auditd regardless of how they're invoked.

**The direct syscall detection rule** - a concept I want to implement with eBPF: correlating libc `connect()` calls with raw `sys_enter_connect` events. A process that makes connect syscalls without hitting libc's connect wrapper is almost certainly doing raw syscall networking - a strong signal of offensive tooling. Very few legitimate applications would trigger this. I considered having Glimmer link against libc networking libraries specifically to avoid flagging the YARA rule marking binaries that don't link them but then go on to open network connections. This would be a good way to catch that scenario.

**Anti-Debugger** - Glimmer is currently trivial to attach a debugger and step through to interesting places. Similarly trivial to trace.

The code is open source on [GitHub](https://github.com/linnemanlabs/glimmer). This is a research tool for authorized security testing - see the repository for the full legal disclaimer and usage policy.

*This is part 1 of an ongoing series. Part 2 will cover network evasion, process architecture evasion, steganography channels, and the detection rules to catch them.*
