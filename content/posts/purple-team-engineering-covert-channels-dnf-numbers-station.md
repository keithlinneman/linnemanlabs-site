---
date: '2026-04-13T00:00:00Z'
title: "Purple Team Engineering: Covert Channels and the DNF Numbers Station"
summary: "Building a C2 channel indistinguishable from package manager traffic, encoding tasking in Apache ETag microseconds, and surveying the surprising state of repository security on Fedora."
tags: ["Purple Team", "Detection Engineering", "YARA", "Wazuh", "Suricata", "Rust", "C2", "Covert Channels", "DNF", "Offensive Security", "Glimmer", "SIEM"]
categories: ["Security Research"]
---

In the [first post](/posts/purple-team-engineering-building-detecting-rust-c2-beacon/) I built Glimmer as a simple HTTP POST beacon and wrote detection rules to catch it. Four independent detection layers - file integrity monitoring, YARA static analysis, auditd syscall monitoring, and Suricata network inspection - all converged on the same binary. Every detection rule I wrote revealed what to harden next. This post covers the second round of that loop: building stealthier channels and more sophisticated detection.

## Auditing My Own Attack Surface

Before building new channels, I needed to understand what network paths already existed on my workstation. I run [OpenSnitch](https://github.com/evilsocket/opensnitch) and manually approve every outbound connection with narrow conditions. Reviewing my approved rules revealed several interesting opportunities.

OpenSnitch uses eBPF to correlate DNS query results with connection IPs. When I approve "/usr/sbin/dnf5 can connect to mirrors.fedoraproject.org on 443," OpenSnitch captures the DNS resolution and maps those IPs to the hostname. Any connection to those IPs from dnf5 is allowed. This is powerful but it also means DNS poisoning could potentially map a legitimate hostname to an attacker-controlled IP, and OpenSnitch would approve the connection because it believes the IP belongs to the approved domain.

**dnf5** stood out immediately. I had gotten tired of approving an ever-rotating list of >300 mirror hostnames and allowed it to connect to any host on ports 80 and 443. Alert fatigue lately feels like the attacker's best friend more than any specific technical vulnerability.

Several other approved rules caught my attention for future research: 
 - AWS SDK calls to various `*.amazonaws.com` endpoints, resulting in the python binary being approved to connect to various *.amazonaws.com endpoints that an attacker can use to reach external accounts.
 - SSH access to github.com (high bandwidth, likely no TLS inspection in upstream networks)
 - Various development tools connecting to CDN-hosted services
 - Claude Code connects to `storage.googleapis.com` at startup, `ingest.us.sentry.io` for error reporting, and `http-intake-logs.us5.datadoghq.com` for telemetry - all generic hostnames that could carry exfiltrated data to attacker-controlled accounts on those same platforms. Sentry and Datadog are common in many environments in general.
 - Go's module proxy (`proxy.golang.org`) is particularly interesting - requesting a non-existent module version causes Google's proxy to fetch from the source repository, potentially allowing an attacker to relay data through Google's infrastructure by encoding it in module paths and version strings.

Each one is a potential channel worth exploring in future posts.

But DNF was the first interesting target. Package manager traffic is expected on every Linux system. It's periodic, goes to external hosts, downloads data, and nobody questions it. If my beacon's traffic IS package manager traffic, the defender has to prove it's NOT legitimate, which is much harder than proving something is suspicious.

## Hardening Round 2

### HTTP Fingerprint Improvements

The first post identified several obvious fingerprints in the HTTP channel. In this round I addressed the most glaring ones.

The beacon now sends realistic browser headers - `User-Agent` matching Chrome, `Accept`, `Accept-Language`, `Accept-Encoding` - all XOR-encoded at build time and decoded only at the moment of use. The server response includes `Date`, `Server: nginx/1.24.0`, `Content-Type`, and a random `X-Request-Id` matching what a real nginx deployment would return.

The POST body format changed from raw `{hex}{base64}` to `data={base64}&token={hex}` - a standard form submission that looks like a data payload with a CSRF token.

What remains detectable: the static session cookie (`sid=` with the same 16-character hex value on every request), `Connection: close` instead of keep-alive, no `Referer` header, and the empty response body. The Suricata rules from post 1 already catch several of these patterns.

This was only intended as an initial basic/testing channel to get things working, this will be replaced entirely as we develop more channels.

### Anti-Debug

I implemented three anti-debug checks that run before config loading and before each beacon cycle. They are well-known methods I won't bother going into detail on here, checking if the process is being traced through a couple of means and doing a timing check on some math functions to try to catch step debugging. This will be re-visited with more creative approaches.

## Detection Infrastructure

### Structured YARA Alerting

I rebuilt the YARA detection pipeline to use structured JSON output. The YARA scan script now writes results to a dedicated `/var/ossec/logs/yara.log` as single-line JSON:

```json
{"timestamp":"2026-04-10T00:21:06-04:00","yara":{"rule":"glimmer_stripped_rust_implant","file":"/path/to/beacon","sha256":"81b823163dc2...","confidence":"high","severity":"critical","mitre_attack_id":"T1027,T1106","mitre_technique":"Obfuscated Files or Information, Native API"}}
```

Wazuh's built-in JSON decoder parses these automatically into `data.yara.*` fields in OpenSearch. Each YARA rule maps to a Wazuh rule ID with appropriate severity, the high-confidence implant detection fires at level 14, the generic entropy check at level 6. The Suricata integration from post 1 was extended with per-signature severity levels in Wazuh, giving each detection rule an appropriate alert priority.

## The DNF Channel

### Reconnaissance

I began by profiling exactly what legitimate DNF traffic looks like. Running `strace` and `tcpdump` during a `dnf check-update` revealed the complete request flow.

DNF's HTTP requests are minimal:
```
GET /repodata/repomd.xml HTTP/1.1
Host: mirror.example.com
User-Agent: libdnf (Fedora Linux 42; kde; Linux.x86_64)
Accept: */*
Cache-Control: no-cache
Pragma: no-cache
Connection: keep-alive
```

Five basic headers with no cookies, no encoded parameters, no authentication tokens, no fields that would reasonably vary or be unpredictable. The User-Agent identifies the OS, desktop environment, and architecture. The request path follows a standard structure: `repomd.xml` first, then the specific metadata files it references.

The mirror response varies by server software, but the CloudFront-hosted Fedora mirror returns:
```
HTTP/1.1 200 OK
Server: Apache
Content-Type: text/xml
ETag: "1142-6325677dd2cca"
Last-Modified: Wed, 09 Apr 2025 11:06:59 GMT
X-Fedora-AppServer: dl03.rdu3.fedoraproject.org
```

Standard Apache response with a content-type-appropriate MIME type, an (sort-of) opaque ETag, and Fedora-specific headers. This is the traffic profile my channel needs to match exactly.

I also profiled PackageKit, the system service that triggers daily repository checks on desktop Fedora. Examining `journalctl` output revealed PackageKit starts at 06:56 daily, triggered via D-Bus from the desktop session - on KDE Plasma, Discover (the app store) sends a `RefreshCache` call to the PackageKit D-Bus interface. It runs as root but the session authorization comes from the desktop user session via polkit. It spawns `packagekit-dnf-refresh-repo` which reads repos from `/etc/yum.repos.d/` and uses a separate cache at `/var/cache/PackageKit/42/metadata/`. Running `strace` against this binary revealed every file it touches - including several user-writable configuration paths that don't exist by default (`~/.config/rpm/`, `~/.rpmmacros`) and an interesting override directory: `/etc/dnf/repos.override.d/`.

### Apache ETag Microsecond Discovery

Apache generates ETags in the format `"{content_size_hex}-{mtime_hex}"` where `mtime_hex` is the file's modification time in **microseconds** since epoch. The `Last-Modified` response header contains the same timestamp but truncated to **seconds**.

This creates a verification gap. A defender examining the response can confirm that the ETag's seconds component matches `Last-Modified`. But the sub-second microsecond portion - up to 999,999 possible values, approximately 20 bits - cannot be verified from the response alone. Confirming it would require fetching the same file from a different mirror and comparing microsecond values. But different mirrors sync at different times, run different server configurations, and produce naturally different sub-second values. Cross-mirror comparison would have massive false positive rates (probably 100%).

I encode tasking into these microseconds. Both the server and beacon derive a 20-bit key mask from `SHA-256(root_secret || "dnf-etag-key" || last_modified_epoch)`. The server XORs the tasking payload with this mask and stores the result in the file's mtime microseconds using `utimensat()`. Apache generates the ETag from the real file metadata, no Apache modification needed. The server is just a normal Apache file server that happens to have specific microsecond timestamps on its files.

The beacon reads the `Last-Modified` header, derives the same key mask, extracts the microsecond portion from the ETag, and XORs to recover the tasking. If decryption produces a valid task code, it's tasking for this node. If it produces garbage, it's either for a different node or there's no tasking.

The ETag isn't the only controllable field. Apache's `AppTime: D=1175` header reports request processing time in microseconds - a value the server controls entirely. This provides approximately 13 additional bits of encoding space that nobody monitors or correlates with ETags. Combined with the microsecond encoding, that's roughly 33 bits per response across two independent fields. I haven't implemented `AppTime` encoding yet but the surface is available.

### Filesystem Timestamp Manipulation

The encoding doesn't require modifying Apache or any web server software. The server sets the file's mtime to a specific microsecond value using `utimensat()` - a standard POSIX syscall for setting file timestamps with nanosecond precision. Apache reads the file's real metadata and generates a standard ETag. The tasking lives entirely in filesystem metadata that Apache accurately serves.

This enables other interesting but niche opportunities. An attacker could use this for inter-process or inter-server communications in a relatively stealthy manner. In my case I control the Apache server, but if this was an attacker wanting to communicate within my environment to other beacons on other nodes, and I was running an Apache server, they could do exactly what I am doing here - alter the microsecond timestamps on legitimate files and my Apache would happily generate an ETag that carries signals for other beacons. The web server operator, the CDN, the network monitoring - none of them are compromised or modified.

This represents a broader class of covert channel. Any system that stores timestamps with sub-second precision but only validates or displays at seconds precision has potential encoding space. File modification times on ext4 use nanosecond precision. How many tools like FIM compare beyond seconds? How many IDS rules inspect sub-second timestamp components? The number of tools looking that deep gets smaller at each precision level, and the earlier they stop the more bits become available.

One of the detections for this would be watching for modified/changed timestamp updates without corresponding changes to the file's sha256sum. This may have a high false positive rate though - for example I frequently hit ctrl+o in nano (ESC :w for you vim fans, sorry emacs fans - I don't know your keybinds) without having changed anything and that would likely trigger this. There are probably system processes touching timestamps without updating content in a similar manner, something to test soon.

### The Numbers Station

This architecture is a numbers station - the server broadcasts to everyone, only the intended recipient can decode the message. Additionally, only the intended recipient can detect that the server is acting as a numbers station. We are using normal microseconds and letting Apache produce accurate, verifiable ETags that match the Last-Modified header in its normal manner.

The beacon never identifies itself through the DNF channel. No cookies, no encoded headers, no node ID. It makes a completely vanilla GET request identical to what every Fedora system sends when checking for updates. The server's response is the same for every client - CDN-cached, served identically to legitimate DNF clients, security scanners, and beacons alike.

The check-in happens over a separate HTTP POST channel that establishes the shared time-based key. After that, the DNF channel is receive-only: the beacon polls, the server broadcasts, encryption handles addressing. This channel is designed for stealth, not high-bandwidth or 'proof-of-life' from the beacon.

For tasking, 20 bits provides an 8-bit task code (256 possible tasks) and 12 bits of arguments (4096 possible values). A codebook maps argument values to predefined parameters - file paths, network ranges, configuration options, etc. More complex tasking that exceeds 20 bits requires switching to a higher-bandwidth channel, which is itself a task that can be delivered through the DNF channel.

The server only updates the ETag when the underlying content actually changes - matching a real mirror's behavior. When a repo sync script updates the mirror content, the server checks its task queue, encodes the next pending task into the file's microsecond mtime, and the ETag legitimately changes because the content changed. The file date and ETag are entirely legitimate and match what happened organically from the sync script with the exception of the microseconds adjustment. Between updates, the ETag is stable. No anomalous per-request variation. Very difficult to detect.

**Scaling constraints:** With 20 bits of encoding space shared across a single file, multi-node deployments require care - the server pre-validates proposed encodings against all known node keys before applying them to avoid cross-node collisions. At larger scales, each node would be assigned a different repodata file, matching DNF's real behavior of fetching multiple metadata files per update check. This is a research and testing tool, not an operational botnet - the single-file approach is appropriate for its intended use case, and the multi-file design is straightforward to implement for anyone who needs it.

### Three Operating Modes

The DNF channel has three distinct operating modes with different tradeoffs.

**Beacon direct connection** - the Glimmer binary makes the HTTP request itself, mimicking DNF's exact headers. The beacon sees the full HTTP response including the ETag, giving it access to the microsecond-encoded tasking. This mode provides the strongest integrity guarantees - the beacon can validate tasking against an 8-bit check value derived from the shared secret, rejecting random or cross-node decodes with 255/256 probability. The tradeoff: the process making the request is an unknown binary, not dnf5. Any process-based monitoring (EDR, OpenSnitch) would flag this immediately. The traffic is perfect but the process is wrong.

**Passive via dnf5/PackageKit** - the legitimate dnf5 binary or PackageKit makes the connection through normal system operations. The beacon never touches the network for this channel. Instead, it reads the cached `repomd.xml` from `/var/cache/PackageKit/` or `/var/cache/libdnf5/` after the system service fetches it. The tradeoff: the ETag is not cached on disk - dnf5 discards HTTP response headers after processing. The beacon can only access the XML content, not the headers. Tasking must be encoded in the XML itself (such as the `<revision>` field) rather than the ETag microseconds. This provides more encoding space but sacrifices the ETag's unverifiability - the revision field is part of the file content and would differ from the legitimate mirror's revision if compared directly. Additionally, not all servers use Apache's mtime-based ETag format - Brave's repo is hosted on S3, which generates ETags as MD5 hashes of file content with no microsecond component to manipulate. The microsecond technique is specific to Apache and servers with similar mtime-based ETag implementations, which is another reason the passive mode uses the revision field instead.

**Beacon-invoked dnf5** - the beacon executes the real dnf5 binary with `--repofrompath=name,url`, forcing it to check against the controlled mirror. The process making the network connection is the legitimate, signed dnf5 binary - not the beacon. No root required, no files written to `/etc`, no FIM alert. When invoked as a normal user, dnf5 writes the cached metadata to `~/.cache/libdnf5/` rather than the system cache - entirely within the user's home directory. The beacon reads the cached `repomd.xml` with the encoded revision field from there. This bridges the two modes: the right process makes the connection, the beacon controls which mirror it contacts, and no persistent configuration changes or elevated privileges are needed.

If you were to create a separate repo instead of mimicking the official Fedora mirror, the repo's package metadata itself also becomes additional encoding surface - package names, version strings, and descriptions are all cached locally and can carry arbitrary data.

This also opens an interesting angle with official mirrors. Some Fedora mirrors serve over http, some over https - this isn't inherently insecure due to metalink checksums, but it means you could submit your server as an official http mirror while hosting an entirely separate repo on the https port for tasking. If a security analyst sees the user-level repo config and researches the domain, they find a legitimate Fedora mirror listed on the official mirror list. You would have to notice that the official mirror listing shows http, compare against the user-level config using https, and investigate further.

The first two modes are implemented. The beacon defaults to direct connection for testing, with the passive mode designed for production deployment where process fingerprinting is a concern.

### On the Wire

The request from the beacon:
```
GET /pub/fedora/linux/updates/42/Everything/x86_64/os/repodata/repomd.xml HTTP/1.1
Host: 127.0.0.1
User-Agent: libdnf (Fedora Linux 42; kde; Linux.x86_64)
Accept: */*
Cache-Control: no-cache
Pragma: no-cache
Connection: keep-alive
```

The response from the server:
```
HTTP/1.1 200 OK
Content-Type: text/xml
Server: Apache
ETag: "1142-64f35c4e030a8"
Last-Modified: Sat, 11 Apr 2026 21:16:55 GMT
X-Fedora-AppServer: dl03.rdu3.fedoraproject.org
Strict-Transport-Security: max-age=31536000; preload
X-Content-Type-Options: nosniff
```

The tasking is hiding in `64f35c4e030a8` - specifically in the last few digits that contain microseconds. The response body is the current, valid `repomd.xml` that any repository parser could consume and will verify to the same checksum. Compare with the real CloudFront Fedora mirror:

```
Real:   ETag: "1142-6325677dd2cca"
Ours:   ETag: "1142-64f35c4e030a8"
```

Same format, same size hex prefix, different mtime. This is exactly what you'd expect from two different mirrors that synced at different times.

### CloudFront Mirror Impersonation

The Fedora metalink lists over 300 mirrors including `d2lzkl7pfhq30w.cloudfront.net`, an official Fedora mirror hosted on AWS CloudFront. CloudFront distributions use opaque `d2xxx.cloudfront.net` hostnames. A second CloudFront distribution serving identical Fedora content is indistinguishable from the first.

Behind CloudFront, the origin controls all response headers. The `X-Fedora-AppServer: dl03.rdu3.fedoraproject.org` header in my response is a claim that cannot be verified/disproven through the CDN. CloudFront adds its own headers (`x-cache`, `via`, `x-amz-cf-pop`) which my distribution also has - because it IS a real CloudFront distribution.

The CDN actively helps the attacker in many ways. From the defender perspective, CloudFront is very opaque and companies frequently rotate to new CloudFront domains. CloudFront caches the response. Multiple requests from different IPs get the same cached ETag. There is no way for a network observer to determine which request came from a beacon versus a legitimate client versus a CDN cache probe. The request is byte-for-byte identical to real DNF traffic because it IS real DNF traffic, just to a different mirror.

Taking this further - Fedora's mirror application process is open and straightforward. Anyone can apply to host an official mirror, sync the content with `dnf reposync`, serve it behind CloudFront with Apache, and appear in the official metalink as a legitimate mirror. At that point there is nothing to distinguish your mirror from any other - it IS an official mirror, serving verified content with valid checksums, that happens to have specific microsecond timestamps on its files. The metalink checksums validate `repomd.xml` and file content, not its filesystem metadata, certainly not its microsecond mtime. 

Alternatively, since you control the server, you aren't limited to Apache's ETag format. A custom HTTP server could include additional response headers with more encoding space - a longer ETag, custom headers that blend with CDN noise, or fields that serve as cryptographic checksums for the microsecond-encoded tasking. Apache's format is the stealthiest because it's indistinguishable from the real Fedora mirror, but the tradeoff between stealth and bandwidth is a tunable, and all of the mirrors use different software today.

### Repository Security Survey

As part of the channel research, I surveyed the verification posture of every enabled repository on my Fedora workstation. The results were surprising.

**Metalink usage** - only Fedora's own repos and RPM Fusion use metalink, which provides mirror lists with SHA-256 checksums for `repomd.xml`. Third-party repos use plain `baseurl` with no external checksum verification. They are relying on the TLS protections that come with the https request for repomd.xml.

**Repodata verification** - of twelve enabled repos, only **Tailscale** enables `repo_gpgcheck` (GPG signature verification on repository metadata). Every other repo - Hashicorp, Brave, Trivy, VS Code, and Wazuh - disables it.

**Package verification** - most repos at least verify GPG signatures on individual packages. The exception: **Slack** disables both `repo_gpgcheck` AND `gpgcheck`. Slack distributes unsigned packages through an unsigned repository hosted by a 3rd party under the 3rd parties' domain. A MITM on Slack's package delivery, or a compromise of their hosting provider, would allow distributing arbitrary code to every Slack user on Fedora with zero cryptographic verification.

This matters for the DNF channel because repos without metalink can be redirected via `repos.override.d` - a configuration directory specifically designed for admin customization of repository settings. A single file in this directory can change an existing repo's `baseurl` to point at my mirror. The repo name stays the same in all logging. No new repository appears.

Even without persistent file writes, `dnf5 --repofrompath=name,url` creates a temporary repository from the command line with no configuration on disk, no FIM alert, and no root required. It's non-persistent - the repo exists only for that invocation - but for a one-time fetch it leaves no trace.

**Brave Browser's repo** is particularly interesting: it's hosted on S3 behind CloudFront (`brave-browser-rpm-release.s3.brave.com` is a CNAME for `d27m38e0qdi7wl.cloudfront.net`), doesn't use metalink, and doesn't verify repodata. A CloudFront distribution serving mirrored Brave packages with a modified `repomd.xml` revision field would be accepted without question.

Tailscale deserves recognition for being the only third-party repo doing this correctly. Someone there cared enough about supply chain security and was given the time to implement GPG verification on repository metadata. It is noticed and appreciated.

### What's Still Detectable

The DNF channel has real detection surfaces:

**Process fingerprinting** - the beacon binary making DNF-like requests is immediately suspicious to any process-based monitoring (EDR, OpenSnitch). The traffic is perfect but the process isn't dnf5. This is the primary weakness and the focus of the next round.

**New CloudFront hostname** - a previously unseen `d2xxx.cloudfront.net` hostname appearing in DNS queries could trigger baseline analysis alerts. However, CloudFront hostnames are opaque and new distributions appear constantly.

**ETag microsecond analysis** - a defender who specifically knows about this technique could compare ETag microseconds across mirrors for the same file. Since mirrors don't actually sync the mtime from the source, no two mirrors will have matching ETags. Even if they did, this would require fetching the same content from a known-good mirror and comparing sub-second values from the decoded mtime_hex - a detection nobody currently implements but which would be straightforward to build. Simpler to just directly compare ETags in that example.

**repos.override.d file** - FIM would catch a new file in this directory. However, the directory is designed for admin configuration changes, making the alert low-priority in most environments. The specific change is the setting of BaseURL=d2xxx.cloudfront.net.

**Cross-source correlation** - correlating the beacon's HTTP POST check-in (which establishes the shared key) with the subsequent DNF channel polling could reveal the relationship. This requires connecting two different traffic patterns from the same host to two different hosts across different time windows - exactly the kind of analysis that would be automated in a detection engine like another tool I am working on, [Vigil](https://github.com/linnemanlabs/vigil).

## Hardening My Own Environment

This research prompted immediate changes to my own workstation:

- **DNF mirror pinning** - out of >300 Fedora mirrors, there's no guarantee none are doing this today. I'm restricting my system to a handful of mirrors I've verified.
- **Slack repo removed** - with zero cryptographic verification on both repodata and packages, I'm not comfortable running it. If Slack won't verify their own packages, I'll install updates manually from their website where I can at least verify checksums.
- **GitHub SSH rule removed** - replaced with HTTPS-only access through a TLS inspection proxy. SSH to GitHub is too useful as a high-bandwidth exfiltration channel to leave open and too easy as a tasking/beaconing channel given apps like vscode are often configured to sync with remotes on a scheduled, frequent basis.
- **DNF5 OpenSnitch rule tightened** - replacing the "any host on 80/443" rule with explicit mirror hostnames. The alert fatigue that led to the broad rule is exactly the weakness this channel exploits.

## What's Next

The DNF channel's primary weakness is that the beacon process itself makes the requests. The next round focuses on having trusted system processes do the fetching instead.

**PackageKit integration** - PackageKit already runs daily to check for updates, making connections to every enabled repo. If the beacon can read the cached response rather than making its own request, it never touches the network for this channel. The cached `repomd.xml` in `/var/cache/PackageKit/` contains the revision field - the beacon just reads a local file.

**iptables/nftables DNAT** - silently redirecting connections from a trusted process to the beacon's server. The process thinks it's connecting to the real mirror. auditd logs a connection to the real mirror IP, OpenSnitch thinks it's connecting to the real mirror IP. Only the kernel's netfilter (and our beacon) knows the truth. This may be less noisy than it seems at first, I will research how heavily monitored the `setsockopt` calls are by common security tools and if they specifically log/alert on `IPT_SO_SET_REPLACE` or monitor NAT entries.

**Browser-based channels** - Chrome and Firefox are whitelisted for broad network access on most workstations. A tracking pixel, a JavaScript analytics call, or a WebSocket connection from the browser's context is indistinguishable from user browsing because it IS the browser making the request.

**Additional channel types** - SSH to GitHub (high bandwidth up and down, no TLS inspection), DNS (classic but heavily monitored), TCP ISN steganography (ultra-low-bandwidth for initial check-in).

**Fedora captive portal check** - every Fedora desktop periodically sends `GET /static/hotspot.txt` to `fedoraproject.org` on port 80, receiving a 2-byte `OK` response. The response headers on this plain HTTP request are available for signaling - another low-bandwidth channel hiding in expected system traffic.

**Process architecture evasion** - separating the beacon into coordinator and worker processes so that YARA flags one binary, auditd catches another, and the correlation query that ties them together requires process lineage tracking across detection sources.

**Detection rules for this round** - writing Suricata, Zeek, and Wazuh rules that would catch the techniques in this post, then iterating. The ETag microsecond detection in particular is an interesting engineering challenge.

The code is open source on [GitHub](https://github.com/linnemanlabs/glimmer). This is a research tool for authorized security testing - see the repository for the full legal disclaimer and usage policy.

This work is certainly increasing the number of 'content warnings' I am receiving in my e-mail daily from different unamused vendors, so part 3 may be "coming soon" for a while as I revisit other projects like [Switchboard](https://github.com/linnemanlabs/switchboard). This is why we can't have nice (secure) things.

*This is part 2 of an ongoing series. Part 3 will cover process execution evasion, browser-based channels, the GitHub ssh channel, the AWS SDK channel, and deeper detection engineering with Zeek traffic analysis.*
