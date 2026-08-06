---
title: "Measuring the Blast Radius of a Root Daemon"
subtitle: "What root exec in a daemon actually buys you. Where SELinux, systemd, and DAC each draw the line."
date: '2026-07-20T00:00:00Z'
summary: "The real confinement of a root daemon is the intersection of SELinux policy, systemd sandboxing, Linux capabilities, and DAC."
tags: ["security", "offensive-security", "selinux", "systemd", "privilege-escalation", "dbus", "linux"]
channels: ["kernel"]
---

This is part 1 of a series on SELinux and systemd confinement.

| Article | Contents |
|---|---|
| [Measuring the Blast Radius of a Root Daemon](/posts/measuring-selinux-systemd-confinement/) | Measure the real constraints when getting root exec |
| [Confined Root Is Still Root](/posts/escaping-selinux-systemd-confinement) | Paths to escaping confinement |
| Hardening and Detection (coming soon) | Hardening and detection configurations |

You found a bug. Memory corruption in a daemon that runs as root - pick your poison: `bluetoothd`, `cupsd`, a `NetworkManager` plugin, the `fingerprint` daemon. You have code execution in that process. On a box with no Mandatory Access Control you are halfway there: root is root, see what you can influence from the systemd sandbox, maybe drop a setuid binary or a cron job and go home.

On an SELinux-enforcing Fedora, RHEL, or SUSE system, you are not finished. The daemon runs inside an SELinux domain along with the normal systemd sandbox. So the normal techniques are frequently prevented. Looking at bluetoothd for example:

| Technique | SELinux | systemd | DAC |
|---|---|---|---|
| setuid, self-promotion | no surviving transition (NNP-pruned) + no authorized setexec transition | NoNewPrivileges, bounding set caps child | - |
| setuid, other unpriv user | requires grant to exec bluetooth_t-created labels | PrivateTmp + ProtectHome + ProtectSystem (paths isolated/read-only, shared /run is nosuid) | - |
| write /etc/cron.d (system_cron_spool_t) | dir search denied | ProtectSystem=strict (EROFS) | would allow (root, 0755 dir) |
| write /var/spool/cron (user_cron_spool_t) | dir search/add_name denied (has file write, inert) | ProtectSystem=strict (EROFS) | dir 0700 root - would allow as root |
| write /usr, /var, /bin | bin_t/usr_t/var_t write denied | ProtectSystem=strict (EROFS) | would allow (root) |

So, the new question:

> **Does the exploit survive Enforcing? If it does, what does the code execution actually buy?**

I found several vulnerabilities that led to code execution in context of various root daemons over the past couple months. In terms of post-exploitation work, on Debian/Ubuntu systems that generally meant dealing with the systemd sandbox. AppArmor rarely came into play. On RHEL/Fedora family systems (also SUSE now) SELinux became a post-exploitation constraint every time. It only provided a hurdle on the path to exploitation in one instance.

Those specific code-exec bugs are still under embargo. These posts are about the process I used to escape SELinux and systemd confinement from various domains. This is all within documented SELinux / systemd / polkit design.

The most important takeaway is to measure the real confinement. The grants and capabilities are misleading at times in both directions.

## Pre-Exploitation

Most vulnerabilities survived unchanged. SELinux is an LSM: it enforces through handlers on the kernel's security hooks - inode access, execve, IPC, socket send/recv, capability checks. It never sees your control of %rip so the corruption and the control-flow hijack happen below its visibility. While SELinux may not impact ROP/JOP, it will see the execve when your gadget chain eventually reaches system()/execve() - if there is no execute on /bin/sh's type that exec is denied. The example in this post is not denied (bluetooth_t can exec base_ro_file_type), so a shell spawns, confined. Most often SELinux constrains what the delivered code can do rather than whether the bug fires. Sometimes there may be a payload it can't stage, no path to providing a crafted input, or an exec it can't run and it constrains the path in, too.

In one case SELinux was a hurdle. The lazy payload of dropping a file in `/dev/shm` and pointing the daemon at it gets denied. The same execution rewritten to use a system binary the domain is already allowed to run succeeds. In the example I encountered, changing the type from its default or getting an unconfined process to run `chcon` to a type the daemon can read also worked.

SELinux may require `process:execmem` for executable anonymous memory and certain writable private executable mappings. systemd adds a separate W^X-oriented control through `MemoryDenyWriteExecute`. In my recent exploitation work this rarely mattered since NX/DEP already blocks executing injected data and neither prevents control-flow reuse such as ROP or JOP, although they can constrain later payload staging.

## Post-Exploitation

The code runs, but in a confined domain instead of `unconfined_t`. The domain you land in decides the severity. Measuring which domain, and what it really holds, is the next step.

I'll assume familiarity with SELinux 101:
- processes run in a **domain**
- objects carry **types**
- an `allow` rule permits a `(domain, type, class, permission)` combination
- everything not explicitly permitted defaults to denied

## The Essentials

The four most important pieces to know.

**SELinux attributes are frequently where the real rules live.** Types are grouped into **attributes**, and `allow` rules are usually written against the attribute, not the type. `bluetooth_t` carries `domain`, `daemon`, `nsswitch_domain`, and more. nsswitch_domain has this rule:

```
allow nsswitch_domain dbusd_unconfined:dbus send_msg;
```

That grants permission to every one of the 540 domains carrying `nsswitch_domain`. `bluetooth_t` is included because it does NSS name lookups. Two consequences. Offensively, a lot of a domain's dangerous reach is inherited for unrelated reasons.

Unconfined dbus access arrives via at least two independent attributes (nsswitch_domain, system_bus_type), and the member list is a surprisingly long but mostly inert list. On my system only 10 distinct domains own a live system-bus name (34 names total) and will be explored in the next post.

`sesearch -A -s bluetooth_t` includes attribute-inherited rules, but prints them under the attribute name, not bluetooth_t. If you run sesearch and grep for source type you'll drop every attribute grant. Filter by target/class/perm instead. The grant you need may live on an attribute.

**A process changes domain in three ways, and `fork` is not one.** A domain changes only at `execve` triggering a `type_transition`, `execve` with explicit `setexeccon`, or `setcon`/`dyntransition` on a running process when policy allows. `fork`/`clone` never changes it: children inherit the parent's context. A subsequent execve only enters a new domain when an authorized transition applies. 

For the bluetooth_t process measured here, no usable transition survives - all execution remains in bluetooth_t. Every escape has to recruit some other, more-trusted process.

`execute_no_trans` is what permits a domain to run a binary while staying in its own domain. It doesn't block a transition - a transition happens only with the full configuration present (a type_transition default or an explicit setexeccon(), backed by execute, transition, and entrypoint). bluetooth_t has execute_no_trans on base_ro_file_type and no surviving transition anywhere, so every execve keeps it bluetooth_t.

**Policy is only the ceiling.** SELinux policy states the maximum a domain could be allowed. What a process can actually do is an intersection:

```
effective  =  SELinux policy  ∩  systemd sandbox and capabilities  ∩  DAC
```

SELinux grants state a maximum, and it is frequently a long list of irrelevant grants that come from attributes. Real capability is the intersection of policy, runtime activity, and the other enforcement layers, and every naive enumeration overstates reach until you measure that intersection.

**Under `NoNewPrivileges`, transitions need explicit permission to survive.** systemd sets `NoNewPrivileges=yes` on most hardened units. Under NNP the kernel refuses a domain transition at `execve` unless policy contains a `process2:nnp_transition` rule from the old type to the new or a policy relationship in which the target SID is bounded by the current SID. A `type_transition` can exist in policy and be dead at runtime because NNP won't honor it. This silently prunes a domain's transition graph.

## Measure the confinement

Find the domain your daemon runs in. I am using `bluetoothd` as an example in this article. It is a good example, because it is relatively hardened and the SELinux policy and its systemd unit disagree.

Ask the SELinux policy what capabilities `bluetooth_t` can hold:

```
# sesearch -A -s bluetooth_t -c capability
allow bluetooth_t bluetooth_t:capability
  { dac_read_search ipc_lock net_admin net_bind_service net_raw setpcap sys_admin sys_tty_config };
```

`CAP_SYS_ADMIN` and `CAP_DAC_READ_SEARCH` are both powerful and within the SELinux cap. But check the systemd unit:

```
# systemctl show bluetooth.service -p CapabilityBoundingSet,NoNewPrivileges
CapabilityBoundingSet=cap_net_bind_service cap_net_admin
NoNewPrivileges=yes
```

Confirm against the running bluetoothd process:
```
$ sudo cat /proc/<pid>/status
CapBnd:  0000000000001400
CapEff:  0000000000001400
NoNewPrivs: 1
Seccomp: 2
```

`0x1400` is only two capabilities: `cap_net_bind_service` and `cap_net_admin`. `sys_admin` and `dac_read_search` are not in the CapabilityBoundingSet and stripped by systemd. Reading `/etc/shadow` even as root is denied twice over: no `dac_read_search` or `dac_override` (DAC fails on chmod 000), and no `shadow_t:file read` in the policy either means SELinux wouldn't allow it anyway.

One more thing the live process shows that the config doesn't: `Seccomp: 2` is a real seccomp filter even though the unit sets no `SystemCallFilter`. It's installed by `RestrictRealtime=yes`. "No `SystemCallFilter`, no seccomp" is one more thing that's wrong if you read the config instead of the process. Measure the process.

## What Can You Reach

Once you know the domain and the capabilities it holds, map its reach with `sesearch -A -s bluetooth_t`. For `bluetooth_t` the reach is almost entirely attribute-driven. The four high-value dimensions:

### Execute

```
allow bluetooth_t base_ro_file_type:file { execute execute_no_trans map };
allow bluetooth_t pppd_exec_t:file { execute getattr ioctl map open read };
allow domain abrt_helper_exec_t:file { execute getattr ioctl map open read };
```

A broad set of ordinary system binaries whose types carry `base_ro_file_type`, including `bin_t` and `shell_exec_t`. But with `execute_no_trans`: the shell you spawn stays `bluetooth_t`.

### Transition out

There are only two `type_transition` options (`pppd_t`, `abrt_helper_t`), both to confined targets, and both dead at runtime under NoNewPrivileges. There is no outbound `nnp_transition` rule from `bluetooth_t` or authorized `setexec` or `dyntransition` paths. Under its real unit, no `execve` by `bluetooth_t` changes its domain. It cannot self-promote.

In a test policy with no applicable type-bounds relationship, I tested NNP on and off with `systemd-run`:

| nnp_transition | NoNewPrivileges | Result |
|---|---|---|
| absent | **yes** | exec **refused** - `status=203`, `avc: denied { nnp_transition } scontext=init_t tcontext=<test> permissive=0` |
| absent | no | runs in the target domain (no NNP -> no check) |
| **present** | **yes** | runs in the target domain |

Under NNP, a domain-changing execution requires either an applicable `process2:nnp_transition` permission or a `type-bounds` relationship in which the destination is bounded by the current domain. Neither condition applies here. In this test policy, denying the transition also prevented execution because the source domain had no usable non-transitioning execution path for the entrypoint. In other policies, SELinux may instead retain the old domain and permit execution through `execute_no_trans`.

This is significant: `pppd_exec_t` actually would provide a path out of confinement through a path I will cover later. NoNewPrivileges prevents the transition and walls it off.

### Relabel

None. No `relabelto`/`relabelfrom` for any type. It cannot forge a label.

### Write

Interesting conflicts between multiple layers here in more detail:

| Target | SELinux | systemd | DAC | Result |
|---|---|---|---|---|
| `/dev/shm/x` (`tmpfs_t`) | N | Y | Y | SELinux: denied {create} ...tmpfs_t... |
| `/`, `/usr`, `/var` | N | N | Y | EROFS (SELinux+ProtectSystem) |
| `/etc/cron.d/x` (`system_cron_spool_t`) | N | N | Y | EACCES (SELinux+ProtectSystem) |
| `/etc/bluetooth/x` | Y | Y | N | DAC - no write bit, no `dac_override` cap, SELinux prevents chmod |
| `/tmp/x` (PrivateTmp) | Y | Y | Y | allowed (isolated) |
| `/var/lib/bluetooth/x` | Y | Y | Y | allowed (systemd makes `StateDirectory` read-write) |
| `/run/x` (`bluetooth_var_run_t`) | Y | Y | Y | allowed (shared `rw,nosuid,nodev` mount, heavily SELinux isolated contents) |

This can get complex to keep track of at first. Even the daemon's own config directory `/etc/bluetooth/` takes many layers to untangle:
- `ProtectSystem=strict` would make /etc read-only - but `ConfigurationDirectory=bluetooth` carves /etc/bluetooth back out read-write, so the mount isn't the blocker.
- SELinux isn't either: a type_transition makes any file the daemon creates there a writable `bluetooth_conf_rw_t`, so policy fully permits the write - a fact you'd miss entirely by grepping the read-only bluetooth_conf_t grant the directory shows.
- What actually stops it is DAC: the directory is 0555, no write bit, no file gets created. Root owns the inode and could `chmod u+w` to fix that - except SELinux denies bluetooth_conf_t:dir setattr, killing the chmod. 

So for /etc/bluetooth/ the systemd sandbox would let the daemon write, SELinux would let the daemon write, DAC won't let it create, and SELinux won't let it escalate around DAC. Three layers, each permitting or denying a different step, and only the combination contains it.

In the end, its useful filesystem writes are limited to its private `/tmp`, `/var/lib/bluetooth/` through StateDirectory, and portions of `/run`. Surprisingly, `/run` remains a shared `rw,nosuid,nodev` tmpfs, with `/run/credentials` and `/run/user` made inaccessible. systemd removes several obvious uses, but SELinux and DAC determine which remaining paths and object types bluetooth_t can actually use.

### Escape

So `bluetooth_t` is in a pretty strict box. It runs programs as itself, writes only its own scratch, talks on the bus, and cannot change its own domain by any means available to it. It is sealed for its own threads.

Sealed for its own threads is not the same as sealed: you just have to find a path - a helper running in a broader domain or without a dedicated confined domain, or an unprivileged user holding a label that can bridge a gap. Recruiting those second actors is the whole of the next post about escaping SELinux and systemd confinement.

## Measure it yourself

All on stock Fedora 44, Enforcing.

View SELinux capability ceiling:

```bash
$ sesearch -A -s bluetooth_t -c capability
allow bluetooth_t bluetooth_t:capability { dac_read_search ipc_lock net_admin net_bind_service net_raw setpcap sys_admin sys_tty_config };
```

View the systemd capability set and NoNewPrivileges settings:

```bash
$ systemctl show bluetooth.service -p CapabilityBoundingSet,NoNewPrivileges
CapabilityBoundingSet=cap_net_bind_service cap_net_admin
NoNewPrivileges=yes
```

Find the PID of the daemon you want to inspect and read its real capabilities:

```bash
$ sudo pgrep bluetoothd
10553

$ sudo grep Cap /proc/10553/status
CapInh: 0000000000000000
CapPrm: 0000000000001400
CapEff: 0000000000001400
CapBnd: 0000000000001400
CapAmb: 0000000000000000
```

View all atributes belonging to the type:

```bash
$ seinfo -t bluetooth_t -x
Types: 1
   type bluetooth_t, corenet_unlabeled_type, daemon, domain, kernel_system_state_reader, netlabel_peer_type, nsswitch_domain, pcmcia_typeattr_1, syslog_client_type;
```

Enumerate the SELinux rules reachable from the source type:

```bash
$ sesearch -A -s bluetooth_t
allow bluetooth_t NetworkManager_t:dbus send_msg;
allow bluetooth_t alsa_var_lib_t:dir { getattr open search };
allow bluetooth_t alsa_var_lib_t:file { getattr ioctl lock open read };
... (snipped 515 lines)
```

Query the permission, not the type name. If you have a specific escape path in mind like an unconfined dbus service (covered in next post), to test its reachability:

```bash
$ sesearch -A -s bluetooth_t -c dbus -p send_msg | grep dbusd_unconfined
allow nsswitch_domain dbusd_unconfined:dbus send_msg;
```

`nsswitch_domain` is an attribute whose member domains inherit an SELinux rule permitting `send_msg` to targets carrying `dbusd_unconfined`. Map out the list of all domains that inherit that same reach:

```bash
$ seinfo -a nsswitch_domain -x

Type Attributes: 1
   attribute nsswitch_domain;
        NetworkManager_ssh_t
        NetworkManager_t
        abrt_helper_t
... ( snipped 537 lines )
```

SELinux permits each of those source domains to send D-Bus messages to dbusd_unconfined targets. Same as the rest of this post, that is the ceiling and starting point - you need to confirm that the bus policy, destination object, interface, method, or application-level authorization will accept a useful request.

On the opposite side, to list all the domains that carry the dbusd_unconfined attribute you can potentially reach now:

```bash
$ seinfo -a dbusd_unconfined -x

Type Attributes: 1
   attribute dbusd_unconfined;
        NetworkManager_dispatcher_custom_t
        abrt_handle_event_t
        anaconda_t
... ( snipped 89 lines )
```

Dig through the services, introspect their D-Bus services, find something that contributes to a chain you want to build.

Maybe you need to fetch a remote file because you are in a confined domain that cant create a filesystem image (that reference will make sense in post 2). Enumerate if you can connect out on TCP or UDP:

```bash
$ sesearch -A -s bluetooth_t -c tcp_socket,udp_socket -p connect
allow bluetooth_t bluetooth_t:tcp_socket { accept append bind connect create getattr getopt ioctl listen lock read setattr setopt shutdown write };
allow bluetooth_t bluetooth_t:udp_socket { append bind connect create getattr getopt ioctl lock read setattr setopt shutdown write };
```

You are halfway there and are allowed to connect both tcp and udp sockets, but can you actually connect to any ports?

```bash
$ sesearch -A -s bluetooth_t -c tcp_socket,udp_socket -p name_connect
allow nsswitch_domain dns_port_t:tcp_socket { name_connect recv_msg send_msg };
allow nsswitch_domain dnssec_port_t:tcp_socket name_connect;
... ( snipped 8 boolean-gated grants )
```

No UDP ports allowed, two tcp types allowed `dns_port_t` and `dnssec_port_t`. Enumerate exactly what ports are in those types:

```bash
$ sudo semanage port -l | grep -E "^(dns_port_t|dnssec_port_t).*tcp"
dns_port_t                     tcp      53, 853
dnssec_port_t                  tcp      8955
```

So all members of `nsswitch_domain` can connect out on tcp ports `53`, `853`, and `8955`. Host and network firewalls may separately block it but SELinux will not.

Can our domain directly transitionto any interesting domains:

```bash
$ sesearch -T -s bluetooth_t -c process
type_transition bluetooth_t abrt_helper_exec_t:process abrt_helper_t;
type_transition bluetooth_t pppd_exec_t:process pppd_t; 
```

If the service is confined with NoNewPrivileges, map out which transitions carry an explicit allow:

```bash
$ sesearch -A -s bluetooth_t -c process2 -p nnp_transition
$
```

```bash
$ seinfo --typebounds pppd_t
Typebounds: 0

$ seinfo --typebounds abrt_helper_t
Typebounds: 0
```

There is no applicable `nnp_transition` permission, and neither `pppd_t` nor `abrt_helper_t` is bounded by `bluetooth_t` - both transitions are denied under NNP.

Have a directory you want to write to? Find it's type, see if you have a grant or transition to it:

```bash
$ ls -dZ /run
system_u:object_r:var_run_t:s0 /run

$ sesearch -A -T -s bluetooth_t -t var_run_t -c dir -p search,write,add_name
allow bluetooth_t var_run_t:dir { add_name remove_name write };
allow domain base_file_type:dir { getattr open search };
allow nsswitch_domain pidfile:dir { getattr open search };

$ sesearch -A -T -s bluetooth_t -t var_run_t -c file
allow domain file_type:file map; [ domain_can_mmap_files ]:True
type_transition bluetooth_t var_run_t:file bluetooth_var_run_t;
```

Can a specific type (in this case init_t) read that file you just wrote?

```bash
$ sesearch -A -s init_t -t bluetooth_var_run_t -c file -p read
allow init_t pidfile:file { ioctl lock map open read unlink };
```

Who else can read that file you just wrote:
```bash
$ sesearch -A -t bluetooth_var_run_t -c file -p read
allow abrt_dump_oops_t non_security_file_type:file { append create getattr ioctl link lock map open read rename setattr unlink watch watch_reads write };
allow aide_t file_type:file { getattr ioctl lock map open read };
allow amanda_t file_type:file { getattr ioctl lock open read };
... (snipped 51 lines)
```

To confirm systemd `ConfigurationDirectory=bluetooth` mounted /etc/bluetooth `rw`:

```bash
$ sudo findmnt --task $(pgrep bluetoothd) /etc/bluetooth
TARGET         SOURCE                                  FSTYPE OPTIONS
/etc/bluetooth /dev/mapper/fedora-root[/etc/bluetooth] ext4   rw,relatime,seclabel
```

To enumerate read-write mounts of real filesystems from within bluetoothd namespace:

```bash
$ sudo findmnt --task $(pgrep bluetoothd) -O rw --real
TARGET                              SOURCE                                                                                                          FSTYPE OPTIONS
/var/lib/bluetooth                  /dev/mapper/fedora-root[/var/lib/bluetooth]                                                                     ext4   rw,relatime,seclabel
/var/tmp                            /dev/mapper/fedora-root[/var/tmp/systemd-private-1ad599cf4d25454b8adcfe93b78163d1-bluetooth.service-8hDKzy/tmp] ext4   rw,relatime,seclabel
/etc/bluetooth                      /dev/mapper/fedora-root[/etc/bluetooth]                                                                         ext4   rw,relatime,seclabel
```

Worth browsing the full list without the `--real` flag though, as that would miss the rw mounts of /run and /dev/shm for example:

```bash
$ sudo findmnt --task $(pgrep bluetoothd) /run
TARGET SOURCE FSTYPE OPTIONS
/run   tmpfs  tmpfs  rw,nosuid,nodev,seclabel,size=13150400k,nr_inodes=819200,mode=755,inode64
```

A writable mount is not necessarily an escalation path. It may still provide a rendezvous point for data, sockets, FIFOs, or files consumed by another domain. I explore those uses in the next post: [Confined Root Is Still Root](/posts/escaping-selinux-systemd-confinement).

## Testing Environment

The shown SELinux policy output and systemd environment I am working on in this post is:
- Fedora 44 Plasma
- Kernel 7.0.10-201.fc44
- systemd-259.6-1.fc44
- selinux-policy-44.1-1.fc44
- bluez-5.86-4.fc44

*This is part 1 in a series, the next post will explore the paths to escaping confinement.*