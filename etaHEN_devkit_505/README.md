# PS4 3.55-5.07 Kernel Exploit
---
## Summary
In this project you will find a full implementation of the second "bpf" kernel exploit for the PlayStation 4 on <=5.07.
It will allow you to run arbitrary code as kernel, to allow jailbreaking and kernel-level modifications to the system.

## Exploits
- webkit: 
- kernel: BPF Double Free exploit by qwertyoruiopz

## Patches included
The following patches are applied in the kernel ROP chain:
1) Disable kernel write protection
2) Allow RWX (read-write-execute) memory mapping
3) Syscall instruction allowed anywhere
4) Dynamic Resolving (`sys_dynlib_dlsym`) allowed from any process
4) Custom system call #11 (`kexec()`) to execute arbitrary code in kernel mode
5) Allow unprivileged users to call `setuid(0)` successfully. Works as a status check, and doubles as a privilege escalation.

## Payloads included
1) PS4HEN (Homebrew ENabler): default
2) Mira: removed
3) Kdumper: optional
4) Update unblocker: optional

## Notes


## Contributors
Massive credits to the following:

- [qwertyoruiopz](https://twitter.com/qwertyoruiopz)
- [Cryptogenic](https://twitter.com/SpecterDev) aka Specter
- [Flatz](https://twitter.com/flat_z)
- [CelesteBlue-dev](https://twitter.com/CelesteBlue123)
- [Vortex](https://github.com/xvortex)
- to be continued
- [OpenOrbis Team](https://github.com/OpenOrbis/)
- Anonymous
