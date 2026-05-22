# Dirty COW Rust Implementation

A small Rust lab for exploring **Dirty COW / CVE-2016-5195** on an intentionally vulnerable Linux VM, with the usual amount of low-level Linux nonsense and a healthy respect for snapshots.

This is very much a **work in progress**. The code technically works, in the sense that it can trigger the Dirty COW write primitive on an old vulnerable Ubuntu box, but the project is currently at the fun/frustrating stage where the race is either:

- too aggressive, and risks getting properly *dirty* by corrupting the target system, or
- too cautious, and loses the race before anything useful happens.

In other words: this is not a polished exploit framework. This is a learning project, a controlled lab, and a slightly chaotic tour through copy-on-write behaviour, memory mappings, process memory, and kernel race conditions.

The runnable path is **`whynot`**. Most of the other Rust files are kept as archaeological evidence: useful traces of false starts, timing experiments, repair attempts, and "ah, so that is how `/etc/passwd` gets sad" moments.

## Project Status

**WIP. Do not treat this as stable tooling.**

Current state:

- Rust implementation of Dirty COW-style write attempts, with `whynot` as the current main demo.
- Older variants kept around as research notes in code form.
- Tested against an old Ubuntu 16.04-era VM.
- Demonstrated modification of `/etc/passwd` from an unprivileged user.
- Also demonstrated that doing that carelessly can break the box.
- Includes a tiny Python repair helper, because sometimes you get excited and break the VM before you back it up.

## Why This Exists

The goal is to learn in the time-tested manner of observing controlled destruction.

Dirty COW is a brilliant teaching bug because it sits at the intersection of:

- virtual memory
- copy-on-write semantics
- file-backed mappings
- process memory
- `/proc/self/mem`
- kernel race conditions
- Unix permissions
- privilege boundaries
- exploit reliability

It is a great way to understand how an OS can be logically correct in normal execution, but still fail under weird timing pressure.

The vibe of the project is:

> Hack the old box, break the old box, understand why it broke, fix the old box, repeat.

Friendly, controlled, and mildly cursed. The point is not to help anyone attack modern systems. Dirty COW is old, fixed, and mostly useful here as a beautiful little fossil of kernel behaviour under stress. The point is to show interest in low-level Linux internals and Rust systems programming, preferably without turning the VM into soup.

**Please don't run this on anything you care about.**

## Target Environment

The lab target is an intentionally deprecated Linux VM.

Current expected setup:

```text
Ubuntu Server 16.04.1 amd64
Kernel around 4.4.0-era
QEMU / UTM x86_64 emulation
SSH forwarded from host port 2222 to guest port 22
```

## Repository Map

The important bits:

- `src/whynot.rs` - current primary Rust demo.
- `restore_root_passwd.py` - emergency first-line `/etc/passwd` repair helper for the VM.
- `DirtyCowExecutionSteps.txt` - scratch execution notes that the README has now absorbed.
- `src/cow*.rs`, `src/rustetcpivot.rs`, `src/exploit.rs`, `src/whynotannoted.rs` - historical experiments and annotated variants.

Only `dirtycow` and `whynot` are registered as Cargo binaries. The older experiments are intentionally left out of the manifest so they can remain useful evidence without blocking the finished demo build.

Local runtime artifacts such as the VM image, compiled `whynot`, `.dSYM` bundles, and `target/` are intentionally ignored.

## Build

On the host:

```bash
cargo build --release --bin whynot
```

For the vulnerable x86_64 Linux VM, build or copy the `whynot` binary into the low-privilege user's home directory. The current lab notes assume `./whynot` and `restore_root_passwd.py` are already present there.

## Execution Runbook

Start the intentionally vulnerable VM:

```bash
qemu-system-x86_64 \
  -m 2048 \
  -smp 2 \
  -drive file=workingvm.qcow2,format=qcow2 \
  -netdev user,id=n1,hostfwd=tcp:127.0.0.1:2223-:22 \
  -device e1000,netdev=n1
```

Log in as the setup user:

```bash
ssh -p 2223 user1@127.0.0.1
```

Quickly prove the baseline:

```bash
whoami
uname -r
id lowpriv
groups lowpriv
sudo deluser lowpriv sudo
```

Switch to the low-privilege account and confirm it is boring, as all good demo victims should be:

```bash
su - lowpriv
whoami
id
groups
cat /etc/shadow
```

Run the current demo:

```bash
./whynot
su a
```

The demo user is `a` and the password is `a`. If the race lands cleanly, `whoami` and `id` should show UID 0 behaviour.

## Repair Step

The `whynot` flow temporarily replaces the first line of `/etc/passwd`. Restore it quickly after the proof. The old VM can panic if left in a bad state too long, so this is a "do it now, admire later" step.

```bash
sudo python3 restore_root_passwd.py
```

The script is intentionally tiny:

```python
from pathlib import Path

p = Path("/etc/passwd")
lines = p.read_text().splitlines()
lines[0] = "root:x:0:0:root:/root:/bin/bash"
p.write_text("\n".join(lines) + "\n")
```

Then sync and check:

```bash
sync
head -n 1 /etc/passwd
```

## Optional Persistence Demo

For a tidy classroom-style ending, promote `lowpriv`, then prove the change:

```bash
usermod -aG sudo lowpriv
su - lowpriv
sudo whoami
sudo cat /etc/shadow
```

To reset that part of the demo:

```bash
sudo deluser lowpriv sudo
```
