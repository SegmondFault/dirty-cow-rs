# Dirty COW Rust Implementation

A small Rust lab for exploring **Dirty COW / CVE-2016-5195** on an intentionally vulnerable Linux VM.

This is very much a **work in progress**. The code technically works, in the sense that it can trigger the Dirty COW write primitive on an old vulnerable Ubuntu box, but the project is currently at the fun/frustrating stage where the race is either:

- too aggressive, and risks getting properly *dirty* by corrupting the target system, or
- too cautious, and loses the race before anything useful happens.

In other words: this is not a polished exploit framework. This is a learning project, a controlled lab, and a slightly chaotic tour through copy-on-write behaviour, memory mappings and kernel race conditions.

## Project status

**WIP. Do not treat this as stable tooling.**

Current state:

- Rust implementation of Dirty COW-style write attempts.
- Static Linux builds using Docker + musl.
- Tested against an old Ubuntu 16.04-era VM.
- Demonstrated modification of `/etc/passwd` from an unprivileged user.
- Also demonstrated that doing that carelessly can break the box.
- Includes a repair payload, `dirtyfix`, because sometimes you get excited and break the vm before you back it up...

## Why this exists

The goal is to learn in the time tested manner of observing controlled destruction.

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

Friendly, controlled, and mildly cursed.

**Please don't run this on anything you care about.**

## Target environment

The lab target is an intentionally deprecated Linux VM.

Current expected setup:

```text
Ubuntu Server 16.04.1 amd64
Kernel around 4.4.0-era
QEMU / UTM x86_64 emulation
SSH forwarded from host port 2222 to guest port 22
