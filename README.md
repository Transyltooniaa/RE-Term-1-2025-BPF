# RE Term 1 (2025) — eBPF Case Studies

Case-studies implementation of **eBPF (extended Berkeley Packet Filter)** for a Reading Elective (RE) term project.  
This repository is organized as a small collection of hands-on eBPF projects and learning materials, primarily in **C** (with small portions of Rust/Shell/Makefile).

> **Repository:** `Transyltooniaa/RE-Term-1-2025-BPF`  
> **Focus:** eBPF programs (kernel space) + user-space loaders/tools (libbpf/bpftool workflows)

---

## Table of Contents

- [What’s Inside](#whats-inside)
- [Prerequisites](#prerequisites)
- [Quick Start (General)](#quick-start-general)
- [Projects / Case Studies](#projects--case-studies)
  - [`rateLimitter/` — TC-based IPv4 Rate Limiter](#ratelimitter--tc-based-ipv4-rate-limiter)
  - [`bad-bpf/` — “Bad BPF” examples (security research)](#bad-bpf--bad-bpf-examples-security-research)
  - [`learning-ebpf/` — Learning eBPF (book companion)](#learning-ebpf--learning-ebpf-book-companion)
- [Common eBPF Debugging Tips](#common-ebpf-debugging-tips)
- [Safety & Ethics Notice](#safety--ethics-notice)
- [Credits / References](#credits--references)
- [License](#license)

---

## What’s Inside

At the repository root you’ll find three main directories:

- **`rateLimitter/`** — an eBPF **Traffic Control (TC) ingress** program implementing a **per-source IPv4 token-bucket rate limiter**, plus a userspace loader that attaches it to an interface and prints events.
- **`bad-bpf/`** — a collection of security-focused examples demonstrating how eBPF can be abused to interfere with user/kernel boundaries (intended for research/education).
- **`learning-ebpf/`** — learning materials and example code that accompany the *Learning eBPF* book.

---

## Prerequisites

These projects require a Linux environment with working eBPF support.

### OS / Kernel
- Linux with eBPF enabled (`CONFIG_BPF=y`)
- For CO-RE style builds, a kernel with **BTF** available (commonly: `/sys/kernel/btf/vmlinux`)
- Root access (or the required capabilities like `CAP_BPF`, `CAP_NET_ADMIN` depending on the example)

### Common tools
Typically needed (varies per folder/example):
- `clang` / `llvm`
- `make`, `gcc`
- `bpftool`
- `libbpf` headers / dev package (or bundled submodule depending on project)
- `libelf`, `zlib`

On Ubuntu/Debian you’ll often need packages similar to:
```bash
sudo apt-get update
sudo apt-get install -y clang llvm gcc make \
  libbpf-dev libelf-dev zlib1g-dev \
  linux-tools-common linux-tools-generic linux-tools-$(uname -r)
```

---

## Quick Start (General)

1. Clone the repository:
   ```bash
   git clone https://github.com/Transyltooniaa/RE-Term-1-2025-BPF.git
   cd RE-Term-1-2025-BPF
   ```

2. Pick a project directory (recommended start: `rateLimitter/`), read its README, then build/run from inside that folder.

---

## Projects / Case Studies

### `rateLimitter/` — TC-based IPv4 Rate Limiter

**Goal:** Demonstrate a high-performance kernel-level rate limiter using **eBPF attached to TC ingress**, implementing a **token bucket** per source IPv4.

**Key ideas covered:**
- TC ingress attach point
- eBPF maps for per-IP state (`hash map`)
- ring buffer (kernel → userspace events)
- libbpf “skeleton” workflow

**Typical workflow (inside the directory):**
```bash
cd rateLimitter
make clean
make
sudo ./rateLimiter --help || true
sudo ./rateLimiter
```

**Notes:**
- You must choose the correct interface (e.g., `eth0`, `ens33`, `wlan0`).  
  Use:
  ```bash
  ip link show
  ```
- If attachment fails due to an existing filter/program, you may need to detach/remove TC filters first:
  ```bash
  sudo tc filter show dev eth0 ingress
  sudo tc filter del dev eth0 ingress
  ```

> The `rateLimitter/README.md` already contains a deep, project-specific explanation (architecture, Makefile breakdown, troubleshooting). Use it as the authoritative guide for that case study.

---

### `bad-bpf/` — “Bad BPF” examples (security research)

**Goal:** Demonstrate how eBPF can be used in **malicious** or **security-relevant** ways (e.g., hiding processes, tampering with data paths), for educational purposes.

**Important:** These examples are powerful and can be harmful if misused. Use only in controlled environments (VM/lab).

**Typical workflow:**
- Read `bad-bpf/README.md`
- Build according to that project’s instructions
- Run as root and test in a safe environment

---

### `learning-ebpf/` — Learning eBPF (book companion)

This folder mirrors example code and setup guidance related to the *Learning eBPF* book.  
It is useful as:
- a reference set of eBPF patterns and examples
- a structured learning path (organized by chapters/topics)

Follow `learning-ebpf/README.md` for installation and dependencies, and consider using a VM environment if you’re not already on Linux.

---

## Common eBPF Debugging Tips

Useful commands while developing/running these examples:

### Check BTF availability
```bash
ls -lh /sys/kernel/btf/vmlinux
```

### Inspect verifier / kernel messages
```bash
sudo dmesg | tail -50
```

### View loaded BPF programs / maps
```bash
sudo bpftool prog show
sudo bpftool map show
sudo bpftool net show
```

### Trace output (when programs write to tracing)
```bash
sudo cat /sys/kernel/debug/tracing/trace_pipe
# or
sudo bpftool prog tracelog
```

---

## Safety & Ethics Notice

This repository includes materials that may relate to **security research** (notably `bad-bpf/`).  
Only run these programs:
- on systems you own or have explicit permission to test
- in isolated lab environments (VMs, test hosts)
- with full understanding of the impact (e.g., TC/XDP programs affect networking; malicious examples can impact system integrity)

---

## Credits / References

- eBPF official site: https://ebpf.io/
- libbpf: https://github.com/libbpf/libbpf
- bpftool: https://github.com/libbpf/bpftool
- *Learning eBPF* (Liz Rice): https://www.oreilly.com/library/view/learning-ebpf/9781098135119/

---

## License

This repo appears to contain multiple subprojects that may have **different licenses** (or license notices inside source files).  
Before redistributing or using commercially, review each directory’s license headers/README and upstream sources.

---

## Contributing

If this is a course/research repo, contributions can include:
- adding new case studies (XDP, LSM, tracing, uprobes)
- improving build scripts and reproducibility (Dockerfile/VM config)
- adding reports/notes for each case study (methodology + results)
- documenting kernel/version compatibility

Open a GitHub issue or PR with a clear description of the change and how it was tested.
