# Bad BPF
A collection of malicious eBPF programs that make use of eBPF's ability to
read and write user data in between the usermode program and the kernel.

- [Overview](#Overview)
- [To Build](#Build)
- [To Run](#Run)
- [Availible Programs](#Programs)


# Overview
See my [blog](https://blog.tofile.dev/2021/08/01/bad-bpf.html) and my [DEF CON talk](https://defcon.org/html/defcon-29/dc-29-speakers.html#path) for an overview on how thee programs work and why this is interesting.

Examples have been tested on:
- Ubuntu 22.04

# Build
To use pre-build binaries, grab them from the [Releases](https://github.com/pathtofile/bad-bpf/releases) page.

To build from source, do the following:

## Dependecies
To build and run all the examples, you will need a Linux kernel version of at least [4.7](https://github.com/iovisor/bcc/blob/master/docs/kernel-versions.md).

As this code makes use of CO-RE, it requires a recent version of Linux that has BTF Type information.
See [these notes in the libbpf README](https://github.com/libbpf/libbpf/tree/master#bpf-co-re-compile-once--run-everywhere)
for more information. For example Ubuntu requries `Ubuntu 20.10`+.

To build it requires these dependecies:
- zlib
- libelf
- libbfd
- clang and llvm **14**
- make

On Ubuntu these can be installed by
```bash
sudo apt install build-essential clang-14 llvm-14 libelf1 libelf-dev zlib1g-dev libbfd-dev libcap-dev linux-tools-common linux-tools-generic
```

## Build
To Build from source, recusivly clone the respository the run `make` in the `src` directory to build:
```bash
# --recursive is needed to also get the libbpf source
git clone --recursive https://github.com/pathtofile/bad-bpf.git
cd bad-bpf/src
make
```
The binaries will built into `bad-bpf/src/`. If you encounter issues with related to `vmlinux.h`,
try remaking the file for your specific kernel and distribution:
```bash
cd bad-bpf/tools
./bpftool btf dump file /sys/kernel/btf/vmlinux format c > ../vmlinux/<arch>/vmlinux.h
```

# Run
To run, launch each program as `root`. Every program has a `--help` option
that has required arguemnts and examples.

# Programs
## Common Arguments
As well as `--help`, every program also has a `--target-ppid`/`-t`.
This option restricts the programs' operation to only programs that are children
of the process matching this PID. This demonstrates to how affect some programs, but not others.


- [Bad BPF](#bad-bpf)
- [Overview](#overview)
- [Build](#build)
  - [Dependecies](#dependecies)
  - [Build](#build-1)
- [Run](#run)
- [Programs](#programs)
  - [Common Arguments](#common-arguments)
  - [Pid-Hide](#pid-hide)
  - [Sudo-Add](#sudo-add)

## Pid-Hide
```
sudo ./pidhide --pid-to-hide 2222
```
This program hides the process matching this pid from tools such as `ps`.

It works by hooking the `getdents64` syscall, as `ps` works by looking for every sub-folder
of `/proc/`. PidHide unlinks the folder matching the PID, so `ps` only sees the folders before
and after it.


## Sudo-Add
```
sudo ./sudoadd --username lowpriv-user
```
This program allows a normally low-privledged user to use `sudo` to become root.

It works by intercepting `sudo`'s reading of the `/etc/sudoers` file, and overwriting the first line
with `<username> ALL=(ALL:ALL) NOPASSWD:ALL #`. This tricks sudo into thinking the user is allowed to become
root. Other programs such as `cat` or `sudoedit` are unnafected, so to those programs the file is unchanged
and the user does not have those privliges. The `#` at the end of the line ensures the rest of the line
is trated as a comment, so it doesn't currup the file's logic.
