# SPDX-License-Identifier: BSD-3-Clause

# =========================
#  Toolchain configuration
# =========================
CC       ?= gcc
CLANG    ?= clang
BPFTOOL  ?= bpftool

CFLAGS      ?= -O2 -g -Wall
BPF_CFLAGS  ?= -O2 -g -target bpf

LIBS := -lbpf -lelf -lz

# =========================
#  Arch detection for BPF
# =========================
UNAME_M := $(shell uname -m)

ifeq ($(UNAME_M),x86_64)
  TARGET_ARCH := x86
else ifeq ($(UNAME_M),aarch64)
  TARGET_ARCH := arm64
else ifeq ($(UNAME_M),arm64)
  TARGET_ARCH := arm64
else ifeq ($(UNAME_M),armv7l)
  TARGET_ARCH := arm
else ifeq ($(UNAME_M),riscv64)
  TARGET_ARCH := riscv
else
  TARGET_ARCH := x86
endif

# =========================
#  Files
# =========================
VMLINUX     := vmlinux.h
BPF_OBJ     := rateLimiter.bpf.o
SKEL_HDR    := rateLimiter.skel.h
USER_BIN    := rateLimiter

# System / libbpf includes
SYS_INC  := -I/usr/include
BPF_INC  := -I/usr/include/bpf

# Clang's builtin search paths (for -target bpf)
CLANG_BPF_SYS_INCLUDES := $(shell $(CLANG) -v -E - </dev/null 2>&1 \
  | sed -n '/<...> search starts here:/,/End of search list./{ s| \(/.*\)|-idirafter \1|p }')

INCLUDES := -I. $(SYS_INC) $(BPF_INC)

# =========================
#  Default target
# =========================
all: $(USER_BIN)

# =========================
#  Build steps
# =========================

# 1) Generate vmlinux.h from kernel BTF
$(VMLINUX):
	@if ! command -v $(BPFTOOL) >/dev/null 2>&1; then \
		echo "ERROR: $(BPFTOOL) is not installed."; \
		exit 1; \
	fi
	( $(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@ ) || \
	( [ -r /boot/vmlinux-$$(uname -r) ] && $(BPFTOOL) btf dump file /boot/vmlinux-$$(uname -r) format c > $@ ) || \
	( echo "ERROR: Could not generate vmlinux.h (missing BTF)."; rm -f $@; exit 1 )

# 2) Compile BPF object
$(BPF_OBJ): rateLimiter.bpf.c $(VMLINUX)
	$(CLANG) $(BPF_CFLAGS) \
		-D__TARGET_ARCH_$(TARGET_ARCH) \
		$(INCLUDES) $(CLANG_BPF_SYS_INCLUDES) \
		-c $< -o $@

# 3) Generate libbpf skeleton header
$(SKEL_HDR): $(BPF_OBJ)
	@if ! command -v $(BPFTOOL) >/dev/null 2>&1; then \
		echo "ERROR: $(BPFTOOL) not found. Install it (e.g. sudo apt-get install bpftool)."; \
		exit 1; \
	fi
	$(BPFTOOL) gen skeleton $< > $@

# 4) Build user-space binary
$(USER_BIN): rateLimiter.c common_um.c common_um.h $(SKEL_HDR)
	$(CC) $(CFLAGS) -o $@ rateLimiter.c common_um.c $(LIBS)

# =========================
#  Convenience targets
# =========================
run: all
	sudo ./$(USER_BIN)

clean:
	rm -f $(BPF_OBJ) $(SKEL_HDR) $(USER_BIN) $(VMLINUX)

.PHONY: all clean run
