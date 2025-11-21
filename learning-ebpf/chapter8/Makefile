ARCH = $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')

BPF_OBJ = ${TARGET:=.bpf.o}

all: $(TARGET) $(BPF_OBJ)
.PHONY: all
.PHONY: $(TARGET)

$(TARGET): $(BPF_OBJ)
	bpftool net detach xdp dev lo
	rm -f /sys/fs/bpf/$(TARGET)
	bpftool prog load $(BPF_OBJ) /sys/fs/bpf/$(TARGET)
	bpftool net attach xdp pinned /sys/fs/bpf/$(TARGET) dev lo

$(BPF_OBJ): %.o: %.c vmlinux.h
	clang \
		-target bpf \
		-D __BPF_TRACING__ \
		-I/usr/include/$(shell uname -m)-linux-gnu \
		-I/usr/src/linux-headers-6.8.0-41-generic/tools/bpf/resolve_btfids/libbpf/include \
		-Wall \
		-O2 -o $@ -c $<

vmlinux.h:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

	- tc filter delete dev docker0 parent ffff:

clean:
	- sudo bpftool net detach xdp dev lo || true
	- sudo bpftool net detach xdp dev docker0 || true
	- sudo rm -f /sys/fs/bpf/$(TARGET) || true
	- rm -f $(BPF_OBJ) || true
	- sudo tc filter delete dev docker0 parent ffff: || true


