# SentinelAI M3B eBPF build (unprivileged: compiles and links only; nothing is loaded or attached).
#
# libbpf: the kernel-headers libbpf 1.4 archive, by explicit path. The system libbpf (0.5.0) cannot
# parse this kernel's BTF and is never used: no -lbpf, no pkg-config, and the build fails if the
# selected headers are not the expected 1.x version or if a linked binary needs a shared libbpf.

KREL        ?= 6.8.0-138-generic
LIBBPF_DIR  ?= /usr/src/linux-headers-$(KREL)/tools/bpf/resolve_btfids/libbpf
LIBBPF_A    ?= $(LIBBPF_DIR)/libbpf.a
LIBBPF_INC  ?= $(LIBBPF_DIR)/include
LIBBPF_EXPECT ?= 1.4
BPFTOOL     ?= /usr/lib/linux-hwe-6.8-tools-6.8.0-138/bpftool
CLANG       ?= /usr/bin/clang-14
LLVM_STRIP  ?= /usr/bin/llvm-strip-14
HOSTCC      ?= /usr/bin/gcc
VMLINUX_BTF ?= /sys/kernel/btf/vmlinux
BUILD       ?= build

HOST_LIBS   := $(LIBBPF_A) -lelf -lz
HOST_CFLAGS := -O2 -g -Wall -Wextra -Wno-unused-parameter -Werror -Iinclude -I$(BUILD) -I$(LIBBPF_INC)
BPF_CFLAGS  := -g -O2 -target bpf -D__TARGET_ARCH_x86 -Wall -Werror -Iinclude -I$(BUILD) -I$(LIBBPF_INC)

ifeq ($(filter clean,$(MAKECMDGOALS)),)
LIBBPF_MAJOR := $(shell sed -n 's/^\#define LIBBPF_MAJOR_VERSION \([0-9][0-9]*\)$$/\1/p' $(LIBBPF_INC)/bpf/libbpf_version.h 2>/dev/null)
LIBBPF_MINOR := $(shell sed -n 's/^\#define LIBBPF_MINOR_VERSION \([0-9][0-9]*\)$$/\1/p' $(LIBBPF_INC)/bpf/libbpf_version.h 2>/dev/null)
ifneq ($(LIBBPF_MAJOR).$(LIBBPF_MINOR),$(LIBBPF_EXPECT))
$(error libbpf headers at $(LIBBPF_INC) report '$(LIBBPF_MAJOR).$(LIBBPF_MINOR)', expected $(LIBBPF_EXPECT); refusing to build)
endif
ifeq ($(wildcard $(LIBBPF_A)),)
$(error libbpf archive $(LIBBPF_A) not found; refusing to fall back to the system libbpf)
endif
ifneq ($(findstring -lbpf,$(HOST_LIBS) $(LDFLAGS) $(LDLIBS)),)
$(error -lbpf must not be used: it resolves to the system libbpf 0.5.0)
endif
ifneq ($(findstring libbpf.so,$(HOST_LIBS) $(LDFLAGS) $(LDLIBS)),)
$(error a shared libbpf must not be linked: only the static 1.4 archive is allowed)
endif
endif

PROGS := $(BUILD)/sentinel_loader $(BUILD)/sentinel_replay

.PHONY: all clean core-check
all: $(BUILD)/sentinel.bpf.o $(BUILD)/sentinel.skel.h $(PROGS) core-check

$(BUILD):
	mkdir -p $@

$(BUILD)/vmlinux.h: $(VMLINUX_BTF) | $(BUILD)
	$(BPFTOOL) btf dump file $(VMLINUX_BTF) format c > $@.tmp && mv $@.tmp $@

$(BUILD)/sentinel.bpf.o: bpf/sentinel.bpf.c include/sentinel_shared.h include/sentinel_core.h $(BUILD)/vmlinux.h
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@.tmp
	$(LLVM_STRIP) -g $@.tmp
	mv $@.tmp $@

$(BUILD)/sentinel.skel.h: $(BUILD)/sentinel.bpf.o
	$(BPFTOOL) gen skeleton $< name sentinel_bpf > $@.tmp && mv $@.tmp $@

# Fails if a linked binary depends on any shared libbpf (it must carry the 1.4 archive statically).
define check_static_libbpf
	@if readelf -d $(1) | grep -q 'NEEDED.*libbpf'; then \
		echo "ERROR: $(1) needs a shared libbpf" >&2; rm -f $(1); exit 1; fi
endef

$(BUILD)/sentinel_loader: loader/sentinel_loader.c include/sentinel_host.h include/sentinel_shared.h $(BUILD)/sentinel.skel.h
	$(HOSTCC) $(HOST_CFLAGS) $< $(HOST_LIBS) -o $@
	$(call check_static_libbpf,$@)
	$(abspath $@) --version > /dev/null || { echo "ERROR: linked libbpf is not $(LIBBPF_EXPECT)" >&2; rm -f $@; exit 1; }

$(BUILD)/sentinel_replay: harness/sentinel_replay.c include/sentinel_host.h include/sentinel_shared.h include/sentinel_core.h | $(BUILD)
	$(HOSTCC) $(HOST_CFLAGS) $< $(HOST_LIBS) -o $@
	$(call check_static_libbpf,$@)

# CO-RE: every relocation of the object must resolve against the running kernel's BTF (offline,
# no bpf() syscall): bpftool computes the minimal BTF the relocations need.
core-check: $(BUILD)/sentinel.bpf.o
	$(BPFTOOL) gen min_core_btf $(VMLINUX_BTF) $(BUILD)/min_core.btf $(BUILD)/sentinel.bpf.o

clean:
	rm -rf $(BUILD)
