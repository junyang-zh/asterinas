# SPDX-License-Identifier: MPL-2.0

BINARY_CACHE_DIR := /opt/linux_binary_cache
VDSO_DIR := ../target
VDSO_LIB := $(VDSO_DIR)/vdso64.so
MKFILE_PATH := $(abspath $(lastword $(MAKEFILE_LIST)))
CUR_DIR := $(patsubst %/,%,$(dir $(MKFILE_PATH)))
ATOMIC_WGET := $(CUR_DIR)/../tools/atomic_wget.sh
BUILD_DIR := $(CUR_DIR)/build
INITRAMFS := $(BUILD_DIR)/initramfs
INITRAMFS_FILELIST := $(BUILD_DIR)/initramfs.filelist
INITRAMFS_SKIP_GZIP ?= 0
ifeq ($(INITRAMFS_SKIP_GZIP),1)
INITRAMFS_IMAGE := $(BUILD_DIR)/initramfs.cpio
else
INITRAMFS_IMAGE := $(BUILD_DIR)/initramfs.cpio.gz
endif
EXT2_IMAGE := $(BUILD_DIR)/ext2.img
EXFAT_IMAGE := $(BUILD_DIR)/exfat.img
BENCH_DATA_IMAGE := $(BUILD_DIR)/bench_data.img
INITRAMFS_EMPTY_DIRS := \
	$(INITRAMFS)/root \
	$(INITRAMFS)/tmp \
	$(INITRAMFS)/opt \
	$(INITRAMFS)/proc \
	$(INITRAMFS)/dev \
	$(INITRAMFS)/ext2 \
	$(INITRAMFS)/exfat
INITRAMFS_ALL_DIRS := \
	$(INITRAMFS)/etc \
	$(INITRAMFS)/lib/x86_64-linux-gnu \
	$(INITRAMFS)/lib64 \
	$(INITRAMFS)/bin \
	$(INITRAMFS)/sbin \
	$(INITRAMFS)/usr/bin \
	$(INITRAMFS)/usr/local \
	$(INITRAMFS)/test \
	$(INITRAMFS)/benchmark \
	$(INITRAMFS_EMPTY_DIRS)
SYSCALL_TEST_DIR := $(INITRAMFS)/opt/syscall_test

PARSEC_KERNELS := canneal dedup streamcluster
PARSEC_APPS := blackscholes bodytrack facesim ferret fluidanimate freqmine vips x264

.PHONY: all
all: build

$(INITRAMFS)/lib/x86_64-linux-gnu: | $(VDSO_LIB)
	@mkdir -p $@
	@cp -L /lib/x86_64-linux-gnu/libc.so.6 $@
	@cp -L /lib/x86_64-linux-gnu/libstdc++.so.6 $@
	@cp -L /lib/x86_64-linux-gnu/libm.so.6 $@
	@cp -L /lib/x86_64-linux-gnu/libgcc_s.so.1 $@
	@cp -L /lib/x86_64-linux-gnu/libpthread.so.0 $@
	@# required for benchmarks
	@cp -L /lib/x86_64-linux-gnu/libcrypto.so.3 $@
	@cp -L /lib/x86_64-linux-gnu/libcrypt.so.1 $@
	@cp -L /lib/x86_64-linux-gnu/libdl.so.2 $@
	@cp -L /lib/x86_64-linux-gnu/libz.so.1 $@
	@cp -L /lib/x86_64-linux-gnu/libmvec.so.1 $@
	@cp -L /usr/local/benchmark/iperf/lib/libiperf.so.0 $@
	@# required for LMbench-network
	@cp -L /lib/x86_64-linux-gnu/libtirpc.so.3 $@
	@cp -L /lib/x86_64-linux-gnu/libgssapi_krb5.so.2 $@
	@cp -L /lib/x86_64-linux-gnu/libkrb5.so.3 $@
	@cp -L /lib/x86_64-linux-gnu/libk5crypto.so.3 $@
	@cp -L /lib/x86_64-linux-gnu/libcom_err.so.2 $@
	@cp -L /lib/x86_64-linux-gnu/libkrb5support.so.0 $@
	@cp -L /lib/x86_64-linux-gnu/libkeyutils.so.1 $@
	@cp -L /lib/x86_64-linux-gnu/libresolv.so.2 $@
	@# required for LevelDB-db_bench_sqlite3
	@cp -L /lib/x86_64-linux-gnu/libsqlite3.so $@
	@# required for memcached
	@cp -L /lib/x86_64-linux-gnu/libevent-2.1.so.7 $@
	@# required for VDSO
	@cp -L $(VDSO_LIB) $@
	@# required for metis/dedup/parsec
	@cp -L /lib/x86_64-linux-gnu/libdb-5.3.so $@
	@cp -L /usr/lib/x86_64-linux-gnu/libgomp.so.1.0.0 $@/libgomp.so.1
	@# TC malloc
	@cp -L /lib/x86_64-linux-gnu/libtcmalloc_minimal.so.4 $@

$(VDSO_LIB): | $(VDSO_DIR) $(BINARY_CACHE_DIR)/vdso64.so
	@# TODO: use a custom compiled vdso.so file in the future.
	@cp $(BINARY_CACHE_DIR)/vdso64.so $@
	
$(VDSO_DIR):
	@mkdir -p $@
	
$(BINARY_CACHE_DIR)/vdso64.so:
	@mkdir -p $(BINARY_CACHE_DIR)
	@$(ATOMIC_WGET) $@ "https://raw.githubusercontent.com/asterinas/linux_vdso/2a6d2db/vdso64.so"

$(INITRAMFS)/lib64:
	@mkdir -p $@
	@cp -L /lib64/ld-linux-x86-64.so.2 $@

$(INITRAMFS)/etc:
	@mkdir -p $@
	@cp $(CUR_DIR)/etc/* $@

# Install busybox into /bin and /usr/bin.
$(INITRAMFS)/bin:
	@mkdir -p $@
	@/bin/busybox --install -s $@

$(INITRAMFS)/sbin:
	@mkdir -p $@
	@cp /sbin/ldconfig $@
	@cp /sbin/ldconfig.real $@

$(INITRAMFS)/usr/bin: | $(INITRAMFS)/bin
	@mkdir -p $@
	@cp /usr/bin/busybox $@
	@cp /usr/bin/env $@
	@cp /usr/bin/bash $@
	@cp /usr/bin/head $@

$(INITRAMFS)/usr/local:
	@mkdir -p $@
	@cp -r /usr/local/nginx $@
	@cp -r /usr/local/redis $@
	@cp -r /usr/local/memcached $@

.PHONY: $(INITRAMFS)/test
$(INITRAMFS)/test:
	@$(MAKE) --no-print-directory -C apps

$(INITRAMFS)/benchmark: | $(INITRAMFS)/benchmark/bin
	@cp -rf $(CUR_DIR)/benchmark/* $@

$(INITRAMFS)/benchmark/bin:
	@mkdir -p $@
	@if [ -d /root/mm-scalability-benchmark/ ]; then \
		mkdir -p $@/metis; \
		cp /root/mm-scalability-benchmark/mosbench/metis_with_radixvm/metis/obj/app/wrmem $@/metis; \
		mkdir -p $@/psearchy; \
		cp /root/mm-scalability-benchmark/mosbench/psearchy/mkdb/pedsort $@/psearchy; \
		cp /root/mm-scalability-benchmark/mosbench/psearchy/mkdb/pedsort-tc $@/psearchy; \
		cp /root/mm-scalability-benchmark/mosbench/psearchy/linux_files_index $@/psearchy; \
		for i in $(PARSEC_KERNELS); do \
			mkdir -p $@/$$i; \
			cp /root/mm-scalability-benchmark/parsec-3.0/pkgs/kernels/$$i/inst/amd64-linux.gcc/bin/$$i $@/$$i; \
		done; \
		for i in $(PARSEC_APPS); do \
			mkdir -p $@/$$i; \
			cp /root/mm-scalability-benchmark/parsec-3.0/pkgs/apps/$$i/inst/amd64-linux.gcc/bin/$$i $@/$$i; \
		done; \
		mkdir -p $@/swaptions; \
		cp /root/mm-scalability-benchmark/parsec-3.0/pkgs/apps/swaptions/obj/amd64-linux.gcc-tbb/swaptions $@/swaptions; \
		cp /root/mm-scalability-benchmark/dedup-tc $@/dedup; \
		mkdir -p $@/vm_scale_bench_data; \
	fi
	
# Make necessary directories.
$(INITRAMFS_EMPTY_DIRS):
	@mkdir -p $@

.PHONY: $(SYSCALL_TEST_DIR)
$(SYSCALL_TEST_DIR):
	@$(MAKE) --no-print-directory -C syscall_test

.PHONY: $(INITRAMFS_IMAGE)
$(INITRAMFS_IMAGE): $(INITRAMFS_FILELIST)
	@if ! cmp -s $(INITRAMFS_FILELIST) $(INITRAMFS_FILELIST).previous || ! test -f $@; then \
		echo "Generating the initramfs image..."; \
		cp -f $(INITRAMFS_FILELIST) $(INITRAMFS_FILELIST).previous; \
		( \
			cd $(INITRAMFS); \
			# `$(INITRAMFS_FILELIST)` contains files' last modification \
			# time in the first column, and files' relative path to \
			# `$(INITRAMFS)` in the second column. This prunes the first \
			# column and passes the second column to `cpio`. \
			cut -d " " -f 2- $(INITRAMFS_FILELIST) | \
				cpio -o -H newc | \
					if [ "$(INITRAMFS_SKIP_GZIP)" != 1 ]; then \
						gzip; \
					else \
						cat; \
					fi \
		) > $@; \
	fi

.PHONY: $(INITRAMFS_FILELIST)
# If the BUILD_SYSCALL_TEST variable is set, we should depend on the
# sub make output to do incremental building.
ifeq ($(BUILD_SYSCALL_TEST), 1)
$(INITRAMFS_FILELIST): | $(INITRAMFS_ALL_DIRS) $(SYSCALL_TEST_DIR)
else
$(INITRAMFS_FILELIST): | $(INITRAMFS_ALL_DIRS)
endif
	@(cd $(INITRAMFS); find . -printf "%T@ %p\n") > $(INITRAMFS_FILELIST)

$(EXT2_IMAGE):
	@dd if=/dev/zero of=$(EXT2_IMAGE) bs=2G count=1
	@mke2fs $(EXT2_IMAGE)

$(EXFAT_IMAGE):
	@fallocate -l 64M $(EXFAT_IMAGE)
	@mkfs.exfat $(EXFAT_IMAGE)

$(BENCH_DATA_IMAGE):
	@dd if=/dev/zero of=$(BENCH_DATA_IMAGE) bs=2G count=4 iflag=fullblock
	@mkfs.ext2 $(BENCH_DATA_IMAGE)
	@if [ -d /root/mm-scalability-benchmark/ ]; then \
		mkdir -p /mnt/data_mount; \
		mount -t ext2 $(BENCH_DATA_IMAGE) /mnt/data_mount; \
		cp -r /root/mm-scalability-benchmark/data/* /mnt/data_mount/; \
		cp -r /root/linux-2.6.35 /mnt/data_mount/; \
		for i in $(PARSEC_KERNELS); do \
			if [ "$$i" != "streamcluster" ]; then \
				mkdir -p /mnt/data_mount/$$i; \
				tar -xf /root/mm-scalability-benchmark/parsec-3.0/pkgs/kernels/$$i/inputs/input_native.tar -C /mnt/data_mount/$$i; \
			fi; \
		done; \
		for i in $(PARSEC_APPS); do \
			mkdir -p /mnt/data_mount/$$i; \
			tar -xf /root/mm-scalability-benchmark/parsec-3.0/pkgs/apps/$$i/inputs/input_native.tar -C /mnt/data_mount/$$i; \
		done; \
		umount /mnt/data_mount; \
		rm -rf /mnt/data_mount/; \
	fi

.PHONY: build
build: $(INITRAMFS_IMAGE) $(EXT2_IMAGE) $(EXFAT_IMAGE) $(BENCH_DATA_IMAGE)

.PHONY: format
format:
	@$(MAKE) --no-print-directory -C apps format

.PHONY: check
check:
	@$(MAKE) --no-print-directory -C apps check

.PHONY: clean
clean:
	@rm -rf $(BUILD_DIR)