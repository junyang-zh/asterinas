#!/bin/bash
# SPDX-License-Identifier: MPL-2.0
set -euo pipefail
: "${ARTIFACT_EXT2_IMAGE:?}" "${ARTIFACT_EXFAT_IMAGE:?}" "${BENCH_DATA_IMAGE:?}"
# Preserve legacy vda/vdb/vdc ordering; no forwarding or graphical console.
# QMP is local-only and used by the measurement runner for vCPU affinity.
benchmark_cpu=host
if [[ -n ${CORTEN_GUEST_TSC_HZ:-} ]]; then
    [[ $CORTEN_GUEST_TSC_HZ =~ ^[1-9][0-9]*$ ]] || {
        echo "CORTEN_GUEST_TSC_HZ must be a positive integer in Hz" >&2
        exit 2
    }
    benchmark_cpu+=",tsc-frequency=$CORTEN_GUEST_TSC_HZ"
fi
cat <<EOF
-cpu $benchmark_cpu -machine q35,kernel-irqchip=split -smp ${SMP:-1} -m ${MEM:-8G}
-no-reboot -display none -serial stdio -monitor none -nic none
-qmp tcp:127.0.0.1:${QMP_PORT:-4444},server=on,wait=off
-device isa-debug-exit,iobase=0xf4,iosize=0x04
-drive if=none,format=raw,id=x0,file=$ARTIFACT_EXT2_IMAGE,snapshot=on
-drive if=none,format=raw,id=x1,file=$ARTIFACT_EXFAT_IMAGE,snapshot=on
-drive if=none,format=raw,id=x2,file=$BENCH_DATA_IMAGE,snapshot=on
-device virtio-blk-pci,drive=x0,disable-legacy=on,disable-modern=off,num-queues=1
-device virtio-blk-pci,drive=x1,disable-legacy=on,disable-modern=off,num-queues=1
-device virtio-blk-pci,drive=x2,disable-legacy=on,disable-modern=off,num-queues=1
-bios ${OVMF_DIR:-/root/ovmf/release}/OVMF.fd
EOF

if [ -n "${BENCH_RESULTS_IMAGE:-}" ]; then
    printf '%s\n' "-drive if=none,format=raw,id=results,file=$BENCH_RESULTS_IMAGE" \
        "-device virtio-blk-pci,drive=results,serial=vbench_results,disable-legacy=on,disable-modern=off,num-queues=1"
fi
