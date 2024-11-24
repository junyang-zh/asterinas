set -ex

# args: start_linux_riscv64.sh [core_count] [mem_size]
# environment variables:
#   QMP_PORT: port for QEMU Machine Protocol (default: 9889)

CORE_COUNT=${1:-128}
MEM_SIZE=${2:-256}

SCRIPT_DIR=$(dirname "$(readlink -f "$0")")
IMG_SRC_DIR="$SCRIPT_DIR/../test"
INITRAMFS_PATH="$IMG_SRC_DIR/build/initramfs.cpio.gz"

if [ ! -f "$INITRAMFS_PATH" ]; then
    make build -C $IMG_SRC_DIR OSDK_TARGET_ARCH=riscv64 ENABLE_BASIC_TEST=true
fi

LINUX_KERNEL="/root/linux-6.13.8/Image"

qemu-system-riscv64 \
    -kernel $LINUX_KERNEL \
    -initrd $INITRAMFS_PATH \
    -append "console=ttyS0 rdinit=/usr/bin/busybox quiet mitigations=off hugepages=0 transparent_hugepage=never SHELL=/bin/sh LOGNAME=root HOME=/ USER=root PATH=/bin:/benchmark ostd.log_level=error -- sh -l" \
    -cpu rv64,zba=true,zbb=true \
    -smp $CORE_COUNT \
    -machine virt \
    -m ${MEM_SIZE}G \
    --no-reboot \
    -nographic \
    -chardev stdio,id=char0,mux=on,signal=off,logfile=qemu.log \
    -serial chardev:char0 \
    -mon chardev=char0 \
    -qmp tcp:127.0.0.1:${QMP_PORT-9889},server,nowait
