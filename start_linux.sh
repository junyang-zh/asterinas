LINUX_KERNEL="./bzImage"

# Disable unsupported ext2 features of Asterinas on Linux to ensure fairness
mke2fs -F -O ^ext_attr -O ^resize_inode -O ^dir_index ${BENCHMARK_DIR}/../build/ext2.img
make initramfs

/usr/local/qemu/bin/qemu-system-x86_64 \
    --no-reboot \
    -smp 128 \
    -m 96G \
    -machine q35,kernel-irqchip=split \
    -cpu Icelake-Server,-pcid,+x2apic \
    --enable-kvm \
    -kernel ${LINUX_KERNEL} \
    -initrd test/build/initramfs.cpio.gz \
    -drive if=none,format=raw,id=x0,file=test/build/ext2.img \
    -device virtio-blk-pci,bus=pcie.0,addr=0x6,drive=x0,serial=vext2,disable-legacy=on,disable-modern=off,queue-size=64,num-queues=1,config-wce=off,request-merging=off,write-cache=off,backend_defaults=off,discard=off,event_idx=off,indirect_desc=off,ioeventfd=off,queue_reset=off \
    -append 'console=ttyS0 rdinit=/usr/bin/busybox quiet mitigations=off hugepages=0 transparent_hugepage=never SHELL=/bin/sh LOGNAME=root HOME=/ USER=root PATH=/bin:/benchmark -- sh -l' \
    -nographic