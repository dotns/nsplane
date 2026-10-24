# Runner image for vm-guest.sh: QEMU, a distribution kernel with its modules, and a static
# busybox for the guest initramfs.
FROM debian:trixie
RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        qemu-system-x86 linux-image-amd64 busybox-static kmod cpio gzip xz-utils zstd \
    && rm -rf /var/lib/apt/lists/*
