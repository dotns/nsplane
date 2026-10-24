# Runner image for vm-guest.sh and vm-wireguard.sh: QEMU, a distribution kernel with its
# modules, a static busybox for the guest initramfs, and the WireGuard tools for the peer.
FROM debian:trixie
RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        qemu-system-x86 linux-image-amd64 busybox-static kmod cpio gzip xz-utils zstd \
        wireguard-tools iproute2 iputils-ping jq \
    && rm -rf /var/lib/apt/lists/*
