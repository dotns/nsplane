#!/usr/bin/env bash
# Runs inside the vm-guest.sh runner container: packs the guest initramfs from the image's
# kernel modules and busybox, starts the unix_gateway example on a Unix socket, boots the
# guest with QEMU attached to that socket, and exits 0 when the serial console shows the
# success line.
#
#   vm-run.sh <unix_gateway binary> <work dir>
set -euo pipefail
BIN=$1
WORK=$2
HERE=$(cd "$(dirname "$0")" && pwd)
KVER=$(ls /lib/modules)
GUEST=$WORK/guest
SOCK=$WORK/guest.sock

echo "== qemu: $(qemu-system-x86_64 --version | head -1)"
echo "== guest kernel: $KVER"

rm -rf "$GUEST"
mkdir -p "$GUEST/root/bin" "$GUEST/root/modules" "$GUEST/root/proc" "$GUEST/root/sys" "$GUEST/root/dev"
cp /bin/busybox "$GUEST/root/bin/busybox"
cp "$HERE/guest-init" "$GUEST/root/init"
cp "$HERE/udhcpc.script" "$GUEST/root/udhcpc.script"
chmod 755 "$GUEST/root/init" "$GUEST/root/udhcpc.script"
n=0
while read -r kind path _; do
  [ "$kind" = insmod ] || continue
  n=$((n + 1))
  out=$GUEST/root/modules/$(printf '%02d' "$n")-$(basename "${path%%.ko*}").ko
  case "$path" in
    *.xz) xz -dc "$path" >"$out" ;;
    *.zst) zstd -qdc "$path" >"$out" ;;
    *) cp "$path" "$out" ;;
  esac
done < <(modprobe -S "$KVER" --show-depends -a af_packet virtio_pci virtio_net)
echo "== guest modules: $(cd "$GUEST/root/modules" && echo *)"
(cd "$GUEST/root" && find . | cpio -o -H newc --quiet) | gzip -1 >"$GUEST/initrd.gz"

rm -f "$SOCK"
"$BIN" "$SOCK" >"$WORK/host.log" 2>&1 &
host=$!
for _ in $(seq 1 50); do
  [ -S "$SOCK" ] && break
  sleep 0.1
done

status=0
timeout 180 qemu-system-x86_64 -enable-kvm -cpu host -m 256 -smp 1 \
  -display none -monitor none -serial "file:$WORK/serial.log" -no-reboot \
  -kernel "/boot/vmlinuz-$KVER" -initrd "$GUEST/initrd.gz" \
  -append "console=ttyS0 panic=-1 loglevel=4" \
  -netdev "stream,id=n0,server=off,addr.type=unix,addr.path=$SOCK" \
  -device virtio-net-pci,netdev=n0,mac=52:54:00:12:34:56,romfile= || status=$?
echo "== qemu exit $status"

for _ in $(seq 1 50); do
  kill -0 "$host" 2>/dev/null || break
  sleep 0.1
done
kill "$host" 2>/dev/null || true
wait "$host" || true

echo "== serial console"
cat "$WORK/serial.log"
echo "== gateway"
cat "$WORK/host.log"
grep -q '^NSPLANE-ETHER-OK ' "$WORK/serial.log"
