#!/usr/bin/env bash
# Runs inside the vm-wireguard.sh runner container: packs the guest initramfs with
# guest-init-wireguard, writes the ACL policy, starts the vm_wireguard example on a Unix
# socket with the peer's key, boots the guest with QEMU attached to that socket, and exits
# 0 when the serial console shows the success line and the ACL counted drops both ways.
#
#   vm-wireguard-run.sh <vm_wireguard binary> <work dir> <peer host>
set -euo pipefail
BIN=$1
WORK=$2
PEER=$3
HERE=$(cd "$(dirname "$0")" && pwd)
KVER=$(ls /lib/modules)
GUEST=$WORK/guest
SOCK=$WORK/guest.sock

echo "== qemu: $(qemu-system-x86_64 --version | head -1)"
echo "== guest kernel: $KVER"

rm -rf "$GUEST"
mkdir -p "$GUEST/root/bin" "$GUEST/root/modules" "$GUEST/root/proc" "$GUEST/root/sys" "$GUEST/root/dev"
cp /bin/busybox "$GUEST/root/bin/busybox"
cp "$HERE/guest-init-wireguard" "$GUEST/root/init"
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
(cd "$GUEST/root" && find . | cpio -o -H newc --quiet) | gzip -1 >"$GUEST/initrd.gz"

# The guest may open TCP 7 and ping; the peer may open TCP 2222 and ping the guest.
cat >"$WORK/policy.json" <<'EOF'
{
  "from_guest": [
    { "id": "guest-out", "protocols": [{ "Tcp": { "Ranges": [{ "start": 7, "end": 7 }] } }, { "Icmp": "Any" }] }
  ],
  "to_guest": [
    {
      "id": "peer-in",
      "sources": ["10.66.0.1/32"],
      "protocols": [{ "Tcp": { "Ranges": [{ "start": 2222, "end": 2222 }] } }, { "Icmp": { "Only": [8] } }]
    }
  ]
}
EOF

rm -f "$SOCK"
"$BIN" --socket "$SOCK" --private-key-file "$WORK/vm.key" --listen 0.0.0.0:51820 \
  --peer "$(cat "$WORK/peer.pub"),endpoint=$PEER:51820,allowed-ips=10.66.0.0/24+10.66.1.0/24+fd66::/64,keepalive=25" \
  --address 10.66.0.2/24 --dns 10.66.0.1 --ipv6-prefix fd66::/64 \
  --policy "$WORK/policy.json" --status-file "$WORK/status.json" --log info \
  >"$WORK/vm.log" 2>&1 &
host=$!
for _ in $(seq 1 50); do
  [ -S "$SOCK" ] && break
  sleep 0.1
done

status=0
timeout 240 qemu-system-x86_64 -enable-kvm -cpu host -m 256 -smp 1 \
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
echo "== vm_wireguard"
cat "$WORK/vm.log"
echo "== status"
cat "$WORK/status.json"
grep -q '^NSPLANE-VM-WG-OK ' "$WORK/serial.log"
jq -e '.extra.acl.denied > 0 and .extra.acl.outbound_denied > 0' "$WORK/status.json" >/dev/null
