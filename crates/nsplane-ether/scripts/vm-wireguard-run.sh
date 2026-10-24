#!/usr/bin/env bash
# Runs inside the vm-wireguard.sh runner container: packs the guest initramfs with
# guest-init-wireguard, writes the ACL policy, starts the vm_wireguard example with the
# peer's key and boots the guest, and exits 0 when the serial console shows the success line,
# the ACL counted drops both ways and the adapter counted proxied ARP and neighbor answers.
# With qemu (the default) the example listens on a Unix socket and QEMU attaches to it; with
# firecracker the example creates the TAP fctap0 and serves it through a packet socket,
# Firecracker (from <firecracker dir>, with its kernel `vmlinux` there) attaches to the TAP,
# and the TAP must be gone after the example exits.
#
#   vm-wireguard-run.sh <vm_wireguard binary> <work dir> <peer host> [qemu|firecracker [<firecracker dir>]]
set -euo pipefail
BIN=$1
WORK=$2
PEER=$3
VMM=${4:-qemu}
FC_DIR=${5:-}
TAP=fctap0
HERE=$(cd "$(dirname "$0")" && pwd)
KVER=$(ls /lib/modules)
GUEST=$WORK/guest
SOCK=$WORK/guest.sock

if [ "$VMM" = firecracker ]; then
  echo "== $("$FC_DIR/firecracker" --version | head -1), guest kernel $FC_DIR/vmlinux"
else
  echo "== qemu: $(qemu-system-x86_64 --version | head -1)"
  echo "== guest kernel: $KVER"
fi

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
done < <(
  # The Firecracker guest kernel has virtio-net built in.
  [ "$VMM" = firecracker ] || modprobe -S "$KVER" --show-depends -a af_packet virtio_pci virtio_net
)
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
if [ "$VMM" = firecracker ]; then
  # Trace level logs every GSO frame the packet socket splits.
  LINK=(--packet "$TAP" --create-tap --log info,nsplane_ether=trace)
else
  LINK=(--socket "$SOCK" --log info)
fi
"$BIN" "${LINK[@]}" --private-key-file "$WORK/vm.key" --listen 0.0.0.0:51820 \
  --peer "$(cat "$WORK/peer.pub"),endpoint=$PEER:51820,allowed-ips=10.66.0.0/24+10.66.1.0/24+fd66::/64,keepalive=25" \
  --address 10.66.0.2/24 --dns 10.66.0.1 --ipv6-prefix fd66::/64 \
  --policy "$WORK/policy.json" --status-file "$WORK/status.json" \
  >"$WORK/vm.log" 2>&1 &
host=$!
for _ in $(seq 1 50); do
  [ -S "$SOCK" ] && break
  grep -q "serving the guest on the interface" "$WORK/vm.log" && break
  sleep 0.1
done

status=0
if [ "$VMM" = firecracker ]; then
  ip -d link show "$TAP"
  cat >"$WORK/firecracker.json" <<EOF
{
  "boot-source": {
    "kernel_image_path": "$FC_DIR/vmlinux",
    "initrd_path": "$GUEST/initrd.gz",
    "boot_args": "console=ttyS0 reboot=k panic=-1 loglevel=4"
  },
  "drives": [],
  "machine-config": { "vcpu_count": 1, "mem_size_mib": 256 },
  "network-interfaces": [
    { "iface_id": "eth0", "guest_mac": "52:54:00:12:34:56", "host_dev_name": "$TAP" }
  ]
}
EOF
  "$FC_DIR/firecracker" --no-api --config-file "$WORK/firecracker.json" >"$WORK/serial.log" 2>&1 &
  vmm=$!
  # The guest powers off after its last check; stop Firecracker once it reported.
  for _ in $(seq 1 240); do
    if grep -qE '^NSPLANE-VM-WG-(OK|FAIL)' "$WORK/serial.log"; then
      sleep 1
      break
    fi
    kill -0 "$vmm" 2>/dev/null || break
    sleep 1
  done
  kill "$vmm" 2>/dev/null || true
  wait "$vmm" || status=$?
  echo "== firecracker exit $status"
  # Packet mode has no disconnect: stop the example, which deletes the TAP.
  kill -INT "$host" 2>/dev/null || true
else
  timeout 240 qemu-system-x86_64 -enable-kvm -cpu host -m 256 -smp 1 \
    -display none -monitor none -serial "file:$WORK/serial.log" -no-reboot \
    -kernel "/boot/vmlinuz-$KVER" -initrd "$GUEST/initrd.gz" \
    -append "console=ttyS0 panic=-1 loglevel=4" \
    -netdev "stream,id=n0,server=off,addr.type=unix,addr.path=$SOCK" \
    -device virtio-net-pci,netdev=n0,mac=52:54:00:12:34:56,romfile= || status=$?
  echo "== qemu exit $status"
fi

for _ in $(seq 1 50); do
  kill -0 "$host" 2>/dev/null || break
  sleep 0.1
done
kill "$host" 2>/dev/null || true
wait "$host" || true

echo "== serial console"
cat "$WORK/serial.log"
echo "== vm_wireguard"
grep -v "splitting a GSO frame" "$WORK/vm.log"
if [ "$VMM" = firecracker ]; then
  echo "== GSO frames split by the packet socket: $(grep -c "splitting a GSO frame" "$WORK/vm.log" || true)"
fi
echo "== status"
cat "$WORK/status.json"
if [ "$VMM" = firecracker ] && ip link show "$TAP" >/dev/null 2>&1; then
  echo "$TAP still exists after the example exited"
  exit 1
fi
grep -q '^NSPLANE-VM-WG-OK ' "$WORK/serial.log"
jq -e '.extra.acl.denied > 0 and .extra.acl.outbound_denied > 0
  and .extra.ether.arp_proxied > 0 and .extra.ether.nd_proxied > 0' "$WORK/status.json" >/dev/null
