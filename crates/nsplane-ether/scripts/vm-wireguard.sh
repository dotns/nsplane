#!/usr/bin/env bash
# Real virtual machine against a standard WireGuard peer: a Linux guest under QEMU with
# KVM, attached by `-netdev stream` to the vm_wireguard example, reaches wireguard-go in
# another container through the example's engine, and back.
#
# With --firecracker the guest runs under Firecracker with KVM instead: the example creates
# the TAP interface (`--packet fctap0 --create-tap`) and serves the guest through a packet
# socket on it, Firecracker attaches its virtio-net device to that TAP with checksum and
# segmentation offloads negotiated, and the guest runs the same checks. Firecracker and its
# CI guest kernel are downloaded once into .tmp/firecracker and verified by SHA-256; the
# runner then also gets NET_ADMIN, NET_RAW and /dev/net/tun.
#
# The peer container runs wireguard-go (built from scripts/bench/wireguard-go) on a TUN
# device with 10.66.0.1/24, 10.66.1.1/24 (an address behind the peer), fd66::1/64 and the
# second addresses 10.66.0.3 and fd66::3; the runner container runs the example and QEMU,
# both on a labelled network. The guest leases 10.66.0.2/24 with MTU 1420, pings and opens
# TCP to the peer, to the second addresses (on-link for the guest, answered by the adapter's
# neighbor proxy) and to the address behind it,
# and finds TCP port 8 blocked by the example's ACL; the peer pings the guest, opens TCP
# 2222 and finds 2223 blocked. Prints the serial console, the example's log and status, and
# the peer's probe; exits 0 when every check passed.
#
# Uses the runner image of vm-guest.sh (ai-agent/nsplane-ether-vm). Needs docker and
# /dev/kvm on the host. The example binary is built in the dev image unless
# NSPLANE_VM_WG_BIN names one.
#
#   crates/nsplane-ether/scripts/vm-wireguard.sh [--firecracker]
set -euo pipefail
cd "$(dirname "$0")/../../.."
VMM=qemu
case ${1:-} in
  "") ;;
  --firecracker) VMM=firecracker ;;
  *) echo "usage: $0 [--firecracker]" >&2; exit 2 ;;
esac
FC_VERSION=v1.17.0
FC_KERNEL=vmlinux-6.1.128
FC_KERNEL_URL=https://s3.amazonaws.com/spec.ccfc.min/firecracker-ci/v1.12/x86_64/$FC_KERNEL
FC_KERNEL_SHA256=27a8310b9a727517e9eb02044524b6ceb77de5728e3491b6974d5c846227ecc8
FC_DIR=$PWD/.tmp/firecracker
PREFIX=nsplane-vm-wg-$$
DEV_IMAGE=${NSPLANE_ETHER_VM_DEV_IMAGE:-ai-agent/nstun-dev}
IMG=ai-agent/nsplane-ether-vm
WGGO_IMG=ai-agent/wireguard-go
LABEL=nsplane-vm-wg=$PREFIX
LABELS=(--label ai-agent=true --label "$LABEL")
NET=$PREFIX-net
PEER=$PREFIX-peer
WORK=$PWD/.tmp/$PREFIX
SCRIPTS=crates/nsplane-ether/scripts
cleanup() {
  docker ps -aq --filter "label=$LABEL" | xargs -r docker rm -f >/dev/null 2>&1 || true
  docker network rm "$NET" >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
trap cleanup EXIT
trap 'exit 130' INT TERM

if [ ! -e /dev/kvm ]; then echo "no /dev/kvm"; exit 1; fi
if [ -z "${NSPLANE_VM_WG_BIN:-}" ]; then
  echo "== build the vm_wireguard example in $DEV_IMAGE"
  NSPLANE_VM_WG_BIN=$(docker run --rm "${LABELS[@]}" --name "$PREFIX-build" -v "$PWD:$PWD" -w "$PWD" \
    -v nstun-cargo-registry:/usr/local/cargo/registry "$DEV_IMAGE" \
    cargo build -p nsplane-examples --bin vm_wireguard --locked --message-format=json \
    | jq -r 'select(.reason == "compiler-artifact" and .target.name == "vm_wireguard") | .executable')
fi
BIN=$NSPLANE_VM_WG_BIN
if [ ! -x "$BIN" ]; then echo "no vm_wireguard binary: '$BIN'"; exit 1; fi

if [ "$VMM" = firecracker ]; then
  echo "== Firecracker $FC_VERSION and the guest kernel $FC_KERNEL in $FC_DIR"
  mkdir -p "$FC_DIR"
  if [ ! -x "$FC_DIR/firecracker" ]; then
    url=https://github.com/firecracker-microvm/firecracker/releases/download/$FC_VERSION/firecracker-$FC_VERSION-x86_64.tgz
    curl -fsSL -o "$FC_DIR/fc.tgz" "$url"
    want=$(curl -fsSL "$url.sha256.txt" | awk '{ print $1 }')
    echo "$want  $FC_DIR/fc.tgz" | sha256sum -c --quiet
    tar -xzf "$FC_DIR/fc.tgz" -C "$FC_DIR" "release-$FC_VERSION-x86_64/firecracker-$FC_VERSION-x86_64"
    mv "$FC_DIR/release-$FC_VERSION-x86_64/firecracker-$FC_VERSION-x86_64" "$FC_DIR/firecracker"
    rm -rf "$FC_DIR/fc.tgz" "$FC_DIR/release-$FC_VERSION-x86_64"
  fi
  if [ ! -f "$FC_DIR/vmlinux" ]; then
    curl -fsSL -o "$FC_DIR/vmlinux.part" "$FC_KERNEL_URL"
    echo "$FC_KERNEL_SHA256  $FC_DIR/vmlinux.part" | sha256sum -c --quiet
    mv "$FC_DIR/vmlinux.part" "$FC_DIR/vmlinux"
  fi
fi

echo "== build the runner image $IMG and wireguard-go"
docker build -q --label ai-agent=true -t "$IMG" "$SCRIPTS" >/dev/null
docker build -q --label ai-agent=true -t "$WGGO_IMG" scripts/bench/wireguard-go >/dev/null
mkdir -p "$WORK"
docker run --rm "${LABELS[@]}" "$WGGO_IMG" cat /usr/local/bin/wireguard-go >"$WORK/wireguard-go"
chmod 755 "$WORK/wireguard-go"
docker network create --label ai-agent=true --label "$LABEL" "$NET" >/dev/null

echo "== start the peer"
docker run -d --rm "${LABELS[@]}" --name "$PEER" --network "$NET" \
  --cap-add NET_ADMIN --device /dev/net/tun --sysctl net.ipv6.conf.all.disable_ipv6=0 \
  -v "$PWD:$PWD" -v "$WORK:$WORK" -v "$WORK/wireguard-go:/usr/local/bin/wireguard-go:ro" \
  -w "$PWD" "$IMG" bash "$SCRIPTS/vm-wireguard-peer.sh" up "$WORK" >/dev/null
for _ in $(seq 1 100); do
  [ -e "$WORK/peer.up" ] && break
  sleep 0.1
done
if [ ! -e "$WORK/peer.up" ]; then docker logs "$PEER"; echo "the peer did not come up"; exit 1; fi

echo "== start the runner ($VMM)"
RUNNER=(--device /dev/kvm)
if [ "$VMM" = firecracker ]; then
  # The example creates the TAP; /proc/sys is read-only in the container, so the TAP's IPv6
  # settings come from net.ipv6.conf.default.
  RUNNER+=(--cap-add NET_ADMIN --cap-add NET_RAW --device /dev/net/tun -v "$FC_DIR:$FC_DIR:ro"
    --sysctl net.ipv6.conf.default.disable_ipv6=1 --sysctl net.ipv6.conf.default.autoconf=0)
fi
docker run -d "${LABELS[@]}" --name "$PREFIX-run" --network "$NET" "${RUNNER[@]}" \
  -v "$PWD:$PWD" -v "$WORK:$WORK" -w "$PWD" "$IMG" \
  bash "$SCRIPTS/vm-wireguard-run.sh" "$BIN" "$WORK" "$PEER" "$VMM" "$FC_DIR" >/dev/null

probe=1
for _ in $(seq 1 180); do
  if grep -q '^GUEST-READY' "$WORK/serial.log" 2>/dev/null; then
    echo "== probe the guest from the peer"
    probe=0
    docker exec "$PEER" bash "$PWD/$SCRIPTS/vm-wireguard-peer.sh" probe || probe=$?
    break
  fi
  grep -q '^NSPLANE-VM-WG-FAIL' "$WORK/serial.log" 2>/dev/null && break
  sleep 1
done
run=$(docker wait "$PREFIX-run")
docker logs "$PREFIX-run"
echo "== wireguard-go"
cat "$WORK/wireguard-go.log"
echo "== runner exit $run, probe exit $probe"
[ "$run" = 0 ] && [ "$probe" = 0 ]
