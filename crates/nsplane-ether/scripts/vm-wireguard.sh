#!/usr/bin/env bash
# Real virtual machine against a standard WireGuard peer: a Linux guest under QEMU with
# KVM, attached by `-netdev stream` to the vm_wireguard example, reaches wireguard-go in
# another container through the example's engine, and back.
#
# The peer container runs wireguard-go (built from scripts/bench/wireguard-go) on a TUN
# device with 10.66.0.1/24, 10.66.1.1/24 (an address behind the peer) and fd66::1/64; the
# runner container runs the example and QEMU, both on a labelled network. The guest leases
# 10.66.0.2/24 with MTU 1420, pings and opens TCP to the peer and to the address behind it,
# and finds TCP port 8 blocked by the example's ACL; the peer pings the guest, opens TCP
# 2222 and finds 2223 blocked. Prints the serial console, the example's log and status, and
# the peer's probe; exits 0 when every check passed.
#
# Uses the runner image of vm-guest.sh (ai-agent/nsplane-ether-vm). Needs docker and
# /dev/kvm on the host. The example binary is built in the dev image unless
# NSPLANE_VM_WG_BIN names one.
#
#   crates/nsplane-ether/scripts/vm-wireguard.sh
set -euo pipefail
cd "$(dirname "$0")/../../.."
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

echo "== start the runner"
docker run -d "${LABELS[@]}" --name "$PREFIX-run" --network "$NET" --device /dev/kvm \
  -v "$PWD:$PWD" -v "$WORK:$WORK" -w "$PWD" "$IMG" \
  bash "$SCRIPTS/vm-wireguard-run.sh" "$BIN" "$WORK" "$PEER" >/dev/null

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
