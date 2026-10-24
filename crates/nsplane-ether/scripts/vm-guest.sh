#!/usr/bin/env bash
# Real virtual machine test of the adapter: a Linux guest under QEMU with KVM, attached by
# `-netdev stream` (length-prefixed frames on a Unix socket) to the unix_gateway example.
# The guest takes its IPv4 address by DHCP and its IPv6 address from the router
# advertisement, then exchanges one line over TCP with the user-space stack behind the
# adapter on each family, and prints `NSPLANE-ETHER-OK <lease address> <IPv6 address>` on
# the serial console.
#
# QEMU, the guest kernel and busybox come from the runner image built from the Dockerfile
# next to this script (kept as ai-agent/nsplane-ether-vm for later runs). Needs docker and
# /dev/kvm on the host. The example binary is built in the dev image unless
# NSPLANE_ETHER_VM_BIN names one. Prints the serial console and the gateway log; exits 0
# when the guest printed the success line.
#
#   crates/nsplane-ether/scripts/vm-guest.sh
set -euo pipefail
cd "$(dirname "$0")/../../.."
PREFIX=nsplane-ether-vm-$$
DEV_IMAGE=${NSPLANE_ETHER_VM_DEV_IMAGE:-ai-agent/nstun-dev}
IMG=ai-agent/nsplane-ether-vm
LABEL=nsplane-ether-vm=$PREFIX
LABELS=(--label ai-agent=true --label "$LABEL")
WORK=$PWD/.tmp/$PREFIX
cleanup() {
  docker ps -aq --filter "label=$LABEL" | xargs -r docker rm -f >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
trap cleanup EXIT
trap 'exit 130' INT TERM

if [ ! -e /dev/kvm ]; then echo "no /dev/kvm"; exit 1; fi
if [ -z "${NSPLANE_ETHER_VM_BIN:-}" ]; then
  echo "== build the unix_gateway example in $DEV_IMAGE"
  NSPLANE_ETHER_VM_BIN=$(docker run --rm "${LABELS[@]}" --name "$PREFIX-build" -v "$PWD:$PWD" -w "$PWD" \
    -v nstun-cargo-registry:/usr/local/cargo/registry "$DEV_IMAGE" \
    cargo build -p nsplane-ether --example unix_gateway --locked --message-format=json \
    | jq -r 'select(.reason == "compiler-artifact" and .target.name == "unix_gateway") | .executable')
fi
BIN=$NSPLANE_ETHER_VM_BIN
if [ ! -x "$BIN" ]; then echo "no unix_gateway binary: '$BIN'"; exit 1; fi

echo "== build the runner image $IMG"
docker build -q --label ai-agent=true -t "$IMG" crates/nsplane-ether/scripts >/dev/null

mkdir -p "$WORK"
docker run --rm "${LABELS[@]}" --name "$PREFIX" --network none --device /dev/kvm \
  -v "$PWD:$PWD" -w "$PWD" "$IMG" \
  bash crates/nsplane-ether/scripts/vm-run.sh "$BIN" "$WORK"
