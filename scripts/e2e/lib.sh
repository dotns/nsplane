#!/usr/bin/env bash
# Library-level end-to-end test: the `nsplane-e2e` container tests (crates/nsplane-e2e/tests/container.rs)
# in container a, against kernel WireGuard in container b.
#
# Each side runs in its own network namespace on a dedicated docker network; nothing on the
# host is reconfigured. Needs docker and the `wireguard` kernel module on the host. The test
# binary is built in the dev image unless NSPLANE_E2E_LIB_BIN names one, and so is the
# release nsplane-cli binary unless NSPLANE_E2E_LIB_CLI names one.
#
#   scripts/e2e/lib.sh
set -euo pipefail
cd "$(dirname "$0")/../.."
PREFIX=${NSPLANE_E2E_LIB_PREFIX:-nsplane-e2e-lib}
NET=$PREFIX-net
VOL=$PREFIX-kernel
IMG=$PREFIX-image
DEV_IMAGE=${NSPLANE_E2E_LIB_DEV_IMAGE:-ai-agent/nstun-dev}
LABEL=${NSPLANE_E2E_LIB_LABEL:-nsplane-e2e-lib=true}
LABELS=(--label "$LABEL" --label ai-agent=true)
cleanup() { docker rm -f "$PREFIX-build" "$PREFIX-a" "$PREFIX-b" >/dev/null 2>&1 || true; docker network rm "$NET" >/dev/null 2>&1 || true; docker volume rm "$VOL" >/dev/null 2>&1 || true; }
trap cleanup EXIT
cleanup

if [ -z "${NSPLANE_E2E_LIB_BIN:-}" ]; then
  echo "== build the nsplane-e2e tests in $DEV_IMAGE"
  NSPLANE_E2E_LIB_BIN=$(docker run --rm "${LABELS[@]}" --name "$PREFIX-build" -v "$PWD:$PWD" -w "$PWD" \
    -v nstun-cargo-registry:/usr/local/cargo/registry "$DEV_IMAGE" \
    cargo test -p nsplane-e2e --no-run --locked --message-format=json \
    | jq -r 'select(.reason == "compiler-artifact" and .target.name == "container" and .profile.test) | .executable')
fi
BIN=$NSPLANE_E2E_LIB_BIN
if [ ! -x "$BIN" ]; then echo "no container test binary: '$BIN'"; exit 1; fi
if [ -z "${NSPLANE_E2E_LIB_CLI:-}" ]; then
  echo "== build nsplane-cli in $DEV_IMAGE"
  NSPLANE_E2E_LIB_CLI=$(docker run --rm "${LABELS[@]}" --name "$PREFIX-build" -v "$PWD:$PWD" -w "$PWD" \
    -v nstun-cargo-registry:/usr/local/cargo/registry "$DEV_IMAGE" \
    cargo build -p nsplane-cli --release --locked --message-format=json \
    | jq -r 'select(.reason == "compiler-artifact" and .target.name == "nsplane-cli" and .executable != null) | .executable')
fi
CLI=$NSPLANE_E2E_LIB_CLI
if [ ! -x "$CLI" ]; then echo "no nsplane-cli binary: '$CLI'"; exit 1; fi

docker build -q "${LABELS[@]}" -t "$IMG" scripts/e2e >/dev/null
docker network create "${LABELS[@]}" "$NET" >/dev/null
docker volume create "${LABELS[@]}" "$VOL" >/dev/null
run() { docker run -d --rm "${LABELS[@]}" --name "$1" --network "$NET" --cap-add NET_ADMIN \
  --device /dev/net/tun --sysctl net.ipv6.conf.all.disable_ipv6=0 -v "$VOL":/kernel \
  -v "$BIN":/usr/local/bin/nsplane-e2e-container:ro -v "$CLI":/usr/local/bin/nsplane-cli:ro \
  "$IMG" sleep infinity >/dev/null; }
run "$PREFIX-a"; run "$PREFIX-b"
A() { docker exec "$PREFIX-a" bash -c "$*"; }
B() { docker exec "$PREFIX-b" bash -c "$*"; }
ip_of() { docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$1"; }
A_IP=$(ip_of "$PREFIX-a"); B_IP=$(ip_of "$PREFIX-b")
A 'umask 077; wg genkey > /k; wg pubkey < /k > /p'; B 'umask 077; wg genkey > /k; wg pubkey < /k > /p'
A_PUB=$(A 'cat /p'); B_PUB=$(B 'cat /p')
PSK=$(B 'umask 077; wg genpsk | tee /psk'); A "umask 077; echo $PSK > /psk"

echo "== kernel wireguard in b (persistent keepalive: b initiates the first handshake)"
B "ip link add wg0 type wireguard; wg set wg0 private-key /k listen-port 51820 peer $A_PUB preshared-key /psk allowed-ips 10.9.1.1/32,fd00:1::1/128 endpoint $A_IP:51820 persistent-keepalive 2"
B 'ip addr add 10.9.1.2/24 dev wg0; ip addr add fd00:1::2/64 dev wg0; ip link set wg0 up'
# The test in a reads the kernel's counters through the shared /kernel: b answers each
# /kernel/request with `wg show wg0 transfer` in /kernel/transfer.
docker exec -d "$PREFIX-b" bash -c 'while :; do if [ -e /kernel/request ]; then rm /kernel/request
  wg show wg0 transfer > /kernel/transfer.tmp; mv /kernel/transfer.tmp /kernel/transfer; fi; sleep 0.05; done'

echo "== nsplane-e2e container tests in a"
docker exec \
  -e NSPLANE_E2E_LIB_PRIVATE_KEY=/k \
  -e NSPLANE_E2E_LIB_PSK=/psk \
  -e NSPLANE_E2E_LIB_PEER_PUB="$B_PUB" \
  -e NSPLANE_E2E_LIB_PEER_ENDPOINT="$B_IP:51820" \
  -e NSPLANE_E2E_LIB_LISTEN_PORT=51820 \
  -e NSPLANE_E2E_LIB_ADDR_V4=10.9.1.1/24 \
  -e NSPLANE_E2E_LIB_ADDR_V6=fd00:1::1/64 \
  -e NSPLANE_E2E_LIB_PEER_V4=10.9.1.2 \
  -e NSPLANE_E2E_LIB_PEER_V6=fd00:1::2 \
  -e NSPLANE_E2E_LIB_KERNEL_DIR=/kernel \
  -e NSPLANE_E2E_LIB_CLI=/usr/local/bin/nsplane-cli \
  "$PREFIX-a" nsplane-e2e-container --ignored --test-threads=1 --nocapture
echo "== wg show (b)"
B 'wg show wg0' | sed 's/^/  /'
echo "PASS"
