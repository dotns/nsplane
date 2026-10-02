#!/usr/bin/env bash
# End-to-end interop test: nsplane (container a) against kernel WireGuard (container b).
#
# Each side runs in its own network namespace on a dedicated docker network; nothing on the
# host is reconfigured. Needs docker and the `wireguard` kernel module on the host.
#
#   cargo build -p nsplane-cli --release && scripts/e2e/linux.sh
set -euo pipefail
cd "$(dirname "$0")/../.."
PREFIX=${NSPLANE_E2E_PREFIX:-nsplane-e2e}
NET=$PREFIX-net
IMG=$PREFIX-image
BIN=${NSPLANE_E2E_BIN:-$PWD/target/release/nsplane-cli}
LABEL=${NSPLANE_E2E_LABEL:-nsplane-e2e=true}
cleanup() { docker rm -f "$PREFIX-a" "$PREFIX-b" >/dev/null 2>&1 || true; docker network rm "$NET" >/dev/null 2>&1 || true; }
trap cleanup EXIT
cleanup
docker build -q --label "$LABEL" -t "$IMG" scripts/e2e >/dev/null
docker network create --label "$LABEL" "$NET" >/dev/null
run() { docker run -d --rm --label "$LABEL" --name "$1" --network "$NET" --cap-add NET_ADMIN \
  --device /dev/net/tun --sysctl net.ipv6.conf.all.disable_ipv6=0 \
  -v "$BIN":/usr/local/bin/nsplane-cli:ro "$IMG" sleep infinity >/dev/null; }
run "$PREFIX-a"; run "$PREFIX-b"
A() { docker exec "$PREFIX-a" bash -c "$*"; }
B() { docker exec "$PREFIX-b" bash -c "$*"; }
ip_of() { docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$1"; }
A_IP=$(ip_of "$PREFIX-a"); B_IP=$(ip_of "$PREFIX-b")
A 'umask 077; wg genkey > /k; wg pubkey < /k > /p'; B 'umask 077; wg genkey > /k; wg pubkey < /k > /p'
A_PUB=$(A 'cat /p'); B_PUB=$(B 'cat /p')

echo "== start nsplane in a"
A 'WG_SUDO=1 WG_LOG_LEVEL=info nsplane-cli wg0 > /log 2>&1 &'
for i in $(seq 1 50); do A 'test -S /var/run/wireguard/wg0.sock' && break; sleep 0.1; done
A "wg set wg0 private-key /k listen-port 51820 peer $B_PUB allowed-ips 10.9.0.2/32,fd00::2/128 endpoint $B_IP:51820"
A 'ip addr add 10.9.0.1/24 dev wg0; ip addr add fd00::1/64 dev wg0; ip link set wg0 up'

echo "== kernel wireguard in b"
B "ip link add wg0 type wireguard; wg set wg0 private-key /k listen-port 51820 peer $A_PUB allowed-ips 10.9.0.1/32,fd00::1/128 endpoint $A_IP:51820"
B 'ip addr add 10.9.0.2/24 dev wg0; ip addr add fd00::2/64 dev wg0; ip link set wg0 up'

echo "== ping a -> b (v4, v6, 1300-byte payload)"
A 'ping -c 3 -W 2 10.9.0.2' | tail -2
A 'ping -6 -c 2 -W 2 fd00::2' | tail -2
A 'ping -c 3 -W 2 -s 1300 10.9.0.2' | tail -2
echo "== ping b -> a"
B 'ping -c 3 -W 2 10.9.0.1' | tail -2

echo "== update the existing peer live: preshared key and keepalive on both sides"
PSK=$(A 'umask 077; wg genpsk | tee /psk'); B "umask 077; echo $PSK > /psk"
A "wg set wg0 peer $B_PUB preshared-key /psk persistent-keepalive 5"
B "wg set wg0 peer $A_PUB preshared-key /psk"
# Drop the kernel side's session: b initiates a handshake that only succeeds if a uses the
# new preshared key.
B "ip link set wg0 down; ip link set wg0 up"
B 'ping -c 3 -W 3 10.9.0.1' | tail -2
echo "== mismatched preshared key must fail"
B 'umask 077; wg genpsk > /psk2'
B "wg set wg0 peer $A_PUB preshared-key /psk2; ip link set wg0 down; ip link set wg0 up"
if B 'ping -c 2 -W 2 10.9.0.1' >/dev/null; then echo "UNEXPECTED: handshake with a wrong psk succeeded"; exit 1; else echo "handshake rejected as expected"; fi
B "wg set wg0 peer $A_PUB preshared-key /psk; ip link set wg0 down; ip link set wg0 up"
B 'ping -c 2 -W 3 10.9.0.1' | tail -1

echo "== replace allowed IPs on a"
A "wg set wg0 peer $B_PUB allowed-ips 10.9.0.2/32"
A 'wg show wg0 allowed-ips'
A 'ping -c 2 -W 2 10.9.0.2' | tail -1

echo "== the UAPI reports the handshake as wall-clock time"
A 'wg show wg0 latest-handshakes' | awk -v now="$(date +%s)" '{ if (now - $2 > 60) { print "UNEXPECTED: " $0; exit 1 } }'
echo "== wg show (a)"
A 'wg show wg0' | sed 's/^/  /'
echo "PASS"
