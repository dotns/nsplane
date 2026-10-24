#!/usr/bin/env bash
# The standard WireGuard peer of vm-wireguard.sh, run in its own container (NET_ADMIN and
# /dev/net/tun): wireguard-go on wg0 with 10.66.0.1/24, an address behind it (10.66.1.1/24)
# and fd66::1/64, MTU 1420, and one-line TCP responders on ports 7 and 8 that answer
# `peer <port> <line>`.
#
#   vm-wireguard-peer.sh up <work dir>      keys in the work dir, wg0 up, then sleeps
#   vm-wireguard-peer.sh probe              reaches the guest: ping, TCP 2222 (allowed),
#                                           TCP 2223 (blocked), then `finish` to 2222
set -euo pipefail

up() {
  local work=$1
  umask 077
  wg genkey >"$work/peer.key"
  wg pubkey <"$work/peer.key" >"$work/peer.pub"
  wg genkey >"$work/vm.key"
  wg pubkey <"$work/vm.key" >"$work/vm.pub"
  umask 022
  chmod 644 "$work/vm.key"

  wireguard-go -f wg0 >"$work/wireguard-go.log" 2>&1 &
  for _ in $(seq 1 100); do
    [ -S /var/run/wireguard/wg0.sock ] && break
    sleep 0.1
  done
  wg set wg0 private-key "$work/peer.key" listen-port 51820 \
    peer "$(cat "$work/vm.pub")" allowed-ips 10.66.0.2/32,fd66::/64
  ip addr add 10.66.0.1/24 dev wg0
  ip addr add 10.66.1.1/24 dev wg0
  ip addr add fd66::1/64 dev wg0
  ip link set wg0 mtu 1420 up

  for port in 7 8; do
    printf '#!/bin/sh\nread -r line\necho "peer %s $line"\n' "$port" >/answer-$port
    chmod 755 /answer-$port
    busybox nc -ll -p "$port" -e /answer-$port &
  done
  echo "peer up: $(wireguard-go --version | head -1)"
  touch "$work/peer.up"
  sleep infinity
}

probe() {
  local status=0 reply
  ping -c 3 -W 2 10.66.0.2 || { echo "PROBE-FAIL ping 10.66.0.2"; status=1; }
  reply=$(echo "hello from the peer" | busybox nc -w 5 10.66.0.2 2222 || true)
  echo "TCP 10.66.0.2 port 2222 reply: $reply"
  [ "$reply" = "guest 2222 hello from the peer" ] || { echo "PROBE-FAIL TCP 2222"; status=1; }
  reply=$(echo "hello from the peer" | busybox nc -w 5 10.66.0.2 2223 || true)
  echo "TCP 10.66.0.2 port 2223 reply: '$reply'"
  [ -z "$reply" ] || { echo "PROBE-FAIL TCP 2223 passed the ACL"; status=1; }
  echo finish | busybox nc -w 5 10.66.0.2 2222 || true
  wg show wg0
  [ "$status" = 0 ] && echo "PROBE-OK"
  return "$status"
}

case ${1:-} in
  up) up "$2" ;;
  probe) probe ;;
  *) echo "usage: $0 up <work dir> | probe" >&2; exit 2 ;;
esac
