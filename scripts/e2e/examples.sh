#!/usr/bin/env bash
# Examples end-to-end test: the nsplane-examples binaries run as the design's
# "Presentation x transport" scenarios (docs/design.md §5), against each other and against
# kernel WireGuard, each node in its own sibling container.
#
# Matrix cells (`cell <row> <transport> <case>...`) and scenarios (`scenario <name>`) record
# PASS/FAIL; the run ends with the matrix and the scenario list and fails if anything failed.
# Rows: TUN, netstack, bridge(fd), bridge(channel); columns: direct UDP, and the single-port
# relay (relay_server) over UDP and over WSS with the direct path blocked. Scenarios add
# native kernel WireGuard through the relay, NAT hole punching behind MASQUERADE routers,
# the direct/relay ladder, plain WireGuard servers under the relay extension, the NAT
# examples (IPv4-only clients reaching an IPv6-only peer through translate_node, and a
# service published through port_map), and the offload and non-offload TUN/UDP paths
# (iperf3 throughput, --no-offload fallback).
# Needs docker and the `wireguard` kernel module on the host; nothing on the host is
# reconfigured. The release example binaries are built in the dev image unless
# NSPLANE_E2E_EX_BIN_DIR names a directory holding them.
#
#   scripts/e2e/examples.sh
#   NSPLANE_E2E_EX_ONLY='acl|hybrid' scripts/e2e/examples.sh   # cases whose id matches
#   NSPLANE_E2E_IPERF_REPS=3 NSPLANE_E2E_IPERF_RATE=2G   # offload_iperf: runs per rate, UDP -b
set -euo pipefail
cd "$(dirname "$0")/../.."
PREFIX=${NSPLANE_E2E_EX_PREFIX:-nsplane-e2e-ex-$$}
ONLY=${NSPLANE_E2E_EX_ONLY:-}
IPERF_REPS=${NSPLANE_E2E_IPERF_REPS:-1}
IPERF_RATE=${NSPLANE_E2E_IPERF_RATE:-0}
DEV_IMAGE=${NSPLANE_E2E_EX_DEV_IMAGE:-ai-agent/nstun-dev}
NET=$PREFIX-net
IMG=$PREFIX-image
LABEL=nsplane-e2e-ex=$PREFIX
LABELS=(--label ai-agent=true --label "$LABEL")
EXAMPLES=(udp_pair tun_node netstack_node hybrid acl_gateway fd_bridge events_stats relay_server app_session
  translate_node port_map)
PORT=51820
WSS_PORT=8443

cleanup() {
  docker ps -aq --filter "label=$LABEL" | xargs -r docker rm -f >/dev/null 2>&1 || true
  docker network ls -q --filter "label=$LABEL" | xargs -r docker network rm >/dev/null 2>&1 || true
  docker image rm "$IMG" >/dev/null 2>&1 || true
}
trap cleanup EXIT
trap 'exit 130' INT TERM

if [ -z "${NSPLANE_E2E_EX_BIN_DIR:-}" ]; then
  echo "== build the examples in $DEV_IMAGE"
  NSPLANE_E2E_EX_BIN_DIR=$(docker run --rm "${LABELS[@]}" --name "$PREFIX-build" -v "$PWD:$PWD" -w "$PWD" \
    -v nstun-cargo-registry:/usr/local/cargo/registry "$DEV_IMAGE" \
    cargo build -p nsplane-examples --release --bins --locked --message-format=json \
    | jq -r 'select(.reason == "compiler-artifact" and .target.name == "tun_node" and .executable != null) | .executable' \
    | xargs -r dirname)
fi
MOUNTS=()
for bin in "${EXAMPLES[@]}"; do
  if [ ! -x "${NSPLANE_E2E_EX_BIN_DIR:-}/$bin" ]; then echo "no example binary: '${NSPLANE_E2E_EX_BIN_DIR:-}/$bin'"; exit 1; fi
  MOUNTS+=(-v "$NSPLANE_E2E_EX_BIN_DIR/$bin:/usr/local/bin/$bin:ro")
done

docker build -q "${LABELS[@]}" -t "$IMG" scripts/e2e >/dev/null
docker network create "${LABELS[@]}" "$NET" >/dev/null

# --- helpers: containers ----------------------------------------------------------------
# Containers are named $PREFIX-$CASE-<name>; `X <name> <cmd>` runs a command in one.
CASE=
ctr() { echo "$PREFIX-$CASE-$1"; }
X() { local c; c=$(ctr "$1"); shift; docker exec "$c" bash -c "$*"; }
# put <ctr> <path>: writes stdin to a file in the container, atomically.
put() { docker exec -i "$(ctr "$1")" bash -c "cat > $2.tmp && mv $2.tmp $2"; }
# start_on <network> <name> [docker run args]...: a container on <network> with a fresh key
# pair in /k (private) and /p (public).
start_on() {
  local net=$1 name=$2; shift 2
  docker run -d --rm "${LABELS[@]}" --label "nsplane-e2e-ex-case=$CASE" --name "$(ctr "$name")" \
    --network "$net" --cap-add NET_ADMIN --device /dev/net/tun -e NO_COLOR=1 \
    --sysctl net.ipv6.conf.all.disable_ipv6=0 "$@" "${MOUNTS[@]}" "$IMG" sleep infinity >/dev/null
  X "$name" 'umask 077; wg genkey > /k; wg pubkey < /k > /p'
}
# start <name>...: a container per name on the shared network.
start() {
  local name
  for name in "$@"; do start_on "$NET" "$name"; done
}
pub() { X "$1" 'cat /p'; }
ip_of() { docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$(ctr "$1")"; }
# ip_on <ctr> <network>: the container's address on one of its networks.
ip_on() { docker inspect -f "{{(index .NetworkSettings.Networks \"$2\").IPAddress}}" "$(ctr "$1")"; }
# case_net <name>: creates an internal network of the current case and prints its name.
case_net() {
  local net
  net=$(ctr "$1")
  docker network create --internal "${LABELS[@]}" --label "nsplane-e2e-ex-case=$CASE" "$net" >/dev/null
  echo "$net"
}
# The containers of the current case: dump their logs and status files, then remove them.
case_containers() { docker ps -aq --filter "label=nsplane-e2e-ex-case=$CASE" --filter "label=$LABEL"; }
dump() {
  local c
  for c in $(case_containers); do
    echo "---- $(docker inspect -f '{{.Name}}' "$c")"
    docker exec "$c" bash -c 'for f in /*.log /*.json; do [ -e "$f" ] && { echo "-- $f"; cat "$f"; echo; }; done
      echo "-- wg show"; wg show all 2>&1; echo "-- ip addr"; ip -brief addr' 2>&1 | sed 's/^/  /' || true
  done
}
remove_case() {
  case_containers | xargs -r docker rm -f >/dev/null 2>&1 || true
  docker network ls -q --filter "label=nsplane-e2e-ex-case=$CASE" --filter "label=$LABEL" \
    | xargs -r docker network rm >/dev/null 2>&1 || true
}

# --- helpers: nodes ---------------------------------------------------------------------
# node <ctr> <example> <args>...: starts an example detached with the container's key and a
# status file; stdout and stderr go to /<example>.log, the status to /<example>.json.
node() {
  local name=$1 bin=$2; shift 2
  local cmd
  cmd=$(printf '%q ' "$bin" --private-key-file /k --status-file "/$bin.json" "$@")
  docker exec -d "$(ctr "$name")" bash -c "echo \$\$ > /$bin.pid; exec $cmd > /$bin.log 2>&1"
}
# node_stop <ctr> <example>: Ctrl-C, then wait for it to exit.
node_stop() { X "$1" "pid=\$(cat /$2.pid); kill -INT \$pid; for i in \$(seq 1 50); do kill -0 \$pid 2>/dev/null || exit 0; sleep 0.1; done; exit 1"; }
# run_fg <ctr> <cmd>...: runs a command to completion with its output in /<cmd>.log.
run_fg() { local name=$1 bin=$2; shift; X "$name" "$(printf '%q ' "$@") > /$bin.log 2>&1"; }
# wait_status <ctr> <example> <jq filter> [secs]: polls the status file until the filter holds.
wait_status() {
  local i
  for i in $(seq 1 $(( ${4:-20} * 2 ))); do
    X "$1" "cat /$2.json 2>/dev/null" | jq -e "$3" >/dev/null 2>&1 && return 0
    sleep 0.5
  done
  echo "status of $2 in $1: '$3' does not hold"; return 1
}
# wait_log <ctr> <example> <regex> [secs]: polls the log until a line matches.
wait_log() {
  local i
  for i in $(seq 1 $(( ${4:-40} * 2 ))); do
    X "$1" "grep -Eq '$3' /$2.log" && return 0
    sleep 0.5
  done
  echo "log of $2 in $1: no line matches '$3'"; return 1
}
# kernel_wg <ctr> <cidr> <peer pubkey> <peer ip> <allowed ips> [route]...: a plain kernel
# WireGuard peer on wg0 (persistent keepalive, so it initiates the handshake).
kernel_wg() {
  local name=$1 cidr=$2 peer=$3 ip=$4 allowed=$5; shift 5
  X "$name" "ip link add wg0 type wireguard
    wg set wg0 private-key /k listen-port $PORT peer $peer allowed-ips $allowed endpoint $ip:$PORT persistent-keepalive 2
    ip addr add $cidr dev wg0; ip link set wg0 up"
  local route
  for route in "$@"; do X "$name" "ip route add $route dev wg0"; done
}
# echo_server <ctr> [port]: TCP and UDP echo with socat on the container's kernel stack.
echo_server() {
  local port=${2:-7}
  docker exec -d "$(ctr "$1")" bash -c "socat TCP4-LISTEN:$port,fork,reuseaddr PIPE > /socat-$port.log 2>&1 &
    socat UDP4-RECVFROM:$port,fork PIPE >> /socat-$port.log 2>&1 & wait"
}
# echo_try <ctr> <tcp|udp> <ip> <port>: one socat echo round trip through the kernel stack.
echo_try() {
  local payload out family=4 ip=$3
  [[ $ip == *:* ]] && { family=6; ip="[$ip]"; }
  payload="nsplane-e2e-$2-$RANDOM$RANDOM"
  out=$(X "$1" "printf %s $payload | timeout 4 socat -t 1 - ${2^^}$family:$ip:$4" 2>/dev/null) || true
  [ "$out" = "$payload" ]
}
# echo_check <ctr> <proto> <ip> <port> [tries]: the echo works (retried while handshaking).
echo_check() {
  local i
  for i in $(seq 1 "${5:-15}"); do
    if echo_try "$1" "$2" "$3" "$4"; then echo "  ok  $1: $2 echo $3:$4"; return 0; fi
    sleep 0.5
  done
  echo "  FAIL $1: $2 echo $3:$4"; return 1
}
# echo_denied <ctr> <proto> <ip> <port>: the echo does not work.
echo_denied() {
  if echo_try "$1" "$2" "$3" "$4"; then echo "  FAIL $1: $2 echo $3:$4 passed"; return 1; fi
  echo "  ok  $1: $2 echo $3:$4 blocked"
}
# ping_check <ctr> <ip>: three replies within 15 s.
ping_check() {
  if X "$1" "ping -c 3 -i 0.3 -w 15 $2" >/dev/null; then echo "  ok  $1: ping $2"; else echo "  FAIL $1: ping $2"; return 1; fi
}
# checks_pass <ctr> <example>: the example's --checks all passed.
checks_pass() {
  wait_log "$1" "$2" '^CHECKS (PASS|FAIL)'
  if X "$1" "grep -q '^CHECKS PASS' /$2.log"; then echo "  ok  $1: $2 CHECKS PASS"; else echo "  FAIL $1: $2 CHECKS FAIL"; return 1; fi
}

# --- results ----------------------------------------------------------------------------
declare -A CELL=()
SCENARIOS=()
FAILED=0
# run_case <id> <function> [args]...: runs a case unless NSPLANE_E2E_EX_ONLY excludes it and
# sets RESULT to PASS, FAIL or - (skipped). Never called as a condition: that would turn
# `set -e` off inside the case.
RESULT=-
run_case() {
  local id=$1; shift
  RESULT=-
  if [ -n "$ONLY" ] && ! [[ $id =~ $ONLY ]]; then return 0; fi
  CASE=${id//[^a-z0-9]/-}
  echo "== $id"
  local rc=0
  set +e; ( set -e; "$@" ); rc=$?; set -e
  if [ "$rc" -ne 0 ]; then RESULT=FAIL; dump; FAILED=1; else RESULT=PASS; fi
  echo "== $id $RESULT"
  remove_case
}
# cell <row> <transport> <case>...: a matrix cell; PASS iff every case function passes.
cell() {
  local row=$1 transport=$2 result=- name; shift 2
  for name in "$@"; do
    run_case "$row/$transport/$name" "case_$name" "$transport"
    case $RESULT in
      PASS) [ "$result" = FAIL ] || result=PASS ;;
      FAIL) result=FAIL ;;
    esac
  done
  [ "$result" = - ] || CELL[$row/$transport]=$result
}
# scenario <name>: a scenario outside the matrix, case function scenario_<name>.
scenario() {
  run_case "scenario/$1" "scenario_$1"
  [ "$RESULT" = - ] || SCENARIOS+=("$1 $RESULT")
}
report() {
  local rows=(tun netstack fd channel) row_names=(TUN netstack "bridge(fd)" "bridge(channel)")
  local cols=(udp relay-udp relay-wss) i col line
  echo
  printf '%-16s %-10s %-10s %-10s\n' "" UDP "relay UDP" "relay WSS"
  for i in "${!rows[@]}"; do
    line=$(printf '%-16s' "${row_names[$i]}")
    for col in "${cols[@]}"; do line+=$(printf ' %-10s' "${CELL[${rows[$i]}/$col]:--}"); done
    echo "$line"
  done
  echo
  echo "scenarios:"
  for line in "${SCENARIOS[@]}"; do echo "  $line"; done
}

# --- cases: UDP column ------------------------------------------------------------------
# Overlay: 10.0.0.1 is the example under test, 10.0.0.2 its peer.

# tun_node <-> tun_node: example echo and checks on one side, socat on the other, ping, UAPI.
case_tun_pair() {
  start a b
  local a_pub b_pub a_ip b_ip
  a_pub=$(pub a); b_pub=$(pub b); a_ip=$(ip_of a); b_ip=$(ip_of b)
  echo_server b
  node a tun_node --address 10.0.0.1/24 --peer "$b_pub,endpoint=$b_ip:$PORT,allowed-ips=10.0.0.2/32" \
    --echo-port 7 --check tcp:10.0.0.2:7 --check udp:10.0.0.2:7
  node b tun_node --address 10.0.0.2/24 --peer "$a_pub,endpoint=$a_ip:$PORT,allowed-ips=10.0.0.1/32" \
    --check tcp:10.0.0.1:7 --check udp:10.0.0.1:7
  checks_pass a tun_node
  checks_pass b tun_node
  echo_check b tcp 10.0.0.1 7; echo_check b udp 10.0.0.1 7
  echo_check a tcp 10.0.0.2 7; echo_check a udp 10.0.0.2 7
  ping_check a 10.0.0.2; ping_check b 10.0.0.1
  X a 'wg show nsp0 peers' | grep -qxF "$b_pub"
  X a 'wg show nsp0 latest-handshakes' | awk '$2 == 0 { exit 1 }'
  echo "  ok  a: wg show nsp0 lists the peer with a handshake"
}

# <example> <-> kernel WireGuard: example echo and checks, socat on the kernel peer, ping.
kernel_peer() {
  local bin=$1; shift
  start a k
  local a_pub k_pub a_ip k_ip
  a_pub=$(pub a); k_pub=$(pub k); a_ip=$(ip_of a); k_ip=$(ip_of k)
  echo_server k
  node a "$bin" "$@" --address 10.0.0.1/24 --peer "$k_pub,endpoint=$k_ip:$PORT,allowed-ips=10.0.0.2/32" \
    --echo-port 7 --check tcp:10.0.0.2:7 --check udp:10.0.0.2:7
  kernel_wg k 10.0.0.2/24 "$a_pub" "$a_ip" 10.0.0.1/32
  checks_pass a "$bin"
  echo_check k tcp 10.0.0.1 7; echo_check k udp 10.0.0.1 7
  ping_check a 10.0.0.2; ping_check k 10.0.0.1
  X a 'wg show nsp0 peers' | grep -qxF "$k_pub"
  echo "  ok  a: wg show nsp0 lists the peer"
}
case_tun_kernel() { kernel_peer tun_node; }
case_fd_kernel() { kernel_peer fd_bridge --mode fd; }

# netstack_node <-> netstack_node: echo on a, checks from b (exit after the checks).
case_netstack_pair() {
  start a b
  local a_pub b_pub a_ip b_ip
  a_pub=$(pub a); b_pub=$(pub b); a_ip=$(ip_of a); b_ip=$(ip_of b)
  node a netstack_node --address 10.0.0.1/24 --peer "$b_pub,endpoint=$b_ip:$PORT,allowed-ips=10.0.0.2/32" --echo-port 7
  run_fg b netstack_node --private-key-file /k --status-file /netstack_node.json --address 10.0.0.2/24 \
    --peer "$a_pub,endpoint=$a_ip:$PORT,allowed-ips=10.0.0.1/32" \
    --check tcp:10.0.0.1:7 --check udp:10.0.0.1:7 --exit-after-checks
  X b 'grep -q "^CHECKS PASS" /netstack_node.log'
  echo "  ok  b: netstack_node CHECKS PASS, exit 0"
}

# netstack_node <-> kernel WireGuard: kernel socat client -> netstack echo, netstack checks
# -> kernel socat echo.
case_netstack_kernel() {
  start a k
  local a_pub k_pub a_ip k_ip
  a_pub=$(pub a); k_pub=$(pub k); a_ip=$(ip_of a); k_ip=$(ip_of k)
  echo_server k
  node a netstack_node --address 10.0.0.1/24 --peer "$k_pub,endpoint=$k_ip:$PORT,allowed-ips=10.0.0.2/32" \
    --echo-port 7 --check tcp:10.0.0.2:7 --check udp:10.0.0.2:7
  kernel_wg k 10.0.0.2/24 "$a_pub" "$a_ip" 10.0.0.1/32
  checks_pass a netstack_node
  echo_check k tcp 10.0.0.1 7; echo_check k udp 10.0.0.1 7
}

# fd_bridge --mode channel <-> tun_node: example echo and checks on the bridge, socat on the
# TUN node, ping both ways.
case_channel_tun() {
  start a b
  local a_pub b_pub a_ip b_ip
  a_pub=$(pub a); b_pub=$(pub b); a_ip=$(ip_of a); b_ip=$(ip_of b)
  echo_server b
  node a fd_bridge --mode channel --address 10.0.0.1/24 --peer "$b_pub,endpoint=$b_ip:$PORT,allowed-ips=10.0.0.2/32" \
    --echo-port 7 --check tcp:10.0.0.2:7 --check udp:10.0.0.2:7
  node b tun_node --address 10.0.0.2/24 --peer "$a_pub,endpoint=$a_ip:$PORT,allowed-ips=10.0.0.1/32"
  checks_pass a fd_bridge
  echo_check b tcp 10.0.0.1 7; echo_check b udp 10.0.0.1 7
  echo_check a tcp 10.0.0.2 7; echo_check a udp 10.0.0.2 7
  ping_check a 10.0.0.2; ping_check b 10.0.0.1
}

# --- helpers: relay ---------------------------------------------------------------------
# Overlay: 10.0.0.254 is the relay's own engine.

# mkey <ctr>...: a machine key in /m, its public key in /m.pub.
mkey() {
  local name
  for name in "$@"; do X "$name" 'relay_server gen-machine-key /m > /m.pub'; done
}
# relay_conf <pinned>... [+ <static>...]: a relay config pinning the machine keys of the
# containers before `+` and relaying to the ones after it at their <ip>:$PORT.
relay_conf() {
  local name static=0 entries=()
  for name in "$@"; do
    if [ "$name" = + ]; then static=1; continue; fi
    if [ "$static" -eq 0 ]; then
      entries+=("$(jq -nc --arg m "$(X "$name" 'cat /m.pub')" --arg w "$(pub "$name")" \
        '{pin: {machine_key: $m, wg_public_key: $w}}')")
    else
      entries+=("$(jq -nc --arg w "$(pub "$name")" --arg e "$(ip_of "$name"):$PORT" \
        '{static: {wg_public_key: $w, endpoint: $e}}')")
    fi
  done
  printf '%s\n' "${entries[@]}" \
    | jq -s '{machine_keys: map(.pin // empty), static_targets: map(.static // empty)}'
}
# relay_up <ctr> [args]...: relay_server with /relay.json (on stdin), own engine 10.0.0.254.
relay_up() {
  local name=$1; shift
  put "$name" /relay.json
  node "$name" relay_server --address 10.0.0.254/24 --config /relay.json "$@"
  wait_status "$name" relay_server '.extra.relay.counters'
}
# relay_counter <ctr> <counter>: one of the relay's counters now.
relay_counter() { X "$1" 'cat /relay_server.json' | jq ".extra.relay.counters.$2"; }
# relay_client <transport> <relay ip>: sets CLIENT (the node flags of relay-udp or relay-wss)
# and RELAY_EP (the endpoint of peers reached through the relay).
CLIENT=()
RELAY_EP=
relay_client() {
  case $1 in
    relay-udp)
      RELAY_EP=$2:$PORT
      CLIENT=(--transport relay --relay "$RELAY_EP" --machine-key-file /m) ;;
    relay-wss)
      RELAY_EP=$2:$WSS_PORT
      CLIENT=(--transport wss --relay-url "wss://relay.example:$WSS_PORT/" --relay-addr "$RELAY_EP"
        --relay-ca /relay.pem --machine-key-file /m) ;;
    *) echo "unknown relay transport '$1'"; return 1 ;;
  esac
}
# capable <ctr> <example> <endpoint>: the node discovered the endpoint as a capable relay.
capable() {
  wait_status "$1" "$2" ".extra.relay.endpoints[\"$3\"].state == \"capable\"" 30
  echo "  ok  $1: relay $3 capable"
}
# block <ctr> <ip>...: drops everything between the container and the addresses.
block() {
  local name=$1 ip; shift
  for ip in "$@"; do X "$name" "iptables -I INPUT -s $ip -j DROP; iptables -I OUTPUT -d $ip -j DROP"; done
}
# echo_rounds <ctr> <ip> <port> <rounds> <file>: TCP and UDP echo rounds run inside the
# container in the background; the number of failed ones goes to <file> at the end.
echo_rounds() {
  docker exec -d "$(ctr "$1")" bash -c "f=0; for i in \$(seq 1 $4); do for p in TCP4 UDP4; do
      s=e\$i\$RANDOM; o=\$(printf %s \$s | timeout 4 socat -t 1 - \$p:$2:$3) || true
      [ \"\$o\" = \"\$s\" ] || f=\$((f+1)); done; done; echo \$f > $5.tmp; mv $5.tmp $5"
}
# wait_file <ctr> <path> [secs]: waits until the file exists and prints it.
wait_file() {
  local i
  for i in $(seq 1 $(( ${3:-30} * 2 ))); do
    X "$1" "cat $2 2>/dev/null" && return 0
    sleep 0.5
  done
  echo "no $2 in $1" >&2; return 1
}

# --- cases: relay columns ---------------------------------------------------------------
# relay_pair <transport> <example> [args]...: the example under test (a, 10.0.0.1) and a
# tun_node (b, 10.0.0.2) reach each other only through relay_server (r): both are pinned
# and register, their peer endpoint is the relay, direct traffic between them is dropped.
# Example checks and echo on a, socat both ways, ping where a has a TUN; the relay's
# counters (and with WSS both carriers' counters) show the traffic went through it.
relay_pair() {
  local transport=$1 bin=$2; shift 2
  start r a b
  local a_pub b_pub r_ip a_ip b_ip
  a_pub=$(pub a); b_pub=$(pub b); r_ip=$(ip_of r); a_ip=$(ip_of a); b_ip=$(ip_of b)
  mkey a b
  local wss=()
  [ "$transport" = relay-wss ] && wss=(--wss-listen "$r_ip:$WSS_PORT" --wss-cert-out /relay.pem)
  relay_conf a b | relay_up r "${wss[@]}"
  if [ "$transport" = relay-wss ]; then
    X r 'cat /relay.pem' | put a /relay.pem
    X r 'cat /relay.pem' | put b /relay.pem
  fi
  block a "$b_ip"; block b "$a_ip"
  relay_client "$transport" "$r_ip"
  echo_server b
  node b tun_node "${CLIENT[@]}" --address 10.0.0.2/24 --peer "$a_pub,endpoint=$RELAY_EP,allowed-ips=10.0.0.1/32"
  capable b tun_node "$RELAY_EP"
  node a "$bin" "$@" "${CLIENT[@]}" --address 10.0.0.1/24 --peer "$b_pub,endpoint=$RELAY_EP,allowed-ips=10.0.0.2/32" \
    --echo-port 7 --check tcp:10.0.0.2:7 --check udp:10.0.0.2:7
  capable a "$bin" "$RELAY_EP"
  checks_pass a "$bin"
  echo_check b tcp 10.0.0.1 7; echo_check b udp 10.0.0.1 7
  if [ "$bin" != netstack_node ]; then
    echo_check a tcp 10.0.0.2 7; echo_check a udp 10.0.0.2 7
    ping_check a 10.0.0.2; ping_check b 10.0.0.1
  fi
  wait_status r relay_server '.extra.relay.counters | .forwarded > 0 and .registrations >= 2 and .dropped_ambiguous == 0' 5
  echo "  ok  r: forwarded $(relay_counter r forwarded), registrations $(relay_counter r registrations), 0 ambiguous"
  wait_status a "$bin" ".peers[0].endpoint == \"$RELAY_EP\"" 5
  wait_status b tun_node ".peers[0].endpoint == \"$RELAY_EP\"" 5
  echo "  ok  a, b: the peer's endpoint is the relay $RELAY_EP"
  if [ "$transport" = relay-wss ]; then
    wait_status r relay_server '.extra.wss | .connections == 2 and .rx > 0 and .tx > 0' 5
    wait_status a "$bin" '.extra.wss | .connected and .tx > 0 and .rx > 0' 5
    wait_status b tun_node '.extra.wss | .connected and .tx > 0 and .rx > 0' 5
    echo "  ok  r, a, b: datagrams carried over WSS"
  fi
}
case_relay_tun() { relay_pair "$1" tun_node; }
case_relay_netstack() { relay_pair "$1" netstack_node; }
case_relay_fd() { relay_pair "$1" fd_bridge --mode fd; }
case_relay_channel() { relay_pair "$1" fd_bridge --mode channel; }

# --- scenarios: relay -------------------------------------------------------------------
# native_wg <keepalive 0|1>: relay r, provider tun_node p (pinned, registered, 10.0.0.1),
# native kernel WireGuard k (10.0.0.2, a static target of the relay) with p behind the
# relay and the relay's own engine as peers, both at the relay's one port; direct traffic
# between k and p is dropped. With keepalive k initiates, without it k stays silent.
native_wg() {
  start r p k
  local p_pub k_pub r_pub r_ip p_ip k_ip keepalive=
  p_pub=$(pub p); k_pub=$(pub k); r_pub=$(pub r); r_ip=$(ip_of r); p_ip=$(ip_of p); k_ip=$(ip_of k)
  [ "$1" -eq 1 ] && keepalive="persistent-keepalive 2"
  mkey p
  relay_conf p + k | relay_up r --peer "$k_pub,allowed-ips=10.0.0.2/32" --echo-port 7
  block p "$k_ip"; block k "$p_ip"
  echo_server k
  local checks=()
  [ "$1" -eq 0 ] && checks=(--check tcp:10.0.0.2:7 --check udp:10.0.0.2:7)
  node p tun_node --transport relay --relay "$r_ip:$PORT" --machine-key-file /m --address 10.0.0.1/24 \
    --peer "$k_pub,endpoint=$r_ip:$PORT,allowed-ips=10.0.0.2/32" --echo-port 7 "${checks[@]}"
  capable p tun_node "$r_ip:$PORT"
  wait_status r relay_server '.extra.relay.counters.registrations >= 1' 10
  X k "ip link add wg0 type wireguard
    wg set wg0 private-key /k listen-port $PORT \
      peer $p_pub allowed-ips 10.0.0.1/32 endpoint $r_ip:$PORT $keepalive \
      peer $r_pub allowed-ips 10.0.0.254/32 endpoint $r_ip:$PORT $keepalive
    ip addr add 10.0.0.2/24 dev wg0; ip link set wg0 up"
}

# Native client -> relay -> provider, and the relay's own engine on the same port at once.
scenario_native_wg() {
  native_wg 1
  echo_check k tcp 10.0.0.1 7; echo_check k udp 10.0.0.1 7
  ping_check k 10.0.0.1; ping_check p 10.0.0.2
  echo_check k tcp 10.0.0.254 7; echo_check k udp 10.0.0.254 7
  echo "  -- coexistence: the provider and the relay's own engine concurrently"
  local own fwd
  own=$(relay_counter r own_engine); fwd=$(relay_counter r forwarded)
  echo_rounds k 10.0.0.1 7 20 /rounds-provider
  echo_rounds k 10.0.0.254 7 20 /rounds-relay
  local provider relay
  provider=$(wait_file k /rounds-provider 120); relay=$(wait_file k /rounds-relay 120)
  [ "$provider" = 0 ] || { echo "  FAIL k: $provider of 40 echo rounds to the provider failed"; return 1; }
  [ "$relay" = 0 ] || { echo "  FAIL k: $relay of 40 echo rounds to the relay's engine failed"; return 1; }
  echo "  ok  k: 40/40 echo rounds each to the provider and to the relay's engine"
  wait_status r relay_server ".extra.relay.counters | .own_engine > $own and .forwarded > $fwd and .dropped_ambiguous == 0" 5
  echo "  ok  r: own_engine $own -> $(relay_counter r own_engine), forwarded $fwd -> $(relay_counter r forwarded), 0 ambiguous"
  X k 'wg show wg0 latest-handshakes' | awk '$2 == 0 { exit 1 }'
  echo "  ok  k: handshakes with both peers"
}

# Provider -> relay -> native client: the native client never sends first, the provider's
# checks open the session through the relay's static target.
scenario_native_wg_reverse() {
  native_wg 0
  checks_pass p tun_node
  X k "wg show wg0 latest-handshakes" | grep -F "$(pub p)" | awk '$2 == 0 { exit 1 }'
  echo "  ok  k: handshake initiated by the provider"
  echo_check k tcp 10.0.0.1 7; echo_check k udp 10.0.0.1 7
  ping_check p 10.0.0.2; ping_check k 10.0.0.1
  wait_status r relay_server ".extra.relay.counters | .forwarded > 0 and .dropped_ambiguous == 0" 5
  wait_status r relay_server ".extra.relay.targets | any(.source == \"$(ip_of k):$PORT\")" 5
  echo "  ok  r: forwarded $(relay_counter r forwarded) to the static target, 0 ambiguous"
}

# ladder <example> <nat 0|1>: nodes a (the example, 10.0.0.1) and b (tun_node, 10.0.0.2)
# with the relay as the peer endpoint and each other's reflexive address (copied by the
# harness from --reflexive-out to --peer-candidates) as direct candidate. The direct path
# goes up first, blocking it falls back to the relay, unblocking returns to direct; echo in
# every phase. With nat each node sits on its own internal network behind a router doing
# MASQUERADE, the relay on the shared network, and the routers block the direct path.
ladder() {
  local bin=$1 nat=$2
  start r
  local r_ip a_ip b_ip ra_pub rb_pub
  r_ip=$(ip_of r)
  if [ "$nat" -eq 1 ]; then
    local name net
    for name in a b; do
      net=$(case_net "net-$name")
      start_on "$NET" "r$name" --sysctl net.ipv4.ip_forward=1
      docker network connect "$net" "$(ctr "r$name")"
      local subnet out gw
      subnet=$(docker network inspect -f '{{(index .IPAM.Config 0).Subnet}}' "$net")
      out=$(X "r$name" "ip -o route get $r_ip" | sed -n 's/.* dev \([^ ]*\).*/\1/p')
      # Unsolicited datagrams to the router are dropped, as a NAT does, so they leave no
      # conntrack entry that would make the router remap the node's port.
      X "r$name" "iptables -t nat -A POSTROUTING -s $subnet -o $out -j MASQUERADE
        iptables -A INPUT -i $out -p udp -j DROP"
      start_on "$net" "$name"
      gw=$(ip_on "r$name" "$net")
      X "$name" "ip route replace default via $gw"
    done
    ra_pub=$(ip_on ra "$NET"); rb_pub=$(ip_on rb "$NET")
  else
    start a b
    a_ip=$(ip_of a); b_ip=$(ip_of b)
  fi
  local a_pub b_pub
  a_pub=$(pub a); b_pub=$(pub b)
  mkey a b
  relay_conf a b | relay_up r
  local client=(--transport relay --relay "$r_ip:$PORT" --machine-key-file /m --peer-candidates /candidates.json
    --reflexive-out /reflexive.json --probe-backoff-ms 500 --register-interval-ms 5000
    --reflexive-interval-ms 5000 --direct-timeout-ms 2000 --direct-probe-interval-ms 3000)
  echo_server b
  node a "$bin" "${client[@]}" --address 10.0.0.1/24 --peer "$b_pub,endpoint=$r_ip:$PORT,allowed-ips=10.0.0.2/32,keepalive=1" \
    --echo-port 7
  node b tun_node "${client[@]}" --address 10.0.0.2/24 --peer "$a_pub,endpoint=$r_ip:$PORT,allowed-ips=10.0.0.1/32,keepalive=1"
  local a_refl b_refl
  a_refl=$(wait_file a /reflexive.json | jq -r .reflexive); b_refl=$(wait_file b /reflexive.json | jq -r .reflexive)
  echo "  ok  reflexive: a $a_refl, b $b_refl"
  if [ "$nat" -eq 1 ]; then
    [ "${a_refl%:*}" = "$ra_pub" ] && [ "${b_refl%:*}" = "$rb_pub" ] \
      || { echo "  FAIL reflexive addresses are not the routers' ($ra_pub, $rb_pub)"; return 1; }
    echo "  ok  the reflexive addresses are the routers' public addresses"
  fi
  jq -n --arg k "$b_pub" --arg e "$b_refl" '{($k): [$e]}' | put a /candidates.json
  jq -n --arg k "$a_pub" --arg e "$a_refl" '{($k): [$e]}' | put b /candidates.json

  echo "  -- direct"
  wait_status a "$bin" ".extra.paths[\"$b_pub\"] | .active == \"direct\" and .confirmed" 30
  wait_status b tun_node ".extra.paths[\"$a_pub\"] | .active == \"direct\" and .confirmed" 30
  wait_status a "$bin" ".peers[0].endpoint == \"$b_refl\"" 5
  echo "  ok  a, b: direct path active and confirmed (a -> $b_refl)"
  ladder_echo "$bin"

  echo "  -- direct blocked"
  if [ "$nat" -eq 1 ]; then
    X ra "iptables -I FORWARD -d $rb_pub -j DROP; iptables -I FORWARD -s $rb_pub -j DROP"
    X rb "iptables -I FORWARD -d $ra_pub -j DROP; iptables -I FORWARD -s $ra_pub -j DROP"
  else
    block a "$b_ip"; block b "$a_ip"
  fi
  wait_status a "$bin" ".extra.paths[\"$b_pub\"] | .active == \"relay\" and .to_relay >= 1" 30
  wait_status b tun_node ".extra.paths[\"$a_pub\"] | .active == \"relay\" and .to_relay >= 1" 30
  echo "  ok  a, b: fell back to the relay"
  local fwd
  fwd=$(relay_counter r forwarded)
  ladder_echo "$bin"
  wait_status r relay_server ".extra.relay.counters.forwarded > $fwd" 5
  echo "  ok  r: forwarded $fwd -> $(relay_counter r forwarded)"

  echo "  -- direct unblocked"
  if [ "$nat" -eq 1 ]; then
    X ra "iptables -D FORWARD -d $rb_pub -j DROP; iptables -D FORWARD -s $rb_pub -j DROP"
    X rb "iptables -D FORWARD -d $ra_pub -j DROP; iptables -D FORWARD -s $ra_pub -j DROP"
  else
    X a "iptables -F INPUT; iptables -F OUTPUT"; X b "iptables -F INPUT; iptables -F OUTPUT"
  fi
  wait_status a "$bin" ".extra.paths[\"$b_pub\"] | .active == \"direct\" and .confirmed and .to_direct >= 1" 30
  wait_status b tun_node ".extra.paths[\"$a_pub\"] | .active == \"direct\" and .confirmed and .to_direct >= 1" 30
  echo "  ok  a, b: back on the direct path"
  ladder_echo "$bin"
}
# ladder_echo <example of a>: echo b -> a, and a -> b where a has a kernel stack.
ladder_echo() {
  echo_check b tcp 10.0.0.1 7; echo_check b udp 10.0.0.1 7
  if [ "$1" != netstack_node ]; then echo_check a tcp 10.0.0.2 7; echo_check a udp 10.0.0.2 7; fi
}
scenario_ladder_tun() { ladder tun_node 0; }
scenario_ladder_netstack() { ladder netstack_node 0; }
scenario_nat_hole_punch() { ladder tun_node 1; }

# Plain WireGuard compatibility: a tun_node n with the relay extension whose --relay is a
# plain kernel WireGuard server s. The server drops the control messages (captured on s,
# never answered), n backs off and stops after the bounded attempts, the handshake is as
# fast as without the extension and the tunnel works. Restarted with a real relay r as
# --relay, n discovers it as capable, registers and reaches the relay's own engine.
scenario_plain_wg_compat() {
  start s n r
  local s_pub n_pub r_pub s_ip n_ip r_ip
  s_pub=$(pub s); n_pub=$(pub n); r_pub=$(pub r); s_ip=$(ip_of s); n_ip=$(ip_of n); r_ip=$(ip_of r)
  mkey n
  docker exec -d "$(ctr s)" bash -c "exec tcpdump -i any -n -U --immediate-mode -w /capture.pcap udp port $PORT > /tcpdump.log 2>&1"
  wait_log s tcpdump 'listening on' 10
  # No keepalive: the node initiates, so its handshake latency is measured.
  X s "ip link add wg0 type wireguard
    wg set wg0 private-key /k listen-port $PORT peer $n_pub allowed-ips 10.0.0.1/32 endpoint $n_ip:$PORT
    ip addr add 10.0.0.2/24 dev wg0; ip link set wg0 up"
  echo_server s
  local attempts=4 backoff=500
  node n tun_node --transport relay --relay "$s_ip:$PORT" --machine-key-file /m --probe-backoff-ms "$backoff" \
    --probe-attempts "$attempts" --address 10.0.0.1/24 --peer "$s_pub,endpoint=$s_ip:$PORT,allowed-ips=10.0.0.2/32" \
    --check tcp:10.0.0.2:7 --check udp:10.0.0.2:7
  local ep=".extra.relay.endpoints[\"$s_ip:$PORT\"]"
  wait_status n tun_node "$ep.state == \"probing\"" 5
  echo "  ok  n: $s_ip:$PORT probing"
  checks_pass n tun_node
  # Handshake latency on the capture: from the node's first datagram (control or WireGuard)
  # to the server's handshake response.
  local first response ms
  first=$(X s "tcpdump -r /capture.pcap -n -tt -c 1 'src host $n_ip and udp dst port $PORT' 2>/dev/null" | awk '{print $1}')
  response=$(X s "tcpdump -r /capture.pcap -n -tt -c 1 'src host $s_ip and udp src port $PORT and udp[8] = 2' 2>/dev/null" | awk '{print $1}')
  ms=$(awk -v a="$first" -v b="$response" 'BEGIN { if (a == "" || b == "") print -1; else printf "%d", (b - a) * 1000 }')
  [ "$ms" -ge 0 ] && [ "$ms" -lt 2000 ] || { echo "  FAIL n: no handshake within 2 s of the first datagram ($first -> $response)"; return 1; }
  echo "  ok  n: handshake response $ms ms after the node's first datagram"
  echo_check n tcp 10.0.0.2 7; echo_check n udp 10.0.0.2 7
  ping_check n 10.0.0.2; ping_check s 10.0.0.1
  wait_status n tun_node "$ep | .state == \"stopped\" and .attempts == $attempts and .control_answered == 0" 20
  echo "  ok  n: $s_ip:$PORT stopped after $attempts unanswered attempts"
  sleep 3
  local times answers
  times=$(X s "tcpdump -r /capture.pcap -n -tt 'dst host $s_ip and udp dst port $PORT and udp[8] >= 0xf0' 2>/dev/null" | awk '{print $1}')
  answers=$(X s "tcpdump -r /capture.pcap -n 'src host $s_ip and udp src port $PORT and udp[8] >= 0xf0' 2>/dev/null" | wc -l)
  [ "$(echo "$times" | grep -c .)" -eq "$attempts" ] \
    || { echo "  FAIL s: captured $(echo "$times" | grep -c .) control messages, want $attempts"; return 1; }
  [ "$answers" -eq 0 ] || { echo "  FAIL s: answered $answers control messages"; return 1; }
  # The gaps between the probes double (500, 1000, 2000 ms).
  echo "$times" | awk 'NR > 1 { gap = $1 - prev; if (NR > 2 && gap < 1.6 * last) bad = 1; if (NR == 2 && gap < 0.4) bad = 1; last = gap } { prev = $1 } END { exit bad }' \
    || { echo "  FAIL s: probe gaps do not back off: $(echo "$times" | tr '\n' ' ')"; return 1; }
  echo "  ok  s: received $attempts control messages with doubling gaps, answered none"

  echo "  -- the same node with a real relay as --relay"
  node_stop n tun_node
  relay_conf n | relay_up r --peer "$n_pub,allowed-ips=10.0.0.1/32" --echo-port 7
  node n tun_node --transport relay --relay "$r_ip:$PORT" --machine-key-file /m --address 10.0.0.1/24 \
    --peer "$s_pub,endpoint=$s_ip:$PORT,allowed-ips=10.0.0.2/32" \
    --peer "$r_pub,endpoint=$r_ip:$PORT,allowed-ips=10.0.0.254/32" \
    --check tcp:10.0.0.2:7 --check tcp:10.0.0.254:7 --check udp:10.0.0.254:7
  capable n tun_node "$r_ip:$PORT"
  wait_status n tun_node ".extra.relay.reflexive == \"$n_ip:$PORT\"" 10
  wait_status r relay_server '.extra.relay.counters.registrations >= 1' 10
  echo "  ok  n: registered with the relay, reflexive $n_ip:$PORT"
  checks_pass n tun_node
  echo_check n tcp 10.0.0.2 7; ping_check n 10.0.0.2
}

# --- scenarios --------------------------------------------------------------------------
# self_check <example> <summary>: a self-checking example exits 0 with its summary line.
self_check() {
  start a
  run_fg a "$1"
  X a "grep -q '^$2\$' /$1.log"
  echo "  ok  a: $1 exit 0, $2"
}
scenario_udp_pair() { self_check udp_pair 'CHECKS PASS'; }
scenario_events_stats() { self_check events_stats 'STEPS PASS'; }
scenario_app_session() { self_check app_session 'CHECKS PASS'; }

# app_session with node A on a TUN next to its netstack: host traffic to the session-only
# peer's address is dropped by the outbound rule while the app's transfer works.
scenario_app_session_tun() {
  start a
  run_fg a app_session --tun nsp-app --status /app_session.json
  X a "grep -q '^STEP tun-outbound PASS\$' /app_session.log"
  X a "grep -q '^CHECKS PASS\$' /app_session.log"
  echo "  ok  a: app_session --tun exit 0, STEP tun-outbound PASS, CHECKS PASS"
  wait_status a app_session '.extra.acl.outbound_denied > 0' 5
  echo "  ok  a: extra.acl.outbound_denied > 0"
}

# hybrid [args]... vs kernel WireGuard: a socat service on the TUN side and the netstack
# echo are both reachable from the kernel peer; nothing is misrouted.
hybrid_kernel() {
  start a k
  local a_pub k_pub a_ip k_ip
  a_pub=$(pub a); k_pub=$(pub k); a_ip=$(ip_of a); k_ip=$(ip_of k)
  echo_server a
  node a hybrid "$@" --tun-address 10.0.0.1/24 --stack-address 10.1.0.1/24 \
    --peer "$k_pub,endpoint=$k_ip:$PORT,allowed-ips=10.0.0.2/32" --echo-port 7
  kernel_wg k 10.0.0.2/24 "$a_pub" "$a_ip" 10.0.0.1/32,10.1.0.1/32 10.1.0.1/32
  echo_check k tcp 10.0.0.1 7; echo_check k udp 10.0.0.1 7
  echo_check k tcp 10.1.0.1 7; echo_check k udp 10.1.0.1 7
  ping_check k 10.0.0.1
  wait_status a hybrid '.extra.splitter.misrouted == 0'
  echo "  ok  a: extra.splitter.misrouted == 0"
}
scenario_hybrid() { hybrid_kernel; }

# acl_gateway vs kernel WireGuard: allowed and denied ports, live policy reload, stateful
# replies to connections the gateway opens.
scenario_acl_gateway() {
  start a k
  local a_pub k_pub a_ip k_ip
  a_pub=$(pub a); k_pub=$(pub k); a_ip=$(ip_of a); k_ip=$(ip_of k)
  local sample=examples/policies/acl_gateway.json
  # Allows only port 9: port 7 is denied. The sample's built-in tests no longer hold.
  local deny7
  deny7=$(jq '.acls |= map(.dst = ["gateway:9"]) | del(.tests)' "$sample")
  put a /policy.json < "$sample"
  echo_server a 8
  echo_server k 7
  node a acl_gateway --address 10.0.0.1/24 --peer "$k_pub,endpoint=$k_ip:$PORT,allowed-ips=10.0.0.2/32" \
    --identity "$k_pub=10.0.0.2" --policy /policy.json --echo-port 7
  kernel_wg k 10.0.0.2/24 "$a_pub" "$a_ip" 10.0.0.1/32
  wait_status a acl_gateway '.extra.acl.policy_loaded and .extra.acl.reloads == 1'
  echo_check k tcp 10.0.0.1 7; echo_check k udp 10.0.0.1 7
  echo_denied k tcp 10.0.0.1 8
  wait_status a acl_gateway '.extra.acl.denied > 0' 5

  echo "  -- policy: deny port 7"
  put a /policy.json <<< "$deny7"
  local i blocked=0
  for i in $(seq 1 10); do
    if ! echo_try k tcp 10.0.0.1 7; then blocked=1; break; fi
    sleep 0.5
  done
  [ "$blocked" -eq 1 ] || { echo "  FAIL k: tcp 7 still passes after the policy change"; return 1; }
  wait_status a acl_gateway '.extra.acl.reloads == 2' 5
  echo_denied k tcp 10.0.0.1 7; echo_denied k udp 10.0.0.1 7

  echo "  -- policy: restore the sample"
  put a /policy.json < "$sample"
  wait_status a acl_gateway '.extra.acl.reloads == 3' 5
  echo_check k tcp 10.0.0.1 7 10; echo_check k udp 10.0.0.1 7 10

  echo "  -- stateful replies: the gateway opens connections the policy does not allow back"
  local replies
  replies=$(X a 'cat /acl_gateway.json' | jq '.extra.acl.replies')
  echo_check a tcp 10.0.0.2 7; echo_check a udp 10.0.0.2 7
  wait_status a acl_gateway ".extra.acl.replies > $replies" 5
  echo "  ok  a: extra.acl.replies grew past $replies"
}

# --- scenarios: NAT --------------------------------------------------------------------
# translate_node t between an IPv4-only client c on t's LAN (an internal network) and a
# kernel WireGuard peer k whose overlay is IPv6 only. t maps k's /127 group (node6
# fd00:a::2:0, node4 fd00:a::2:1) to alias4 10.200.0.2, its own self4 10.200.0.1 to node4
# fd00:a::1:1, and the LAN's IPv4 subnet to fd00:1::/96. c routes 10.200.0.2 through t;
# k sees the requests from fd00:1::<c's IPv4> to node4 and answers over IPv6.
scenario_translate_node() {
  local lan
  lan=$(case_net lan)
  start_on "$NET" t --sysctl net.ipv4.ip_forward=1
  docker network connect "$lan" "$(ctr t)"
  start_on "$lan" c --sysctl net.ipv6.conf.all.disable_ipv6=1
  start k
  local t_pub k_pub t_ip k_ip lan4 t_lan
  t_pub=$(pub t); k_pub=$(pub k); t_ip=$(ip_on t "$NET"); k_ip=$(ip_of k); t_lan=$(ip_on t "$lan")
  lan4=$(docker network inspect -f '{{(index .IPAM.Config 0).Subnet}}' "$lan")
  [ "$(X c 'cat /proc/sys/net/ipv6/conf/all/disable_ipv6')" = 1 ] || { echo "  FAIL c: IPv6 is enabled"; return 1; }
  X c "ip route add 10.200.0.2/32 via $t_lan"
  echo "  ok  c: IPv4 only, LAN $lan4, 10.200.0.2 via t ($t_lan)"
  docker exec -d "$(ctr k)" bash -c "socat TCP6-LISTEN:7,fork,reuseaddr PIPE > /socat-7.log 2>&1 &
    socat UDP6-RECVFROM:7,fork PIPE >> /socat-7.log 2>&1 & wait"
  node t translate_node --self 10.200.0.1=fd00:a::1:1 --peer "$k_pub,endpoint=$k_ip:$PORT" \
    --map "$k_pub,node6=fd00:a::2:0,node4=fd00:a::2:1,alias4=10.200.0.2" --lan "$lan4=fd00:1::/96"
  # node4 is k's preferred source, so its UDP replies come from the address c talks to.
  kernel_wg k fd00:a::2:1/128 "$t_pub" "$t_ip" fd00:1::/96,fd00:a::1:0/127 fd00:1::/96 fd00:a::1:0/127
  X k 'ip addr add fd00:a::2:0/128 dev wg0 preferred_lft 0'
  echo_check c tcp 10.200.0.2 7; echo_check c udp 10.200.0.2 7
  ping_check c 10.200.0.2
  echo_check t tcp 10.200.0.2 7; echo_check t udp 10.200.0.2 7
  wait_status t translate_node '.extra.translate | .translated_out > 0 and .translated_in > 0' 5
  echo "  ok  t: translated $(X t 'cat /translate_node.json' | jq -c '.extra.translate | {translated_out, translated_in, dropped_out, dropped_in}')"
  X k 'wg show wg0 transfer' | awk '$2 == 0 || $3 == 0 { exit 1 }'
  echo "  ok  k: traffic on the IPv6-only tunnel both ways"

  echo "  -- t with --no-offload: full-MTU IPv4 packets grow in place"
  node_stop t translate_node
  X t 'rm -f /translate_node.json'
  local mtu=1420
  node t translate_node --no-offload --mtu "$mtu" --self 10.200.0.1=fd00:a::1:1 \
    --peer "$k_pub,endpoint=$k_ip:$PORT" \
    --map "$k_pub,node6=fd00:a::2:0,node4=fd00:a::2:1,alias4=10.200.0.2" --lan "$lan4=fd00:1::/96"
  wait_log t translate_node 'TUN device opened.* offload=off'
  # The replies are the translated size, 20 bytes over the MTU; k's IPv4 underlay has room.
  X k "ip link set wg0 mtu $(( mtu + 20 ))"
  if X c "ping -c 3 -i 0.3 -w 15 -M do -s $(( mtu - 28 )) 10.200.0.2" >/dev/null; then
    echo "  ok  c: ping 10.200.0.2 with $mtu-byte packets"
  else
    echo "  FAIL c: ping 10.200.0.2 with $mtu-byte packets"; return 1
  fi
  wait_status t translate_node '.extra.translate | .translated_out > 0 and .grown_copies == 0' 5
  echo "  ok  t: translated $(X t 'cat /translate_node.json' | jq -c '.extra.translate | {translated_out, grown_copies}')"
}

# udp_from <ctr> <ip6> <port> <source port>: one UDP echo round trip from a fixed port.
udp_from() {
  local payload out
  payload="nsplane-e2e-udp-$RANDOM$RANDOM"
  out=$(X "$1" "printf %s $payload | timeout 4 socat -t 1 - UDP6:[$2]:$3,sourceport=$4" 2>/dev/null) || true
  [ "$out" = "$payload" ]
}

# port_map a publishes its echo port 7 as [fd00:b::1]:8007 (TCP for the kernel WireGuard
# peer k only, UDP for every peer) and as TCP 8008 for another peer only. k reaches the
# service through the listen port (the replies come back SNATed, or socat would not take
# them), 8008 is refused, and an idle UDP flow expires after --udp-timeout.
scenario_port_map() {
  start a k
  local a_pub k_pub a_ip k_ip other
  a_pub=$(pub a); k_pub=$(pub k); a_ip=$(ip_of a); k_ip=$(ip_of k)
  other=$(X a 'wg genkey | wg pubkey')
  local timeout=3
  node a port_map --address fd00:b::1/64 --peer "$k_pub,endpoint=$k_ip:$PORT,allowed-ips=fd00:b::2/128" \
    --peer "$other,allowed-ips=fd00:b::3/128" --echo-port 7 \
    --publish "tcp:[fd00:b::1]:8007=[fd00:b::1]:7@$k_pub" --publish "udp:[fd00:b::1]:8007=[fd00:b::1]:7" \
    --publish "tcp:[fd00:b::1]:8008=[fd00:b::1]:7@$other" --udp-timeout "$timeout"
  kernel_wg k fd00:b::2/64 "$a_pub" "$a_ip" fd00:b::1/128
  wait_status a port_map '.extra.port_map.rules == 3'
  echo_check k tcp fd00:b::1 8007; echo_check k udp fd00:b::1 8007
  echo_denied k tcp fd00:b::1 8008
  wait_status a port_map '.extra.port_map.conntrack | .inserted >= 2 and .hits > 0' 5
  echo "  ok  a: flows mapped, $(X a 'cat /port_map.json' | jq -c '.extra.port_map.conntrack')"

  echo "  -- a UDP flow from one source port: reused while active, expired after ${timeout}s"
  local inserted
  inserted=$(X a 'cat /port_map.json' | jq '.extra.port_map.conntrack.inserted')
  udp_from k fd00:b::1 8007 40000 || { echo "  FAIL k: udp echo from port 40000"; return 1; }
  wait_status a port_map ".extra.port_map.conntrack.inserted == $((inserted + 1))" 5
  udp_from k fd00:b::1 8007 40000 || { echo "  FAIL k: second udp echo from port 40000"; return 1; }
  sleep 1.5
  wait_status a port_map ".extra.port_map.conntrack.inserted == $((inserted + 1))" 5
  echo "  ok  a: the second datagram reused the flow"
  sleep $((timeout + 1))
  udp_from k fd00:b::1 8007 40000 || { echo "  FAIL k: udp echo from port 40000 after the timeout"; return 1; }
  wait_status a port_map ".extra.port_map.conntrack | .inserted == $((inserted + 2)) and .expired > 0" 5
  echo "  ok  a: the flow expired after ${timeout}s idle and a new one was recorded"
}

# --- scenarios: offload -----------------------------------------------------------------

# tun_node with --no-offload <-> kernel WireGuard: the UDP cell's checks on the plain TUN
# device and UDP without GSO/GRO.
scenario_offload_fallback() {
  kernel_peer tun_node --no-offload
  wait_log a tun_node 'TUN node started.* offload=off'
  X a "grep -q 'udp_offload=off' /tun_node.log"
  echo "  ok  a: tun_node logs offload=off, udp_offload=off"
}

# hybrid with --no-offload <-> kernel WireGuard: the hybrid scenario's checks on the plain
# TUN device and UDP without GSO/GRO.
scenario_offload_fallback_hybrid() {
  hybrid_kernel --no-offload
  X a "grep -Eq 'hybrid node started.* offload=off' /hybrid.log"
  X a "grep -q 'udp_offload=off' /hybrid.log"
  echo "  ok  a: hybrid logs offload=off, udp_offload=off"
}

# relay_server and two tun_nodes (relay UDP, direct path blocked), all with --no-offload:
# a UDP check from a to b through the relay.
scenario_offload_fallback_relay() {
  start r a b
  local a_pub b_pub r_ip a_ip b_ip name
  a_pub=$(pub a); b_pub=$(pub b); r_ip=$(ip_of r); a_ip=$(ip_of a); b_ip=$(ip_of b)
  mkey a b
  relay_conf a b | relay_up r --no-offload
  block a "$b_ip"; block b "$a_ip"
  relay_client relay-udp "$r_ip"
  echo_server b
  node b tun_node --no-offload "${CLIENT[@]}" --address 10.0.0.2/24 \
    --peer "$a_pub,endpoint=$RELAY_EP,allowed-ips=10.0.0.1/32"
  node a tun_node --no-offload "${CLIENT[@]}" --address 10.0.0.1/24 \
    --peer "$b_pub,endpoint=$RELAY_EP,allowed-ips=10.0.0.2/32" --check udp:10.0.0.2:7
  checks_pass a tun_node
  wait_status r relay_server '.extra.relay.counters.forwarded > 0' 5
  echo "  ok  r: forwarded $(relay_counter r forwarded)"
  X r "grep -q 'udp_offload=off' /relay_server.log"
  echo "  ok  r: relay_server logs udp_offload=off"
  for name in a b; do
    X "$name" "grep -Eq 'TUN node started.* offload=off' /tun_node.log"
    X "$name" "grep -q 'udp_offload=off' /tun_node.log"
    echo "  ok  $name: tun_node logs offload=off, udp_offload=off"
  done
}

# iperf_run <ctr> <tcp|udp> [iperf3 args]...: one 5 s iperf3 run against 10.0.0.2 (UDP at
# NSPLANE_E2E_IPERF_RATE); prints the received Mbit/s and, for UDP, the loss in percent,
# and fails unless data arrived.
iperf_run() {
  local name=$1 proto=$2 out; shift 2
  local args=(-c 10.0.0.2 -t 5 -J --connect-timeout 5000 "$@")
  # 1392 bytes fill the tunnel MTU (1420) with IPv4 and UDP headers.
  [ "$proto" = udp ] && args+=(-u -b "$IPERF_RATE" -l 1392)
  out=$(X "$name" "timeout 30 iperf3 $(printf '%q ' "${args[@]}") 2>> /iperf3.log") || return 1
  jq -e '.end.sum_received.bytes > 0' <<< "$out" >/dev/null || return 1
  jq -r '"\(.end.sum_received.bits_per_second / 1e6 | floor)"
    + (.end.sum.lost_percent | if . == null then "" else " \(. * 10 | round / 10)" end)' <<< "$out"
}

# iperf_median <run>...: the median Mbit/s (and loss) of runs printed by iperf_run.
iperf_median() {
  local mbit loss
  mbit=$(printf '%s\n' "$@" | awk '{print $1}' | sort -n | awk '{v[NR]=$1} END {print v[int((NR+1)/2)]}')
  loss=$(printf '%s\n' "$@" | awk 'NF>1 {print $2}' | sort -g | awk '{v[NR]=$1} END {if (NR) print v[int((NR+1)/2)]}')
  echo "$mbit${loss:+ (loss $loss%)}"
}

# tun_node (offload on, then --no-offload) <-> kernel WireGuard: iperf3 TCP and UDP in both
# directions through the tunnel, NSPLANE_E2E_IPERF_REPS times each (UDP at
# NSPLANE_E2E_IPERF_RATE, iperf3 -b: 0 is unlimited). Passes when every run moved data;
# prints the median of all 8 rates.
scenario_offload_iperf() {
  local mode a k a_pub k_pub a_ip k_ip dir result rep
  local -A rate=()
  for mode in on off; do
    a=a-$mode; k=k-$mode
    start "$a" "$k"
    a_pub=$(pub "$a"); k_pub=$(pub "$k"); a_ip=$(ip_of "$a"); k_ip=$(ip_of "$k")
    local flags=()
    [ "$mode" = off ] && flags=(--no-offload)
    node "$a" tun_node "${flags[@]}" --address 10.0.0.1/24 \
      --peer "$k_pub,endpoint=$k_ip:$PORT,allowed-ips=10.0.0.2/32"
    kernel_wg "$k" 10.0.0.2/24 "$a_pub" "$a_ip" 10.0.0.1/32
    if [ "$mode" = on ]; then wait_log "$a" tun_node 'TUN node started.* offload=tso'
    else wait_log "$a" tun_node 'TUN node started.* offload=off'; fi
    X "$a" "grep -E 'TUN node started' /tun_node.log" | grep -oE 'offload=[a-z_,]+' | sed "s/^/  $a: /"
    ping_check "$a" 10.0.0.2
    docker exec -d "$(ctr "$k")" iperf3 -s
    sleep 0.5
    for dir in "tcp a->k" "tcp k->a" "udp a->k" "udp k->a"; do
      local args=() runs=()
      [[ $dir == *"k->a" ]] && args=(-R)
      for rep in $(seq 1 "$IPERF_REPS"); do
        if ! result=$(iperf_run "$a" "${dir%% *}" "${args[@]}"); then
          echo "  FAIL $a: iperf3 $dir (offload $mode, run $rep)"; return 1
        fi
        runs+=("$result")
        echo "  ok  $a: iperf3 $dir (offload $mode, run $rep): $result"
      done
      rate[$dir/$mode]=$(iperf_median "${runs[@]}")
    done
    # Datagrams above the path MTU fail with EMSGSIZE (DF set): reported, not gated.
    echo "  $a: EMSGSIZE in the node log: $(X "$a" "grep -cE 'Message too long|os error 90' /tun_node.log" || true)"
  done
  echo "  iperf3 Mbit/s, median of $IPERF_REPS (UDP -b $IPERF_RATE)"
  echo "                  offload on              offload off"
  for dir in "tcp a->k" "tcp k->a" "udp a->k" "udp k->a"; do
    printf '  %-15s %-23s %s\n' "$dir" "${rate[$dir/on]}" "${rate[$dir/off]}"
  done
}

# --- run --------------------------------------------------------------------------------
cell tun udp tun_pair tun_kernel
cell netstack udp netstack_pair netstack_kernel
cell fd udp fd_kernel
cell channel udp channel_tun
for transport in relay-udp relay-wss; do
  cell tun "$transport" relay_tun
  cell netstack "$transport" relay_netstack
  cell fd "$transport" relay_fd
  cell channel "$transport" relay_channel
done
scenario udp_pair
scenario events_stats
scenario app_session
scenario app_session_tun
scenario hybrid
scenario acl_gateway
scenario native_wg
scenario native_wg_reverse
scenario ladder_tun
scenario ladder_netstack
scenario nat_hole_punch
scenario plain_wg_compat
scenario translate_node
scenario port_map
scenario offload_fallback
scenario offload_fallback_hybrid
scenario offload_fallback_relay
scenario offload_iperf

report
if [ "$FAILED" -ne 0 ]; then echo "FAIL"; exit 1; fi
echo "PASS"
