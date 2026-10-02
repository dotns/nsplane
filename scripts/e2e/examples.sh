#!/usr/bin/env bash
# Examples end-to-end test: the nsplane-examples binaries run as the design's
# "Presentation x transport" scenarios (docs/design.md §5), against each other and against
# kernel WireGuard, each node in its own sibling container.
#
# Matrix cells (`cell <row> <transport> <case>...`) and scenarios (`scenario <name>`) record
# PASS/FAIL; the run ends with the matrix and the scenario list and fails if anything failed.
# Needs docker and the `wireguard` kernel module on the host; nothing on the host is
# reconfigured. The release example binaries are built in the dev image unless
# NSPLANE_E2E_EX_BIN_DIR names a directory holding them.
#
#   scripts/e2e/examples.sh
#   NSPLANE_E2E_EX_ONLY='acl|hybrid' scripts/e2e/examples.sh   # cases whose id matches
set -euo pipefail
cd "$(dirname "$0")/../.."
PREFIX=${NSPLANE_E2E_EX_PREFIX:-nsplane-e2e-ex-$$}
ONLY=${NSPLANE_E2E_EX_ONLY:-}
DEV_IMAGE=${NSPLANE_E2E_EX_DEV_IMAGE:-ai-agent/nstun-dev}
NET=$PREFIX-net
IMG=$PREFIX-image
LABEL=nsplane-e2e-ex=$PREFIX
LABELS=(--label ai-agent=true --label "$LABEL")
EXAMPLES=(udp_pair tun_node netstack_node hybrid acl_gateway fd_bridge events_stats)
PORT=51820

cleanup() {
  docker ps -aq --filter "label=$LABEL" | xargs -r docker rm -f >/dev/null 2>&1 || true
  docker network rm "$NET" >/dev/null 2>&1 || true
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
# start <name>...: a container per name with a fresh key pair in /k (private) and /p (public).
start() {
  local name
  for name in "$@"; do
    docker run -d --rm "${LABELS[@]}" --label "nsplane-e2e-ex-case=$CASE" --name "$(ctr "$name")" \
      --network "$NET" --cap-add NET_ADMIN --device /dev/net/tun -e NO_COLOR=1 \
      --sysctl net.ipv6.conf.all.disable_ipv6=0 "${MOUNTS[@]}" "$IMG" sleep infinity >/dev/null
    X "$name" 'umask 077; wg genkey > /k; wg pubkey < /k > /p'
  done
}
pub() { X "$1" 'cat /p'; }
ip_of() { docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$(ctr "$1")"; }
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
remove_case() { case_containers | xargs -r docker rm -f >/dev/null 2>&1 || true; }

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
  local payload out
  payload="nsplane-e2e-$2-$RANDOM$RANDOM"
  out=$(X "$1" "printf %s $payload | timeout 4 socat -t 1 - ${2^^}4:$3:$4" 2>/dev/null) || true
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

# hybrid vs kernel WireGuard: a socat service on the TUN side and the netstack echo are both
# reachable from the kernel peer; nothing is misrouted.
scenario_hybrid() {
  start a k
  local a_pub k_pub a_ip k_ip
  a_pub=$(pub a); k_pub=$(pub k); a_ip=$(ip_of a); k_ip=$(ip_of k)
  echo_server a
  node a hybrid --tun-address 10.0.0.1/24 --stack-address 10.1.0.1/24 \
    --peer "$k_pub,endpoint=$k_ip:$PORT,allowed-ips=10.0.0.2/32" --echo-port 7
  kernel_wg k 10.0.0.2/24 "$a_pub" "$a_ip" 10.0.0.1/32,10.1.0.1/32 10.1.0.1/32
  echo_check k tcp 10.0.0.1 7; echo_check k udp 10.0.0.1 7
  echo_check k tcp 10.1.0.1 7; echo_check k udp 10.1.0.1 7
  ping_check k 10.0.0.1
  wait_status a hybrid '.extra.splitter.misrouted == 0'
  echo "  ok  a: extra.splitter.misrouted == 0"
}

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

# --- run --------------------------------------------------------------------------------
cell tun udp tun_pair tun_kernel
cell netstack udp netstack_pair netstack_kernel
cell fd udp fd_kernel
cell channel udp channel_tun
scenario udp_pair
scenario events_stats
scenario hybrid
scenario acl_gateway

report
if [ "$FAILED" -ne 0 ]; then echo "FAIL"; exit 1; fi
echo "PASS"
