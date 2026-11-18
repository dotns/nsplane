#!/usr/bin/env bash
# Netstack TCP over a shaped link, next to kernel TCP over the same link.
#
#   a (client) ---+--- b (server)
#                 |
#                 r (router, tc netem)
#
# Three containers on one docker network this script creates. a and b reach each other
# through r, which forwards on its one interface and shapes each direction on the way out:
# "forward" is a -> b (the data), "return" is b -> a (the acknowledgements). Nothing on the
# host is reconfigured.
#
#   scripts/bench/slot.sh scripts/bench/netem.sh
#
# Per profile and pair, from a to b:
#   transfer       BENCH_BYTES written at once with the shaping in place: seconds
#                  (iperf3 stops when the sender has written them: its time is scaled
#                  by sent over received bytes)
#   late transfer  the same on a connection opened before the shaping applies, so its first
#                  round trip was fast (netstack only: iperf3 cannot wait after connecting)
#
# Pairs: netstack (netstack_bench on both ends, WireGuard over the shaped link) and kernel
# (iperf3 over kernel TCP on the shaped link, no tunnel: what TCP does on that link).
#
# Profiles (BENCH_PROFILES, space separated; default: all):
#   none  delay20  delay100  jitter20  jitter100  loss1  loss5  reorder  rate10  burst-queue
#   held100  held1000  held-ack100  held-ack300  held-ack1000  held-data300
#
# Environment:
#   BENCH_PROFILES      see above
#   BENCH_PAIRS         "netstack kernel"
#   BENCH_BYTES         bytes per transfer (default 4194304)
#   BENCH_LIMIT         seconds after which a transfer counts as stalled (default 120)
#   BENCH_CPUS_A/_B     CPU sets of a and b (slot.sh exports them; r shares b's)
#   NETSTACK_BENCH_BIN  netstack_bench binary (default target/release/netstack_bench)
#   BENCH_OUT           output directory (default .tmp/bench/netem-<timestamp>)
#   BENCH_PREFIX        name prefix of containers and the network (default nsplane-netem-$$)
set -euo pipefail

REPO=$(cd "$(dirname "$0")/../.." && pwd)
abs() { case $1 in /*) echo "$1" ;; *) echo "$PWD/$1" ;; esac; }
ALL='none delay20 delay100 jitter20 jitter100 loss1 loss5 reorder rate10 burst-queue held100 held1000 held-ack100 held-ack300 held-ack1000 held-data300'
PROFILES=${BENCH_PROFILES:-$ALL}
PAIRS=${BENCH_PAIRS:-netstack kernel}
BYTES=${BENCH_BYTES:-4194304}
LIMIT=${BENCH_LIMIT:-120}
CPUS_A=${BENCH_CPUS_A:-8-11}
CPUS_B=${BENCH_CPUS_B:-12-15}
NETSTACK_BIN=$(abs "${NETSTACK_BENCH_BIN:-$REPO/target/release/netstack_bench}")
OUT=$(abs "${BENCH_OUT:-$REPO/.tmp/bench/netem-$(date -u +%Y%m%dT%H%M%SZ)}")
PREFIX=${BENCH_PREFIX:-nsplane-netem-$$}
IMG=ai-agent/nsplane-bench
LABELS=(--label ai-agent=true --label "nsplane-bench=$PREFIX")
A=$PREFIX-a B=$PREFIX-b R=$PREFIX-r NET=$PREFIX-net
# A late transfer starts this long after its connection; the shaping applies halfway.
START_DELAY_MS=2000
TUN_A=10.77.0.1 TUN_B=10.77.0.2

# The netem arguments of a profile, per direction; empty means unshaped.
shape() {
  case $1:$2 in
    none:*) ;;
    delay20:*) echo 'delay 20ms' ;;
    delay100:*) echo 'delay 100ms' ;;
    jitter20:*) echo 'delay 20ms 2ms' ;;
    jitter100:*) echo 'delay 100ms 10ms' ;;
    loss1:*) echo 'loss 1%' ;;
    loss5:*) echo 'loss 5%' ;;
    reorder:*) echo 'delay 5ms reorder 25%' ;;
    rate10:*) echo 'rate 10mbit limit 64' ;;
    burst-queue:*) echo 'rate 1gbit limit 256' ;;
    held100:*) echo 'slot 100ms' ;;
    held1000:*) echo 'slot 1000ms' ;;
    held-ack100:return) echo 'slot 100ms' ;;
    held-ack300:return) echo 'slot 300ms' ;;
    held-ack1000:return) echo 'slot 1000ms' ;;
    held-ack*:forward) ;;
    held-data300:forward) echo 'slot 300ms' ;;
    held-data300:return) ;;
    *) echo "unknown profile $1" >&2; return 1 ;;
  esac
}

cleanup() {
  docker ps -aq --filter "label=nsplane-bench=$PREFIX" | xargs -r docker rm -f >/dev/null 2>&1 || true
  docker network rm "$NET" >/dev/null 2>&1 || true
}
trap cleanup EXIT
trap 'exit 130' INT TERM

mkdir -p "$OUT"
exec > >(tee -a "$OUT/run.log") 2>&1
log() { echo "== $*"; }
dx() { local c=$1; shift; docker exec "$c" bash -c "$*"; }
ip_of() { docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$1"; }

for profile in $PROFILES; do shape "$profile" forward >/dev/null; done
[[ -x $NETSTACK_BIN ]] || { echo "missing $NETSTACK_BIN" >&2; exit 1; }
docker image inspect "$IMG" >/dev/null 2>&1 || docker build -q --label ai-agent=true -t "$IMG" "$REPO/scripts/bench" >/dev/null

docker network create "${LABELS[@]}" "$NET" >/dev/null
run() { docker run -d "${LABELS[@]}" --cap-add NET_ADMIN --network "$NET" "$@" "$IMG" sleep infinity >/dev/null; }
run --name "$A" --cpuset-cpus "$CPUS_A" --sysctl net.ipv4.conf.all.accept_redirects=0
run --name "$B" --cpuset-cpus "$CPUS_B" --sysctl net.ipv4.conf.all.accept_redirects=0
run --name "$R" --cpuset-cpus "$CPUS_B" --sysctl net.ipv4.ip_forward=1 \
  --sysctl net.ipv4.conf.all.send_redirects=0 --sysctl net.ipv4.conf.default.send_redirects=0
IP_A=$(ip_of "$A") IP_B=$(ip_of "$B") IP_R=$(ip_of "$R")
dx "$A" "ip route add $IP_B/32 via $IP_R"
dx "$B" "ip route add $IP_A/32 via $IP_R"
[[ $(dx "$A" "ping -c 2 -W 2 $IP_B" || true) == *ttl=63* ]] || { echo "a does not reach b through r" >&2; exit 1; }
for c in "$A" "$B"; do docker cp -q "$NETSTACK_BIN" "$c:/usr/local/bin/netstack_bench"; done
# One band per direction on r's interface; unshaped bands are plain FIFOs.
dx "$R" "tc qdisc add dev eth0 root handle 1: prio bands 3 priomap 2 2 2 2 2 2 2 2 2 2 2 2 2 2 2 2 \
  && tc filter add dev eth0 parent 1: protocol ip u32 match ip dst $IP_B/32 flowid 1:1 \
  && tc filter add dev eth0 parent 1: protocol ip u32 match ip dst $IP_A/32 flowid 1:2"

unshape() { dx "$R" 'tc qdisc del dev eth0 parent 1:1 2>/dev/null; tc qdisc del dev eth0 parent 1:2 2>/dev/null; true'; }
apply() {
  local fwd ret
  fwd=$(shape "$1" forward) ret=$(shape "$1" return)
  [[ -z $fwd ]] || dx "$R" "tc qdisc replace dev eth0 parent 1:1 handle 10: netem $fwd"
  [[ -z $ret ]] || dx "$R" "tc qdisc replace dev eth0 parent 1:2 handle 20: netem $ret"
}

# Starts the servers of a pair on b; netstack nodes get fresh keys.
start_pair() {
  case $1 in
    netstack)
      dx "$A" 'wg genkey > /k'; dx "$B" 'wg genkey > /k'
      PUB_A=$(dx "$A" 'wg pubkey < /k') PUB_B=$(dx "$B" 'wg pubkey < /k')
      docker exec -d "$B" bash -c "netstack_bench --private-key-file /k --listen 0.0.0.0:51820 --address $TUN_B/24 --peer $PUB_A,allowed-ips=$TUN_A/32 server --port 5201 > /server.log 2>&1"
      ;;
    kernel) docker exec -d "$B" bash -c 'iperf3 -s > /server.log 2>&1' ;;
  esac
  sleep 0.5
}
stop_pair() { dx "$B" 'pkill -x netstack_bench; pkill -x iperf3; true'; sleep 0.3; }

# client PAIR ARGS...: one client run on a, JSON on stdout. ARGS are netstack_bench's.
client() {
  local pair=$1; shift
  case $pair in
    netstack)
      dx "$A" "timeout $LIMIT netstack_bench --private-key-file /k --listen 0.0.0.0:51820 --address $TUN_A/24 --peer $PUB_B,endpoint=$IP_B:51820,allowed-ips=$TUN_B/32 client --target $TUN_B:5201 --mode tcp $* 2>/client.log"
      ;;
    kernel)
      dx "$A" "timeout $LIMIT iperf3 -J -c $IP_B ${*/--bytes/-n} 2>/client.log" |
        jq -c '.end | {seconds: (.sum_received.seconds * .sum_sent.bytes / ([.sum_received.bytes, 1] | max)), received: .sum_received.bytes, retransmits: .sum_sent.retransmits}'
      ;;
  esac
}

seconds() { jq -r '.seconds | . * 100 | round / 100 | "\(.) s"'; }
printf '| Profile | Pair | %s MiB transfer | Late transfer |\n|---|---|---|---|\n' "$((BYTES >> 20))" > "$OUT/results.md"
for profile in $PROFILES; do
  for pair in $PAIRS; do
    log "$profile $pair"
    unshape; apply "$profile"; start_pair "$pair"
    if json=$(client "$pair" --bytes "$BYTES") && [[ -n $json ]]; then
      echo "$json" > "$OUT/$profile-$pair-transfer.json"
      transfer=$(seconds <<<"$json")
    else
      transfer="stalled (> $LIMIT s)"
    fi
    stop_pair
    late=-
    if [[ $pair == netstack ]]; then
      unshape; start_pair "$pair"
      ( sleep "$((START_DELAY_MS / 2000))"; apply "$profile" ) &
      shaper=$!
      if json=$(client "$pair" --bytes "$BYTES" --start-delay "$START_DELAY_MS") && [[ -n $json ]]; then
        echo "$json" > "$OUT/$profile-$pair-late.json"
        late=$(seconds <<<"$json")
      else
        late="stalled (> $LIMIT s)"
      fi
      wait "$shaper"
      stop_pair
    fi
    echo "| \`$profile\` | $pair | $transfer | $late |" >> "$OUT/results.md"
  done
done
unshape
{
  echo
  echo "- kernel $(uname -r), $(grep -m1 'model name' /proc/cpuinfo | cut -d: -f2 | xargs), CPUs a=$CPUS_A b,r=$CPUS_B"
  echo "- nsplane $(git -C "$REPO" describe --always --dirty 2>/dev/null || echo unknown), load $(cut -d' ' -f1-3 /proc/loadavg)"
} >> "$OUT/results.md"
cat "$OUT/results.md"
