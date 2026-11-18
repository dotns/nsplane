#!/usr/bin/env bash
# Netstack tunnel between a container on this host and a remote host, in both directions,
# next to what the path between them loses on its own.
#
#   local container (netstack_bench, net_probe) <---- the path ----> remote host (the same)
#
# The remote host is reached over SSH and runs its processes in the foreground of SSH
# sessions this script holds open. "up" is remote -> local, "down" is local -> remote.
#
#   scripts/bench/slot.sh scripts/bench/cross-host.sh <ssh target> <unix|windows>
#
# Per direction, the median of BENCH_REPS runs:
#   baseline  net_probe: loss of 3227 unpaced 1300-byte datagrams and at 10, 50 and
#             200 Mbit/s paced, with reordered datagrams and the longest loss run; ping from
#             the local container at 50 ms and 1 s intervals (down only)
#   tunnel    TCP 10 s with 1 and 4 streams; 4 MiB and 64 MiB written at once; UDP at
#             50 Mbit/s paced for 5 s; 1-byte round trips back to back and 1 s apart
#
# Environment:
#   BENCH_LOCAL_ADDR    address of this host as the remote reaches it (required), or
#                       "container" for the local container's own address
#   BENCH_REMOTE_ADDR   address of the remote as this host reaches it; unset if it is behind
#                       NAT: the tunnel then follows the remote's keepalive, and the baseline
#                       and ping towards it are left out
#   BENCH_PORT          tunnel UDP port on both ends (default 47920); the probe uses the next
#   BENCH_NETWORK       docker network of the local container (default: the default bridge,
#                       with both ports published on this host)
#   BENCH_SSH           ssh command (default "ssh -o BatchMode=yes")
#   BENCH_SCP           scp command (default "scp -q -o BatchMode=yes")
#   BENCH_REMOTE_BIN    local directory with netstack_bench and net_probe built for the
#                       remote (windows: with .exe). Without it (unix only) the work tree is
#                       copied to the remote and built there with cargo
#   BENCH_NETEM         netem arguments for the local container's egress, e.g. "delay 50ms":
#                       shapes the down direction only
#   BENCH_REPS          runs per measurement (default 3)
#   BENCH_RR_COUNT      back-to-back round trips per run (default 1000; fewer on a link
#                       shaped with a long delay)
#   BENCH_LIMIT         seconds after which a run counts as stalled (default 120)
#   BENCH_LOCK          a lock file to hold while the remote host is in use (shared hosts)
#   BENCH_CPUS_A        CPU set of the local container (slot.sh exports it)
#   NETSTACK_BENCH_BIN, NET_PROBE_BIN   local binaries (default target/release/...)
#   BENCH_OUT           output directory (default .tmp/bench/cross-host-<timestamp>)
#   BENCH_PREFIX        name of the container and the remote directory (default nsplane-cross-$$)
set -euo pipefail

[[ $# -eq 2 && $2 =~ ^(unix|windows)$ ]] || { echo "usage: $0 <ssh target> <unix|windows>" >&2; exit 2; }
TARGET=$1 OS=$2
REPO=$(cd "$(dirname "$0")/../.." && pwd)
abs() { case $1 in /*) echo "$1" ;; *) echo "$PWD/$1" ;; esac; }
: "${BENCH_LOCAL_ADDR:?address of this host as the remote reaches it, or \"container\"}"
REMOTE_ADDR=${BENCH_REMOTE_ADDR:-}
PORT=${BENCH_PORT:-47920}
PPORT=$((PORT + 1))
read -r -a SSH <<<"${BENCH_SSH:-ssh -o BatchMode=yes}"
read -r -a SCP <<<"${BENCH_SCP:-scp -q -o BatchMode=yes}"
REPS=${BENCH_REPS:-3}
RR_COUNT=${BENCH_RR_COUNT:-1000}
LIMIT=${BENCH_LIMIT:-120}
NETSTACK_BIN=$(abs "${NETSTACK_BENCH_BIN:-$REPO/target/release/netstack_bench}")
PROBE_BIN=$(abs "${NET_PROBE_BIN:-$REPO/target/release/net_probe}")
OUT=$(abs "${BENCH_OUT:-$REPO/.tmp/bench/cross-host-$(date -u +%Y%m%dT%H%M%SZ)}")
PREFIX=${BENCH_PREFIX:-nsplane-cross-$$}
IMG=ai-agent/nsplane-bench
C=$PREFIX
RDIR=$PREFIX
TUN_L=10.88.0.1 TUN_R=10.88.0.2
if [[ $OS == windows ]]; then EXE=.exe; else EXE=; fi

if [[ -n ${BENCH_LOCK:-} ]]; then
  exec 9>"$BENCH_LOCK"
  flock 9
fi

r() { "${SSH[@]}" "$TARGET" "$1"; }
dx() { docker exec "$C" bash -c "$*"; }
log() { echo "== $*" >&2; }
remote_kill() {
  if [[ $OS == windows ]]; then
    r 'Get-Process netstack_bench,net_probe -ErrorAction SilentlyContinue | Stop-Process -Force' || true
  else
    # The bracket keeps the pattern from matching the shell that runs pkill.
    r "pkill -f '[${RDIR:0:1}]${RDIR:1}/bin/' || true" || true
  fi
}
cleanup() {
  remote_kill >/dev/null 2>&1
  if [[ $OS == windows ]]; then
    r "Remove-Item -Recurse -Force $RDIR -ErrorAction SilentlyContinue" >/dev/null 2>&1 || true
  else
    r "rm -rf $RDIR" >/dev/null 2>&1 || true
  fi
  docker rm -f "$C" >/dev/null 2>&1 || true
}
trap cleanup EXIT
trap 'exit 130' INT TERM

mkdir -p "$OUT"
for bin in "$NETSTACK_BIN" "$PROBE_BIN"; do [[ -x $bin ]] || { echo "missing $bin" >&2; exit 1; }; done
docker image inspect "$IMG" >/dev/null 2>&1 || docker build -q --label ai-agent=true -t "$IMG" "$REPO/scripts/bench" >/dev/null

# The remote's binaries: copied, or built there from this work tree.
log "remote binaries"
if [[ $OS == windows ]]; then
  : "${BENCH_REMOTE_BIN:?directory with netstack_bench.exe and net_probe.exe}"
  r "New-Item -ItemType Directory -Force $RDIR/bin | Out-Null"
else
  r "mkdir -p $RDIR/bin"
fi
if [[ -n ${BENCH_REMOTE_BIN:-} ]]; then
  "${SCP[@]}" "$BENCH_REMOTE_BIN/netstack_bench$EXE" "$BENCH_REMOTE_BIN/net_probe$EXE" "$TARGET:$RDIR/bin/"
else
  git -C "$REPO" ls-files -z --cached --others --exclude-standard |
    tar -C "$REPO" --null -T - -cf - | r "mkdir -p $RDIR/src && tar -xf - -C $RDIR/src"
  r "cd $RDIR/src && { [ ! -f ~/.cargo/env ] || . ~/.cargo/env; } && cargo build --release --locked -p nsplane-examples --bin netstack_bench --bin net_probe 2>&1 | tail -2 && cp target/release/netstack_bench target/release/net_probe ../bin/" >&2
fi
RBIN=./$RDIR/bin

log "local container"
publish=(-p "$PORT:$PORT/udp" -p "$PPORT:$PPORT/udp")
[[ -z ${BENCH_NETWORK:-} ]] || publish=(--network "$BENCH_NETWORK")
docker run -d --label ai-agent=true --label "nsplane-bench=$PREFIX" --name "$C" --cap-add NET_ADMIN \
  ${BENCH_CPUS_A:+--cpuset-cpus "$BENCH_CPUS_A"} "${publish[@]}" "$IMG" sleep infinity >/dev/null
docker cp -q "$NETSTACK_BIN" "$C:/usr/local/bin/netstack_bench"
docker cp -q "$PROBE_BIN" "$C:/usr/local/bin/net_probe"
LOCAL_ADDR=$BENCH_LOCAL_ADDR
[[ $LOCAL_ADDR != container ]] ||
  LOCAL_ADDR=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$C")
[[ -z ${BENCH_NETEM:-} ]] || dx "tc qdisc add dev eth0 root netem $BENCH_NETEM"

# Throwaway keys; the remote's goes over SSH on its command line. The peer is quoted for
# PowerShell, where a bare comma makes a list.
KEY_L=$(dx 'wg genkey') KEY_R=$(dx 'wg genkey')
PUB_L=$(dx "echo $KEY_L | wg pubkey") PUB_R=$(dx "echo $KEY_R | wg pubkey")
NODE_L="netstack_bench --private-key $KEY_L --listen 0.0.0.0:$PORT --address $TUN_L/24 --peer '$PUB_R,${REMOTE_ADDR:+endpoint=$REMOTE_ADDR:$PORT,}allowed-ips=$TUN_R/32,keepalive=5'"
NODE_R="$RBIN/netstack_bench$EXE --private-key $KEY_R --listen 0.0.0.0:$PORT --address $TUN_R/24 --peer '$PUB_L,endpoint=$LOCAL_ADDR:$PORT,allowed-ips=$TUN_L/32,keepalive=5'"

# cell FILE UNIT FILTER...: the median of each FILTER over the runs in FILE, joined by
# " / ", or "failed".
cell() {
  local file=$1 unit=$2 value out=
  shift 2
  for filter; do
    value=$(jq -s -r "map($filter) | sort | .[(length - 1) / 2 | floor] // empty" <"$file" 2>/dev/null) || value=
    [[ -n $value ]] || { printf 'failed'; return; }
    out+=${out:+ / }$value
  done
  printf '%s' "$out${unit:+ $unit}"
}

# probe DIRECTION NAME COUNT RATE: REPS runs of the underlay probe into $OUT/NAME-DIRECTION.jsonl.
probe() {
  local dir=$1 name=$2 count=$3 rate=$4 file=$OUT/$2-$1.jsonl job
  : >"$file"
  for _ in $(seq "$REPS"); do
    if [[ $dir == up ]]; then
      docker exec -d "$C" bash -c "net_probe listen --bind 0.0.0.0:$PPORT --runs 1 > /probe.json 2>/probe.log"
      sleep 0.5
      r "$RBIN/net_probe$EXE send --to $LOCAL_ADDR:$PPORT --count $count --rate $rate" >/dev/null || true
      sleep 3
      dx 'pkill -x net_probe; cat /probe.json' >>"$file" || true
    else
      r "$RBIN/net_probe$EXE listen --bind 0.0.0.0:$PPORT --runs 1" >>"$file" &
      job=$!
      sleep 2
      dx "net_probe send --to $REMOTE_ADDR:$PPORT --count $count --rate $rate" >/dev/null || true
      sleep 3
      remote_kill
      wait "$job" || true
    fi
  done
}

remote_server() {
  r "$NODE_R server --port 5201" >>"$OUT/remote-server.log" 2>&1 &
  server=$!
  sleep 3
}
stop_remote_server() {
  remote_kill
  wait "$server" || true
}

# tunnel DIRECTION NAME ARGS...: REPS client runs against the other end's server.
tunnel() {
  local dir=$1 name=$2 file=$OUT/$2-$1.jsonl
  shift 2
  : >"$file"
  for _ in $(seq "$REPS"); do
    if [[ $dir == up ]]; then
      timeout "$((LIMIT + 30))" "${SSH[@]}" "$TARGET" "$NODE_R client --target $TUN_L:5201 $*" \
        2>>"$OUT/remote-client.log" >>"$file" || remote_kill
    else
      # A local node without the remote's address waits for the remote's handshake,
      # which a remote node sends when it starts: one remote server per run.
      [[ -n $REMOTE_ADDR ]] || remote_server
      dx "timeout $LIMIT $NODE_L client --target $TUN_R:5201 $* 2>>/client.log" >>"$file" || true
      [[ -n $REMOTE_ADDR ]] || stop_remote_server
    fi
  done
}

measure() {
  local dir=$1
  tunnel "$dir" tcp1 --mode tcp --duration 10
  tunnel "$dir" tcp4 --mode tcp --streams 4 --duration 10
  tunnel "$dir" xfer4 --mode tcp --bytes 4194304
  tunnel "$dir" xfer64 --mode tcp --bytes 67108864
  tunnel "$dir" udp50 --mode udp --rate 50000000 --duration 5
  tunnel "$dir" rr --mode rr --count "$RR_COUNT"
  tunnel "$dir" rr1s --mode rr --count 20 --interval 1000
}

DIRS=(up)
[[ -z $REMOTE_ADDR ]] || DIRS+=(down)
for dir in "${DIRS[@]}"; do
  log "baseline $dir"
  probe "$dir" burst 3227 0
  probe "$dir" paced10 1923 10000000
  probe "$dir" paced50 9615 50000000
  probe "$dir" paced200 38461 200000000
done
if [[ -n $REMOTE_ADDR ]]; then
  dx "ping -q -c 40 -i 0.05 $REMOTE_ADDR" >"$OUT/ping-dense.txt" 2>&1 || true
  dx "ping -q -c 10 -i 1 $REMOTE_ADDR" >"$OUT/ping-sparse.txt" 2>&1 || true
fi

log "tunnel up"
docker exec -d "$C" bash -c "$NODE_L server --port 5201 > /server.log 2>&1"
sleep 1
measure up
dx 'pkill -x netstack_bench; true'

log "tunnel down"
[[ -z $REMOTE_ADDR ]] || remote_server
measure down
[[ -z $REMOTE_ADDR ]] || stop_remote_server

loss='.loss * 1000 | round / 10'
mbit='.bits_per_second / 1e6 | round'
ms() { echo ".$1 / 100 | round / 10"; }
{
  echo "| Measurement | up (remote -> local) | down (local -> remote) |"
  echo "|---|---|---|"
  # row LABEL NAME UNIT FILTER...
  row() {
    local label=$1 name=$2 down=-
    shift 2
    [[ ! -f $OUT/$name-down.jsonl ]] || down=$(cell "$OUT/$name-down.jsonl" "$@")
    echo "| $label | $(cell "$OUT/$name-up.jsonl" "$@") | $down |"
  }
  row 'Raw UDP, 3227 x 1300 B unpaced, loss' burst % "$loss"
  row 'Raw UDP, 10 Mbit/s paced, loss' paced10 % "$loss"
  row 'Raw UDP, 50 Mbit/s paced, loss' paced50 % "$loss"
  row 'Raw UDP, 200 Mbit/s paced, loss' paced200 % "$loss"
  row 'Raw UDP, 200 Mbit/s paced, reordered / longest loss run' paced200 '' .reordered .longest_loss_run
  row 'Tunnel TCP, 1 stream, 10 s' tcp1 Mbit/s "$mbit"
  row 'Tunnel TCP, 4 streams, 10 s' tcp4 Mbit/s "$mbit"
  row 'Tunnel, 4 MiB at once' xfer4 s '.seconds * 100 | round / 100'
  row 'Tunnel, 64 MiB at once' xfer64 s '.seconds * 100 | round / 100'
  row 'Tunnel UDP, 50 Mbit/s paced, loss' udp50 % '.loss_pct * 10 | round / 10'
  row 'Tunnel, 1-byte round trip, p50 / p99' rr ms "$(ms p50_us)" "$(ms p99_us)"
  row 'Tunnel, 1-byte round trip 1 s apart, p50 / max' rr1s ms "$(ms p50_us)" "$(ms max_us)"
  echo
  ping_line() { [[ ! -f $1 ]] || echo "- ping, $2: $(grep -E 'rtt|round-trip' "$1" | cut -d= -f2 | xargs || true) (min/avg/max/mdev)"; }
  ping_line "$OUT/ping-dense.txt" '50 ms interval'
  ping_line "$OUT/ping-sparse.txt" '1 s interval'
  echo "- median of $REPS runs; remote $OS${BENCH_NETEM:+, local egress shaped with netem $BENCH_NETEM}"
  echo "- nsplane $(git -C "$REPO" describe --always --dirty 2>/dev/null || echo unknown), local load $(cut -d' ' -f1-3 /proc/loadavg)"
} >"$OUT/results.md"
cat "$OUT/results.md"
