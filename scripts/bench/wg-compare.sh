#!/usr/bin/env bash
# Throughput and latency comparison of WireGuard implementations on this Linux host.
#
# Each pair runs in two fresh containers (side a = sender, side b = receiver) on a dedicated
# docker network, pinned to two CPU sets. Every WireGuard implementation is configured with
# `wg` and `ip` exactly like kernel WireGuard. Nothing on the host is reconfigured. Needs
# docker and the `wireguard` kernel module on the host. See scripts/bench/README.md.
#
#   cargo build -p nsplane-cli --release --locked && scripts/bench/wg-compare.sh
#
# Knobs (environment):
#   BENCH_PAIRS        comma-separated pairs; default all:
#                      kernel-kernel,nsplane-nsplane,nsplane-kernel,kernel-nsplane,wggo-wggo,netstack
#                      (first named side = side a = sender)
#   BENCH_DURATION     seconds per iperf3 / netstack_bench run (default 30)
#   BENCH_REPS         repetitions; the table reports medians (default 3)
#   BENCH_UDP_RATES    comma-separated UDP rates, iperf3 -b syntax (default 1G,3G)
#   BENCH_PING_COUNT   pings per latency run at 10 ms intervals (default 1000)
#   BENCH_CPUS_A       --cpuset-cpus of side a (default 8-11, slot 1; see slot.sh)
#   BENCH_CPUS_B       --cpuset-cpus of side b (default 12-15, slot 1; see slot.sh)
#   BENCH_NSPLANE_VARIANTS
#                      ';'-separated nsplane-nsplane variants NAME[:ENV[:ARGS]], ENV and ARGS
#                      space-separated, applied to nsplane-cli on both sides, e.g.
#                      "default;t2:WG_THREADS=2;dbg:WG_LOG_LEVEL=debug:--threads 8"
#                      (default: offload on/off x crypto workers 0/2, $DEFAULT_VARIANTS)
#   NSPLANE_CLI_BIN    nsplane-cli binary under test (default target/release/nsplane-cli)
#   NETSTACK_BENCH_BIN netstack_bench binary (default target/release/netstack_bench); the
#                      netstack pair is skipped when it is missing
#   BENCH_OUT          run directory (default .tmp/bench/<UTC timestamp>, gitignored)
#   BENCH_PREFIX       container/network name prefix (default nsplane-bench-<pid>)
set -euo pipefail
CALLER=$PWD
cd "$(dirname "$0")/../.."
REPO=$PWD
abs() { case $1 in /*) echo "$1" ;; *) echo "$CALLER/$1" ;; esac; }

PAIRS=${BENCH_PAIRS:-kernel-kernel,nsplane-nsplane,nsplane-kernel,kernel-nsplane,wggo-wggo,netstack}
DURATION=${BENCH_DURATION:-30}
REPS=${BENCH_REPS:-3}
UDP_RATES=${BENCH_UDP_RATES:-1G,3G}
PING_COUNT=${BENCH_PING_COUNT:-1000}
CPUS_A=${BENCH_CPUS_A:-8-11}
CPUS_B=${BENCH_CPUS_B:-12-15}
# "default" is the stock configuration (offload on, no crypto workers).
DEFAULT_VARIANTS='default;w2:WG_CRYPTO_WORKERS=2;nooffload:WG_NO_OFFLOAD=1;nooffload-w2:WG_NO_OFFLOAD=1 WG_CRYPTO_WORKERS=2'
VARIANTS=${BENCH_NSPLANE_VARIANTS:-$DEFAULT_VARIANTS}
NSPLANE_BIN=$(abs "${NSPLANE_CLI_BIN:-$REPO/target/release/nsplane-cli}")
NETSTACK_BIN=$(abs "${NETSTACK_BENCH_BIN:-$REPO/target/release/netstack_bench}")
OUT=$(abs "${BENCH_OUT:-$REPO/.tmp/bench/$(date -u +%Y%m%dT%H%M%SZ)}")
PREFIX=${BENCH_PREFIX:-nsplane-bench-$$}
NET=$PREFIX-net
IMG=ai-agent/nsplane-bench
WGGO_IMG=ai-agent/wireguard-go
LABELS=(--label ai-agent=true --label "nsplane-bench=$PREFIX")
TUN_A=10.77.0.1 TUN_B=10.77.0.2 TUN_C=10.77.0.3
KMARK='†'

cleanup() {
  docker ps -aq --filter "label=nsplane-bench=$PREFIX" | xargs -r docker rm -f >/dev/null 2>&1 || true
  docker network rm "$NET" >/dev/null 2>&1 || true
}
trap cleanup EXIT
trap 'exit 130' INT TERM

mkdir -p "$OUT"
exec > >(tee -a "$OUT/run.log") 2>&1
log() { echo "== $*"; }
note() { echo "- $*" >> "$OUT/notes.md"; log "$*"; }

# --- helpers ---------------------------------------------------------------------------------

dx() { local c=$1; shift; docker exec "$c" bash -c "$*"; }
ip_of() { docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$1"; }
cpu_usec() { docker exec "$1" awk '$1 == "usage_usec" { print $2 }' /sys/fs/cgroup/cpu.stat; }
loadavg() { cut -d' ' -f1-3 /proc/loadavg; }
# CPU seconds per GB: cpu_per_gb USEC_BEFORE USEC_AFTER BYTES
cpu_per_gb() { awk -v a="$1" -v b="$2" -v n="$3" 'BEGIN { printf "%.3f\n", (b - a) / 1e6 / (n / 1e9) }'; }
# 500M -> 500000000 (iperf3 -b units, decimal)
rate_bits() {
  awk -v r="$1" 'BEGIN { u = toupper(substr(r, length(r))); m = u == "K" ? 1e3 : u == "M" ? 1e6 : u == "G" ? 1e9 : 1; printf "%.0f\n", (r + 0) * m }'
}
# Percentile (nearest rank) of the numbers on stdin: pct P
pct() { sort -g | awk -v p="$1" '{ v[NR] = $1 } END { if (!NR) { print "n/a"; exit } i = int((p * NR + 99) / 100); printf "%.3f\n", v[i < 1 ? 1 : i] }'; }
# Median of the numeric lines of a file: median FILE DIGITS
median() {
  { grep -E '^[0-9.eE+-]+$' "$1" 2>/dev/null || true; } | sort -g |
    awk -v d="$2" '{ v[NR] = $1 } END { if (!NR) { print "n/a"; exit } m = NR % 2 ? v[(NR + 1) / 2] : (v[NR / 2] + v[NR / 2 + 1]) / 2; printf "%.*f\n", d, m }'
}
# Record ping p50/p99 (ms) of a ping output file: ping_stats FILE KIND
ping_stats() {
  local times; times=$(grep -o 'time=[0-9.]*' "$1" | cut -d= -f2 || true)
  pct 50 <<<"$times" >> "$U/ping-$2-p50.vals"
  pct 99 <<<"$times" >> "$U/ping-$2-p99.vals"
}

# --- WireGuard pairs (kernel, nsplane, wggo) ---------------------------------------------------

# up_wg CONTAINER IMPL EXTRA_ENV EXTRA_ARGS: creates wg0 with the key /k, prints its UDP port.
# nsplane-cli keeps the ephemeral port it bound at startup: a UAPI listen-port rebinds the
# socket with offload on, which would undo WG_NO_OFFLOAD.
up_wg() {
  local c=$1 impl=$2 env=$3 args=$4
  case $impl in
    kernel) dx "$c" 'ip link add wg0 type wireguard' ;;
    nsplane) docker exec -d "$c" bash -c "env WG_SUDO=1 $env nsplane-cli $args wg0 > /wg.log 2>&1" ;;
    wggo) docker exec -d "$c" bash -c 'wireguard-go -f wg0 > /wg.log 2>&1' ;;
  esac
  if [[ $impl != kernel ]]; then
    for _ in $(seq 1 100); do dx "$c" 'test -S /var/run/wireguard/wg0.sock' && break; sleep 0.1; done
    dx "$c" 'test -S /var/run/wireguard/wg0.sock' || { dx "$c" 'cat /wg.log' >&2; return 1; }
  fi
  if [[ $impl == nsplane ]]; then dx "$c" 'wg set wg0 private-key /k && wg show wg0 listen-port'
  else dx "$c" 'wg set wg0 private-key /k listen-port 51820 && echo 51820'; fi
}

# peer_wg CONTAINER ADDR PEER_ADDR PEER_PUB PEER_IP PEER_PORT
peer_wg() {
  local c=$1 addr=$2 peer_addr=$3 peer_pub=$4 peer_ip=$5 peer_port=$6
  dx "$c" "wg set wg0 peer $peer_pub allowed-ips $peer_addr/32 endpoint $peer_ip:$peer_port" \
    "&& ip addr add $addr/24 dev wg0 && ip link set wg0 mtu 1420 up"
}

iperf() { sleep 1; docker exec "$A" iperf3 -c "$TUN_B" -J "$@"; }

rep_wg() {
  local d=$1 a0 b0 a1 b1 bytes rate load
  a0=$(cpu_usec "$A"); b0=$(cpu_usec "$B")
  iperf -t "$DURATION" -P 1 > "$d/tcp-p1.json"
  a1=$(cpu_usec "$A"); b1=$(cpu_usec "$B")
  bytes=$(jq '.end.sum_received.bytes' "$d/tcp-p1.json")
  jq '.end.sum_received.bits_per_second / 1e9' "$d/tcp-p1.json" >> "$U/tcp1.vals"
  cpu_per_gb "$a0" "$a1" "$bytes" >> "$U/cpu-a.vals"
  cpu_per_gb "$b0" "$b1" "$bytes" >> "$U/cpu-b.vals"
  iperf -t "$DURATION" -P 4 > "$d/tcp-p4.json"
  jq '.end.sum_received.bits_per_second / 1e9' "$d/tcp-p4.json" >> "$U/tcp4.vals"
  for rate in ${UDP_RATES//,/ }; do
    iperf -t "$DURATION" -u -b "$rate" -l 1380 > "$d/udp-$rate.json"
    jq '.end.sum.lost_percent' "$d/udp-$rate.json" >> "$U/udp-$rate.vals"
  done
  # ping exits 1 when a reply is missing; lost replies just do not count.
  docker exec "$A" ping -i 0.01 -c "$PING_COUNT" -W 1 "$TUN_B" > "$d/ping-idle.txt" || true
  ping_stats "$d/ping-idle.txt" idle
  # The saturating flow outlasts the pings; the first 2 s are its ramp-up.
  iperf -t $((PING_COUNT / 50 + 4)) -P 1 > "$d/ping-load-tcp.json" &
  load=$!
  sleep 3
  docker exec "$A" ping -i 0.01 -c "$PING_COUNT" -W 1 "$TUN_B" > "$d/ping-loaded.txt" || true
  wait "$load"
  ping_stats "$d/ping-loaded.txt" loaded
}

# unit_wg IMPL_A IMPL_B EXTRA_ENV EXTRA_ARGS
unit_wg() {
  local ia=$1 ib=$2 env=$3 args=$4 rep pub_a pub_b port_a port_b
  local opts=(--cap-add NET_ADMIN --device /dev/net/tun -v "$NSPLANE_BIN:/usr/local/bin/nsplane-cli:ro")
  docker run -d --rm "${LABELS[@]}" --name "$A" --network "$NET" --cpuset-cpus "$CPUS_A" "${opts[@]}" "$IMG" sleep infinity >/dev/null
  docker run -d --rm "${LABELS[@]}" --name "$B" --network "$NET" --cpuset-cpus "$CPUS_B" "${opts[@]}" "$IMG" sleep infinity >/dev/null
  if [[ $ia == wggo || $ib == wggo ]]; then
    docker cp -q "$OUT/bin/wireguard-go" "$A:/usr/local/bin/wireguard-go"
    docker cp -q "$OUT/bin/wireguard-go" "$B:/usr/local/bin/wireguard-go"
  fi
  IP_A=$(ip_of "$A"); IP_B=$(ip_of "$B")
  dx "$A" 'umask 077; wg genkey > /k; wg pubkey < /k > /p'; dx "$B" 'umask 077; wg genkey > /k; wg pubkey < /k > /p'
  pub_a=$(dx "$A" 'cat /p'); pub_b=$(dx "$B" 'cat /p')
  port_a=$(up_wg "$A" "$ia" "$env" "$args"); port_b=$(up_wg "$B" "$ib" "$env" "$args")
  peer_wg "$A" "$TUN_A" "$TUN_B" "$pub_b" "$IP_B" "$port_b"
  peer_wg "$B" "$TUN_B" "$TUN_A" "$pub_a" "$IP_A" "$port_a"
  for _ in $(seq 1 20); do dx "$A" "ping -c 1 -W 1 $TUN_B >/dev/null" && break; done
  dx "$A" "ping -c 1 -W 1 $TUN_B >/dev/null" || { log "tunnel did not come up"; return 1; }
  dx "$B" 'iperf3 -s -D'
  for rep in $(seq 1 "$REPS"); do
    log "$LABEL rep $rep/$REPS"
    mkdir -p "$U/rep$rep"
    rep_wg "$U/rep$rep"
  done
  for c in "$A" "$B"; do dx "$c" 'cat /wg.log 2>/dev/null; wg show' > "$U/$([[ $c == "$A" ]] && echo a || echo b)-wg.txt" || true; done
}

# --- netstack pair (user-space mode, in-process load) ------------------------------------------

# ns_client KEY_FILE ADDR LISTEN_PORT MODE ARGS...
ns_client() {
  local key=$1 addr=$2 port=$3 mode=$4; shift 4
  docker exec "$A" netstack_bench --private-key-file "$key" --listen "0.0.0.0:$port" --address "$addr/24" \
    --peer "$PUB_B,endpoint=$IP_B:51820,allowed-ips=$TUN_B/32" \
    client --target "$TUN_B:5201" --mode "$mode" "$@"
}

rep_netstack() {
  local d=$1 a0 b0 a1 b1 bytes rate load
  a0=$(cpu_usec "$A"); b0=$(cpu_usec "$B")
  sleep 1; ns_client /k "$TUN_A" 51820 tcp --streams 1 --duration "$DURATION" > "$d/tcp-p1.json"
  a1=$(cpu_usec "$A"); b1=$(cpu_usec "$B")
  bytes=$(jq '.bytes' "$d/tcp-p1.json")
  jq '.bits_per_second / 1e9' "$d/tcp-p1.json" >> "$U/tcp1.vals"
  cpu_per_gb "$a0" "$a1" "$bytes" >> "$U/cpu-a.vals"
  cpu_per_gb "$b0" "$b1" "$bytes" >> "$U/cpu-b.vals"
  sleep 1; ns_client /k "$TUN_A" 51820 tcp --streams 4 --duration "$DURATION" > "$d/tcp-p4.json"
  jq '.bits_per_second / 1e9' "$d/tcp-p4.json" >> "$U/tcp4.vals"
  for rate in ${UDP_RATES//,/ }; do
    sleep 1; ns_client /k "$TUN_A" 51820 udp --streams 1 --duration "$DURATION" --rate "$(rate_bits "$rate")" > "$d/udp-$rate.json"
    jq '.loss_pct' "$d/udp-$rate.json" >> "$U/udp-$rate.vals"
  done
  sleep 1; ns_client /k "$TUN_A" 51820 rr --streams 1 --duration "$DURATION" --count "$PING_COUNT" > "$d/rr-idle.json"
  jq '.p50_us / 1000' "$d/rr-idle.json" >> "$U/ping-idle-p50.vals"
  jq '.p99_us / 1000' "$d/rr-idle.json" >> "$U/ping-idle-p99.vals"
  if [[ $NS_LOADED == 1 ]]; then
    # rr from a second peer (10.77.0.3, key /k2) while the first saturates one TCP stream.
    ns_client /k "$TUN_A" 51820 tcp --streams 1 --duration $((PING_COUNT / 50 + 4)) > "$d/rr-load-tcp.json" &
    load=$!
    sleep 3
    ns_client /k2 "$TUN_C" 51821 rr --streams 1 --duration "$DURATION" --count "$PING_COUNT" > "$d/rr-loaded.json" || true
    wait "$load"
    jq '.p50_us / 1000' "$d/rr-loaded.json" >> "$U/ping-loaded-p50.vals" || true
    jq '.p99_us / 1000' "$d/rr-loaded.json" >> "$U/ping-loaded-p99.vals" || true
  fi
}

unit_netstack() {
  local rep pub_a pub_c base
  docker run -d --rm "${LABELS[@]}" --name "$A" --network "$NET" --cpuset-cpus "$CPUS_A" "$IMG" sleep infinity >/dev/null
  docker run -d --rm "${LABELS[@]}" --name "$B" --network "$NET" --cpuset-cpus "$CPUS_B" "$IMG" sleep infinity >/dev/null
  docker cp -q "$NETSTACK_BIN" "$A:/usr/local/bin/netstack_bench"
  docker cp -q "$NETSTACK_BIN" "$B:/usr/local/bin/netstack_bench"
  IP_A=$(ip_of "$A"); IP_B=$(ip_of "$B")
  dx "$A" 'umask 077; wg genkey > /k; wg pubkey < /k > /k.pub; wg genkey > /k2; wg pubkey < /k2 > /k2.pub'
  dx "$B" 'umask 077; wg genkey > /k; wg pubkey < /k > /k.pub'
  pub_a=$(dx "$A" 'cat /k.pub'); pub_c=$(dx "$A" 'cat /k2.pub'); PUB_B=$(dx "$B" 'cat /k.pub')
  base="netstack_bench --private-key-file /k --listen 0.0.0.0:51820 --address $TUN_B/24 --peer $pub_a,allowed-ips=$TUN_A/32"
  # A second peer serves the loaded rr; without it the loaded column is n/a.
  NS_LOADED=1
  docker exec -d "$B" bash -c "$base --peer $pub_c,allowed-ips=$TUN_C/32 server --port 5201 > /ns.log 2>&1"
  sleep 1
  if ! dx "$B" 'pgrep -x netstack_bench >/dev/null'; then
    note "netstack: the server rejected a second --peer; loaded rr not measured"
    NS_LOADED=0
    docker exec -d "$B" bash -c "$base server --port 5201 > /ns.log 2>&1"
    sleep 1
  fi
  for rep in $(seq 1 "$REPS"); do
    log "$LABEL rep $rep/$REPS"
    mkdir -p "$U/rep$rep"
    rep_netstack "$U/rep$rep"
  done
  dx "$B" 'cat /ns.log' > "$U/b-server.log" || true
}

# --- one pair/variant: containers up, reps, a table row ----------------------------------------

# run_unit SLUG LABEL IMPL_A IMPL_B EXTRA_ENV EXTRA_ARGS
run_unit() {
  local slug=$1 ia=$3 ib=$4 env=$5 args=$6 udp="" rate ca cb
  LABEL=$2 U=$OUT/$slug
  mkdir -p "$U"
  log "$LABEL (a=$ia on $CPUS_A, b=$ib on $CPUS_B)"
  local load0; load0=$(loadavg)
  if [[ $ia == netstack ]]; then unit_netstack; else unit_wg "$ia" "$ib" "$env" "$args"; fi
  echo "| $LABEL | $load0 | $(loadavg) |" >> "$OUT/loads.md"
  for rate in ${UDP_RATES//,/ }; do udp+="${udp:+, }$rate: $(median "$U/udp-$rate.vals" 2)"; done
  ca=$(median "$U/cpu-a.vals" 2); cb=$(median "$U/cpu-b.vals" 2)
  [[ $ia == kernel ]] && ca+=" $KMARK"
  [[ $ib == kernel ]] && cb+=" $KMARK"
  printf '| %s | %s | %s | %s | %s / %s | %s / %s | %s | %s |\n' "$LABEL" \
    "$(median "$U/tcp1.vals" 2)" "$(median "$U/tcp4.vals" 2)" "$udp" \
    "$(median "$U/ping-idle-p50.vals" 3)" "$(median "$U/ping-idle-p99.vals" 3)" \
    "$(median "$U/ping-loaded-p50.vals" 3)" "$(median "$U/ping-loaded-p99.vals" 3)" \
    "$ca" "$cb" >> "$OUT/rows.md"
}

# --- main --------------------------------------------------------------------------------------

UNITS=()
for pair in ${PAIRS//,/ }; do
  case $pair in
    netstack)
      if [[ -x $NETSTACK_BIN ]]; then UNITS+=("netstack|netstack (user-space)|netstack|netstack||")
      else note "netstack: skipped, binary not found: $NETSTACK_BIN"; fi ;;
    kernel-kernel | nsplane-nsplane | nsplane-kernel | kernel-nsplane | wggo-wggo)
      if [[ $pair == *nsplane* && ! -x $NSPLANE_BIN ]]; then
        note "$pair: skipped, binary not found: $NSPLANE_BIN"; continue
      fi
      if [[ $pair == nsplane-nsplane ]]; then
        IFS=';' read -ra vs <<<"$VARIANTS"
        for v in "${vs[@]}"; do
          name=${v%%:*} rest=""; [[ $v == *:* ]] && rest=${v#*:}
          venv=${rest%%:*} vargs=""; [[ $rest == *:* ]] && vargs=${rest#*:}
          label=$pair; [[ $name != default ]] && label="$pair ($name)"
          UNITS+=("$pair-$name|$label|nsplane|nsplane|$venv|$vargs")
        done
      else
        UNITS+=("$pair|$pair|${pair%-*}|${pair#*-}||")
      fi ;;
    *) echo "unknown pair: $pair" >&2; exit 2 ;;
  esac
done

log "run directory $OUT"
LOAD_START=$(loadavg)
docker build -q "${LABELS[@]:0:2}" -t "$IMG" scripts/bench >/dev/null
WGGO_VERSION="not built"
if [[ ,$PAIRS, == *,wggo-wggo,* ]]; then
  docker build -q "${LABELS[@]:0:2}" -t "$WGGO_IMG" scripts/bench/wireguard-go >/dev/null
  mkdir -p "$OUT/bin"
  docker run --rm "${LABELS[@]}" "$WGGO_IMG" cat /usr/local/bin/wireguard-go > "$OUT/bin/wireguard-go"
  chmod +x "$OUT/bin/wireguard-go"
  WGGO_VERSION=$(docker run --rm "${LABELS[@]}" "$WGGO_IMG" cat /wireguard-go.version)
fi
IPERF_VERSION=$(docker run --rm "${LABELS[@]}" "$IMG" iperf3 --version | head -1)
NSPLANE_COMMIT=unknown
if git -C "$(dirname "$NSPLANE_BIN")" rev-parse --short HEAD >/dev/null 2>&1; then
  NSPLANE_COMMIT=$(git -C "$(dirname "$NSPLANE_BIN")" rev-parse --short HEAD)
  git -C "$(dirname "$NSPLANE_BIN")" diff --quiet HEAD || NSPLANE_COMMIT+="-dirty"
fi
docker network create "${LABELS[@]}" "$NET" >/dev/null

: > "$OUT/rows.md"; : > "$OUT/loads.md"; touch "$OUT/notes.md"
i=0
for unit in "${UNITS[@]}"; do
  i=$((i + 1))
  IFS='|' read -r slug label ia ib venv vargs <<<"$unit"
  A=$PREFIX-u$i-a B=$PREFIX-u$i-b
  # A subshell per unit: a failing pair is reported and the others still run.
  run_unit "$slug" "$label" "$ia" "$ib" "$venv" "$vargs" &
  if ! wait $!; then
    echo "| $label | failed (see run.log) | | | | | | |" >> "$OUT/rows.md"
    note "$label: failed, see run.log"
  fi
  docker rm -f "$A" "$B" >/dev/null 2>&1 || true
done
LOAD_END=$(loadavg)

{
  echo "# WireGuard implementations: throughput and latency"
  echo
  echo "## Setup"
  echo
  echo "- Date (UTC): $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "- Host: $(hostname), $(nproc) CPUs: $(awk -F': ' '/^model name/ { print $2; exit }' /proc/cpuinfo)"
  echo "- Kernel: $(uname -r)"
  echo "- CPU sets: side a $CPUS_A, side b $CPUS_B (docker --cpuset-cpus)"
  echo "- Load average (1/5/15 min): start $LOAD_START, end $LOAD_END; per pair below"
  echo "- Duration ${DURATION} s per run, $REPS reps (medians), UDP rates $UDP_RATES (-l 1380), $PING_COUNT pings at 10 ms"
  echo "- nsplane-cli: $NSPLANE_BIN at $NSPLANE_COMMIT; variants: $VARIANTS"
  echo "- wireguard-go: $WGGO_VERSION"
  echo "- netstack_bench: $NETSTACK_BIN"
  echo "- $IPERF_VERSION; MTU 1420; tunnel $TUN_A/24 (a) -> $TUN_B/24 (b)"
  echo
  echo "## Results"
  echo
  echo "| Pair (a -> b) | TCP P1 Gbit/s | TCP P4 Gbit/s | UDP rate: loss % | ping p50 / p99 idle ms | ping p50 / p99 loaded ms | CPU s/GB a | CPU s/GB b |"
  echo "|---|---|---|---|---|---|---|---|"
  cat "$OUT/rows.md"
  echo
  echo "Throughput is the receiver-side sum. Loaded ping runs next to one saturating TCP stream."
  echo "CPU s/GB: cgroup \`usage_usec\` of each container over the TCP P1 run divided by the GB"
  echo "received; it includes iperf3's own CPU. $KMARK Kernel WireGuard encrypts in kernel workqueue"
  echo "threads that are not charged to the container cgroup, so its side is an undercount."
  echo "netstack: the WireGuard engine and an in-process load generator (\`netstack_bench\`) in one"
  echo "process per side, no TUN; its ping columns are 1-byte TCP request/response round trips."
  echo
  echo "## Load average per pair (1/5/15 min)"
  echo
  echo "| Pair | before | after |"
  echo "|---|---|---|"
  cat "$OUT/loads.md"
  if [[ -s $OUT/notes.md ]]; then echo; echo "## Notes"; echo; cat "$OUT/notes.md"; fi
} > "$OUT/results.md"
log "results: $OUT/results.md"
cat "$OUT/results.md"
