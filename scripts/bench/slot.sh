#!/usr/bin/env bash
# Run one timing-sensitive command in a bench slot.
#
# The host has two CCDs with separate L3 caches: CCD0 = cores 0-7 (CPUs 0-7, SMT 16-23) and
# CCD1 = cores 8-15 (CPUs 8-15, SMT 24-31). A slot is one CCD's physical cores, so two
# measurements can run at the same time without sharing a core or an L3:
#
#   slot 0: BENCH_CPUS_A=1-3   BENCH_CPUS_B=4-7    BENCH_CPUS=1-7   (CPU 0 left to the host)
#   slot 1: BENCH_CPUS_A=8-11  BENCH_CPUS_B=12-15  BENCH_CPUS=8-15
#
# The SMT siblings (16-31) are not used by benches. Both slots still share memory bandwidth,
# the package power budget and the kernel network stack, so compare A and B only within one
# slot invocation (interleaved A,B,A,B), and take release tables on an otherwise idle host.
#
#   scripts/bench/slot.sh <command> [args...]
#
# The command gets BENCH_SLOT, BENCH_CPUS_A, BENCH_CPUS_B and BENCH_CPUS in its environment;
# wg-compare.sh picks up the first two, criterion benches in a container pass
# `--cpuset-cpus "$BENCH_CPUS"`. The first free slot is taken; if both are busy, it waits for
# either. It also holds /tmp/nsplane-bench.lock shared, so a runner that still takes that lock
# exclusively (the old single-slot rule) never overlaps a slot run.
#
# BENCH_LOCK_DIR (default /tmp) moves the lock files, for tests of this script.
#
# Fairness: one A/B per invocation; wait 120 s before taking a slot again. Builds and tests that
# do not measure time do not take a slot.
set -euo pipefail

if [ $# -eq 0 ]; then
  echo "usage: $0 <command> [args...]" >&2
  exit 2
fi

DIR=${BENCH_LOCK_DIR:-/tmp}
GLOBAL=$DIR/nsplane-bench.lock
SLOTS=("$DIR/nsplane-bench-slot0.lock" "$DIR/nsplane-bench-slot1.lock")
CPUS_A=(1-3 8-11)
CPUS_B=(4-7 12-15)
CPUS=(1-7 8-15)

exec {global}>>"$GLOBAL"
flock -s "$global"

slot=""
while [ -z "$slot" ]; do
  for i in 0 1; do
    exec {fd}>>"${SLOTS[$i]}"
    if flock -n "$fd"; then
      slot=$i
      break
    fi
    exec {fd}>&-
  done
  [ -n "$slot" ] || sleep 5
done

export BENCH_SLOT=$slot
export BENCH_CPUS_A=${CPUS_A[$slot]}
export BENCH_CPUS_B=${CPUS_B[$slot]}
export BENCH_CPUS=${CPUS[$slot]}
echo "bench slot $slot: a=$BENCH_CPUS_A b=$BENCH_CPUS_B all=$BENCH_CPUS load=$(cut -d' ' -f1-3 /proc/loadavg)" >&2
"$@"
