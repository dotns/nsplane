#!/usr/bin/env bash
# Product-term scan: product concepts must not appear in the public API or rustdoc of the
# nsplane crates (ADR docs/decisions/2026-10-06-business-agnostic-scope.md).
#
#   scripts/check-product-terms.sh [--report] [--crate <name>]... [--self-test] [-h|--help]
#
# Scanned, in crates/*/src/**/*.rs outside test code:
#   - rustdoc: `///` and `//!` lines, `#[doc = ...]` attributes;
#   - lines that start with bare `pub ` (not `pub(crate)` and the like);
#   - every line inside the body of a `pub struct`, `pub enum` or a multi-line `pub use`.
# Only non-test code is scanned. Skipped: files under a `tests/` directory, files named
# `tests.rs`, inline `#[cfg(test)] mod name { ... }` blocks and the files of
# `#[cfg(test)] mod name;`. `benches/` and crate-level `tests/` sit outside `src/` and are never
# scanned. Test literals (say `b"NSGWP2P1"` in a test module) are out of scope.
#
# Terms: `ns` and `Quick` as whole words (case-sensitive); `quick-v2` / `quick v2`; and,
# case-insensitive with no letter right before (a camelCase boundary counts): nsd, nsgw,
# realm, subject, group, terminate, idp, alias4, alias6, node6, gateway consumer. `nsd` and
# `idp` also need no letter right after.
#
# Allowlist: scripts/product-terms-allow.txt, `<path>|<term>|<substring>|<reason>` (no `|`
# inside a field); a
# substring of `*` covers every line of that path and term. Generic networking vocabulary is
# allowlisted with a reason, never renamed; product uses are reworded, never allowlisted.
#
# Gate mode (default) exits 1 on any hit or stale allowlist entry; --report always exits 0.
# A malformed allowlist exits 2 in both modes. Tools: bash, grep, awk, sed, sort (no cargo).
set -euo pipefail

usage() {
  cat <<'EOF'
usage: scripts/check-product-terms.sh [--report] [--crate <name>]... [--self-test]

  (no flag)       gate mode: print hits and a per-crate summary; exit 1 on any hit or
                  stale allowlist entry
  --report        same output, always exit 0 (malformed allowlist still exits 2)
  --crate <name>  scan only crates/<name> (repeatable)
  --self-test     run the scanner against built-in fixtures
  -h, --help      show this help
EOF
}

# Prints the target files of `#[cfg(test)] mod name;` declarations in the given files.
test_mod_files() {
  LC_ALL=C awk '
    FNR == 1 { pending = 0; path = "" }
    {
      line = $0
      if (line ~ /^[ \t]*#\[cfg\(test\)\]/) {
        pending = 1; path = ""
        sub(/^[ \t]*#\[cfg\(test\)\][ \t]*/, "", line)
        if (line == "") next
      } else if (!pending) next
      if (line ~ /^[ \t]*$/) next
      if (line ~ /^[ \t]*#\[path[ \t]*=/) {
        path = line
        sub(/^[^"]*"/, "", path); sub(/".*$/, "", path)
        next
      }
      if (line ~ /^[ \t]*#\[/) next
      pending = 0
      if (line !~ /^[ \t]*(pub(\([^)]*\))?[ \t]+)?mod[ \t]+[A-Za-z0-9_]+[ \t]*;/) next
      name = line
      sub(/^[ \t]*(pub(\([^)]*\))?[ \t]+)?mod[ \t]+/, "", name); sub(/[^A-Za-z0-9_].*$/, "", name)
      dir = FILENAME; sub(/\/[^\/]*$/, "", dir)
      base = FILENAME; sub(/^.*\//, "", base)
      if (path != "") { print dir "/" path; next }
      if (base != "lib.rs" && base != "main.rs" && base != "mod.rs") {
        stem = base; sub(/\.rs$/, "", stem); dir = dir "/" stem
      }
      print dir "/" name ".rs"
      print dir "/" name "/mod.rs"
    }
  ' "$@"
}

# The scanner. Arguments: allowlist file, space-separated crate list, then the files.
# Prints hits, stale entries and the summary; exits 0 (clean), 1 (findings) or 2 (bad allowlist).
scan_files() {
  local allow=$1 crates=$2
  shift 2
  LC_ALL=C awk -v q="'" -v allow="$allow" -v crates="$crates" '
    function trim(s) { sub(/^[ \t]+/, "", s); sub(/[ \t]+$/, "", s); return s }
    function hashes(n,   s) { s = ""; while (n-- > 0) s = s "#"; return s }

    # Walks one line of code, keeping string state across lines. Sets CODE (the line without
    # a trailing or block comment) and OPEN / CLOSE (braces outside strings, chars, comments).
    function sanitize(s,   i, n, c, out, j, p) {
      n = length(s); out = ""; OPEN = 0; CLOSE = 0
      for (i = 1; i <= n; i++) {
        c = substr(s, i, 1)
        if (st == 1) {
          out = out c
          if (c == "\\") { out = out substr(s, i + 1, 1); i++ }
          else if (c == "\"") st = 0
          continue
        }
        if (st == 2) {
          out = out c
          if (c == "\"" && substr(s, i + 1, rh) == hashes(rh)) {
            out = out substr(s, i + 1, rh); i += rh; st = 0
          }
          continue
        }
        if (st == 3) {
          if (c == "*" && substr(s, i + 1, 1) == "/") { i++; if (--cd == 0) st = 0 }
          else if (c == "/" && substr(s, i + 1, 1) == "*") { i++; cd++ }
          continue
        }
        if (c == "/" && substr(s, i + 1, 1) == "/") break
        if (c == "/" && substr(s, i + 1, 1) == "*") { st = 3; cd = 1; i++; continue }
        if (c == "\"") { st = 1; out = out c; continue }
        p = (i == 1) ? "" : substr(s, i - 1, 1)
        if (c == "r" && match(substr(s, i), /^r#*"/) && (p !~ /[A-Za-z0-9_]/ || (p == "b" && (i == 2 || substr(s, i - 2, 1) !~ /[A-Za-z0-9_]/)))) {
          rh = RLENGTH - 2; out = out substr(s, i, RLENGTH); i += RLENGTH - 1; st = 2
          continue
        }
        if (c == q) {
          if (substr(s, i + 1, 1) == "\\") {
            j = index(substr(s, i + 3), q)
            if (j > 0) { out = out substr(s, i, j + 3); i += j + 2; continue }
          } else if (substr(s, i + 2, 1) == q) {
            out = out substr(s, i, 3); i += 2; continue
          }
        }
        if (c == "{") OPEN++
        else if (c == "}") CLOSE++
        out = out c
      }
      CODE = out
    }

    function camelsplit(s,   out) {
      out = ""
      while (match(s, /[a-z][A-Z]/)) { out = out substr(s, 1, RSTART) "_"; s = substr(s, RSTART + 1) }
      return out s
    }

    function either(a, b, re) { return a ~ re || b ~ re }

    function scan(t,   lc, sp) {
      if (t ~ /(^|[^A-Za-z0-9_])ns([^A-Za-z0-9_]|$)/) hit("ns")
      if (t ~ /(^|[^A-Za-z0-9_])Quick([^A-Za-z0-9_]|$)/) hit("Quick")
      lc = tolower(t); sp = tolower(camelsplit(t))
      if (lc ~ /quick[- ]v2/) hit("quick-v2")
      if (either(lc, sp, "(^|[^a-z])nsd([^a-z]|$)")) hit("nsd")
      if (either(lc, sp, "(^|[^a-z])nsgw")) hit("nsgw")
      if (either(lc, sp, "(^|[^a-z])realm")) hit("realm")
      if (either(lc, sp, "(^|[^a-z])subject")) hit("subject")
      if (either(lc, sp, "(^|[^a-z])group")) hit("group")
      if (either(lc, sp, "(^|[^a-z])terminate")) hit("terminate")
      if (either(lc, sp, "(^|[^a-z])idp([^a-z]|$)")) hit("idp")
      if (either(lc, sp, "(^|[^a-z])alias4")) hit("alias4")
      if (either(lc, sp, "(^|[^a-z])alias6")) hit("alias6")
      if (either(lc, sp, "(^|[^a-z])node6")) hit("node6")
      if (either(lc, sp, "(^|[^a-z])gateway[ _]?consumer")) hit("gateway consumer")
    }

    function hit(term,   k, parts) {
      for (k = 1; k <= na; k++)
        if (apath[k] == FILENAME && aterm[k] == term && (asub[k] == "*" || index(RAW, asub[k]) > 0)) { aused[k]++; return }
      split(FILENAME, parts, "/")
      count[parts[2]]++; total++
      printf "%s:%d: [%s] %s\n", FILENAME, FNR, term, trim(RAW)
    }

    BEGIN {
      nterms = split("ns Quick quick-v2 nsd nsgw realm subject group terminate idp alias4 alias6 node6", tl, " ")
      for (k = 1; k <= nterms; k++) known[tl[k]] = 1
      known["gateway consumer"] = 1
      ncr = split(crates, cl, " ")
      for (k = 1; k <= ncr; k++) { scanned[cl[k]] = 1; count[cl[k]] = 0 }
      na = 0; bad = 0; ln = 0
      while ((getline line < allow) > 0) {
        ln++
        if (line ~ /^[ \t]*(#|$)/) continue
        nf = split(line, f, "|")
        if (nf != 4 || trim(f[1]) == "" || f[3] == "" || trim(f[4]) == "" || !(trim(f[2]) in known)) {
          printf "%s:%d: malformed allowlist entry (need exactly <path>|<term>|<substring>|<reason>, a known term and a reason): %s\n", allow, ln, line > "/dev/stderr"
          bad = 1
          continue
        }
        na++
        apath[na] = trim(f[1]); aterm[na] = trim(f[2]); asub[na] = f[3]; aline[na] = ln; atext[na] = line
        aused[na] = 0
      }
      if (bad) exit 2
    }

    FNR == 1 { depth = 0; st = 0; skip = 0; pending = 0; body = -1; pbody = -1 }

    {
      RAW = $0
      if (st == 0 && RAW ~ /^[ \t]*\/\/[\/!]/) { if (!skip) scan(RAW); next }
      if (st == 0 && RAW ~ /^[ \t]*\/\//) next
      sanitize(RAW)
      d0 = depth; depth += OPEN - CLOSE

      if (skip) { if (depth <= skipbase) skip = 0; next }

      line = CODE
      if (line ~ /^[ \t]*#\[cfg\(test\)\]/) {
        sub(/^[ \t]*#\[cfg\(test\)\][ \t]*/, "", line)
        pending = 1
      }
      if (pending) {
        if (line ~ /^[ \t]*$/ || line ~ /^[ \t]*#\[/) next
        pending = 0
        if (line ~ /^[ \t]*(pub(\([^)]*\))?[ \t]+)?mod[ \t]+[A-Za-z0-9_]+/) {
          if (depth > d0) { skip = 1; skipbase = d0 }
          next
        }
      }

      inbody = body >= 0 && d0 > body
      if (inbody || CODE ~ /^[ \t]*pub[ \t]/ || CODE ~ /^[ \t]*#!?\[doc[ \t]*=/) scan(CODE)
      if (CODE ~ /^[ \t]*pub[ \t]+(enum|struct|use)[ \t]/) pbody = d0
      if (pbody >= 0) {
        if (OPEN > 0) { if (depth > pbody) body = pbody; pbody = -1 }
        else if (CODE ~ /;/) pbody = -1
      }
      if (body >= 0 && depth <= body) body = -1
    }

    END {
      if (bad) exit 2
      stale = 0
      for (k = 1; k <= na; k++) {
        split(apath[k], parts, "/")
        if (aused[k] == 0 && (parts[2] in scanned)) {
          printf "%s:%d: stale allowlist entry (suppresses nothing): %s\n", allow, aline[k], atext[k]
          stale++
        }
      }
      print ""
      printf "%-20s %s\n", "crate", "hits"
      for (k = 1; k <= ncr; k++) printf "%-20s %d\n", cl[k], count[cl[k]]
      printf "%-20s %d\n", "total", total
      printf "stale allowlist entries: %d\n", stale
      exit (total > 0 || stale > 0) ? 1 : 0
    }
  ' "$@"
}

# Scans crates under the current directory. Arguments: allowlist file, crate names.
scan_tree() {
  local allow=$1
  shift
  local dirs=() c
  for c in "$@"; do
    [ -d "crates/$c/src" ] || { echo "no such crate: crates/$c/src" >&2; return 2; }
    dirs+=("crates/$c/src")
  done
  local all excluded files
  all=$(find "${dirs[@]}" -type f -name '*.rs' | grep -Ev '/src/(.*/)?tests/|/tests\.rs$' | sort || true)
  [ -n "$all" ] || { echo "no source files found" >&2; return 2; }
  local list=()
  mapfile -t list <<<"$all"
  excluded=$(test_mod_files "${list[@]}" | sort -u)
  files=$(grep -vxF -e "${excluded:-/nonexistent}" <<<"$all" || true)
  [ -n "$files" ] || { echo "no source files left after excluding tests" >&2; return 2; }
  mapfile -t list <<<"$files"
  scan_files "$allow" "$*" "${list[@]}"
}

all_crates() {
  find crates -mindepth 2 -maxdepth 2 -type d -name src | sed 's|^crates/||; s|/src$||' | sort
}

self_test() {
  local tmp failures=0 out rc
  tmp=$(mktemp -d)
  trap 'rm -rf "$tmp"' RETURN
  mkdir -p "$tmp/crates/x/src/sub/tests" "$tmp/crates/y/src"
  cat >"$tmp/crates/x/src/lib.rs" <<'EOF'
//! Crate for the realm service.
// A plain comment about a group.
use std::fmt;

/// Ends the session.
pub fn terminate_session() {}

fn private_group() {}

pub(crate) fn crate_group() {}

pub enum Kind {
    Plain,
    NodeGroup,
}

pub struct Stats {
    pub dns_server: u32,
    pub ns_per_op: u64,
    note: &'static str, // the realm in a trailing comment
}

pub fn allowed_group() {}

#[cfg(test)]
mod helpers;

#[cfg(test)]
mod tests {
    /// A subject in a test.
    pub const MAGIC: &[u8] = b"NSGWP2P1";
    pub fn realm_group() {
        if true { let _ = '{'; }
    }
}

pub const AFTER_TESTS: &str = "nsd";

#[doc = "The ns gateway."]
pub mod sub;

pub struct GatewayConsumer;
EOF
  printf '/// A subject in a cfg(test) file.\npub fn subject() {}\n' >"$tmp/crates/x/src/helpers.rs"
  printf '/// A subject in tests.rs.\npub fn subject() {}\n' >"$tmp/crates/x/src/sub/tests.rs"
  printf '/// A subject under tests/.\npub fn subject() {}\n' >"$tmp/crates/x/src/sub/tests/a.rs"
  printf '//! Generic.\n#[cfg(test)]\nmod tests;\n' >"$tmp/crates/x/src/sub.rs"
  printf '/// Spawns the benchmark group.\npub fn bench() {}\n' >"$tmp/crates/y/src/lib.rs"
  printf '/// Waits until the connection is terminated.\npub fn terminated(&self) {}\n' >"$tmp/crates/y/src/tcp.rs"
  printf '/// Splits packets into segment groups.\npub fn coalesce() {}\n/// One group.\npub struct Group;\n' >"$tmp/crates/y/src/offload.rs"
  cat >"$tmp/allow.txt" <<'EOF'
# header comment

crates/x/src/lib.rs|group|pub fn allowed_group|a generic group in the fixture
crates/x/src/lib.rs|realm|no such line|a stale entry
crates/y/src/lib.rs|group|benchmark group|a criterion benchmark group
crates/y/src/tcp.rs|terminate|terminated|TCP connection state
crates/y/src/offload.rs|group|*|GSO segment groups
EOF

  check() {
    if [ "$1" = "$2" ]; then echo "ok   $3"; else echo "FAIL $3: expected [$1], got [$2]"; failures=$((failures + 1)); fi
  }

  rc=0
  out=$(cd "$tmp" && scan_tree "$tmp/allow.txt" x) || rc=$?
  check 1 "$rc" "crate x with hits and a stale entry exits 1"
  check "crates/x/src/lib.rs:1: [realm]
crates/x/src/lib.rs:6: [terminate]
crates/x/src/lib.rs:14: [group]
crates/x/src/lib.rs:37: [nsd]
crates/x/src/lib.rs:39: [ns]
crates/x/src/lib.rs:42: [gateway consumer]" "$(grep -E '^crates/' <<<"$out" | sed 's/\] .*/]/')" "expected hits in crate x"
  check 1 "$(grep -c 'stale allowlist entry.*no such line' <<<"$out")" "stale entry reported"
  check 1 "$(grep -Ec '^x +6$' <<<"$out")" "summary row for crate x"

  rc=0
  out=$(cd "$tmp" && scan_tree "$tmp/allow.txt" y) || rc=$?
  check 0 "$rc" "allowlisted crate y (terminated, segment groups) exits 0, x entries not stale"
  check 0 "$(grep -c '^crates/' <<<"$out" || true)" "no hits in crate y"

  rc=0
  out=$("$0" --self-test-report "$tmp" x 2>&1) || rc=$?
  check 0 "$rc" "--report exits 0 with hits"

  printf 'crates/y/src/lib.rs|group|benchmark group|\n' >"$tmp/bad.txt"
  rc=0
  out=$(cd "$tmp" && scan_tree "$tmp/bad.txt" y 2>&1) || rc=$?
  check 2 "$rc" "entry without a reason exits 2"

  if [ "$failures" -eq 0 ]; then echo "self-test passed"; else echo "self-test: $failures failure(s)"; return 1; fi
}

report=0
crates=()
while [ $# -gt 0 ]; do
  case $1 in
    --report) report=1 ;;
    --crate)
      [ $# -ge 2 ] || { usage >&2; exit 2; }
      crates+=("$2")
      shift
      ;;
    --self-test) self_test; exit ;;
    --self-test-report)
      # Internal: report mode against a fixture root (used by --self-test).
      cd "$2"
      rc=0
      scan_tree "$2/allow.txt" "$3" || rc=$?
      [ "$rc" -eq 1 ] && rc=0
      exit "$rc"
      ;;
    -h | --help) usage; exit 0 ;;
    *) usage >&2; exit 2 ;;
  esac
  shift
done

cd "$(dirname "$0")/.."
[ ${#crates[@]} -gt 0 ] || mapfile -t crates < <(all_crates)
rc=0
scan_tree "$PWD/scripts/product-terms-allow.txt" "${crates[@]}" || rc=$?
if [ "$report" -eq 1 ] && [ "$rc" -eq 1 ]; then rc=0; fi
exit "$rc"
