#!/usr/bin/env bash
# Documentation check: product documents and code comments describe current behavior
# (docs/README.md, "Writing rules").
#
#   scripts/check-docs.sh [--report] [--self-test] [-h|--help]
#
# Three checks:
#
# 1. Wording. Product documents (README.md, examples/README.md, docs/*.md except
#    docs/changelog.md, docs/reference/*.md, docs/specs/*.md) and the comment lines (`//`,
#    `///`, `//!`, and trailing `// ...`) of crates/**/*.rs and examples/**/*.rs must not
#    contain these rules:
#      id       plan, campaign or slice ids (`MD-7`, `OE-1`, `AG-4`), `Phase 3`
#      ref      process references: `docs/plan/`, `docs/task/`, a plan timestamp
#               (`20261017-1800`), `campaign`
#      date     an ISO date (ADR slugs such as `2026-10-06-business-agnostic-scope` are not
#               dates); not checked in docs/performance.md
#      version  version history: `since 0.13`, `in 0.14.2`, `as in 0.14.2`, `before v0.12`
#      history  `as before`, `used to be`, `for now`, `for the time being`
#      intent   `TODO`, `FIXME`, `will be removed` (and added, replaced, changed, dropped),
#               `<modal> be <verb> later` / `in the future`, `planned`, `roadmap`,
#               `not yet implemented` / `supported` / `verified`, `next release`
#    CHANGELOG.md, docs/changelog.md, docs/plan/, docs/task/ and docs/decisions/ are process
#    or decision records and are not checked for wording.
# 2. Links. Every relative markdown link in the product documents and docs/decisions/*.md
#    points to an existing file, and its `#anchor` to a heading of that file (GitHub slugs).
# 3. Coverage. Every published crate (crates/* without `publish = false`) has
#    docs/reference/<crate>.md.
#
# Allowlist: scripts/check-docs-allow.txt, `<path>|<rule>|<fixed substring or *>|<reason>`
# (no `|` inside a field; `*` covers every line of that path and rule). Stale entries fail.
#
# Gate mode (default) exits 1 on any finding or stale entry; --report always exits 0.
# A malformed allowlist exits 2. Tools: bash, grep, awk, sed, find, sort.
set -euo pipefail

usage() {
  cat <<'EOF'
usage: scripts/check-docs.sh [--report] [--self-test]

  (no flag)    gate mode: print findings; exit 1 on any finding or stale allowlist entry
  --report     same output, always exit 0 (a malformed allowlist still exits 2)
  --self-test  run the checks against built-in fixtures
  -h, --help   show this help
EOF
}

# Product documents under the current directory, one per line.
product_docs() {
  {
    [ -f README.md ] && echo README.md
    [ -f examples/README.md ] && echo examples/README.md
    find docs -maxdepth 1 -type f -name '*.md' ! -name changelog.md 2>/dev/null
    find docs/reference docs/specs -type f -name '*.md' 2>/dev/null
  } | sort -u
}

# Rust sources whose comments are checked, one per line.
rust_sources() {
  find crates examples -type f -name '*.rs' 2>/dev/null | grep -v '/target/' | sort
}

# Check 1. Arguments: allowlist, then the markdown files, `--`, then the Rust files.
# Prints findings and stale entries; exits 0, 1 (findings) or 2 (bad allowlist).
wording() {
  local allow=$1
  shift
  LC_ALL=C awk -v allow="$allow" '
    function trim(s) { sub(/^[ \t]+/, "", s); sub(/[ \t]+$/, "", s); return s }

    # The comment text of a Rust line, or "" when the line has none.
    function comment(s,   i, n, c, st) {
      if (s ~ /^[ \t]*\/\//) return s
      n = length(s); st = 0
      for (i = 1; i < n; i++) {
        c = substr(s, i, 1)
        if (st) { if (c == "\\") i++; else if (c == "\"") st = 0; continue }
        if (c == "\"") { st = 1; continue }
        if (c == "/" && substr(s, i + 1, 1) == "/") return substr(s, i)
      }
      return ""
    }

    function check(t, md,   lc, d) {
      lc = tolower(t)
      d = t
      gsub(/(RFC|CVE|UTF|ISO|SHA|AES|IEEE|ECMA|BLAKE|HMAC|TLS|MTU|IPv|FNV)-[0-9]+/, "", d)
      gsub(/[A-Za-z0-9]-[0-9]+-[A-Za-z0-9]/, "", d)
      if (d ~ /(^|[^A-Za-z0-9_-])[A-Z][A-Z0-9]?[A-Z]?-[0-9]+[a-z]?([^A-Za-z0-9_-]|$)/ || t ~ /(^|[^A-Za-z])Phase [0-9]/) hit("id")
      if (t ~ /docs\/(plan|task)\// || t ~ /(^|[^0-9])20[0-9][0-9][01][0-9][0-3][0-9]-[0-2][0-9][0-5][0-9]([^0-9]|$)/ || lc ~ /(^|[^a-z])campaign/) hit("ref")
      if (checkdate) {
        d = t
        gsub(/20[0-9][0-9]-[01][0-9]-[0-3][0-9]-[a-z][a-z0-9-]*/, "", d)
        if (d ~ /(^|[^0-9])20[0-9][0-9]-[01][0-9]-[0-3][0-9]([^0-9]|$)/) hit("date")
      }
      if (lc ~ /(^|[^a-z])(since|in|until|before|after|as of|as in|from) v?0\.[0-9]+(\.[0-9]+)?([^0-9.]|$)/) hit("version")
      if (lc ~ /(^|[^a-z])(as before|used to be|for now|for the time being)([^a-z]|$)/) hit("history")
      if (t ~ /(^|[^A-Za-z])(TODO|FIXME)([^A-Za-z]|$)/ ||
          lc ~ /will be (removed|added|replaced|changed|dropped)/ ||
          lc ~ /(^|[^a-z])(will|may|might|could|can|should) be [a-z]+ (later|in the future)([^a-z]|$)/ ||
          lc ~ /(^|[^a-z])(planned|roadmap|next release|upcoming)([^a-z]|$)/ ||
          lc ~ /not yet (implemented|supported|verified)/) hit("intent")
    }

    function hit(rule,   k) {
      for (k = 1; k <= na; k++)
        if (apath[k] == FILENAME && arule[k] == rule && (asub[k] == "*" || index(RAW, asub[k]) > 0)) { aused[k]++; return }
      total++
      printf "%s:%d: [%s] %s\n", FILENAME, FNR, rule, trim(RAW)
    }

    BEGIN {
      split("id ref date version history intent", rl, " ")
      for (k in rl) known[rl[k]] = 1
      na = 0; bad = 0; ln = 0
      while ((getline line < allow) > 0) {
        ln++
        if (line ~ /^[ \t]*(#|$)/) continue
        nf = split(line, f, "|")
        if (nf != 4 || trim(f[1]) == "" || f[3] == "" || trim(f[4]) == "" || !(trim(f[2]) in known)) {
          printf "%s:%d: malformed allowlist entry (need <path>|<rule>|<substring>|<reason> with a known rule): %s\n", allow, ln, line > "/dev/stderr"
          bad = 1
          continue
        }
        na++
        apath[na] = trim(f[1]); arule[na] = trim(f[2]); asub[na] = f[3]; aline[na] = ln; atext[na] = line
      }
      if (bad) exit 2
      for (i = 1; i < ARGC; i++) if (ARGV[i] == "--") { rust_from = i; ARGV[i] = "" }
    }

    FNR == 1 {
      for (i = 1; i < ARGC; i++) if (ARGV[i] == FILENAME) idx = i
      md = idx < rust_from
      checkdate = FILENAME !~ /(^|\/)docs\/performance\.md$/
      fence = 0
    }

    {
      RAW = $0
      if (md) { check(RAW, 1); next }
      c = comment(RAW)
      if (c != "") check(c, 0)
    }

    END {
      if (bad) exit 2
      stale = 0
      for (k = 1; k <= na; k++)
        if (aused[k] == 0) {
          printf "%s:%d: stale allowlist entry (suppresses nothing): %s\n", allow, aline[k], atext[k]
          stale++
        }
      printf "wording: %d finding(s), %d stale allowlist entr%s\n", total, stale, (stale == 1 ? "y" : "ies")
      exit (total > 0 || stale > 0) ? 1 : 0
    }
  ' "$@"
}

# The GitHub heading slugs of a markdown file, one per line (duplicates get -1, -2, ...).
slugs() {
  LC_ALL=C awk '
    /^```/ { fence = !fence; next }
    fence { next }
    /^#+[ \t]/ {
      s = $0
      sub(/^#+[ \t]+/, "", s); sub(/[ \t]+#*[ \t]*$/, "", s)
      gsub(/`/, "", s)
      gsub(/<[^>]*>/, "", s)
      while (match(s, /\[[^]]*\]\([^)]*\)/)) {
        t = substr(s, RSTART, RLENGTH); sub(/^\[/, "", t); sub(/\]\(.*$/, "", t)
        s = substr(s, 1, RSTART - 1) t substr(s, RSTART + RLENGTH)
      }
      s = tolower(s)
      # Full-width punctuation (UTF-8): GitHub drops it like ASCII punctuation.
      gsub(/\xef\xbc[\x81-\x8f\x9a-\xa0\xbb-\xbf]|\xef\xbd[\x9b-\xa0]|\xe3\x80[\x81-\x83\x88-\x91\x94-\x9f]|\xe2\x80[\x90-\x9f\xa6]/, "", s)
      gsub(/[!-,.\/:-@[-^`{-~]/, "", s)
      gsub(/ /, "-", s)
      if (s in seen) { n = seen[s]++; print s "-" n } else { seen[s] = 1; print s }
    }
  ' "$1"
}

# Check 2. Arguments: the markdown files. Prints broken links; exits 0 or 1.
links() {
  local file total=0 target path anchor dir resolved
  for file in "$@"; do
    dir=$(dirname "$file")
    while IFS= read -r target; do
      case $target in
        http://* | https://* | mailto:* | '') continue ;;
      esac
      path=${target%%#*}
      anchor=
      [ "$path" != "$target" ] && anchor=${target#*#}
      if [ -z "$path" ]; then resolved=$file; else resolved=$dir/$path; fi
      if [ ! -e "$resolved" ]; then
        echo "$file: broken link: $target (no such file)"
        total=$((total + 1))
        continue
      fi
      if [ -n "$anchor" ] && [ -f "$resolved" ] && [[ $resolved == *.md ]]; then
        if ! slugs "$resolved" | grep -qxF -- "$anchor"; then
          echo "$file: broken link: $target (no such heading)"
          total=$((total + 1))
        fi
      fi
    done < <(LC_ALL=C awk '
      /^```/ { fence = !fence; next }
      fence { next }
      {
        s = $0
        gsub(/`[^`]*`/, "", s)
        while (match(s, /\]\([^) ]*\)/)) {
          print substr(s, RSTART + 2, RLENGTH - 3)
          s = substr(s, RSTART + RLENGTH)
        }
      }
    ' "$file")
  done
  echo "links: $total broken"
  [ "$total" -eq 0 ]
}

# Check 3. Prints crates without a reference document; exits 0 or 1.
coverage() {
  local toml crate total=0
  for toml in crates/*/Cargo.toml; do
    grep -qE '^publish[ \t]*=[ \t]*false' "$toml" && continue
    crate=$(basename "$(dirname "$toml")")
    if [ ! -f "docs/reference/$crate.md" ]; then
      echo "docs/reference/$crate.md: missing (published crate $crate)"
      total=$((total + 1))
    fi
  done
  echo "coverage: $total missing"
  [ "$total" -eq 0 ]
}

# Runs every check in the current directory. Argument: allowlist. Exits 0, 1 or 2.
check_tree() {
  local allow=$1 rc=0 file
  local md=() rs=() adr=()
  while IFS= read -r file; do md+=("$file"); done < <(product_docs)
  while IFS= read -r file; do rs+=("$file"); done < <(rust_sources)
  wording "$allow" ${md[@]+"${md[@]}"} -- ${rs[@]+"${rs[@]}"} || rc=$?
  [ "$rc" -eq 2 ] && return 2
  while IFS= read -r file; do adr+=("$file"); done < <(find docs/decisions -type f -name '*.md' 2>/dev/null | sort)
  links ${md[@]+"${md[@]}"} ${adr[@]+"${adr[@]}"} || rc=1
  coverage || rc=1
  return "$rc"
}

self_test() {
  local tmp failures=0 out rc
  tmp=$(mktemp -d)
  trap 'rm -rf "$tmp"' RETURN
  mkdir -p "$tmp/docs/reference" "$tmp/docs/decisions" "$tmp/crates/a/src" "$tmp/crates/b/src" "$tmp/examples"
  printf '[package]\nname = "a"\n' >"$tmp/crates/a/Cargo.toml"
  printf '[package]\nname = "b"\npublish = false\n' >"$tmp/crates/b/Cargo.toml"
  cat >"$tmp/README.md" <<'EOF'
# Top

See [the guide](docs/guide.md#2-crates-and-when-to-use-them) and [a](docs/reference/a.md).
[gone](docs/missing.md), [bad anchor](docs/guide.md#nope), [web](https://example.com/x).
As before, the engine drops it. The OE-1 fix and Phase 5. UTF-8 and RFC-7915 are fine.
EOF
  cat >"$tmp/docs/guide.md" <<'EOF'
# Guide

## 2. Crates and when to use them

## 快速上手：两个节点

See [zh](#快速上手两个节点) and ADR `2026-10-06-business-agnostic-scope` (an ADR slug).
Measured on 2026-10-04. Since 0.13 it is faster. Plan `20261017-1800`, docs/plan/x.md.
It may be relaxed later. Two connections can no longer collide.
EOF
  printf '# a\n\nBehavior.\n' >"$tmp/docs/reference/a.md"
  printf '# ADR\n\n[guide](../guide.md#guide)\n' >"$tmp/docs/decisions/2026-01-01-x.md"
  cat >"$tmp/crates/a/src/lib.rs" <<'EOF'
//! The crate. TODO: tidy.
/// The MT-2 side, for now.
pub fn f() {
    let s = "http://x//y"; // trailing: as in 0.14.2
    let t = "no // comment here";
}
// A plain comment that says the packet is dropped.
EOF
  cat >"$tmp/allow.txt" <<'EOF'
# fixture allowlist
crates/a/src/lib.rs|intent|TODO: tidy|upstream text
docs/guide.md|ref|*|fixture
README.md|history|no such text|stale entry
EOF

  check() {
    if [ "$1" = "$2" ]; then echo "ok   $3"; else echo "FAIL $3: expected [$1], got [$2]"; failures=$((failures + 1)); fi
  }

  rc=0
  out=$(cd "$tmp" && check_tree "$tmp/allow.txt" 2>&1) || rc=$?
  check 1 "$rc" "fixture with findings exits 1"
  check "README.md:5: [history]
README.md:5: [id]
crates/a/src/lib.rs:2: [history]
crates/a/src/lib.rs:2: [id]
crates/a/src/lib.rs:4: [version]
docs/guide.md:8: [date]
docs/guide.md:8: [version]
docs/guide.md:9: [intent]" "$(grep -E '^[a-zA-Z/._]+:[0-9]+: \[' <<<"$out" | sed 's/\] .*/]/' | LC_ALL=C sort)" "wording findings"
  check 1 "$(grep -c 'stale allowlist entry.*no such text' <<<"$out")" "stale entry reported"
  check "README.md: broken link: docs/missing.md (no such file)
README.md: broken link: docs/guide.md#nope (no such heading)" "$(grep 'broken link' <<<"$out")" "broken links, CJK and numbered anchors resolve"
  check 0 "$(grep -c 'docs/reference/b.md' <<<"$out" || true)" "unpublished crate needs no reference"

  rm "$tmp/docs/reference/a.md"
  rc=0
  out=$(cd "$tmp" && coverage 2>&1) || rc=$?
  check 1 "$rc" "missing reference document exits 1"

  printf 'README.md|history|x|\n' >"$tmp/bad.txt"
  rc=0
  out=$(cd "$tmp" && wording "$tmp/bad.txt" README.md -- 2>&1) || rc=$?
  check 2 "$rc" "entry without a reason exits 2"

  mkdir -p "$tmp/empty/docs/reference" "$tmp/empty/docs/specs" "$tmp/empty/docs/decisions" "$tmp/empty/crates/a" "$tmp/empty/examples"
  printf '# Empty project\n' >"$tmp/empty/README.md"
  printf '[package]\nname = "a"\npublish = false\n' >"$tmp/empty/crates/a/Cargo.toml"
  : >"$tmp/empty/allow.txt"
  rc=0
  out=$(cd "$tmp/empty" && check_tree "$tmp/empty/allow.txt" 2>&1) || rc=$?
  check 0 "$rc" "empty source and decision lists exit 0"
  check "wording: 0 finding(s), 0 stale allowlist entries
links: 0 broken
coverage: 0 missing" "$out" "empty source and decision lists run every check"

  if [ "$failures" -eq 0 ]; then echo "self-test passed"; else echo "self-test: $failures failure(s)"; return 1; fi
}

report=0
while [ $# -gt 0 ]; do
  case $1 in
    --report) report=1 ;;
    --self-test) self_test; exit ;;
    -h | --help) usage; exit 0 ;;
    *) usage >&2; exit 2 ;;
  esac
  shift
done

cd "$(dirname "$0")/.."
rc=0
check_tree "$PWD/scripts/check-docs-allow.txt" || rc=$?
if [ "$report" -eq 1 ] && [ "$rc" -eq 1 ]; then rc=0; fi
exit "$rc"
