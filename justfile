# Quality gates (pma-rust Lock 8). There is no CI; run `just check` before pushing.

default: check

# Run every gate.
check: fmt clippy test doc-test deny shear typos msrv examples product-terms

fmt:
    cargo fmt --all --check

clippy:
    cargo hack clippy --workspace --each-feature --all-targets --locked

test:
    cargo nextest run --workspace --all-features --locked

doc-test:
    cargo test --workspace --all-features --doc --locked

deny:
    cargo deny check

shear:
    cargo shear

typos:
    typos

msrv:
    cargo hack check --workspace --rust-version --all-features --locked

# Build every example binary.
examples:
    cargo build -p nsplane-examples --bins --locked

# Product-term scan of the public API and rustdoc (ADR 2026-10-06 business-agnostic scope).
product-terms:
    scripts/check-product-terms.sh

# Cross-target clippy: macOS through zig (cargo-zigbuild), Windows through mingw-w64 + nasm.
cross:
    cargo-zigbuild clippy --workspace --all-targets --all-features --target aarch64-apple-darwin
    cargo hack clippy -p nsplane-noise -p nsplane -p nsplane-tun -p nsplane-uapi --each-feature --all-targets --target x86_64-pc-windows-gnu

# Windows unit tests under wine (no Wintun driver: the device itself cannot start).
test-windows:
    CARGO_TARGET_X86_64_PC_WINDOWS_GNU_RUNNER=wine cargo test -p nsplane-noise -p nsplane -p nsplane-tun -p nsplane-uapi --all-features --target x86_64-pc-windows-gnu --locked

# Interop against kernel WireGuard in two containers (needs docker and the wireguard module).
e2e:
    cargo build -p nsplane-cli --release --locked
    scripts/e2e/linux.sh

# WireGuard implementations compared: throughput, latency, CPU per GB in pinned containers (needs docker and the wireguard module; see scripts/bench/README.md).
bench-wg:
    cargo build -p nsplane-cli --release --locked
    if [ -f examples/src/bin/netstack_bench.rs ]; then cargo build -p nsplane-examples --release --bin netstack_bench --locked; fi
    scripts/bench/wg-compare.sh

# Library-level e2e: nsplane-e2e container tests against kernel WireGuard (needs docker and the wireguard module).
e2e-lib:
    scripts/e2e/lib.sh

# Examples e2e: the example binaries as the design's scenarios in containers, against each other and kernel WireGuard (needs docker and the wireguard module).
e2e-examples:
    scripts/e2e/examples.sh
