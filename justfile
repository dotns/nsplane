# Quality gates (pma-rust Lock 8). There is no CI; run `just check` before pushing.

default: check

# Run every gate.
check: fmt clippy test doc-test deny shear typos msrv

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

# Cross-target clippy: macOS through zig (cargo-zigbuild), Windows through mingw-w64 + nasm.
cross:
    cargo-zigbuild clippy --workspace --all-targets --all-features --target aarch64-apple-darwin
    cargo clippy -p boringtun --all-targets --features ffi-bindings --target x86_64-pc-windows-gnu

# Interop against kernel WireGuard in two containers (needs docker and the wireguard module).
e2e:
    cargo build -p boringtun-cli --release --locked
    scripts/e2e/linux.sh

# Integration tests need root, a TUN device and docker.
integration:
    sudo -E cargo test -p boringtun --features device --locked -- --ignored
