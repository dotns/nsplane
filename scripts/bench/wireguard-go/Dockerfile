# Builder for the wireguard-go reference of scripts/bench/wg-compare.sh: upstream source at a
# pinned tag, a static binary at /usr/local/bin/wireguard-go and its tag and commit in
# /wireguard-go.version. A benchmark tool only, never a dependency.
FROM golang:1.24-trixie
ARG WIREGUARD_GO_TAG=0.0.20250522
RUN git clone --depth 1 --branch "$WIREGUARD_GO_TAG" https://git.zx2c4.com/wireguard-go /src \
 && cd /src \
 && CGO_ENABLED=0 go build -trimpath -o /usr/local/bin/wireguard-go . \
 && echo "$WIREGUARD_GO_TAG ($(git rev-parse --short HEAD))" > /wireguard-go.version
