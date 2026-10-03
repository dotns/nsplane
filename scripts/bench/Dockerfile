# Bench node: WireGuard tools, iperf3 and ping for scripts/bench/wg-compare.sh.
FROM debian:trixie-slim
RUN echo "iperf3 iperf3/start_daemon boolean false" | debconf-set-selections \
 && apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      iperf3 wireguard-tools iproute2 iputils-ping jq procps \
 && rm -rf /var/lib/apt/lists/*
