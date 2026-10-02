FROM debian:trixie-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends wireguard-tools iproute2 iputils-ping \
 && rm -rf /var/lib/apt/lists/*
# socat: the kernel-stack echo servers and clients of examples.sh.
RUN apt-get update \
 && apt-get install -y --no-install-recommends socat \
 && rm -rf /var/lib/apt/lists/*
# iptables, tcpdump: blocked paths, NAT routers and captures of the relay scenarios.
RUN apt-get update \
 && apt-get install -y --no-install-recommends iptables tcpdump \
 && rm -rf /var/lib/apt/lists/*
# iperf3: offload throughput scenarios of examples.sh (no daemon, no debconf prompt).
RUN echo "iperf3 iperf3/start_daemon boolean false" | debconf-set-selections \
 && apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends iperf3 \
 && rm -rf /var/lib/apt/lists/*
