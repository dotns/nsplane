FROM debian:trixie-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends wireguard-tools iproute2 iputils-ping \
 && rm -rf /var/lib/apt/lists/*
