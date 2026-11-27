FROM golang:1.26-bookworm
# libpcap is only for the pcap baseline; the production binary does not use it.
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      libpcap-dev iproute2 ethtool iperf3 jq procps \
 && rm -rf /var/lib/apt/lists/*
