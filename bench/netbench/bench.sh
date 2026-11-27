#!/usr/bin/env bash
# Real-device throughput benchmark of the Linux engine, see run.sh.
# Needs Docker with a Linux VM or host; no root on the machine itself.
#
#   bench/netbench/bench.sh
#   DURATION=15 VARIANTS="pcap native" PROFILES="clean:0:0" bench/netbench/bench.sh
#   PROFILE=1 VARIANTS=native bench/netbench/bench.sh    # CPU profile per run
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../.." && pwd)

docker build -q -t pcap2socks-netbench "$here" >/dev/null
docker run --rm --privileged \
  -e DURATION -e VARIANTS -e PROFILES -e DEBUG_QDISC -e PROFILE -e PROFILE_NODES -e LAN_GRO \
  -v "$repo":/src:ro \
  -v pcap2socks-netbench-gomod:/go/pkg/mod \
  -v pcap2socks-netbench-gocache:/root/.cache/go-build \
  pcap2socks-netbench bash /src/bench/netbench/run.sh
