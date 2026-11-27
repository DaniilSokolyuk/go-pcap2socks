#!/usr/bin/env bash
# Runs inside the benchmark container (see bench.sh). Builds a three node
# network out of namespaces and measures TCP throughput from a "console"
# through the engine:
#
#   console ns         wire ns       root ns ("the PC")         wan ns
#   c0 172.26.0.5/16 - bridge ------ lan0 192.168.50.2  w0 ---- w1 203.0.113.10
#   kernel TCP client  delay, loss   variant under test         iperf3 server
#
# Variants:
#   router   kernel IP forwarding, nothing of ours. The ceiling: TCP is not
#            terminated at all, so it is a reference, not a competitor.
#   pcap     the production engine on libpcap, one frame per call: how the
#            Linux build worked before, kept as the baseline.
#   native   the production binary: capture and batched transmit on a packet
#            socket, no libpcap, no cgo.
#
# Offloads are switched off on the console link so frames are MTU sized, as on
# a physical wire; otherwise veth hands 64KB super-frames to pcap. Delay and
# loss are applied on a bridge between the console and the PC (see topology).
set -euo pipefail

DURATION=${DURATION:-8}
VARIANTS=${VARIANTS:-"router pcap native"}
# name:delay:loss, applied to both directions of the console link.
PROFILES=${PROFILES:-"clean:0:0 wifi-good:1ms:0.1% wifi-bad:3ms:1% far-lossy:20ms:0.5%"}
BIN=/tmp/bin
OUT=${OUT:-/tmp/results.tsv}

log() { echo "== $*" >&2; }

build() {
  log "building"
  mkdir -p $BIN
  cd /src
  CGO_ENABLED=0 go build -buildvcs=false -o $BIN/go-pcap2socks .
  go build -buildvcs=false -tags netbench -o $BIN/pcapengine ./bench/netbench/pcapengine
}

topology() {
  ip netns add console
  ip netns add wire
  ip netns add wan

  # The console link runs through a bridge in its own namespace, and that is
  # where delay and loss are applied. They cannot sit on the sender's own
  # interface: Linux TCP hands the qdisc 64KB super-packets and segments them
  # afterwards, so netem there drops one skb where a wire would have dropped
  # forty frames, and a kernel sender looks several times better than it is.
  ip link add lan0 type veth peer name wl netns wire
  ip -n console link add c0 type veth peer name wc netns wire
  ip -n wire link add wbr0 type bridge forward_delay 0
  ip -n wire link set wl master wbr0
  ip -n wire link set wc master wbr0
  ip -n wire link set wl up
  ip -n wire link set wc up
  ip -n wire link set wbr0 up

  ip link add w0 type veth peer name w1 netns wan

  ip addr add 192.168.50.2/24 dev lan0
  ip link set lan0 up
  ip addr add 10.200.0.1/24 dev w0
  ip link set w0 up
  ip route add 203.0.113.0/24 via 10.200.0.2

  # 1486 is the MTU the production binary tells the user to configure.
  ip -n console addr add 172.26.0.5/16 dev c0
  ip -n console link set c0 up mtu 1486
  ip -n console link set lo up
  ip -n console route add default via 172.26.0.1

  ip -n wan addr add 10.200.0.2/24 dev w1
  ip -n wan link set w1 up
  ip -n wan link set lo up
  ip -n wan addr add 203.0.113.10/32 dev lo
  ip -n wan route add default via 10.200.0.1

  local off="tx off sg off tso off gso off gro off"
  ethtool -K lan0 $off >/dev/null
  ip netns exec console ethtool -K c0 $off >/dev/null
  ip netns exec wire ethtool -K wl $off >/dev/null
  ip netns exec wire ethtool -K wc $off >/dev/null

  # LAN_GRO=1 turns receive offload back on for the PC's interface, which is
  # how a physical NIC runs by default: the kernel merges TCP segments before
  # a packet socket sees them.
  if [ -n "${LAN_GRO:-}" ]; then
    ethtool -K lan0 gro on >/dev/null
  fi

  sysctl -qw net.ipv4.ip_forward=0
  ip netns exec wan iperf3 -s -B 203.0.113.10 -D >/dev/null
}

set_link() { # delay loss
  local dev
  for dev in wl wc; do
    ip netns exec wire tc qdisc del dev $dev root 2>/dev/null || true
    if [ "$1" != 0 ] || [ "$2" != 0 ]; then
      local args=(netem limit 20000)
      [ "$1" != 0 ] && args+=(delay "$1")
      [ "$2" != 0 ] && args+=(loss "$2")
      ip netns exec wire tc qdisc add dev $dev root "${args[@]}"
    fi
  done
}

ENGINE_PID=
wait_ready() { # logfile pattern
  for _ in $(seq 100); do
    grep -q "$2" "$1" 2>/dev/null && return 0
    kill -0 "$ENGINE_PID" 2>/dev/null || { cat "$1" >&2; return 1; }
    sleep 0.1
  done
  cat "$1" >&2
  return 1
}

start_variant() {
  ENGINE_PID=
  case $1 in
    router)
      ip addr add 172.26.0.1/16 dev lan0
      sysctl -qw net.ipv4.ip_forward=1
      ip -n wan route add 172.26.0.0/16 via 10.200.0.1
      ;;
    pcap|native)
      cat >/tmp/pcap.json <<JSON
{"pcap":{"interfaceGateway":"192.168.50.2","network":"172.26.0.0/16","localIP":"172.26.0.1"},
 "routing":{"rules":[]},"outbounds":[{"tag":"","direct":{}}]}
JSON
      if [ "$1" = native ]; then
        SLOG_LEVEL=warn $BIN/go-pcap2socks /tmp/pcap.json >/tmp/engine.log 2>&1 &
        ENGINE_PID=$!
        sleep 1
        kill -0 $ENGINE_PID || { cat /tmp/engine.log >&2; return 1; }
      else
        $BIN/pcapengine /tmp/pcap.json lan0 >/tmp/engine.log 2>&1 &
        ENGINE_PID=$!
        wait_ready /tmp/engine.log ready
      fi
      ;;
  esac
  # Fresh ARP for every variant: the gateway MAC differs between them.
  ip -n console neigh flush dev c0
}

stop_variant() {
  if [ -n "$ENGINE_PID" ]; then
    kill "$ENGINE_PID" 2>/dev/null || true
    for _ in $(seq 30); do
      kill -0 "$ENGINE_PID" 2>/dev/null || break
      sleep 0.1
    done
    if kill -0 "$ENGINE_PID" 2>/dev/null; then
      # Keep the goroutine dump: a process that ignores SIGTERM is a finding.
      log "$1 did not exit within 3s of SIGTERM, dump in /tmp/hang-$1.log"
      kill -QUIT "$ENGINE_PID" 2>/dev/null || true
      sleep 0.5
      cp /tmp/engine.log "/tmp/hang-$1.log"
      kill -KILL "$ENGINE_PID" 2>/dev/null || true
    fi
    wait "$ENGINE_PID" 2>/dev/null || true
  fi
  case $1 in
    router)
      ip addr del 172.26.0.1/16 dev lan0
      sysctl -qw net.ipv4.ip_forward=0
      ip -n wan route del 172.26.0.0/16
      ;;
  esac
}

cpu_ticks() { # utime+stime of the engine, in clock ticks
  [ -n "$ENGINE_PID" ] && awk '{print $14+$15}' "/proc/$ENGINE_PID/stat" 2>/dev/null || echo 0
}

measure() { # variant profile direction
  local flag=
  [ "$3" = download ] && flag=-R
  local before after json bps cpu dev=tx frames0 bytes0 frame
  # Average size of the frames carrying the payload on the console link, to
  # confirm they are MTU sized and no offload is flattering the numbers.
  [ "$3" = upload ] && dev=rx
  frames0=$(cat /sys/class/net/lan0/statistics/${dev}_packets)
  bytes0=$(cat /sys/class/net/lan0/statistics/${dev}_bytes)
  local profile= profile_pid=
  if [ -n "${PROFILE:-}" ] && [ "$1" = native ]; then
    # The production binary serves pprof on :8085.
    profile=/tmp/prof-$2-$3.pb.gz
    curl -s -o "$profile" "http://127.0.0.1:8085/debug/pprof/profile?seconds=$((DURATION - 2))" &
    profile_pid=$!
  fi
  before=$(cpu_ticks)
  if ! json=$(ip netns exec console iperf3 -c 203.0.113.10 -t "$DURATION" $flag -J 2>/dev/null); then
    printf '%s\t%s\t%s\tFAILED\t-\n' "$1" "$2" "$3" | tee -a "$OUT"
    return
  fi
  after=$(cpu_ticks)
  if [ -n "$profile" ]; then
    wait "$profile_pid" || true
    { echo "-- cpu profile: $1 $2 $3"
      go tool pprof -top -nodecount=${PROFILE_NODES:-28} $BIN/go-pcap2socks "$profile" 2>/dev/null | tail -n +4; } >&2 || true
  fi
  if [ -n "${DEBUG_QDISC:-}" ]; then
    # What netem actually saw: skb count, bytes and drops per direction.
    { echo "-- $1 $2 $3 (to console, then to PC)"
      ip netns exec wire tc -s qdisc show dev wc | grep -A1 netem
      ip netns exec wire tc -s qdisc show dev wl | grep -A1 netem; } >&2 || true
  fi
  bps=$(jq -r '.end.sum_received.bits_per_second // 0' <<<"$json")
  cpu=$(awk -v a="$after" -v b="$before" -v hz="$(getconf CLK_TCK)" -v d="$DURATION" \
        'BEGIN{printf "%.0f", (a-b)/hz/d*100}')
  frame=$(awk -v p0="$frames0" -v b0="$bytes0" \
        -v p1="$(cat /sys/class/net/lan0/statistics/${dev}_packets)" \
        -v b1="$(cat /sys/class/net/lan0/statistics/${dev}_bytes)" \
        'BEGIN{printf "%.0f", (p1>p0) ? (b1-b0)/(p1-p0) : 0}')
  printf '%s\t%s\t%s\t%.1f\t%s\t%s\n' "$1" "$2" "$3" "$(awk -v b="$bps" 'BEGIN{print b/1e6}')" "$cpu" "$frame" | tee -a "$OUT"
}

build
topology
: >"$OUT"
printf 'variant\tprofile\tdirection\tMbit/s\tengine_cpu%%\tavg_frame\n'
for variant in $VARIANTS; do
  log "variant $variant"
  start_variant "$variant"
  for profile in $PROFILES; do
    IFS=: read -r name delay loss <<<"$profile"
    set_link "$delay" "$loss"
    for direction in download upload; do
      measure "$variant" "$name" "$direction"
    done
  done
  set_link 0 0
  stop_variant "$variant"
done
for dump in /tmp/hang-*.log; do
  [ -e "$dump" ] || continue
  log "$dump (goroutines blocked in our code)"
  grep -B1 -A12 -E '^goroutine .*\[(semacquire|sync\.|chan receive|select|syscall|IO wait)' "$dump" \
    | grep -E '^goroutine|go-pcap2socks|gopacket' | head -40 >&2 || true
done
