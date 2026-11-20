#!/usr/bin/env bash
# Three-node testbed on one Linux host (requires root / CAP_NET_ADMIN):
#
#   client (current netns)        router (netns np_rtr)            server (netns np_srv)
#   np0 10.77.0.1  <--veth-->  r0 10.77.0.254 | r1 10.78.0.254  <--veth-->  np1 10.78.0.2
#                                              ^ tc netem here (router -> server)
#
# The emulated bottleneck sits on the router, not on the measuring host, so
# that queue overflow drops packets *in the network* (as on a real path)
# instead of back-pressuring the sender's TCP stack through its own qdisc
# (TCP Small Queues), which would hide retransmissions.
# Segmentation offloads are disabled so netem and the capture see
# wire-sized packets rather than 64 KB GSO super-frames.

NP_RTR=${NP_RTR:-np_rtr}
NP_NS=${NP_NS:-np_srv}
NP_CLI_IF=np0
NP_SRV_IF=np1
NP_BOTTLENECK_IF=r1
NP_CLI_IP=10.77.0.1
NP_SRV_IP=10.78.0.2
NETPROBE=${NETPROBE:-netprobe}

np_require_root() {
    if [[ $(id -u) -ne 0 ]]; then
        echo "this scenario creates network namespaces and needs root (e.g. sudo -E $0)" >&2
        exit 77
    fi
    for t in ip tc; do
        command -v "$t" >/dev/null || { echo "missing tool: $t (iproute2)" >&2; exit 69; }
    done
}

_np_nooffload() {  # _np_nooffload <netns|-> <iface>
    command -v ethtool >/dev/null || return 0
    if [[ $1 == - ]]; then ethtool -K "$2" tso off gso off gro off >/dev/null 2>&1 || true
    else ip netns exec "$1" ethtool -K "$2" tso off gso off gro off >/dev/null 2>&1 || true; fi
}

np_setup() {
    np_teardown
    ip netns add "$NP_RTR"
    ip netns add "$NP_NS"
    ip link add "$NP_CLI_IF" type veth peer name r0
    ip link set r0 netns "$NP_RTR"
    ip link add "$NP_SRV_IF" type veth peer name r1
    ip link set "$NP_SRV_IF" netns "$NP_NS"
    ip link set r1 netns "$NP_RTR"

    ip addr add "$NP_CLI_IP/24" dev "$NP_CLI_IF"
    ip link set "$NP_CLI_IF" up
    ip route add 10.78.0.0/24 via 10.77.0.254

    ip netns exec "$NP_RTR" ip addr add 10.77.0.254/24 dev r0
    ip netns exec "$NP_RTR" ip addr add 10.78.0.254/24 dev r1
    ip netns exec "$NP_RTR" ip link set r0 up
    ip netns exec "$NP_RTR" ip link set r1 up
    ip netns exec "$NP_RTR" ip link set lo up
    ip netns exec "$NP_RTR" sysctl -qw net.ipv4.ip_forward=1

    ip netns exec "$NP_NS" ip addr add "$NP_SRV_IP/24" dev "$NP_SRV_IF"
    ip netns exec "$NP_NS" ip link set "$NP_SRV_IF" up
    ip netns exec "$NP_NS" ip link set lo up
    ip netns exec "$NP_NS" ip route add 10.77.0.0/24 via 10.78.0.254

    _np_nooffload - "$NP_CLI_IF"
    _np_nooffload "$NP_RTR" r0
    _np_nooffload "$NP_RTR" r1
    _np_nooffload "$NP_NS" "$NP_SRV_IF"
}

np_netem() {  # np_netem delay 20ms loss 1%   |   np_netem (no args) clears
    ip netns exec "$NP_RTR" tc qdisc del dev "$NP_BOTTLENECK_IF" root >/dev/null 2>&1 || true
    if [[ $# -gt 0 ]]; then
        ip netns exec "$NP_RTR" tc qdisc add dev "$NP_BOTTLENECK_IF" root netem "$@"
    fi
}

np_start_servers() {
    ip netns exec "$NP_NS" $NETPROBE server --bind "$NP_SRV_IP" >/dev/null 2>&1 &
    NP_SERVER_PID=$!
    if command -v iperf3 >/dev/null; then
        ip netns exec "$NP_NS" iperf3 -s -D -B "$NP_SRV_IP" >/dev/null 2>&1 || true
    fi
    sleep 1
}

np_teardown() {
    [[ -n ${NP_SERVER_PID:-} ]] && kill "$NP_SERVER_PID" >/dev/null 2>&1 || true
    pkill -f "iperf3 -s -D -B $NP_SRV_IP" >/dev/null 2>&1 || true
    ip netns del "$NP_NS" >/dev/null 2>&1 || true
    ip netns del "$NP_RTR" >/dev/null 2>&1 || true
    ip link del "$NP_CLI_IF" >/dev/null 2>&1 || true
}
