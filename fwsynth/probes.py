"""Boundary probe generation.

For every spec constraint, build a canonical matching packet and then vary one
dimension at a time to its edges and just past them: CIDR network/broadcast
addresses and their neighbors outside the block, port-range corners and the
adjacent out-of-range ports, and a different protocol. This is where LLM
mistakes live — off-by-one port ranges, inverted CIDRs, wrong rule order —
and one-dimension-at-a-time keeps the probe count linear, not combinatorial.
"""

from ipaddress import IPv4Network, ip_address, ip_network

from .model import PORT_MAX, PORT_MIN, Packet, Property, Spec

_OTHER_PROTO = {"tcp": "udp", "udp": "tcp", "icmp": "tcp", "any": None}


def _addr_variants(net: IPv4Network) -> list[str]:
    """Edges inside the block plus the addresses just outside it."""
    first, last = int(net.network_address), int(net.broadcast_address)
    mid = (first + last) // 2
    inside = {first, mid, last}
    outside = set()
    if first - 1 >= int(ip_address("0.0.0.0")):
        outside.add(first - 1)
    if last + 1 <= int(ip_address("255.255.255.255")):
        outside.add(last + 1)
    return [str(ip_address(v)) for v in sorted(inside | outside)]


def _port_variants(lo: int, hi: int) -> list[int]:
    ports = {lo, hi, (lo + hi) // 2}
    if lo - 1 >= PORT_MIN:
        ports.add(lo - 1)
    if hi + 1 <= PORT_MAX:
        ports.add(hi + 1)
    return sorted(ports)


def _canonical(prop: Property) -> Packet:
    src = str(ip_address((int(prop.src_net.network_address)
                          + int(prop.src_net.broadcast_address)) // 2))
    dst = str(ip_address((int(prop.dst_net.network_address)
                          + int(prop.dst_net.broadcast_address)) // 2))
    proto = "tcp" if prop.proto == "any" else prop.proto
    dport = 0 if proto == "icmp" else (prop.dport_lo + prop.dport_hi) // 2
    return Packet(src=src, dst=dst, proto=proto, dport=dport)


def probes_for_property(prop: Property) -> list[Packet]:
    base = _canonical(prop)
    packets: set[Packet] = {base}

    for src in _addr_variants(prop.src_net):
        packets.add(Packet(src=src, dst=base.dst, proto=base.proto, dport=base.dport))
    for dst in _addr_variants(prop.dst_net):
        packets.add(Packet(src=base.src, dst=dst, proto=base.proto, dport=base.dport))
    if base.proto != "icmp":
        for dport in _port_variants(prop.dport_lo, prop.dport_hi):
            packets.add(Packet(src=base.src, dst=base.dst, proto=base.proto, dport=dport))
    other = _OTHER_PROTO.get(prop.proto)
    if other:
        dport = 0 if other == "icmp" else base.dport
        packets.add(Packet(src=base.src, dst=base.dst, proto=other, dport=dport))

    return sorted(packets, key=str)


# default-behaviour sanity probes, deliberately far from typical spec ranges
_BACKGROUND = [
    Packet("192.0.2.77", "198.51.100.9", "tcp", 4444),
    Packet("198.51.100.1", "192.0.2.200", "udp", 9),
    Packet("203.0.113.5", "203.0.113.200", "icmp", 0),
]


def generate_probes(spec: Spec) -> list[Packet]:
    packets: set[Packet] = set(_BACKGROUND)
    for prop in spec.properties:
        packets.update(probes_for_property(prop))
    return sorted(packets, key=str)
