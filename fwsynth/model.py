"""Core data model: packets, rules, rulesets, and intent specs.

The spec is the verification oracle: a set of constraints (packet class ->
required verdict) plus a default. The ruleset is the artifact under test:
an ordered first-match-wins rule list. Both are plain JSON-serializable
dataclasses so the LLM can emit them via structured outputs.
"""

from dataclasses import asdict, dataclass, field
from ipaddress import IPv4Network, ip_network

PROTOCOLS = ("tcp", "udp", "icmp", "any")
PORT_MIN, PORT_MAX = 0, 65535


@dataclass(frozen=True)
class Packet:
    src: str          # IPv4 address
    dst: str          # IPv4 address
    proto: str        # tcp | udp | icmp
    dport: int        # 0 for icmp

    def __str__(self) -> str:
        return f"{self.proto} {self.src} -> {self.dst}:{self.dport}"


@dataclass
class Rule:
    action: str       # allow | deny
    src: str          # CIDR
    dst: str          # CIDR
    proto: str        # tcp | udp | icmp | any
    dport_lo: int
    dport_hi: int
    comment: str = ""

    def __post_init__(self) -> None:
        _validate_match_fields(self)

    @property
    def src_net(self) -> IPv4Network:
        return ip_network(self.src)

    @property
    def dst_net(self) -> IPv4Network:
        return ip_network(self.dst)


@dataclass
class Property:
    """A spec constraint: every packet in this class MUST get this verdict."""
    action: str       # allow | deny
    src: str
    dst: str
    proto: str
    dport_lo: int
    dport_hi: int
    description: str = ""

    def __post_init__(self) -> None:
        _validate_match_fields(self)

    @property
    def src_net(self) -> IPv4Network:
        return ip_network(self.src)

    @property
    def dst_net(self) -> IPv4Network:
        return ip_network(self.dst)


@dataclass
class Ruleset:
    default: str                      # allow | deny
    rules: list[Rule] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: dict) -> "Ruleset":
        return cls(default=_validate_action(data["default"]),
                   rules=[Rule(**r) for r in data["rules"]])

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class Spec:
    default: str                      # allow | deny
    properties: list[Property] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: dict) -> "Spec":
        return cls(default=_validate_action(data["default"]),
                   properties=[Property(**p) for p in data["properties"]])

    def to_dict(self) -> dict:
        return asdict(self)


def _validate_action(action: str) -> str:
    if action not in ("allow", "deny"):
        raise ValueError(f"invalid action: {action!r}")
    return action


def _validate_match_fields(obj) -> None:
    _validate_action(obj.action)
    if obj.proto not in PROTOCOLS:
        raise ValueError(f"invalid proto: {obj.proto!r}")
    ip_network(obj.src)  # raises on bad CIDR
    ip_network(obj.dst)
    if not (PORT_MIN <= obj.dport_lo <= obj.dport_hi <= PORT_MAX):
        raise ValueError(f"invalid port range: {obj.dport_lo}-{obj.dport_hi}")
