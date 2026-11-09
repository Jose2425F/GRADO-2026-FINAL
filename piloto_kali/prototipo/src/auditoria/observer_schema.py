"""Frontera del observador: sólo hechos tipados, sin campos libres ni etiquetas."""
from __future__ import annotations

from ipaddress import ip_address, ip_network
from typing import Annotated, Literal

from pydantic import AfterValidator, BaseModel, ConfigDict, Field, ValidationError


class ObserverResponseError(ValueError):
    pass


def _ip(value):
    return str(ip_address(value))


IP = Annotated[str, AfterValidator(_ip)]
UInt = Annotated[int, Field(ge=0, le=2**64-1)]
Time = Annotated[float, Field(ge=0, allow_inf_nan=False)]
Interface = Annotated[str, Field(pattern=r"^[A-Za-z0-9_.:-]{1,64}$")]
Nonce = Annotated[str, Field(pattern=r"^[a-f0-9]{16,64}$")]


class Record(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class Packet(Record):
    source: IP
    destination: IP


class Fragment(Packet):
    id: Annotated[int, Field(ge=0, le=2**32-1)]
    offset: Annotated[int, Field(ge=0, le=8191)]
    more: Literal[0, 1]


class RouterAdvertisement(Packet):
    hop_limit: Annotated[int, Field(ge=0, le=255)]
    router_lifetime: Annotated[int, Field(ge=0, le=65535)]
    prefix: IP | None
    prefix_length: Annotated[int, Field(ge=0, le=128)] | None
    autonomous: bool | None
    advertised_mtu: UInt | None


class Neighbor(Packet):
    target: IP


class Delivery(Record):
    nonce: Nonce
    source: IP
    length: Annotated[int, Field(ge=0, le=65535)]


class MtuChange(Record):
    mtu: UInt
    observed_at: Time


class PacketObserver(Record):
    fragments: list[Fragment] = Field(max_length=64)
    router_advertisements: list[RouterAdvertisement] = Field(max_length=64)
    neighbor_advertisements: list[Neighbor] = Field(max_length=64)
    neighbor_solicitations: list[Neighbor] = Field(max_length=64)
    udp_deliveries: list[Delivery] = Field(max_length=64)
    mtu_changes: list[MtuChange] = Field(max_length=64)


class AddressInfo(Record):
    family: Literal["inet", "inet6"]
    local: IP
    prefixlen: Annotated[int, Field(ge=0, le=128)]
    scope: Literal["global", "link", "host", "site"]
    label: Interface | None = None
    valid_life_time: UInt | Literal["forever"] | None = None
    preferred_life_time: UInt | Literal["forever"] | None = None
    dynamic: bool | None = None
    tentative: bool | None = None
    dadfailed: bool | None = None
    mngtmpaddr: bool | None = None
    noprefixroute: bool | None = None
    temporary: bool | None = None


class Address(Record):
    ifindex: UInt
    ifname: Interface
    addr_info: list[AddressInfo] = Field(max_length=64)
    flags: list[Literal["UP", "BROADCAST", "MULTICAST", "LOWER_UP", "LOOPBACK", "NOARP", "POINTOPOINT", "DORMANT"]] = Field(default_factory=list,max_length=16)
    mtu: UInt | None = None
    qdisc: Literal["noqueue", "fq_codel", "pfifo_fast", "fq", "mq"] | None = None
    operstate: Literal["UP", "DOWN", "UNKNOWN", "DORMANT", "LOWERLAYERDOWN", "NOTPRESENT", "TESTING"] | None = None
    group: Literal["default"] | None = None
    txqlen: UInt | None = None
    link_type: Literal["ether", "loopback", "none"] | None = None
    link_index: UInt | None = None
    link_netnsid: int | None = None
    address: Annotated[str, Field(pattern=r"^[a-fA-F0-9:]{17}$")] | None = None
    broadcast: Annotated[str, Field(pattern=r"^[a-fA-F0-9:]{17}$")] | None = None


class Forwarding(Record):
    ipv4: bool
    ipv6: bool


class Counters(Record):
    Ip6ReasmReqds: UInt
    Ip6ReasmOKs: UInt
    Ip6ReasmFails: UInt
    Ip6InHdrErrors: UInt
    Udp6InDatagrams: UInt
    Icmp6InErrors: UInt


def _destination(value):
    return value if value == "default" else str(ip_network(value, strict=False))


class Route(Record):
    dst: Annotated[str, AfterValidator(_destination)]
    gateway: IP | None = None
    dev: Interface | None = None
    protocol: Literal["kernel", "static", "ra", "boot", "dhcp"] | None = None
    metric: UInt | None = None
    pref: Literal["low", "medium", "high"] | None = None
    prefsrc: IP | None = None
    scope: Literal["global", "link", "host"] | None = None
    type: Literal["unicast", "local", "unreachable", "blackhole", "broadcast", "multicast"] | None = None
    table: UInt | Literal["main", "local", "default"] | None = None
    expires: UInt | None = None
    flags: list[Literal["onlink", "linkdown"]] = Field(default_factory=list,max_length=4)


class NeighborEntry(Record):
    dst: IP
    dev: Interface
    lladdr: Annotated[str, Field(pattern=r"^[a-fA-F0-9:]{17}$")] | None = None
    state: list[Literal["REACHABLE", "STALE", "DELAY", "PROBE", "FAILED", "INCOMPLETE", "PERMANENT", "NOARP", "NONE"]] = Field(max_length=4)
    router: bool | None = None


class Link(Address):
    addr_info: list[AddressInfo] = Field(default_factory=list,max_length=0)
    linkmode: Literal["DEFAULT", "DORMANT"] | None = None


class VirtualState(Record):
    addresses: list[Address] = Field(max_length=32)
    routes: list[Route] = Field(max_length=256)
    neighbors: list[NeighborEntry] = Field(max_length=256)
    link: list[Link] = Field(max_length=32)
    kernel_counters: Counters
    forwarding: Forwarding
    udp_deliveries: list[Delivery] = Field(max_length=32)


class VirtualSnapshot(Record):
    asset_id: Annotated[str, Field(pattern=r"^[A-Za-z0-9_-]{1,64}$")]
    state: VirtualState


def virtual_observer(value, asset_id):
    try:
        parsed = VirtualSnapshot.model_validate(value)
        if parsed.asset_id != asset_id:
            raise ValueError("identity_mismatch")
        return parsed.model_dump(mode="json",exclude_none=True)
    except (ValidationError, ValueError, TypeError):
        raise ObserverResponseError("observer_schema_rejected") from None


def packet_observer(value):
    try:
        return PacketObserver.model_validate(value).model_dump(mode="json")
    except (ValidationError, ValueError, TypeError):
        # ValidationError includes input values: never forward or persist it.
        raise ObserverResponseError("observer_schema_rejected") from None
