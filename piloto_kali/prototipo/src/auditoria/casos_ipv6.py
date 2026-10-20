"""Catálogo de perfiles IPv6 finitos; no contiene el ground truth experimental."""

from __future__ import annotations

from dataclasses import dataclass

from .contracts import Category


@dataclass(frozen=True)
class IPv6Case:
    case_id: str
    category: Category
    action_profile: str
    reference: str


CASES: dict[str, IPv6Case] = {
    "GT-09": IPv6Case("GT-09", Category.IPV6_NDP, "ipv6_ra_route_v1", "RFC 4861"),
    "GT-10": IPv6Case("GT-10", Category.IPV6_NDP, "ipv6_na_neighbor_v1", "RFC 4861"),
    "GT-11": IPv6Case("GT-11", Category.IPV6_NDP, "ipv6_dad_v1", "RFC 4862"),
    "GT-12": IPv6Case("GT-12", Category.IPV6_NDP, "ipv6_ra_mtu_v1", "RFC 4861"),
    "GT-13": IPv6Case("GT-13", Category.IPV6_FRAGMENTATION, "ipv6_overlap_initial_v1", "RFC 8200"),
    "GT-14": IPv6Case("GT-14", Category.IPV6_FRAGMENTATION, "ipv6_overlap_middle_v1", "RFC 8200"),
    "GT-15": IPv6Case("GT-15", Category.IPV6_FRAGMENTATION, "ipv6_atomic_v1", "RFC 6946"),
    "GT-16": IPv6Case("GT-16", Category.IPV6_FRAGMENTATION, "ipv6_incomplete_chain_v1", "RFC 7112"),
}

DEFAULT_CASE_IDS = ("GT-12", "GT-13")


def selected_case_ids(case_ids: list[str]) -> list[str]:
    """Mantiene el orden autorizado; el piloto histórico conserva GT-12/GT-13."""
    return case_ids or list(DEFAULT_CASE_IDS)
