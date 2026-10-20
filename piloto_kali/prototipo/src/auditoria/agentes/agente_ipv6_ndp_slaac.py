"""Agente IPv6 NDP/SLAAC: cuatro perfiles finitos con observación y restauración."""

from __future__ import annotations

import json
import time
from uuid import uuid4

from ..casos_ipv6 import CASES
from ..contracts import Category, Task, TaskResult, TaskStatus
from ..ipv6_lab import (DAD_TARGET, INTERFACE, SENDER, TARGET, IPv6LabError,
                        prime_neighbor, restore_target, send_dad_probe, send_probe,
                        target_snapshot, verify_ipv6_lab)
from ..store import RunStore


PROFILES = {"GT-09": "ra_route", "GT-10": "na_neighbor",
            "GT-11": "dad_na", "GT-12": "ra_mtu"}


def _neighbor(snapshot: dict) -> str | None:
    return next((entry.get("lladdr") for entry in snapshot["neighbors"]
                 if entry.get("dst") == SENDER), None)


def _dad_flags(snapshot: dict) -> list[str]:
    return next(([name for name in ("dadfailed", "tentative") if entry.get(name)]
                 for interface in snapshot["addresses"]
                 for entry in interface.get("addr_info", [])
                 if entry.get("local") == DAD_TARGET), [])


def _observations(case_id: str, before: dict, after: dict, probe: dict) -> dict:
    observer_before, observer_after = before["observer"], after["observer"]
    common = {"case_id": case_id, "reference": CASES[case_id].reference,
              "interpretation": "observation_only_pending_validation"}
    if case_id in {"GT-09", "GT-12"}:
        seen = len(observer_after["router_advertisements"]) > len(
            observer_before["router_advertisements"])
        if case_id == "GT-09":
            old_routes = [entry for entry in before["routes"] if entry.get("dst") == "default"]
            new_routes = [entry for entry in after["routes"] if entry.get("dst") == "default"]
            return {**common, "packet_observed": seen, "route_before": old_routes,
                    "route_after": new_routes, "route_changed": old_routes != new_routes}
        return {**common, "packet_observed": seen,
                "mtu_before": before["ipv6_mtu"], "mtu_after": after["ipv6_mtu"],
                "changed": before["ipv6_mtu"] != after["ipv6_mtu"]}
    seen = len(observer_after["neighbor_advertisements"]) > len(
        observer_before["neighbor_advertisements"])
    if case_id == "GT-10":
        old_mac, new_mac = _neighbor(before), _neighbor(after)
        return {**common, "packet_observed": seen, "neighbor_before": old_mac,
                "neighbor_after": new_mac, "neighbor_changed": old_mac != new_mac}
    return {**common, "packet_observed": seen,
            "solicitation_seen": probe.get("solicitation_seen"),
            "dad_flags_after": _dad_flags(after),
            "dad_failed": "dadfailed" in _dad_flags(after)}


def run_ndp(task: Task, store: RunStore, *, timeout_seconds: int) -> TaskResult:
    if task.target.address != TARGET or task.target.interface != INTERFACE:
        raise IPv6LabError("objetivo NDP/SLAAC distinto del piloto aislado")
    if task.case_id not in PROFILES or task.action_profile != CASES[task.case_id].action_profile:
        raise ValueError("perfil NDP/SLAAC no implementado")
    if task.agent_type != Category.IPV6_NDP or timeout_seconds < 5:
        raise IPv6LabError("agente o presupuesto NDP/SLAAC inválido")
    lab = verify_ipv6_lab()
    if task.case_id == "GT-10":
        prime_neighbor()
        time.sleep(0.3)
    before = target_snapshot()
    packet = b""
    probe = after = restored = None
    failure = None
    try:
        if task.case_id == "GT-11":
            packet, probe = send_dad_probe(lab["target_mac"], uuid4().hex[:16])
        else:
            packet, probe = send_probe(PROFILES[task.case_id], lab["target_mac"], uuid4().hex[:16])
        time.sleep(0.7)
        after = target_snapshot()
    except IPv6LabError as exc:
        failure = str(exc)[:200]
    finally:
        try:
            restored = restore_target(before)
        except IPv6LabError as exc:
            failure = f"restore_failed: {str(exc)[:150]}"

    packet_ref = packet_hash = None
    if packet:
        packet_ref, packet_hash = store.evidence(task.task_id, "pcap", packet)
    diagnostic = {"case_id": task.case_id, "before": before, "after": after,
                  "restored": restored, "probe": probe, "error": failure}
    diag_ref, diag_hash = store.evidence(task.task_id, "json", json.dumps(
        diagnostic, ensure_ascii=False, sort_keys=True).encode())
    observations = (_observations(task.case_id, before, after, probe or {})
                    if after is not None else {"case_id": task.case_id})
    if restored is not None:
        observations["restored"] = True
    observed = observations.get("packet_observed", False)
    status = TaskStatus.COMPLETED_NO_FINDINGS if observed and not failure else TaskStatus.FAILED
    reason = None if status == TaskStatus.COMPLETED_NO_FINDINGS else (
        "restore_failed" if failure and failure.startswith("restore_failed") else
        "observer_missing" if not observed and not failure else "probe_failed")
    return TaskResult(
        task_id=task.task_id, status=status, reason_code=reason,
        observations=observations, evidence_ref=packet_ref, evidence_sha256=packet_hash,
        diagnostic_ref=diag_ref, diagnostic_sha256=diag_hash,
        command=["scapy", task.action_profile, lab["sender"], lab["target"]],
    )
