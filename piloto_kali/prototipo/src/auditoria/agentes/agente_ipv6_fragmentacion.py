"""Agente IPv6 de Fragmentación: cuatro casos con controles positivos."""

from __future__ import annotations

import json
import time
from uuid import uuid4

from ..casos_ipv6 import CASES
from ..contracts import Category, Task, TaskResult, TaskStatus
from ..ipv6_lab import (INTERFACE, TARGET, UDP_PORT, IPv6LabError, restore_target,
                        send_probe, target_snapshot, verify_ipv6_lab)
from ..store import RunStore


PROFILES = {
    "GT-13": ("control", "overlap", 2),
    "GT-14": ("control_middle", "overlap_middle", 3),
    "GT-15": ("plain", "atomic", 1),
    "GT-16": ("control", "incomplete_chain", 2),
}


def _seen_fragments(snapshot: dict, fragment_id: int | None) -> int:
    if fragment_id is None:
        return 0
    return sum(item["id"] == fragment_id for item in snapshot["observer"]["fragments"])


def _delivered(snapshot: dict, nonce: str) -> bool:
    return any(item["nonce"] == nonce for item in snapshot["observer"]["udp_deliveries"])


def run_fragmentation(task: Task, store: RunStore, *, timeout_seconds: int) -> TaskResult:
    if (task.target.address != TARGET or task.target.interface != INTERFACE or
            task.target.ports != [UDP_PORT]):
        raise IPv6LabError("objetivo de fragmentación distinto del piloto aislado")
    if task.case_id not in PROFILES or task.action_profile != CASES[task.case_id].action_profile:
        raise ValueError("perfil de fragmentación no implementado")
    if task.agent_type != Category.IPV6_FRAGMENTATION or timeout_seconds < 8:
        raise IPv6LabError("agente o presupuesto de fragmentación inválido")
    lab = verify_ipv6_lab()
    before = target_snapshot()
    control_profile, variant_profile, expected_fragments = PROFILES[task.case_id]
    control_nonce, variant_nonce = uuid4().hex[:16], uuid4().hex[:16]
    control_packet = variant_packet = b""
    control_probe = variant_probe = control_state = variant_state = restored = None
    failure = None
    try:
        control_packet, control_probe = send_probe(control_profile, lab["target_mac"], control_nonce)
        time.sleep(0.6)
        control_state = target_snapshot()
        control_seen = (control_probe["fragment_id"] is None or
                        _seen_fragments(control_state, control_probe["fragment_id"]) >=
                        control_probe["packet_count"])
        if control_seen and _delivered(control_state, control_nonce):
            variant_packet, variant_probe = send_probe(variant_profile, lab["target_mac"], variant_nonce)
            time.sleep(0.6)
            variant_state = target_snapshot()
    except IPv6LabError as exc:
        failure = str(exc)[:200]
    finally:
        try:
            restored = restore_target(before)
        except IPv6LabError as exc:
            failure = f"restore_failed: {str(exc)[:150]}"

    control_ref = control_hash = variant_ref = variant_hash = None
    if control_packet:
        control_ref, control_hash = store.evidence(f"{task.task_id}_control", "pcap", control_packet)
    if variant_packet:
        variant_ref, variant_hash = store.evidence(f"{task.task_id}_variant", "pcap", variant_packet)
    diagnostic = {"case_id": task.case_id, "before": before,
                  "control": {"probe": control_probe, "state": control_state},
                  "variant": {"probe": variant_probe, "state": variant_state},
                  "restored": restored, "error": failure}
    diag_ref, diag_hash = store.evidence(task.task_id, "json", json.dumps(
        diagnostic, ensure_ascii=False, sort_keys=True).encode())
    control_received = control_state is not None and _delivered(control_state, control_nonce)
    variant_seen = (variant_state is not None and variant_probe is not None and
                    _seen_fragments(variant_state, variant_probe["fragment_id"]) >= expected_fragments)
    variant_delivered = variant_state is not None and _delivered(variant_state, variant_nonce)
    if not control_received:
        status, reason = TaskStatus.FAILED, "control_not_delivered"
    elif not variant_seen:
        status, reason = TaskStatus.FAILED, "observer_missing"
    elif failure:
        status, reason = TaskStatus.FAILED, "restore_failed" if failure.startswith("restore_failed") else "probe_failed"
    else:
        status, reason = TaskStatus.COMPLETED_NO_FINDINGS, None
    observations = {
        "case_id": task.case_id, "reference": CASES[task.case_id].reference,
        "control_received": control_received, "variant_fragments_observed": variant_seen,
        "variant_udp_delivered": variant_delivered,
        "kernel_reassembly_fails_before": before["kernel_counters"].get("Ip6ReasmFails"),
        "kernel_reassembly_fails_after": (variant_state or control_state or before)["kernel_counters"].get("Ip6ReasmFails"),
        "interpretation": "observation_only_pending_validation",
        "control_pcap_ref": control_ref, "control_pcap_sha256": control_hash,
        "restored": restored is not None,
    }
    return TaskResult(
        task_id=task.task_id, status=status, reason_code=reason,
        observations=observations,
        evidence_ref=variant_ref, evidence_sha256=variant_hash,
        diagnostic_ref=diag_ref, diagnostic_sha256=diag_hash,
        command=["scapy", task.action_profile, lab["sender"], lab["target"]],
    )
