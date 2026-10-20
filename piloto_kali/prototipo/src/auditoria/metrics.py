"""Evaluación separada del LLM: TP/FP/FN y comparación pareada sin inventar denominadores."""

from __future__ import annotations

import csv
import hashlib
import json
import math
import random
import statistics
from pathlib import Path

from .contracts import AuditRequest, LabPolicy
from .findings import confirm_findings
from .store import write_json
from .validation import load_run, validate_results


def truth_keys(truth: dict) -> tuple[set, set]:
    if not isinstance(truth, dict) or not isinstance(truth.get("entries"), list):
        raise ValueError("ground truth requiere una lista entries")
    positive, negative = set(), set()
    for entry in truth["entries"]:
        if not isinstance(entry, dict) or any(
            not isinstance(entry.get(k), str) or not entry[k] for k in ["asset_id", "defect_key"]
        ):
            raise ValueError("cada etiqueta requiere asset_id y defect_key")
        key = (entry["asset_id"], entry["defect_key"])
        if key in positive | negative or not isinstance(entry.get("present"), bool):
            raise ValueError("ground truth duplicado o inválido")
        (positive if entry["present"] else negative).add(key)
    return positive, negative


def score_run(root: Path, truth: dict) -> dict:
    positive, negative = truth_keys(truth)
    report, tasks, results = load_run(root)
    validation = validate_results(root, tasks, results)
    policy = LabPolicy.model_validate_json((root / "policy.json").read_text())
    findings = confirm_findings(root, policy, tasks, results, validation)
    found = {(f["asset_id"], f["defect_key"]) for f in findings}
    tp, fp, fn = len(found & positive), len(found - positive), len(positive - found)
    elapsed = report.get("metrics", {}).get("elapsed_seconds")
    tokens = report.get("llm", {}).get("total_tokens")
    return {
        "audit_id": report["audit_id"],
        "run_path": str(root.resolve()),
        "architecture": report.get("architecture"),
        "status": report["status"],
        "mode": report["mode"],
        "TP": tp,
        "FP": fp,
        "FN": fn,
        "TN": len(negative - found),
        "precision": tp / (tp + fp) if tp + fp else None,
        "recall": tp / (tp + fn) if tp + fn else None,
        "elapsed_seconds": elapsed,
        "tokens": tokens,
        "cost_estimate_usd": report.get("llm", {}).get("cost_estimate_usd"),
        "completion": report.get("metrics", {}).get("tasks_completed", 0) / len(tasks)
        if tasks
        else 0,
        "evidence_valid": all(r["evidence_integrity"]["valid"] is not False for r in validation),
        "missed": sorted([list(k) for k in positive - found]),
        "false_positives": sorted([list(k) for k in found - positive]),
    }


def kpis(single: dict, multi: dict) -> dict:
    def number(x):
        return (
            isinstance(x, (int, float)) and not isinstance(x, bool) and x >= 0 and math.isfinite(x)
        )

    tu, tm = single.get("elapsed_seconds"), multi.get("elapsed_seconds")
    pu, pm = single["TP"], multi["TP"]
    ku, km = single.get("tokens"), multi.get("tokens")
    trto = (tu - tm) / tu * 100 if number(tu) and tu > 0 and number(tm) else None
    ide = (pm - pu) / pu * 100 if pu > 0 else None
    etv = (
        (ku / pu) / (km / pm)
        if pu > 0 and pm > 0 and number(ku) and number(km) and km > 0
        else None
    )
    return {
        "TRTO_percent": trto,
        "IDE_percent": ide,
        "ETV_ratio": etv,
        "targets": {"TRTO_percent": 30, "IDE_percent": 20, "ETV_ratio": 1.10},
        "met": {
            "TRTO": trto >= 30 if trto is not None else None,
            "IDE": ide >= 20 if ide is not None else None,
            "ETV": etv >= 1.10 if etv is not None else None,
        },
    }


def comparison_context(root: Path) -> dict:
    request = AuditRequest.model_validate_json((root / "request.json").read_text())
    manifest = json.loads((root / "manifest.json").read_text())
    lab = manifest.get("lab") or {}
    targets = lab.get("targets", [])
    return {
        "bank": request.bank,
        "lab_bank": lab.get("bank"),
        "lab_source_sha256": lab.get("source_sha256"),
        "lab_kernel": lab.get("kernel"),
        "fixture_seed_sha256": lab.get("fixture_seed_sha256"),
        "lab_resources": sorted((t["container"], t.get("nano_cpus"), t.get("memory_limit_bytes"), t.get("pids_limit"))
                                for t in targets if t.get("container")),
        "targets": [t.model_dump(mode="json") for t in request.targets],
        "categories": request.categories,
        "case_ids": request.case_ids,
        "scope_ipv4": request.scope_ipv4,
        "scope_ipv6": request.scope_ipv6,
        "runtime_budget": request.max_runtime_seconds,
        "attempt_budget": request.max_attempts,
        "token_budget": request.token_budget,
        "llm_mode": request.llm_mode,
        "llm_provider": request.llm_provider,
        "execution_policy": request.execution_policy,
        "stop_on_verified_access": request.stop_on_verified_access,
        "policy_sha256": manifest["policy_sha256"],
        "tools": manifest["tools"],
        "model": manifest.get("llm_model"),
        "llm_config": manifest.get("llm_config"),
        "prototype_version": manifest.get("prototype_version"),
        "source_sha256": manifest.get("source_sha256"),
        "images": sorted({t["image_id"] for t in targets}),
        "sender_image_id": lab.get("sender_image_id"),
    }


def compare_pair(single_root: Path, multi_root: Path, truth_path: Path) -> dict:
    if single_root.resolve() == multi_root.resolve():
        raise ValueError("se requieren corridas distintas")
    truth = json.loads(truth_path.read_text())
    single, multi = score_run(single_root, truth), score_run(multi_root, truth)
    reasons = []
    if (single["architecture"], multi["architecture"]) != ("single", "multiagent"):
        reasons.append("architecture_mismatch")
    if single["audit_id"] == multi["audit_id"]:
        reasons.append("same_audit_id")
    if comparison_context(single_root) != comparison_context(multi_root):
        reasons.append("experimental_context_changed")
    for name, root, score in [("single", single_root, single), ("multiagent", multi_root, multi)]:
        report = json.loads((root / "report.json").read_text())
        request = AuditRequest.model_validate_json((root / "request.json").read_text())
        if request.stop_on_verified_access:
            reasons.append(name + "_access_demo_not_full_evaluation")
        if score["status"] != "complete" or score["mode"] != "live" or not score["evidence_valid"]:
            reasons.append(name + "_run_incomplete")
        if (
            score["elapsed_seconds"] is None
            or score["elapsed_seconds"] > request.max_runtime_seconds
        ):
            reasons.append(name + "_runtime_budget_exceeded_or_unmeasured")
        llm = report.get("llm", {})
        if (
            request.llm_mode != "scheduler"
            or llm.get("status") != "accepted"
            or not llm.get("usage_complete")
            or not llm.get("calls")
            or not llm.get("model")
        ):
            reasons.append(name + "_llm_unmeasured_or_fallback")
    return {
        "schema_version": "1",
        "ground_truth_sha256": hashlib.sha256(truth_path.read_bytes()).hexdigest(),
        "population": truth.get("scope"),
        "single": single,
        "multiagent": multi,
        "eligible": not reasons,
        "ineligibility_reasons": reasons,
        "exploratory_kpis": kpis(single, multi),
        "formal_kpis": kpis(single, multi) if not reasons else None,
    }


def bootstrap_ci(values: list[float], *, seed: int, resamples: int = 2000) -> list[float] | None:
    if len(values) < 2:
        return None
    rng = random.Random(seed)
    estimates = sorted(
        statistics.mean(rng.choices(values, k=len(values))) for _ in range(resamples)
    )
    return [estimates[int(0.025 * resamples)], estimates[int(0.975 * resamples)]]


def summarize_experiment(root: Path, truth_path: Path) -> dict:
    attempts = json.loads((root / "attempts.json").read_text())
    design_path = root / "design.json"
    design = json.loads(design_path.read_text()) if design_path.exists() else {}
    planned_blocks = design.get("blocks", [])
    planned_ids = {b["block"] for b in planned_blocks}
    truth = json.loads(truth_path.read_text())
    positives, _ = truth_keys(truth)
    def run_path(attempt):
        path = Path(attempt["run_path"])
        return path if path.is_absolute() else root / path
    rows = []
    for attempt in attempts:
        row = {**attempt}
        if attempt.get("run_path"):
            try:
                row.update(score_run(run_path(attempt), truth))
            except (OSError, ValueError, KeyError, TypeError):
                row.update(TP=0, FP=0, FN=len(positives), status="evaluation_failed", tokens=None)
        else:
            row.update(
                TP=0,
                FP=0,
                FN=len(positives),
                status=attempt.get("status", "interrupted"),
                tokens=None,
            )
        rows.append(row)
    pairs = []
    for block in sorted({a["block"] for a in attempts}):
        entries = [a for a in attempts if a["block"] == block]
        by_arch = {a["architecture"]: a for a in entries}
        if set(by_arch) == {"single", "multiagent"} and all(a.get("run_path") for a in entries):
            try:
                pair = compare_pair(
                    run_path(by_arch["single"]),
                    run_path(by_arch["multiagent"]),
                    truth_path,
                )
                pair["block"] = block
                pairs.append(pair)
            except (OSError, ValueError, KeyError, TypeError):
                pairs.append(
                    {
                        "block": block,
                        "eligible": False,
                        "ineligibility_reasons": ["evaluation_failed"],
                    }
                )
        else:
            pairs.append(
                {
                    "block": block,
                    "eligible": False,
                    "ineligibility_reasons": ["pair_missing_or_interrupted"],
                }
            )
    values = {
        name: [
            p["formal_kpis"][name]
            for p in pairs
            if p["eligible"] and p["formal_kpis"][name] is not None
        ]
        for name in ["TRTO_percent", "IDE_percent", "ETV_ratio"]
    }
    summary = {
        "schema_version": "1",
        "runs_started": len(attempts),
        "runs_planned": len(planned_blocks) * 2,
        "pairs_planned": len(planned_blocks),
        "pairs": pairs,
        "runs": rows,
        "pairs_eligible": sum(p["eligible"] for p in pairs),
        "formal_cohort_complete": bool(planned_ids)
        and len(planned_ids) == len(planned_blocks)
        and len(attempts) == len(planned_blocks) * 2
        and {p["block"] for p in pairs} == planned_ids
        and all(p["eligible"] for p in pairs),
        "pilot": design.get("pilot", False) if design_path.exists() else None,
        "analysis": {
            k: {
                "n_defined": len(v),
                "mean": statistics.mean(v) if v else None,
                "paired_bootstrap_CI95": bootstrap_ci(v, seed=2026),
            }
            for k, v in values.items()
        },
        "note": "No excluir silenciosamente fallos. Los abortos conservan FN; TRTO formal requiere pares completos. IC exploratorio por remuestreo de bloques, no prueba de significancia.",
    }
    write_json(root / "evaluation.json", summary)
    fields = [
        "block",
        "order",
        "architecture",
        "status",
        "TP",
        "FP",
        "FN",
        "precision",
        "recall",
        "tokens",
        "elapsed_seconds",
        "completion",
        "run_path",
    ]
    with (root / "runs.csv").open("w", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)
    return summary
