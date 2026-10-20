#!/usr/bin/env python3
"""Consolida metadatos saneados sin ejecutar auditorías ni modificar fuentes.

Solo escribe docs/cierre-final-2026-10-17/evidencias. Los IDs deduplican las
copias; los hashes registran conflictos. No exporta prompts, direcciones,
credenciales, respuestas LLM ni payloads de eventos.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import re
import sqlite3
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from random import Random
from statistics import mean, median, stdev

ROOT = Path(__file__).resolve().parents[1]
PILOT = ROOT / "piloto_kali/prototipo"
OUT = ROOT / "docs/cierre-final-2026-10-17/evidencias"
BASES = [PILOT / "corridas", PILOT / "archivo_corridas", PILOT / "experimentos",
         ROOT / "docs", PILOT / ".verificacion"]


def read(path, default=None):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {} if default is None else default


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def relative(path):
    return str(path.relative_to(ROOT))


def ref(path):
    return {"path": relative(path), "sha256": sha(path)} if path.is_file() else None


def files(name):
    return sorted({p for base in BASES if base.exists() for p in base.rglob(name)
                   if OUT not in p.parents})


def events(directory):
    path = directory / "events.sqlite3"
    if not path.exists():
        return []
    try:
        connection = sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True)
        try:
            rows = connection.execute("SELECT timestamp,monotonic_ns,component,kind,task_id,payload_json FROM events ORDER BY monotonic_ns").fetchall()
        finally:
            connection.close()
        return [{"time": t, "mono": m, "component": c, "kind": k, "task": task,
                 "data": json.loads(payload)} for t, m, c, k, task, payload in rows]
    except (sqlite3.Error, ValueError):
        return []


def identity(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def reason_code(value):
    value = str(value)
    return value if re.fullmatch(r"[A-Za-z0-9_.:-]{1,80}", value) else "redacted_non_catalog_message"


def quantile(values, fraction):
    ordered = sorted(values)
    position = (len(ordered) - 1) * fraction
    lower = int(position)
    upper = min(lower + 1, len(ordered) - 1)
    return ordered[lower] + (ordered[upper] - ordered[lower]) * (position - lower)


def descriptive(values, *, paired_bootstrap=False):
    """Describe únicamente valores medidos; el remuestreo usa parejas, no tareas."""
    values = [v for v in values if type(v) in (int, float) and math.isfinite(v)]
    if not values:
        return {"n": 0, "status": "NO_CALCULABLE"}
    result = {"n": len(values), "mean": mean(values), "median": median(values),
              "min": min(values), "max": max(values), "q1": quantile(values, .25),
              "q3": quantile(values, .75), "sample_sd": stdev(values) if len(values) > 1 else None,
              "all_observed_equal": len(set(values)) == 1}
    if paired_bootstrap:
        result["sample_unit"] = "paired_audit_block"
        result["mean_ci95_percentile_bootstrap"] = None
        if len(values) > 1:
            rng = Random(20261017)
            draws = [mean(rng.choices(values, k=len(values))) for _ in range(4000)]
            result.update(mean_ci95_percentile_bootstrap=[quantile(draws, .025), quantile(draws, .975)],
                          bootstrap_replicates=4000, bootstrap_seed=20261017)
        interval = result["mean_ci95_percentile_bootstrap"]
        result["interval_degenerate"] = interval[0] == interval[1] if interval else None
        result["uncertainty_note"] = ("Intervalo exploratorio condicionado a las parejas observadas de este banco y versión. "
                                      "Un intervalo degenerado del banco observado no demuestra equivalencia general, ausencia universal de FN ni potencia garantizada. "
                                      "Repetir casos no añade vulnerabilidades independientes; no se prueba significancia.")
    return result


def study_statistics(rows, comparisons):
    """Separa toda fase y cohorte; nunca combina pilotos con posiciones formales."""
    by_id = {r["audit_id"]: r for r in rows}
    grouped = defaultdict(list)
    context_fields = ("scenario", "provider", "model", "source_sha256", "adapter_sha256", "extensions_sha256", "scope_signature", "image_signature", "token_budget", "maximum_runtime_seconds", "context_sha256")
    context_key = lambda row: identity({field: row.get(field) for field in context_fields})
    for pair in comparisons:
        members = [by_id[pair[k]] for k in ("single_id", "multiagent_id") if pair.get(k) in by_id]
        recorded_phase = next((r.get("phase") for r in members if r.get("phase")), "historical_unclassified")
        phase = pair.get("phase") or ("pilot" if pair.get("historical_pilot") is True else "formal_historical" if pair.get("historical_pilot") is False else recorded_phase)
        contexts = {context_key(row) for row in members}
        partition = identity(sorted(contexts))
        key = (pair.get("cohort") or (pair.get("source") or {}).get("path"), phase, partition)
        grouped[key].append(pair)
    result = []
    for (cohort, phase, partition), observed in grouped.items():
        ids = {p[k] for p in observed for k in ("single_id", "multiagent_id") if p.get(k)}
        population = [by_id[k] for k in ids if k in by_id]
        contexts = {context_key(row) for row in population}
        legacy_directories = {row["legacy_cohort_directory"] for row in population if row.get("legacy_cohort_directory")}
        extra = [r for r in rows if r["audit_id"] not in ids and r["api_requested"] and context_key(r) in contexts
                 and ((r.get("cohort") == cohort and r.get("phase") == phase)
                      or (r.get("legacy_cohort_directory") in legacy_directories
                          and (r.get("phase") == phase or (str(r.get("phase")).startswith("formal") and str(phase).startswith("formal")))))]
        population.extend(extra)
        eligible = [p for p in observed if p["valid_for_exploratory_comparison"]]
        eligible_ids = {p[key] for p in eligible for key in ("single_id", "multiagent_id") if p.get(key)}
        metrics = {metric: descriptive([p["recalculated_kpis"].get(metric) for p in eligible if p.get("recalculated_kpis")], paired_bootstrap=True)
                   for metric in ("TRTO_percent", "IDE_percent", "ETV_ratio", "recall_difference_pp", "time_difference_seconds", "token_difference")}
        for descriptor in metrics.values():
            descriptor["summary_definition"] = "Media y mediana de métricas calculadas por pareja; no razón de medias ni cociente de sumas de brazos."
        arms = {}
        for architecture in ("single", "multiagent"):
            arm = [r for r in population if r["architecture"] == architecture]
            scored = [r for r in arm if r["scoring_status"] != "NO_CALCULABLE" and not r["score_copy_conflict"]]
            counts = {key: sum(r[key] for r in scored) if scored else None for key in ("TP", "FP", "FN", "TN")}
            tp, fp, fn = counts["TP"], counts["FP"], counts["FN"]
            costs = [r["cost_known_estimate_usd"] for r in arm if r["cost_known_estimate_usd"] is not None]
            elapsed = [r["elapsed_seconds"] for r in arm if r["status"] == "complete"]
            arms[architecture] = {
                "attempts_including_failures": len(arm), "status_counts": dict(Counter(r["status"] for r in arm)),
                "completed": sum(r["status"] == "complete" for r in arm),
                "completion_rate": sum(r["status"] == "complete" for r in arm) / len(arm) if arm else None,
                "valid_reserved_reference_runs": len(scored), "unscorable_runs": len(arm) - len(scored),
                "condition_observations_repeated": counts,
                "precision_micro": tp / (tp + fp) if tp is not None and tp + fp else None,
                "recall_micro": tp / (tp + fn) if tp is not None and tp + fn else None,
                "precision_macro_per_run": descriptive([r["precision"] for r in scored]),
                "recall_macro_per_run": descriptive([r["recall"] for r in scored]),
                "completed_duration_seconds": descriptive(elapsed),
                "duration_seconds_eligible_pairs_only": descriptive([r["elapsed_seconds"] for r in arm if r["audit_id"] in eligible_ids]),
                "stages_completed_runs": {key: descriptive([r.get(key) for r in arm if r["status"] == "complete"]) for key in ("execution_seconds", "review_seconds")},
                "stage_timing_note": "Etapas del controlador desde attempts/metrics. No se suman tareas concurrentes; la comparación conjunta no aísla causalmente especialización, contexto y concurrencia.",
                "known_tokens_all_attempts": descriptive([r["tokens_known"] for r in arm]),
                "tokens_per_TP_measured_complete_runs": descriptive([r["tokens_known"] / r["TP"] for r in scored if r["TP"] > 0 and r["usage_complete"] and r["status"] == "complete"]),
                "tokens_per_TP_eligible_pairs_only": descriptive([r["tokens_known"] / r["TP"] for r in scored if r["TP"] > 0 and r["audit_id"] in eligible_ids]),
                "usage_closed_runs": sum(r["usage_complete"] for r in arm),
                "usage_incomplete_runs": sum(not r["usage_complete"] for r in arm),
                "known_cost_minimum_total_usd": round(sum(costs), 8) if costs else None,
                "cost_unavailable_runs": sum(r["cost_known_estimate_usd"] is None for r in arm),
                "recorded_cost_estimates_usd": descriptive(costs),
                "runs_with_fallback": sum(bool(r["fallbacks"]) for r in arm),
                "fallback_decisions_by_reason": dict(sum((Counter(r["fallback_reasons"]) for r in arm), Counter())),
                "provider_http_errors_by_code": dict(sum((Counter(r["provider_http_errors"]) for r in arm), Counter())),
                "task_failures_by_code": dict(sum((Counter(r["task_failure_codes"]) for r in arm), Counter())),
                "provider_retries": sum(r["provider_retries"] for r in arm),
                "duration_boundaries": dict(Counter(r["duration_boundary"] for r in arm)),
                "precision_recall_note": "Las sumas TP/FP/FN/TN son observaciones repetidas de condiciones; no son defectos únicos ni ensayos binomiales independientes. Sin intervalo binomial por tarea."}
        result.append({"cohort_or_evaluator_source": cohort, "phase": phase, "context_partition_sha256": partition,
                       "pairs_observed_including_incomplete": len(observed), "eligible_pairs": len(eligible),
                       "attempts_not_represented_in_pair_table": len(extra),
                       "excluded_pairs": len(observed) - len(eligible),
                       "exclusion_reasons": dict(Counter(reason for p in observed for reason in p["current_consolidation_reasons"])),
                       "analysis": "descriptive_exploratory_only" if eligible else "NO_CALCULABLE",
                       **{key: value.get("mean") for key, value in metrics.items()}, "metrics": metrics, "arms": arms,
                       "population_note": "Solo esta cohorte y fase; restauración fuera del reloj, de acuerdo con la frontera registrada. Sin mezcla de proveedores, versiones o escenarios."})
    return result


def collect():
    copies = defaultdict(set)
    for name in ("report.json", "request.json"):
        for path in files(name):
            data = read(path)
            if isinstance(data, dict) and data.get("audit_id"):
                copies[data["audit_id"]].add(path.parent)

    truths = defaultdict(list)
    for path in sorted({*files("ground_truth.json"), *PILOT.glob(".lab*/ground_truth.json"),
                        *PILOT.glob(".lab-suite/*/ground_truth.json"),
                        *PILOT.glob(".lab-suite/capsules/*/*/ground_truth.json"),
                        *PILOT.glob(".lab-suite/legacy-references/*/ground_truth.json")}):
        truths[sha(path)].append(ref(path))

    scores, cohort_rows, comparisons = defaultdict(list), [], []
    # Per-run scores are admitted only if an evaluator artifact and a matching
    # reserved reference are preserved. No truth is inferred from findings.
    seen_evaluations = set()
    for path in files("evaluation.json"):
        d = read(path)
        if not isinstance(d, dict):
            continue
        if "audit_id" in read(path.parent / "report.json"):
            scores[read(path.parent / "report.json")["audit_id"]].append((d, path))
        for run in d.get("runs", []):
            if run.get("audit_id"):
                # Legacy aggregate keeps reference at pair level.
                g = next((p.get("ground_truth_sha256") for p in d.get("pairs", [])
                          if run["audit_id"] in [p.get("single", {}).get("audit_id"), p.get("multiagent", {}).get("audit_id")]), None)
                scores[run["audit_id"]].append(({**run, "ground_truth_sha256": g}, path))
        for pair in d.get("pairs", []):
            ids = tuple(pair.get(a, {}).get("audit_id") for a in ("single", "multiagent"))
            if not all(ids) or ids in seen_evaluations:
                continue
            seen_evaluations.add(ids)
            comparisons.append({"single_id": ids[0], "multiagent_id": ids[1], "source": ref(path),
                                "block": pair.get("block"), "historical_pilot": d.get("pilot"),
                                "historical_eligible": pair.get("eligible"),
                                "historical_reasons": pair.get("ineligibility_reasons", []),
                                "ground_truth_sha256": pair.get("ground_truth_sha256"),
                                "historical_kpis": pair.get("formal_kpis")})

    attempts, protocols = {}, {}
    for path in files("attempts.json"):
        proto = read(path.parent / "protocol.json")
        raw = read(path, [])
        if not isinstance(raw, list) or not proto.get("id"):
            continue
        protocols[proto["id"]] = proto
        frozen = read(path.parent / "formal_design.json")
        state = read(path.parent / "state.json")
        cohort_rows.append({"id": proto.get("id", path.parent.name), "protocol": ref(path.parent / "protocol.json"),
                            "attempts_source": ref(path), "state": ref(path.parent / "state.json"),
                            "model": proto.get("model", {}).get("model"),
                            "tokens_per_run": proto.get("tokens_per_run"),
                            "code_identity": proto.get("code_identity"),
                            "study_status": state.get("status"),
                            "planned_formal_pairs": frozen.get("pairs", proto.get("planned_formal_pairs")),
                            "formal_design_source": ref(path.parent / "formal_design.json"),
                            "budget_snapshot": {k: state.get(k) for k in ("budget_usd", "known_cost_total_usd", "budget_committed_usd", "unknown_reserved_total_usd")},
                            "budget_note": "Los totales acumulados de la cadena son snapshots; no se suman entre cohortes sucesoras.",
                            "pilot_attempts": sum(x.get("phase") == "pilot" for x in raw),
                            "formal_attempts": sum(x.get("phase") == "formal" for x in raw)})
        for attempt in raw:
            key = attempt.get("run_key", "")
            directory = PILOT / "corridas" / key
            request = read(directory / "request.json")
            audit_id = request.get("audit_id") or attempt.get("audit_id")
            if audit_id:
                attempts[audit_id] = (attempt, proto, path)
                copies[audit_id].add(directory)

    rows = []
    for audit_id, locations in sorted(copies.items()):
        dirs = sorted(locations, key=lambda p: (not (p / "report.json").exists(),
                                               "archivo_corridas" in p.parts, "docs" in p.parts,
                                               ".verificacion" in p.parts, str(p)))
        directory = dirs[0]
        report, request, manifest = (read(directory / n) for n in ("report.json", "request.json", "manifest.json"))
        trace = events(directory)
        llm = report.get("llm", {})
        calls = llm.get("calls")
        if not isinstance(calls, list):
            calls = [e["data"] for e in trace if e["component"] == "llm" and e["kind"] == "decision"]
        attempt, proto, attempt_path = attempts.get(audit_id, ({}, {}, None))
        if not proto:
            proto = protocols.get(manifest.get("study_context", {}).get("study_id"), {})
        generations = [c for c in calls if c.get("generation_sent") is True]
        tokens = llm.get("known_tokens", llm.get("total_tokens"))
        if tokens is None:
            tokens = sum(c.get("total_tokens") or 0 for c in calls)
        usage_complete = bool(report) and llm.get("usage_complete") is True
        provider = llm.get("provider") or request.get("llm_provider") or manifest.get("llm_provider")
        model = llm.get("model") or manifest.get("llm_model") or proto.get("model", {}).get("model")
        if not model:
            models = sorted({c.get("response_model") for c in calls if c.get("response_model")})
            model = ",".join(models) or None
        is_api = (request.get("llm_mode") == "scheduler" or bool(generations)
                  or (request.get("llm_mode") != "disabled" and llm.get("status") != "disabled" and bool(model)))
        if not is_api:
            provider, model = None, None
        sources = [ref(p / name) for p in dirs for name in ("report.json", "request.json", "manifest.json", "evaluation.json", "events.sqlite3") if (p / name).is_file()]
        report_hashes = {sha(p / "report.json") for p in dirs if (p / "report.json").exists()}
        valid_scores = [(s, p) for s, p in scores[audit_id]
                        if s.get("evidence_valid") is True and s.get("ground_truth_sha256") in truths
                        and all(type(s.get(k)) is int and s[k] >= 0 for k in ("TP", "FP", "FN", "TN"))]
        score = valid_scores[0][0] if valid_scores else {}
        confusion = {k: score.get(k) for k in ("TP", "FP", "FN", "TN")}
        tp, fp, fn = (confusion[k] for k in ("TP", "FP", "FN"))
        precision = tp / (tp + fp) if tp is not None and tp + fp else None
        recall = tp / (tp + fn) if tp is not None and tp + fn else None
        status = report.get("status") or attempt.get("status") or "interrupted"
        mode = report.get("mode") or manifest.get("mode")
        phase = attempt.get("phase") or manifest.get("study_context", {}).get("phase")
        legacy_design_path = next((parent / "design.json" for parent in directory.parents if (parent / "design.json").is_file()), None)
        legacy_design = read(legacy_design_path) if legacy_design_path else {}
        if phase is None and "pilot" in legacy_design:
            phase = "pilot" if legacy_design["pilot"] else "formal_historical_incomplete_or_completed"
        if phase is None:
            phase = "acceptance_without_ia" if not is_api else "historical_or_manual"
        fallback_reasons = Counter(reason_code(c.get("reason", "unspecified")) for c in calls if c.get("status") == "fallback")
        errors = Counter(str(c["provider_http_status"]) for c in calls if c.get("provider_http_status") is not None)
        failures = Counter(reason_code(t.get("reason_code") or t.get("status")) for t in report.get("tasks", [])
                           if t.get("status") not in ("completed", "completed_no_findings", "skipped"))
        elapsed = attempt.get("elapsed_seconds", report.get("metrics", {}).get("elapsed_seconds"))
        observed_span = (trace[-1]["mono"] - trace[0]["mono"]) / 1e9 if trace else None
        cost = llm.get("known_cost_estimate_usd", llm.get("cost_estimate_usd"))
        # Recover only the known minimum of interrupted events, using the
        # tariff preserved in that same protocol; never current web pricing.
        known_cost_calls = [c for c in calls if isinstance(c.get("input_tokens"), int) and isinstance(c.get("provider_output_tokens"), int)]
        if cost is None and known_cost_calls and proto.get("pricing"):
            price = proto["pricing"]
            cost = sum(((c.get("input_tokens") or 0) - (c.get("cached_tokens") or 0) - (c.get("cache_write_tokens") or 0)) * price.get("input_per_million", 0)
                       + (c.get("cached_tokens") or 0) * price.get("cached_per_million", 0)
                       + (c.get("provider_output_tokens") or 0) * price.get("output_per_million", 0)
                       + (c.get("cache_write_tokens") or 0) * price.get("cache_write_per_million", 0) for c in known_cost_calls) / 1e6
        score_ref = ref(valid_scores[0][1]) if valid_scores else None
        lab = manifest.get("lab") or {}
        image_ids = proto.get("images") or {k: v for k, v in lab.items() if k.endswith("image_id")}
        for target in lab.get("targets", []):
            if target.get("image_id"):
                image_ids[target.get("container", target.get("asset_id", str(len(image_ids))))] = target["image_id"]
        rows.append({"audit_id": audit_id, "scenario": request.get("bank") or manifest.get("bank") or (manifest.get("lab") or {}).get("bank"),
                     "architecture": report.get("architecture") or request.get("architecture"),
                     "responsible_roles": sorted({c.get("role") for c in calls if c.get("role")}),
                     "started_at_utc": attempt.get("started_at") or (trace[0]["time"] if trace else request.get("not_before")),
                     "phase": phase, "cohort": proto.get("id") or manifest.get("study_context", {}).get("study_id") or (legacy_design.get("id") if legacy_design else None),
                     "block": attempt.get("block", manifest.get("study_context", {}).get("block")),
                     "context_sha256": attempt.get("context_sha256"),
                     "legacy_design_sha256": sha(legacy_design_path) if legacy_design_path else None,
                     "legacy_cohort_directory": relative(legacy_design_path.parent) if legacy_design_path else None,
                     "protocol_sha256": attempt.get("protocol_sha256") or manifest.get("study_context", {}).get("protocol_sha256"),
                     "mode": mode, "api_requested": is_api, "provider": provider, "model": model,
                     "reported_models": sorted({c.get("response_model") for c in calls if c.get("response_model")}),
                     "prototype_version": manifest.get("prototype_version"),
                     "source_sha256": manifest.get("source_sha256"), "adapter_sha256": manifest.get("adapter_sha256"),
                     "extensions_sha256": manifest.get("extensions_sha256"),
                     "code_identity": proto.get("code_identity"),
                     "scope_signature": identity({k: request.get(k) for k in ("scope_ipv4", "scope_ipv6", "categories", "case_ids", "targets", "execution_policy", "max_attempts", "stop_on_verified_access")}),
                     "tool_profile": manifest.get("tool_profile"),
                     "image_signature": identity(image_ids) if image_ids else None,
                     "token_budget": request.get("token_budget", llm.get("budget")),
                     "maximum_runtime_seconds": request.get("max_runtime_seconds"),
                     "status": status, "api_status": llm.get("status") or ("interrupted_without_report" if is_api else "disabled"),
                     "tasks_planned": len(read(directory / "plan.json", [])) or len(report.get("tasks", [])),
                     "tasks_terminal": len(report.get("tasks", [])) if report else len({e["task"] for e in trace if e["kind"] == "task_terminal"}),
                     "findings_reported": len(report.get("findings", [])) if report else None,
                     "elapsed_seconds": elapsed, "observed_trace_span_seconds": observed_span,
                     "execution_seconds": attempt.get("execution_seconds", report.get("metrics", {}).get("execution_seconds")),
                     "review_seconds": attempt.get("review_seconds", report.get("metrics", {}).get("expert_review_seconds")),
                     "duration_boundary": "controller_total" if attempt.get("elapsed_seconds") is not None else "report_metrics" if elapsed is not None else "no_final_duration",
                     "tokens_known": tokens, "tokens_measurement": "closed" if usage_complete else "minimum_or_unavailable",
                     "usage_complete": usage_complete, "generations_explicitly_sent": len(generations),
                     "decision_events_or_calls": len(calls),
                     "expert_mode": manifest.get("expert_mode", llm.get("expert_mode", False)) is True,
                     "review_roles": [{"role": r.get("role"), "status": r.get("status"), "reason": reason_code(r.get("reason")) if r.get("reason") else None} for r in llm.get("specialist_reviews", [])],
                     "fallbacks": llm.get("fallbacks", sum(c.get("status") == "fallback" for c in calls)),
                     "fallback_reasons": dict(fallback_reasons), "provider_http_errors": dict(errors),
                     "provider_retries": sum(e["kind"] == "provider_retry" for e in trace),
                     "task_failure_codes": dict(failures),
                     "cost_known_estimate_usd": round(cost, 9) if cost is not None else None,
                     "cost_is_lower_bound": not usage_complete,
                     **confusion, "precision": precision, "recall": recall,
                     "scoring_status": "reserved_reference_and_evaluator_preserved" if score else "NO_CALCULABLE",
                     "ground_truth_sha256": score.get("ground_truth_sha256"),
                     "score_copy_conflict": len({tuple(s.get(k) for k in ("TP", "FP", "FN", "TN", "ground_truth_sha256")) for s, _ in valid_scores}) > 1,
                     "reference_sources": truths.get(score.get("ground_truth_sha256"), []),
                     "evaluator_source": score_ref, "copy_hash_conflict": len(report_hashes) > 1,
                     "copies": [relative(p) for p in dirs], "sources": sources,
                     "no_report_note": "No final report; trace span is not completed audit duration" if not report else None})

    by_id = {r["audit_id"]: r for r in rows}
    current_blocks = defaultdict(dict)
    for row in rows:
        if row["cohort"] and row["block"] is not None and row["phase"] in ("pilot", "formal"):
            current_blocks[(row["cohort"], row["phase"], row["block"])][row["architecture"]] = row
    for (cohort, phase, block), arms in current_blocks.items():
        pair_ids = tuple(arms.get(a, {}).get("audit_id") for a in ("single", "multiagent"))
        if pair_ids in seen_evaluations:
            continue
        source = next((c["protocol"] for c in cohort_rows if c["id"] == cohort), None)
        comparisons.append({"single_id": pair_ids[0], "multiagent_id": pair_ids[1], "source": source,
                            "cohort": cohort, "phase": phase, "block": block,
                            "historical_pilot": phase == "pilot", "historical_eligible": None,
                            "historical_reasons": [], "historical_kpis": None,
                            "eligibility_origin": "Reconstructed from persisted study context; not an original eligibility claim"})
    for pair in comparisons:
        single, multi = (by_id.get(pair[k]) for k in ("single_id", "multiagent_id"))
        reasons = []
        if not single or not multi:
            reasons.append("source_run_missing")
        else:
            for field in ("scenario", "model", "source_sha256", "scope_signature", "token_budget", "maximum_runtime_seconds", "image_signature"):
                if single.get(field) is None or single[field] != multi.get(field):
                    reasons.append(field + "_missing_or_different")
            for field in ("adapter_sha256", "extensions_sha256", "tool_profile", "code_identity"):
                if single.get(field) != multi.get(field):
                    reasons.append(field + "_different")
            if single.get("ground_truth_sha256") != multi.get("ground_truth_sha256"):
                reasons.append("ground_truth_sha256_different")
            if single["expert_mode"] or multi["expert_mode"]:
                if not single["reported_models"] or single["reported_models"] != multi["reported_models"]:
                    reasons.append("reported_models_missing_or_different")
                if not single.get("context_sha256") or single["context_sha256"] != multi.get("context_sha256"):
                    reasons.append("expert_context_missing_or_different")
                for row in (single, multi):
                    expected_roles = {"generalist"} if row["architecture"] == "single" else {"network", "credentials", "applications", "ipv6", "fragmentation"}
                    reviews = row["review_roles"]
                    if len(reviews) != len(expected_roles) or {r["role"] for r in reviews} != expected_roles or any(r["status"] != "accepted" for r in reviews):
                        reasons.append(row["architecture"] + "_reviews_missing_or_rejected")
                    if row["generations_explicitly_sent"] < 1:
                        reasons.append(row["architecture"] + "_API_generation_not_proven")
            if single["mode"] != "live" or multi["mode"] != "live":
                reasons.append("mode_not_live")
            if not single["usage_complete"] or not multi["usage_complete"]:
                reasons.append("usage_incomplete")
            if any(r["fallbacks"] or r["status"] != "complete" for r in (single, multi)):
                reasons.append("fallback_or_incomplete")
            if not all(r["scoring_status"] != "NO_CALCULABLE" for r in (single, multi)):
                reasons.append("reserved_reference_not_proven")
            if any(r["copy_hash_conflict"] or r["score_copy_conflict"] for r in (single, multi)):
                reasons.append("conflicting_preserved_sources")
        pair["current_consolidation_reasons"] = reasons
        pair["valid_for_exploratory_comparison"] = pair["historical_eligible"] is not False and not reasons
        pair["recalculated_kpis"] = None
        if pair["valid_for_exploratory_comparison"]:
            calculated = {"TRTO_percent": None, "IDE_percent": None, "ETV_ratio": None,
                          "recall_difference_pp": None, "time_difference_seconds": None,
                          "token_difference": single["tokens_known"] - multi["tokens_known"]}
            if all(type(r["elapsed_seconds"]) in (int, float) and math.isfinite(r["elapsed_seconds"]) and r["elapsed_seconds"] > 0 for r in (single, multi)):
                calculated["TRTO_percent"] = 100 * (single["elapsed_seconds"] - multi["elapsed_seconds"]) / single["elapsed_seconds"]
                calculated["time_difference_seconds"] = single["elapsed_seconds"] - multi["elapsed_seconds"]
            if single["TP"] > 0:
                calculated["IDE_percent"] = 100 * (multi["TP"] - single["TP"]) / single["TP"]
            if all(r["TP"] > 0 and r["tokens_known"] > 0 for r in (single, multi)):
                calculated["ETV_ratio"] = (single["tokens_known"] / single["TP"]) / (multi["tokens_known"] / multi["TP"])
            if single["recall"] is not None and multi["recall"] is not None:
                calculated["recall_difference_pp"] = 100 * (multi["recall"] - single["recall"])
            pair["recalculated_kpis"] = calculated
        pair["interpretation"] = "Exploratory within preserved cohort; no population superiority claim"
    return rows, cohort_rows, comparisons


def write_csv(path, rows, fields):
    with path.open("w", newline="", encoding="utf-8") as output:
        writer = csv.DictWriter(output, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow({k: json.dumps(v, ensure_ascii=False, sort_keys=True) if isinstance(v, (dict, list)) else v for k, v in row.items() if k in fields})


def write_critical_verifications():
    """Deriva aserciones concretas solo de casos aprobados y fuentes identificadas."""
    import ast

    receipt_path = ROOT / "docs/cierre-final-2026-10-17/qa-panel.json"
    receipt = read(receipt_path)
    passed = {row.get("id"): row for row in receipt.get("tests", []) if row.get("status") == "APROBADA"}
    specifications = [
        ("Autorizar operaciones HTTP", "Panel local", "PanelTests.test_control_requires_origin_and_csrf", "test_dualstack_panel", "RF-03;RF-04;RNF-05", "Enviar solicitudes sin origen o CSRF y una configuración fuera de límite mediante el cliente de la fixture.", "Los rechazos devuelven 403/400 y la lista de operaciones permanece vacía; una comprobación admitida responde 202."),
        ("Rechazar direcciones públicas y prefijos IPv6", "Configuración por IP", "PersonalLabTests.test_scope_rejects_public_cidr_mixed_lists_and_ipv6_prefixes", "test_laboratorio_personal", "RF-02;RF-03;RO-02", "Validar CIDR público, listas mixtas, prefijos IPv6, entradas incompletas y zona de interfaz incrustada.", "Cada entrada inválida produce ValueError; una lista no vuelve autorizado un destino público."),
        ("Exigir ruta directa por la interfaz elegida", "Resolución de destinos", "PersonalLabTests.test_routes_must_be_direct_and_match_the_selected_interface", "test_laboratorio_personal", "RF-03;RF-04;RNF-08", "Inyectar respuestas de ruta directa, ruta con gateway y ruta por otra interfaz.", "La ruta directa resuelve los dos destinos previstos; gateway y discrepancia de interfaz se rechazan antes de ejecutar herramientas."),
        ("Acotar el proceso de descubrimiento y su plazo", "Puertos automáticos", "AutomaticPortsTests.test_execute_revalidates_route_and_timeout_is_not_an_empty_success", "test_puertos_personales", "RF-14;RF-38;RNF-03;RNF-06", "Proporcionar una revalidación sin destino y después un runner que inspecciona argumentos y produce timeout.", "No se invoca herramienta antes de validar ruta; shell es falso, timeout no supera 65 s y el resultado es failed, scan_complete falso y lista de servicios vacía."),
        ("Vincular la recomendación a evidencia del mismo activo", "Contrato de revisión LLM", "ExpertsTests.test_schema_expresses_validator_limits_and_binds_action_to_same_asset", "test_panel_expertos", "RF-33;RF-36;RNF-09", "Examinar el esquema enviado al transporte simulado de revisión generalista.", "Interpretación acotada a 600 caracteres, tres acciones como máximo y referencias permitidas que corresponden al activo de cada acción."),
        ("Evitar instrucciones del banner en el contexto", "Contexto observacional", "ExpertsTests.test_untrusted_service_strings_never_enter_the_llm_context", "test_panel_expertos", "RF-33;RNF-09;RNF-10", "Introducir un nombre de servicio permitido y otro con instrucciones no confiables.", "El contexto conserva categorías normalizadas ssh/other y no incluye la cadena de instrucciones. Verifica esta mitigación, no ausencia universal de prompt injection."),
        ("Exigir corroboración de autenticación", "Credenciales", "CredentialsPresentationTests.test_positive_credentials_have_evidence_and_independent_validation", "test_laboratorio_empresa_panel", "RF-21;RF-31;RF-34", "Ejecutar la fixture de credencial aceptada y revisar la validación y el archivo de confirmación.", "Se produce un hallazgo, independent_confirmation es verdadero, hay una tarea y resultado, y existe el archivo de confirmación referido."),
        ("Rechazar evidencia indeterminada y deduplicar la causa", "Validador", "EmpresaPanelTests.test_invalid_evidence_is_a_failure_and_findings_are_deduplicated", "test_laboratorio_empresa_panel", "RF-34;RF-36;RF-37", "Usar primero una validación indeterminada y después dos perfiles RA que declaran la misma causa del mismo activo.", "La primera ejecución termina con código 3 y evidence_not_validated; la segunda conserva un único hallazgo deduplicado."),
        ("Distinguir informe técnico y ejecutivo", "Reportes", "PanelTests.test_two_reports_share_findings_but_target_distinct_readers", "test_dualstack_panel", "RF-40;RF-41;RNF-17", "Solicitar ambos públicos sobre la misma fixture y una audiencia no permitida.", "El técnico incluye herramientas y referencias de evidencia; el ejecutivo incluye decisiones y excluye el apéndice técnico. La audiencia arbitraria se rechaza."),
        ("Conservar incidentes y excluir revisión rechazada", "Presentación de revisión", "FocusedReportTests.test_reports_keep_real_incidents_and_only_accepted_llm_interpretations", "test_panel_informe", "RF-41;RNF-17;RNF-22", "Renderizar ambos informes con una incidencia, una revisión aceptada con caracteres HTML y una revisión no disponible.", "Ambos conservan la incidencia y el análisis aceptado escapado; la interpretación no disponible no aparece."),
        ("Rechazar parejas de condiciones experimentales distintas", "Comparación emparejada", "StudyTests.test_different_model_reference_or_context_cannot_be_paired", "test_estudio_novaflow", "RF-43;RF-44;RO-10", "Cambiar por separado modelo, referencia, contexto, arquitectura y pertenencia; contrastar además versión del conductor y CPU del contexto.", "La pareja queda excluida con context_errors y sin TRTO/IDE/ETV; cambiar conductor o CPU modifica la firma de contexto."),
        ("Conservar reserva ante consumo desconocido", "Contabilidad experimental", "DriverIntegrationTests.test_unknown_usage_stops_after_first_paid_attempt_and_preserves_it", "test_estudio_novaflow", "RF-38;RF-39;RO-11", "Simular el primer intento con uso desconocido mediante el conductor de pruebas, sin proveedor real.", "Se detiene con código 3 tras un piloto, conserva el intento, no inicia formal, mantiene USD 0,60 reservados y no liquida gasto desconocido.")]
    rows = []
    for index, (objective, component, case_name, module, requirements, procedure, assertion) in enumerate(specifications, 1):
        case_id = module + "." + case_name
        path = ROOT / "scripts/tests" / (module + ".py")
        source = path.read_text(encoding="utf-8")
        method = case_name.rsplit(".", 1)[1]
        node = next(n for n in ast.walk(ast.parse(source)) if isinstance(n, ast.FunctionDef) and n.name == method)
        actual_sha = sha(path)
        recorded_sha = receipt.get("source_sha256", {}).get(relative(path))
        record = passed.get(case_id)
        matches = bool(record) and recorded_sha == actual_sha
        rows.append({"id": f"VC-{index:02}", "component": component, "objective": objective,
                     "requirements_related_not_adjudicated": requirements, "test_id": case_id,
                     "procedure": procedure, "expected_assertion": assertion,
                     "obtained": "Caso APROBADA en recibo preservado y hash de fuente coincidente; no reejecutado para este cuadro." if matches else "Evidencia insuficiente para asociar la fuente actual con un caso aprobado.",
                     "status": "APROBADA" if matches else "PARCIAL", "test_source": relative(path),
                     "source_line": node.lineno, "source_end_line": node.end_lineno,
                     "source_sha256": actual_sha, "source_sha256_in_qa_receipt": recorded_sha,
                     "method_sha256": hashlib.sha256(ast.get_source_segment(source, node).encode()).hexdigest(),
                     "qa_receipt": ref(receipt_path), "case_recorded_at_utc": (record or {}).get("at"),
                     "limitations": "Verificación de software bajo sus fixtures; no es una corrida API real ni prueba de todos los casos del requisito."})
    OUT.mkdir(parents=True, exist_ok=True)
    payload = {"generated_at_utc": datetime.now(timezone.utc).isoformat(), "source_receipt": ref(receipt_path),
               "receipt_case_count": receipt.get("executed"), "executed_new_tests": False,
               "method": "Lectura de recibo aprobado, correspondencia de ID, cotejo SHA-256 de fuente y lectura de aserciones del método; no se reescriben los recibos originales.",
               "status": "APROBADA" if all(r["status"] == "APROBADA" for r in rows) else "PARCIAL", "checks": rows}
    (OUT / "verificaciones-criticas.json").write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    lines = ["# Verificaciones críticas derivadas de QA", "", "Este cuadro explica doce verificaciones concretas ya ejecutadas. Se cotejaron ID, resultado aprobado, huella de la fuente y aserciones. No inicia pruebas, API ni auditorías; no transforma esos casos en cumplimiento automático de los 79 requisitos.", "",
             f"Recibo fuente: `docs/cierre-final-2026-10-17/qa-panel.json`, {receipt.get('executed')} casos; SHA-256 `{sha(receipt_path)}`. Estado del cotejo: **{payload['status']}**.", "",
             "| ID | Objetivo | Procedimiento y aserción comprobada | Estado |", "|---|---|---|---|"]
    lines.extend(f"| {r['id']} | {r['objective']} | {r['procedure']} {r['expected_assertion']} | {r['status']} |" for r in rows)
    lines += ["", "## Localizadores verificables", ""]
    for r in rows:
        lines += [f"- **{r['id']}** · `{r['test_id']}` · `{r['test_source']}:{r['source_line']}`. Fuente SHA-256 `{r['source_sha256']}`; método SHA-256 `{r['method_sha256']}`. {r['obtained']}"]
    lines += ["", "El JSON acompañante conserva procedimiento, resultado esperado y obtenido, fecha del caso, requisitos relacionados y hashes. Las pruebas con transporte o validadores simulados solo acreditan su contrato bajo esas fixtures. La mitigación de banners no elimina toda inyección de instrucciones; deduplicar una causa configurada no demuestra cobertura universal. La matriz de requisitos conserva su propia adjudicación parcial."]
    (OUT / "VERIFICACIONES-CRITICAS.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(json.dumps({"critical_verifications": len(rows), "status": payload["status"], "new_tests_executed": False}, ensure_ascii=False))
    return payload


def closure_evidence_state():
    """Lee productos congelados; no recalcula ni consulta el estudio en marcha."""
    inventory = read(OUT / "inventario.json")
    statistics = read(OUT / "metricas-por-cohorte.json", [])
    qa = read(ROOT / "docs/cierre-final-2026-10-17/qa.json")
    terminal = []
    for cohort in inventory.get("summary", {}).get("novaflow_studies", []):
        planned = cohort.get("planned_formal_pairs")
        if cohort.get("study_status") != "complete" or type(planned) is not int or planned < 1 or cohort.get("formal_attempts") != 2 * planned:
            continue
        groups = [group for group in statistics if group.get("cohort_or_evaluator_source") == cohort["id"] and group.get("phase") == "formal"]
        useful = [group for group in groups if group.get("eligible_pairs", 0) > 0 and all(group.get("metrics", {}).get(key, {}).get("n", 0) > 0 for key in ("TRTO_percent", "IDE_percent", "ETV_ratio"))]
        if useful:
            terminal.append({"id": cohort["id"], "planned_pairs": planned,
                             "attempts": cohort["formal_attempts"], "eligible_pairs": sum(group["eligible_pairs"] for group in useful)})
    latest = sorted(terminal, key=lambda row: row["id"])[-1] if terminal else None
    operational_pilot = any(group.get("phase") == "pilot" and group.get("eligible_pairs", 0) >= 3 for group in statistics)
    software_qa = all(qa.get(key, {}).get("status") == "APROBADA" for key in ("core", "panel", "suite_acceptance"))
    architecture_documented = False
    main = ROOT / "docs/TrabajoDeGrado_II_Completo.docx"
    if main.is_file() and (ROOT / "docs/diagramas-finales/fuentes.json").is_file():
        import zipfile
        import xml.etree.ElementTree as element_tree
        try:
            with zipfile.ZipFile(main) as archive:
                document = element_tree.fromstring(archive.read("word/document.xml"))
            content = " ".join(node.text or "" for node in document.iter("{http://schemas.openxmlformats.org/wordprocessingml/2006/main}t"))
            architecture_documented = all(marker in content for marker in ("3.11", "ThreadPoolExecutor", "LangGraph"))
        except (OSError, zipfile.BadZipFile, element_tree.ParseError):
            pass
    return {"evaluation_performed": bool(latest), "latest_terminal_evaluation": latest,
            "implementation_verified_in_declared_scope": software_qa and operational_pilot,
            "architecture_documented": architecture_documented,
            "sources": [ref(path) for path in (OUT / "inventario.json", OUT / "metricas-por-cohorte.json", ROOT / "docs/cierre-final-2026-10-17/qa.json") if path.is_file()]}


def write_traceability():
    """Mapea compromisos del anexo vigente; no supone que existir sea aprobar."""
    import xml.etree.ElementTree as element_tree
    import zipfile

    main, annex = (ROOT / "docs" / n for n in ("TrabajoDeGrado_II_Completo.docx", "TrabajoDeGrado_II_Anexos.docx"))
    if not annex.exists():
        return
    ns = {"w": "http://schemas.openxmlformats.org/wordprocessingml/2006/main"}
    with zipfile.ZipFile(annex) as document:
        body = element_tree.fromstring(document.read("word/document.xml"))
    requirements = []
    seen_requirements = set()
    closure = closure_evidence_state()
    final_comparison = closure["latest_terminal_evaluation"]
    comparison_limit = (f"Campaña terminal {final_comparison['id']}: {final_comparison['attempts']} intentos formales y {final_comparison['eligible_pairs']} parejas útiles de {final_comparison['planned_pairs']} previstas. Comparar está cumplido en alcance exploratorio; alcanzar metas favorables es un resultado separado. No mezclar pilotos ni cohortes." if final_comparison else "La campaña formal no consta cerrada en estos productos derivados. Se conservan comparaciones históricas y pilotos; el cierre se actualizará solo desde un estado terminal y sus denominadores.")
    groups = [
        (range(1, 5), "OE2;OE3", "Solicitud y autorización determinista", "scripts/laboratorio_empresa.py;scripts/laboratorio_personal.py", "scripts/tests/test_laboratorio_empresa_panel.py;scripts/tests/test_laboratorio_personal.py", "Admisión cerrada y validación por IP son alcances distintos; una aceptación no acredita todas las redes."),
        (range(5, 11), "OE2;OE3", "Controlador, dependencias y estados", "scripts/laboratorio_empresa.py;piloto_kali/prototipo/src/auditoria", "scripts/tests/test_laboratorio_empresa_panel.py;scripts/tests/test_interrupciones.py", "El flujo NovaFlow usa Python y ThreadPoolExecutor; LangGraph corresponde al núcleo histórico. No hay reanudación automática."),
        (range(11, 18), "OE3", "Inventario dual-stack y candidatos CVE", "scripts/laboratorio_personal.py;scripts/tesis/candidatos.py", "scripts/tests/test_laboratorio_personal.py;scripts/tests/test_puertos_personales.py;scripts/tests/test_tesis_workspace.py", "El catálogo CVE es acotado y sus candidatos no constituyen confirmación. No hay cobertura universal de vulnerabilidades."),
        (range(18, 22), "OE3", "Credenciales sintéticas y corroboración", "piloto_kali/prototipo/src/auditoria/adapters; scripts/laboratorio_empresa.py", "scripts/tests/test_laboratorio_empresa_panel.py", "Cobertura de perfiles autorizados de SSH/FTP/HTTP Basic/PostgreSQL; sin fuerza bruta general ni credenciales de terceros."),
        (range(22, 31), "OE3", "NDP/SLAAC y fragmentación instrumentados", "piloto_kali/prototipo/src/auditoria;scripts/laboratorio_empresa.py", "scripts/tests/test_laboratorios_suite.py;scripts/tests/test_referencia_laboratorio.py", "La detección depende de observación del receptor y política sintética. Un control conforme no es vulnerabilidad y un silencio no prueba causalidad."),
        (range(31, 38), "OE3;OE4", "Evidencia, validador y deduplicación", "scripts/tesis/evaluacion.py;piloto_kali/prototipo/src/auditoria", "scripts/tests/test_referencia_laboratorio.py;scripts/tests/test_laboratorio_empresa_panel.py", "Corroboración independiente no equivale siempre a repetir el perfil en un attempt_id nuevo; conciliar RF35 con el contrato implementado."),
        (range(38, 43), "OE3;OE4", "Presupuesto, informes y trazas", "scripts/llm_especialistas.py;scripts/tesis/presupuesto.py;scripts/panel_informe.py", "scripts/tests/test_panel_expertos.py;scripts/tests/test_interrupciones.py;scripts/tests/test_panel_informe.py", "Uso conocido es mínimo ante interrupción. Los fallbacks no son decisiones aceptadas del LLM; los informes no garantizan ausencia de riesgo."),
        (range(43, 46), "OE4", "Diseño emparejado y exportación KPI", "scripts/tesis/estudio.py;scripts/tesis/estudio_multilab.py;scripts/consolidar_evidencias_final.py", "scripts/tests/test_estudio_novaflow.py;scripts/tests/test_estudio_multilab.py", comparison_limit)]
    for tr in body.findall(".//w:tr", ns):
        cells = ["".join(t.text or "" for t in cell.findall(".//w:t", ns)) for cell in tr.findall("w:tc", ns)]
        if not cells or not re.fullmatch(r"(?:RF|RNF|RO)-\d+", cells[0]):
            continue
        key = cells[0]
        # El Anexo H es canónico y aparece antes del P derivado. Releer P como
        # requisito nuevo duplicaría la matriz en cada regeneración del Word.
        if key in seen_requirements:
            continue
        seen_requirements.add(key)
        numeric = int(key.split("-")[1])
        if key.startswith("RF-"):
            _, oe, function, code, tests, limitation = next(g for g in groups if numeric in g[0])
        elif key.startswith("RNF-"):
            oe, function = "OE2;OE3;OE4", "Calidad transversal: seguridad, límites, trazabilidad y reproducibilidad"
            code = "scripts/tesis;scripts/dualstack_panel.py;piloto_kali/prototipo/src/auditoria"
            tests = "scripts/tests/test_dualstack_panel.py;scripts/tests/test_panel_expertos.py;scripts/tests/test_interrupciones.py"
            limitation = "La aceptación funcional de un perfil no certifica todos los criterios no funcionales ni permite declarar 100 % global. Vincular cada caso al recibo QA final."
        else:
            oe, function = "OE2;OE3;OE4", "Restricción operacional y separación de evaluación"
            code = "scripts/laboratorio_empresa.py;scripts/laboratorio_personal.py;scripts/tesis/evaluacion.py"
            tests = "scripts/tests/test_laboratorio_empresa_panel.py;scripts/tests/test_laboratorio_personal.py;scripts/tests/test_estudio_novaflow.py"
            limitation = "El banco cerrado y el modo por IP tienen restricciones diferentes. Preservar los intentos fallidos y la referencia reservada; no ampliar las conclusiones a producción."
        requirements.append({"objective": oe, "requirement": key, "academic_commitment": cells[2] if key.startswith(("RF-", "RNF-")) and len(cells) > 2 else cells[1],
                             "function": function, "implementation": code, "test_sources": tests,
                             "status": "PARCIAL", "evidence": "docs/cierre-final-2026-10-17/evidencias/inventario.json;docs/validacion-suite-2026-10-17/aceptacion-real.json",
                             "interpretation": "Trazabilidad de implementación y evidencia histórica; no adjudicación automática de cumplimiento íntegro del requisito.",
                             "limitation": limitation})
    objectives = [
        {"id": "OE1", "commitment": "Identificar sistemas multiagente LLM para pentesting IPv4/IPv6 en el estado del arte.", "status": "PARCIAL", "evidence": "docs/TrabajoDeGrado_II_Completo.docx;docs/TrabajoDeGrado_II_Anexos.docx", "remaining": "Conciliar registros bibliográficos 425 frente a 35 fuentes y recuperar soportes originales faltantes."},
        {"id": "OE2", "commitment": "Diseñar la arquitectura multiagente orquestada dual-stack.", "status": "APROBADA" if closure["architecture_documented"] else "PARCIAL", "evidence": "scripts/laboratorio_empresa.py;scripts/llm_especialistas.py;scripts/tesis/llm_contexto.py;docs/diagramas-finales/fuentes.json;docs/TrabajoDeGrado_II_Completo.docx", "remaining": "Diseño y evolución contrastados con módulos y diagramas: LangGraph histórico y controlador Python actual diferenciados. La aprobación institucional y de presentación se verifica aparte; no es certificación de arquitectura." if closure["architecture_documented"] else "La formulación arquitectónica está disponible; incorporar al corte principal la distinción explícita del controlador implementado y sus diagramas."},
        {"id": "OE3", "commitment": "Implementar agentes especializados e informes automáticos de remediación dual-stack.", "status": "APROBADA" if closure["implementation_verified_in_declared_scope"] else "PARCIAL", "evidence": "docs/cierre-final-2026-10-17/qa.json;docs/cierre-final-2026-10-17/aceptacion-suite.json;docs/cierre-final-2026-10-17/evidencias/inventario.json", "remaining": "Implementación, regresión posterior al reinicio, aceptación sin IA y piloto LLM verificados dentro del catálogo declarado; esto no adjudica automáticamente los 79 requisitos ni cobertura universal." if closure["implementation_verified_in_declared_scope"] else "La implementación está disponible; falta reunir en este corte los recibos de regresión, aceptación y piloto medido. No se sustituye su evidencia por existencia de código."},
        {"id": "OE4", "commitment": "Comparar tiempo, detección y tokens frente a agente único con controles equivalentes.", "status": "APROBADA" if final_comparison else "PARCIAL", "evidence": "docs/evaluacion-api-v2/evaluation.json;docs/cierre-final-2026-10-17/evidencias/inventario.json;docs/cierre-final-2026-10-17/evidencias/metricas-por-cohorte.json", "remaining": comparison_limit}]
    qa_sources = [ref(path) for path in (ROOT / "docs/cierre-final-2026-10-17/qa-panel.json",
                                       ROOT / "docs/cierre-final-2026-10-17/qa.json",
                                       PILOT / ".verificacion/cierre-final-20261017/qa-nucleo-junit.xml") if path.is_file()]
    package = {"academic_source": ref(annex), "main_source": ref(main), "objectives": objectives, "requirements": requirements,
               "academic_source_note": "Fuente leída antes de construir la versión académica que consume este CSV. La procedencia del Word final se actualiza en un recibo separado, sin republicar los insumos.",
               "qa_receipts_if_available": qa_sources, "closure_state_from_frozen_products": closure,
               "note": "No sustituye adjudicación requisito por requisito; estados PARCIAL son deliberados mientras se concilia evidencia completa del cierre. Existencia de código o archivo de test no prueba aprobación."}
    (OUT / "trazabilidad.json").write_text(json.dumps(package, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    write_csv(OUT / "trazabilidad.csv", requirements, ["objective", "requirement", "academic_commitment", "function", "implementation", "test_sources", "status", "evidence", "limitation"])
    body = ["# Trazabilidad de objetivos y requisitos", "", f"Fuente académica: `{relative(annex)}` (SHA-256 `{sha(annex)}`). Se mapearon {len(requirements)} compromisos RF/RNF/RO, sin cambiar su formulación original.", "",
            "Una prueba funcional aprobada en un banco verifica esos perfiles y esa configuración. No acredita cumplimiento universal del requisito ni 100 % del producto. Los archivos de prueba se identifican como fuentes; su mera existencia no equivale a prueba ejecutada.", "",
            "| Objetivo | Estado | Evidencia y pendiente |", "|---|---|---|"]
    body.extend(f"| {o['id']} · {o['commitment']} | {o['status']} | {o['remaining']} |" for o in objectives)
    body += ["", "El detalle por requisito está en `trazabilidad.csv` y `trazabilidad.json`. Las evidencias del reinicio y QA final se incorporan como recibos separados, sin reescribir resultados históricos. Los criterios de 100 % presentes en el diseño se conservan como compromisos que deben verificarse o delimitarse; no se transforman en resultados por declaración."]
    (OUT / "TRAZABILIDAD.md").write_text("\n".join(body) + "\n", encoding="utf-8")


def write_document_provenance():
    """Último paso: coteja Word y sus insumos sin republicar inventario ni CSV."""
    source = ROOT / "piloto_kali/prototipo/.verificacion/cierre-final-20261017/consolidacion.json"
    builder = read(source)
    if not builder:
        raise ValueError("No hay recibo del constructor académico")
    checks = []
    for name, metadata in builder.get("insumos", {}).items():
        path = ROOT / name
        checks.append({"kind": "builder_input", "path": name, "expected_sha256": metadata.get("sha256"), "matches": path.is_file() and sha(path) == metadata.get("sha256")})
    for name, metadata in builder.get("salidas", {}).items():
        path = ROOT / "docs" / name
        checks.append({"kind": "academic_output", "path": relative(path), "expected_sha256": metadata.get("sha256"), "matches": path.is_file() and sha(path) == metadata.get("sha256")})
    payload = {"generated_at_utc": datetime.now(timezone.utc).isoformat(), "status": "APROBADA" if checks and all(row["matches"] for row in checks) else "FALLIDA",
               "builder_receipt": ref(source), "checks": checks,
               "stable_inputs_not_rewritten": [ref(path) for path in (OUT / "inventario.json", OUT / "trazabilidad.csv") if path.is_file()],
               "note": "Recibo separado posterior al Word. No reescribe inventario.json, trazabilidad.csv, sus fechas ni los documentos académicos. Actualizar QA aparte no modifica los insumos del constructor."}
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "procedencia-documental.json").write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"document_provenance": payload["status"], "checks": len(checks), "inventory_republished": False}, ensure_ascii=False))
    return payload


def publish():
    rows, cohorts, comparisons = collect()
    # Only generated outputs are replaced. Source reports, SQLite, protocols,
    # requests and all historical evidence are never written by this script.
    OUT.mkdir(parents=True, exist_ok=True)
    api = [r for r in rows if r["api_requested"]]
    summary = {"unique_audits": len(rows), "api_requested": len(api),
               "api_by_provider": dict(Counter(r["provider"] or "not_recorded" for r in api)),
               "api_by_status": dict(Counter(r["status"] for r in api)),
               "api_by_api_status": dict(Counter(r["api_status"] for r in api)),
               "api_attempts_with_generation_evidence": sum(r["tokens_known"] > 0 or r["generations_explicitly_sent"] > 0 for r in api),
               "api_configured_but_not_started": sum(r["api_status"] == "not_started" for r in api),
               "without_ia": len(rows) - len(api),
               "after_2026_10_14_api": sum((r["started_at_utc"] or "") >= "2026-10-15" for r in api),
               "copy_hash_conflicts": sum(r["copy_hash_conflict"] for r in rows),
               "scored_with_preserved_reference": sum(r["scoring_status"] != "NO_CALCULABLE" for r in rows),
               "novaflow_studies": cohorts,
               "deduplication": "audit_id; all physical source locations and file hashes retained; copies are not new attempts",
               "scope": "Conserved audits only; diagnostics without an audit request are not counted; no API or Docker executed",
               "comparability": "No pooling across providers, code versions, banks, budgets, or pilot/formal phases"}
    payload = {"schema_version": "1", "generated_at_utc": datetime.now(timezone.utc).isoformat(),
               "summary": summary, "runs": rows, "historical_pairs": comparisons}
    (OUT / "inventario.json").write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    fields = ["audit_id", "scenario", "architecture", "started_at_utc", "phase", "cohort", "mode", "api_requested", "provider", "model", "source_sha256", "token_budget", "status", "api_status", "tasks_planned", "tasks_terminal", "findings_reported", "elapsed_seconds", "execution_seconds", "review_seconds", "duration_boundary", "tokens_known", "tokens_measurement", "usage_complete", "fallbacks", "fallback_reasons", "cost_known_estimate_usd", "TP", "FP", "FN", "TN", "precision", "recall", "scoring_status", "copy_hash_conflict", "copies"]
    write_csv(OUT / "corridas.csv", rows, fields)
    write_csv(OUT / "fuentes-sha256.csv", [{"audit_id": r["audit_id"], **s} for r in rows for s in r["sources"]], ["audit_id", "path", "sha256"])
    write_csv(OUT / "parejas.csv", [{**p, **(p.get("recalculated_kpis") or {})} for p in comparisons], ["single_id", "multiagent_id", "cohort", "phase", "block", "historical_pilot", "historical_eligible", "valid_for_exploratory_comparison", "TRTO_percent", "IDE_percent", "ETV_ratio", "recall_difference_pp", "time_difference_seconds", "token_difference", "current_consolidation_reasons", "source"])
    group_summary = study_statistics(rows, comparisons)
    (OUT / "metricas-por-cohorte.json").write_text(json.dumps(group_summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    lines = ["# Evidencias experimentales consolidadas", "", "Generado offline con `python scripts/consolidar_evidencias_final.py`. Las fuentes originales se leen; solo se actualiza este directorio de productos derivados.", "",
             f"Se conservaron **{len(rows)} auditorías únicas**: {len(api)} solicitaron API y {len(rows)-len(api)} no utilizaron IA. No equivale a ese número de evaluaciones válidas ni de réplicas independientes.", "",
             f"De las solicitudes API, {summary['api_configured_but_not_started']} no iniciaron el proveedor y {summary['api_attempts_with_generation_evidence']} conservan evidencia de generación o uso positivo. Proveedores declarados: {json.dumps(summary['api_by_provider'], ensure_ascii=False)}. Hay {summary['after_2026_10_14_api']} solicitudes posteriores al 14 de octubre (fecha UTC). No se elimina el resto de los intentos rechazados o sin uso conocido.", "",
             "Los diagnósticos mínimos de proveedor sin auditoría no se incluyen. El inventario histórico del 14 de octubre es un antecedente de 54 intentos; este inventario busca también en el archivo trasladado y en las ejecuciones posteriores. Un estado complete certifica cierre del controlador, no uso íntegro de IA.", "",
             "Las copias se deduplican por audit_id. Cada fuente tiene ruta relativa y SHA-256; los conflictos quedan marcados. No se publican prompts, credenciales, respuestas, IP ni payloads. Los archivos referenciados pueden permanecer en almacenamiento privado.", "",
             "## Reglas de medición", "", "Precisión = TP/(TP+FP); recall = TP/(TP+FN). Se publican solo cuando el evaluador y una referencia reservada cuyo hash coincide se conservan. Los denominadores nulos y las evidencias insuficientes se registran como NO CALCULABLE.", "",
             "TRTO = 100×(Túnico−Tmulti)/Túnico. IDE = 100×(TPmulti−TPúnico)/TPúnico. ETV por brazo = tokens/TP; razón ETV = ETVúnico/ETVmulti. Una razón mayor que 1 favorece al multiagente en consumo por detección. No se interpreta una interrupción como auditoría más rápida.", "",
             "Los tiempos controller_total incluyen revisión y persistencia del controlador; report_metrics preserva el límite original. El lapso SQLite de una interrupción se conserva por separado. Tokens conocidos son un mínimo si falta cierre. Los costos son estimaciones de las tarifas registradas, no facturación del proveedor.", "",
             "TRTO, IDE y razón ETV se calculan primero por pareja y después se resumen con media y mediana; no se sustituyen por una razón de medias de brazos. Los descriptores de execution_seconds y review_seconds conservan las etapas del controlador y no suman duraciones de tareas concurrentes. La comparación evalúa conjuntamente roles, contexto y concurrencia; no identifica el efecto causal aislado de la especialización.", "",
             "Los resúmenes de metricas-por-cohorte.json separan cohorte y fase piloto/formal. Cada indicador conserva su n definido, media, mediana, desviación muestral, cuartiles y rango. El intervalo percentil exploratorio remuestrea bloques emparejados (4.000 réplicas, semilla fija); con una pareja no se calcula. Un intervalo degenerado como [0,0] no demuestra equivalencia poblacional. No se agregan hipótesis de significancia ni intervalos binomiales por tareas repetidas.", "",
             "Por brazo se informan todos los intentos, terminación, corridas adjudicables, precisión/recall micro y macro, uso completo/incompleto, costos mínimos y fallos. Las sumas TP/FP/FN/TN son observaciones repetidas, no condiciones únicas. Los casos no adjudicables no se convierten automáticamente en controles negativos ni se omiten del denominador de terminación.", "",
             "## Cohortes NovaFlow", "", "| Cohorte | Pilotos iniciados | Formales iniciados | Tokens por corrida |", "|---|---:|---:|---:|"]
    for c in cohorts:
        lines.append(f"| {c['id']} | {c['pilot_attempts']} | {c['formal_attempts']} | {c['tokens_per_run']} |")
    lines += ["", "## Resultados históricos conservados", "", "| Fuente | Parejas elegibles históricas | TRTO medio | IDE medio | Razón ETV media |", "|---|---:|---:|---:|---:|"]
    for label in ("docs/regresion-api-v1/evaluation.json", "docs/pilotos-api-v2/ajustado/evaluation.json", "docs/evaluacion-api-v2/evaluation.json"):
        d = read(ROOT / label); a = d.get("analysis", {})
        lines.append(f"| `{label}` | {d.get('pairs_eligible')} | {a.get('TRTO_percent',{}).get('mean')} | {a.get('IDE_percent',{}).get('mean')} | {a.get('ETV_ratio',{}).get('mean')} |")
    lines += ["", "El IDE histórico de 0 % se conserva. El estudio v2 inició 6/30 corridas (5 completas y 1 parcial), con 2 parejas elegibles de 15 previstas. Es una muestra incompleta y no debe presentarse como validación poblacional. La regresión v1 y el piloto ajustado v2 se mantienen separados.", "",
              "Los tres pares del piloto NovaFlow 175031 tienen análisis temporal original desfavorable (TRTO medio −3,8579 %, IDE 0 %, razón ETV 0,7739). En agente único hubo respaldo por presupuesto y revisión rechazada: sirven para diagnosticar operación y costo, **no son parejas íntegras de IA**. No se eliminan ni se recombinan para favorecer resultados.", "",
              "El intento NovaFlow 201343 quedó sin informe final. Su tabla histórica muestra 0 tokens porque no hubo cierre; SQLite acredita al menos 9.419 tokens. El inventario recupera ese mínimo sin modificar la fila histórica ni liberar reservas de costo desconocido.", "",
              "`inventario.json` conserva los detalles y controles de comparabilidad; `corridas.csv` permite análisis; `fuentes-sha256.csv` verifica integridad. Las corridas sin informe, con fallback o evidencia insuficiente siguen presentes."]
    (OUT / "LEEME.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    write_traceability()
    if (ROOT / "docs/cierre-final-2026-10-17/qa-panel.json").is_file():
        write_critical_verifications()
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return payload


def self_test():
    """Verifica los riesgos metodológicos con fixtures temporales, sin red."""
    import tempfile
    import unittest

    class ConsolidationTests(unittest.TestCase):
        def setUp(self):
            global ROOT, PILOT, BASES, OUT
            self.saved = ROOT, PILOT, BASES, OUT
            self.temporary = tempfile.TemporaryDirectory()
            ROOT = Path(self.temporary.name)
            PILOT = ROOT / "piloto_kali/prototipo"
            BASES = [PILOT / "corridas", ROOT / "docs"]
            OUT = ROOT / "generated"
            self.run = PILOT / "corridas/run_one"
            self.write(self.run / "request.json", {"audit_id": "test_single", "architecture": "single", "llm_mode": "scheduler"})
            self.write(self.run / "report.json", {"audit_id": "test_single", "architecture": "single", "status": "complete", "mode": "live", "llm": {"status": "accepted", "usage_complete": True, "known_tokens": 7}})

        def tearDown(self):
            global ROOT, PILOT, BASES, OUT
            ROOT, PILOT, BASES, OUT = self.saved
            self.temporary.cleanup()

        def write(self, path, value):
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(value), encoding="utf-8")

        def test_copies_are_one_attempt_and_sources_unchanged(self):
            copy = ROOT / "docs/copy/report.json"
            self.write(copy, read(self.run / "report.json"))
            original_hash = sha(self.run / "report.json")
            rows, _, _ = collect()
            self.assertEqual(len(rows), 1)
            self.assertEqual(len(rows[0]["copies"]), 2)
            self.assertFalse(rows[0]["copy_hash_conflict"])
            self.assertEqual(original_hash, sha(self.run / "report.json"))

        def test_conflicting_copy_is_visible(self):
            self.write(ROOT / "docs/copy/report.json", {**read(self.run / "report.json"), "status": "partial"})
            self.assertTrue(collect()[0][0]["copy_hash_conflict"])

        def test_metrics_require_matching_reserved_reference(self):
            truth = PILOT / ".lab/ground_truth.json"
            self.write(truth, {"reserved": True})
            self.write(self.run / "evaluation.json", {"TP": 3, "FP": 1, "FN": 2, "TN": 4, "evidence_valid": True, "ground_truth_sha256": sha(truth)})
            r = collect()[0][0]
            self.assertEqual(r["precision"], .75)
            self.assertEqual(r["recall"], .6)
            self.write(truth, {"reserved": "changed"})
            r = collect()[0][0]
            self.assertIsNone(r["TP"])
            self.assertEqual(r["scoring_status"], "NO_CALCULABLE")

        def test_interruption_recovers_minimum_without_double_counting_transport(self):
            (self.run / "report.json").unlink()
            connection = sqlite3.connect(self.run / "events.sqlite3")
            connection.execute("CREATE TABLE events(timestamp TEXT, monotonic_ns INTEGER, component TEXT, kind TEXT, task_id TEXT, payload_json TEXT)")
            for idx, (kind, payload) in enumerate([("decision", {"total_tokens": 3}), ("api_request_finished", {"total_tokens": 100}), ("decision", {"total_tokens": 4})]):
                connection.execute("INSERT INTO events VALUES(?,?,?,?,?,?)", ("2026-10-17T00:00:00Z", idx * 1000000000, "llm", kind, None, json.dumps(payload)))
            connection.commit()
            connection.close()
            r = collect()[0][0]
            self.assertEqual(r["tokens_known"], 7)
            self.assertFalse(r["usage_complete"])
            self.assertIsNone(r["elapsed_seconds"])
            self.assertEqual(r["observed_trace_span_seconds"], 2)
            self.assertIsNone(r["TP"])

        def test_acceptance_in_api_protocol_is_not_api_execution(self):
            self.write(PILOT / "corridas/study/protocol.json", {"id": "study", "model": {"model": "test-model"}})
            self.write(PILOT / "corridas/study/attempts.json", [])
            self.write(self.run / "manifest.json", {"study_context": {"study_id": "study"}})
            self.write(self.run / "request.json", {"audit_id": "test_single", "llm_mode": "disabled"})
            self.write(self.run / "report.json", {"audit_id": "test_single", "llm": {"status": "disabled", "usage_complete": True, "known_tokens": 0}})
            r = collect()[0][0]
            self.assertFalse(r["api_requested"])
            self.assertIsNone(r["model"])

        def test_code_version_mismatch_blocks_pair(self):
            other = PILOT / "corridas/run_two"
            request = read(self.run / "request.json")
            report = read(self.run / "report.json")
            self.write(other / "request.json", {**request, "audit_id": "test_multi", "architecture": "multiagent"})
            self.write(other / "report.json", {**report, "audit_id": "test_multi", "architecture": "multiagent"})
            self.write(self.run / "manifest.json", {"source_sha256": "a" * 64})
            self.write(other / "manifest.json", {"source_sha256": "b" * 64})
            self.write(ROOT / "docs/evaluation.json", {"pairs": [{"single": {"audit_id": "test_single"}, "multiagent": {"audit_id": "test_multi"}, "eligible": True}]})
            pair = collect()[2][0]
            self.assertFalse(pair["valid_for_exploratory_comparison"])
            self.assertIn("source_sha256_missing_or_different", pair["current_consolidation_reasons"])

        def test_statistics_separate_pilot_and_formal_in_same_cohort(self):
            original = collect()[0][0]
            rows, pairs = [], []
            for phase, value in (("pilot", -5), ("formal", 10)):
                for architecture in ("single", "multiagent"):
                    rows.append({**original, "audit_id": phase + architecture, "cohort": "same_study", "phase": phase, "architecture": architecture})
                pairs.append({"cohort": "same_study", "phase": phase, "single_id": phase + "single", "multiagent_id": phase + "multiagent",
                              "valid_for_exploratory_comparison": True, "current_consolidation_reasons": [],
                              "recalculated_kpis": {"TRTO_percent": value, "IDE_percent": 0, "ETV_ratio": 1}})
            summaries = study_statistics(rows, pairs)
            self.assertEqual(len(summaries), 2)
            self.assertEqual({row["phase"]: row["TRTO_percent"] for row in summaries}, {"pilot": -5, "formal": 10})

        def test_uncertainty_retains_zero_and_does_not_invent_single_pair_interval(self):
            self.assertIsNone(descriptive([0], paired_bootstrap=True)["mean_ci95_percentile_bootstrap"])
            many = descriptive([0] * 15, paired_bootstrap=True)
            self.assertEqual(many["n"], 15)
            self.assertEqual(many["mean_ci95_percentile_bootstrap"], [0, 0])
            self.assertTrue(many["all_observed_equal"])
            self.assertIn("no demuestra equivalencia", many["uncertainty_note"])

        def test_derived_annex_matrix_does_not_duplicate_canonical_requirements(self):
            import zipfile
            path = ROOT / "docs/TrabajoDeGrado_II_Anexos.docx"
            path.parent.mkdir(parents=True, exist_ok=True)
            xml = '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body>'
            for text in ("Canónico", "Derivado"):
                xml += '<w:tbl><w:tr>' + ''.join('<w:tc><w:p><w:r><w:t>' + cell + '</w:t></w:r></w:p></w:tc>' for cell in ("RF-01", "EP-01", text, "Criterio")) + '</w:tr></w:tbl>'
            xml += '</w:body></w:document>'
            with zipfile.ZipFile(path, 'w') as document:
                document.writestr('word/document.xml', xml)
            OUT.mkdir(parents=True)
            write_traceability()
            matrix = read(OUT / "trazabilidad.json")
            self.assertEqual(len(matrix["requirements"]), 1)
            self.assertEqual(matrix["requirements"][0]["academic_commitment"], "Canónico")

        def test_cache_write_tokens_are_costed_once_in_recovered_minimum(self):
            (self.run / "report.json").unlink()
            self.write(PILOT / "corridas/study/protocol.json", {"id": "study", "pricing": {"input_per_million": 2, "cached_per_million": .1, "cache_write_per_million": 2.5, "output_per_million": 10}})
            self.write(PILOT / "corridas/study/attempts.json", [])
            self.write(self.run / "manifest.json", {"study_context": {"study_id": "study"}})
            connection = sqlite3.connect(self.run / "events.sqlite3")
            connection.execute("CREATE TABLE events(timestamp TEXT, monotonic_ns INTEGER, component TEXT, kind TEXT, task_id TEXT, payload_json TEXT)")
            call = {"generation_sent": True, "input_tokens": 10, "provider_output_tokens": 1, "cached_tokens": 0, "cache_write_tokens": 4, "total_tokens": 11}
            connection.execute("INSERT INTO events VALUES(?,?,?,?,?,?)", ("2026-10-17T00:00:00Z", 0, "llm", "decision", None, json.dumps(call)))
            connection.commit()
            connection.close()
            self.assertEqual(collect()[0][0]["cost_known_estimate_usd"], .000032)

    result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(ConsolidationTests))
    if not result.wasSuccessful():
        raise SystemExit(1)
    return result.testsRun


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true", help="Comprueba deduplicación, conflictos, referencia reservada y recuperación de mínimos sin API")
    parser.add_argument("--critical-checks-only", action="store_true", help="Deriva doce verificaciones críticas del recibo QA; no lee ni analiza auditorías")
    parser.add_argument("--document-provenance-only", action="store_true", help="Coteja Word e insumos congelados en un recibo separado; nunca republica inventario ni CSV")
    arguments = parser.parse_args()
    if arguments.self_test:
        count = self_test()
        OUT.mkdir(parents=True, exist_ok=True)
        (OUT / "verificacion-consolidador-final.json").write_text(json.dumps({
            "verified_at_utc": datetime.now(timezone.utc).isoformat(),
            "script_sha256": sha(Path(__file__)), "unit_checks": count,
            "unit_checks_status": "APROBADA", "fixture_scope": "Temporary isolated files; no real audits, Docker or provider calls",
            "original_historical_receipt": ref(OUT / "verificacion-consolidador.json"),
            "note": "Recibo nuevo; conserva la verificación anterior y no suma estos casos a las corridas del estudio."}, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    elif arguments.critical_checks_only:
        write_critical_verifications()
    elif arguments.document_provenance_only:
        write_document_provenance()
    else:
        publish()
