"""Verifica RNF-07 sobre evidencia histórica sin modificarla ni revelar secretos.

No importa la aplicación, no ejecuta agentes y no usa red. Los valores de
referencia y sus representaciones permanecen en memoria. El recibo contiene
únicamente cobertura, contajes, rutas, clases de coincidencia y limitaciones.
"""
from __future__ import annotations

import argparse
import ast
import base64
from collections import Counter
import csv
from dataclasses import dataclass, field
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import sqlite3
from urllib.parse import quote, quote_plus


SENSITIVE_KEYS = {
    "password", "passwd", "pwd", "api_key", "apikey", "secret",
    "access_token", "refresh_token", "authorization", "private_key",
}
REDACTIONS = {"", "redacted", "[redacted]", "<redacted>", "hidden", "[hidden]", "***", "****", "*****", "********"}
REQUIRED_ARTIFACTS = ("request.json", "report.json", "plan.json", "manifest.json", "events.sqlite3")
TOKEN_PATTERNS = {
    "private_key_marker": re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----"),
    "api_key_shape": re.compile(rb"(?<![A-Za-z0-9_-])sk-[A-Za-z0-9_-]{20,}"),
    "authorization_header_value": re.compile(rb"(?i)authorization[\"' \t]*:[ \t]*[\"']?(?:bearer|basic)[ \t]+[A-Za-z0-9+/=_-]{16,}"),
}


def relative(path: Path, root: Path) -> str:
    return path.relative_to(root).as_posix()


def contained(root: Path, candidate: Path) -> bool:
    return candidate.resolve().is_relative_to(root.resolve()) and not candidate.is_symlink()


def parse_env(path: Path) -> dict[str, str]:
    """Lee asignaciones de fixture; nunca interpreta shell ni expande comandos."""
    values = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[7:]
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        key, value = key.strip(), value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        values[key] = value
    return values


def interpolate(value: str, environment: dict[str, str]) -> str | None:
    """Resuelve solamente ${VAR}, ${VAR:-default} y ${VAR-default}."""
    unresolved = False

    def substitute(match: re.Match) -> str:
        nonlocal unresolved
        expr = match.group(1)
        parts = re.split(r"(:?-)", expr, maxsplit=1)
        name = parts[0]
        fallback = parts[2] if len(parts) == 3 else None
        if name in environment and (environment[name] or (len(parts) == 3 and parts[1] == "-")):
            return environment[name]
        if fallback is not None:
            return fallback
        unresolved = True
        return ""

    result = re.sub(r"\$\{([^}]+)\}", substitute, value)
    return None if unresolved or "$" in result else result


@dataclass(repr=False)
class References:
    passwords: set[str] = field(default_factory=set, repr=False)
    usernames: set[str] = field(default_factory=set, repr=False)
    fixture_sources: dict[str, list[Path]] = field(default_factory=dict, repr=False)
    sources: set[Path] = field(default_factory=set)
    unresolved_values: int = 0


def collect_references(repo: Path) -> References:
    """Incluye fixtures actuales y cápsulas originales; no muestra sus valores."""
    proto = repo / "piloto_kali/prototipo"
    paths = [proto / ".lab-empresa/lab.env"]
    paths += list((proto / ".lab-suite").glob("*/lab.env"))
    paths += list((proto / ".lab-suite/capsules").glob("*/*/lab.env"))
    references = References()
    for path in sorted(set(paths)):
        if not path.is_file() or not contained(repo, path):
            continue
        env = parse_env(path)
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        references.fixture_sources.setdefault(digest, []).append(path)
        references.sources.add(path)
        # Estos son los nombres de las credenciales del banco; la semilla del
        # fixture es otro dato y no se confunde con una contraseña.
        for key, value in env.items():
            if key.startswith(("LAB_NOVA_", "LAB_ACTUAL_", "LAB_SUITE_")) and value:
                references.passwords.add(value)
        for name in ("compose.json", "compose-pinned.json"):
            compose_path = path.parent / name
            if not compose_path.is_file() or not contained(repo, compose_path):
                continue
            references.sources.add(compose_path)
            compose = json.loads(compose_path.read_text(encoding="utf-8"))
            for service in compose.get("services", {}).values():
                environment = service.get("environment", {})
                if isinstance(environment, list):
                    environment = dict(item.split("=", 1) for item in environment if isinstance(item, str) and "=" in item)
                for key, value in environment.items():
                    if not isinstance(value, str):
                        continue
                    password_key = key.endswith(("_PASSWORD", "_PASS", "_SECRET", "_TOKEN", "_API_KEY"))
                    username_key = key.endswith(("_USER", "_USERNAME"))
                    if not (password_key or username_key):
                        continue
                    resolved = interpolate(value, env)
                    if resolved is None:
                        references.unresolved_values += 1
                    elif resolved:
                        (references.passwords if password_key else references.usernames).add(resolved)
        policy_path = path.parent / "policy.json"
        if policy_path.is_file() and contained(repo, policy_path):
            references.sources.add(policy_path)
            policy = json.loads(policy_path.read_text(encoding="utf-8"))
            for entry in policy.get("credentials", {}).values():
                if isinstance(entry, dict) and isinstance(entry.get("username"), str):
                    references.usernames.add(entry["username"])
    # Extrae el usuario por defecto como dato estático, sin importar/ejecutar
    # el adaptador. Se usa sólo para detectar Basic base64(usuario:contraseña).
    adapter = proto / "src/auditoria/empresa_agent.py"
    if adapter.is_file() and contained(repo, adapter):
        references.sources.add(adapter)
        tree = ast.parse(adapter.read_text(encoding="utf-8"))
        for function in ast.walk(tree):
            if isinstance(function, ast.FunctionDef) and function.name == "_credential_profile":
                for node in ast.walk(function):
                    if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                            and node.func.attr == "get" and len(node.args) >= 2
                            and isinstance(node.args[0], ast.Constant) and node.args[0].value == "username"
                            and isinstance(node.args[1], ast.Constant) and isinstance(node.args[1].value, str)):
                        references.usernames.add(node.args[1].value)
    return references


class Matcher:
    def __init__(self, passwords: set[str], usernames: set[str] | None = None):
        self.patterns: dict[str, set[bytes]] = {}

        def add(kind: str, value: bytes) -> None:
            if value:
                self.patterns.setdefault(kind, set()).add(value)

        for password in passwords:
            plain = password.encode("utf-8")
            add("known_password_plain", plain)
            add("known_password_utf16", password.encode("utf-16le"))
            add("known_password_utf16", password.encode("utf-16be"))
            escaped = json.dumps(password, ensure_ascii=True)[1:-1].encode("utf-8")
            if escaped != plain:
                add("known_password_json_escaped", escaped)
            for encoded in {quote(password, safe=""), quote_plus(password, safe="")}:
                if encoded.encode("utf-8") != plain:
                    add("known_password_url_encoded", encoded.encode("utf-8"))
            add("known_password_base64", base64.b64encode(plain))
            for username in usernames or set():
                add("known_basic_credential_base64", base64.b64encode((username + ":" + password).encode("utf-8")))

    def scan_bytes(self, data: bytes) -> Counter:
        counts = Counter()
        for kind, values in self.patterns.items():
            for value in values:
                counts[kind] += data.count(value)
        for kind, pattern in TOKEN_PATTERNS.items():
            counts[kind] += sum(1 for _ in pattern.finditer(data))
        return +counts


def sensitive_fields(value) -> int:
    """Contaje de campos sensibles poblados, sin conservar claves ni valores."""
    if isinstance(value, list):
        return sum(sensitive_fields(item) for item in value)
    if not isinstance(value, dict):
        return 0
    count = 0
    for key, child in value.items():
        if (str(key).lower() in SENSITIVE_KEYS and isinstance(child, str)
                and child.strip().lower() not in REDACTIONS):
            count += 1
        count += sensitive_fields(child)
    return count


def json_objects(text: str):
    try:
        yield json.loads(text)
        return
    except (ValueError, TypeError):
        pass
    for line in text.splitlines():
        if line.lstrip().startswith(("{", "[")):
            try:
                yield json.loads(line)
            except ValueError:
                pass


def text_values(value):
    if isinstance(value, str):
        yield value
    elif isinstance(value, list):
        for item in value:
            yield from text_values(item)
    elif isinstance(value, dict):
        for item in value.values():
            yield from text_values(item)


def artifact_type(path: Path) -> str:
    if path.name.startswith("llm_") and path.suffix == ".txt":
        return "provider_prompt_context"
    if path.suffix in {".sqlite3", ".db", ".sqlite"}:
        return "events_database"
    if path.name in REQUIRED_ARTIFACTS:
        return path.stem
    if "evidence" in path.parts:
        return "technical_evidence"
    return "retained_run_state_metadata"


def scan_sqlite(path: Path, matcher: Matcher) -> tuple[Counter, Counter, list[dict], list[dict]]:
    """Lee tablas y celdas con SQLite inmutable; nunca crea WAL/journal."""
    counts, coverage, issues, decisions = Counter(), Counter(), [], []
    connection = sqlite3.connect(path.resolve().as_uri() + "?mode=ro&immutable=1", uri=True)
    try:
        connection.execute("PRAGMA query_only=ON")
        tables = [row[0] for row in connection.execute("SELECT name FROM sqlite_schema WHERE type='table' AND name NOT LIKE 'sqlite_%'")]
        coverage["tables"] = len(tables)
        for table in tables:
            quoted = '"' + table.replace('"', '""') + '"'
            columns = [row[1] for row in connection.execute("PRAGMA table_info(" + quoted + ")")]
            for row in connection.execute("SELECT * FROM " + quoted):
                coverage["rows"] += 1
                mapping = dict(zip(columns, row))
                for value in row:
                    if isinstance(value, str):
                        coverage["text_cells"] += 1
                        counts.update(matcher.scan_bytes(value.encode("utf-8")))
                        for parsed in json_objects(value):
                            counts["sensitive_field_nonempty"] += sensitive_fields(parsed)
                            for decoded in text_values(parsed):
                                counts.update(matcher.scan_bytes(decoded.encode("utf-8")))
                    elif isinstance(value, bytes):
                        coverage["blob_cells"] += 1
                        counts.update(matcher.scan_bytes(value))
                if table == "events" and mapping.get("kind") == "decision":
                    try:
                        payload = json.loads(mapping.get("payload_json", ""))
                        if isinstance(payload, dict):
                            decisions.append(payload)
                    except (ValueError, TypeError):
                        issues.append({"type": "invalid_decision_payload"})
    finally:
        connection.close()
    return +counts, coverage, issues, decisions


def snapshot(paths: list[Path]) -> dict[Path, tuple[int, int, str]]:
    # Estas huellas del archivo entero sólo se comparan en memoria; el recibo
    # no contiene contraseñas, huellas individuales ni huellas de referencias.
    return {path: (path.stat().st_size, path.stat().st_mtime_ns, hashlib.sha256(path.read_bytes()).hexdigest()) for path in paths}


def inspect_prompt(run_path: Path, call: dict, repo: Path) -> tuple[dict, list[dict]]:
    issues = []
    result = {"reference_present": 0, "hash_verified": 0, "context_present": 0}
    ref = call.get("prompt_ref")
    if not isinstance(ref, str) or not ref:
        return result, [{"path": relative(run_path, repo), "type": "missing_prompt_reference"}]
    path = run_path / ref
    if not contained(run_path, path) or not path.is_file():
        return result, [{"path": relative(run_path, repo), "type": "missing_or_unsafe_prompt"}]
    result["reference_present"] = 1
    data = path.read_bytes()
    if isinstance(call.get("prompt_sha256"), str) and hashlib.sha256(data).hexdigest() == call["prompt_sha256"]:
        result["hash_verified"] = 1
    else:
        issues.append({"path": relative(path, repo), "type": "prompt_integrity_unverified"})
    objects = list(json_objects(data.decode("utf-8", errors="replace")))
    if any(isinstance(obj, dict) and (isinstance(obj.get("context"), dict) or "task_facts" in obj) for obj in objects):
        result["context_present"] = 1
    else:
        issues.append({"path": relative(path, repo), "type": "prompt_context_not_retained"})
    return result, issues


def verify(repo: Path, expected_runs: int = 50) -> dict:
    repo = repo.resolve()
    inventory_path = repo / "docs/evaluacion-langgraph/runs.json"
    csv_path = repo / "docs/evaluacion-langgraph/evaluacion-langgraph-corridas.csv"
    runs = json.loads(inventory_path.read_text(encoding="utf-8"))
    issues: list[dict] = []
    if not isinstance(runs, list) or any(not isinstance(run, dict) or not isinstance(run.get("run_id"), str) for run in runs):
        raise ValueError("invalid_inventory")
    run_ids = [run["run_id"] for run in runs]
    if len(runs) != expected_runs or len(set(run_ids)) != len(runs):
        issues.append({"type": "inventory_count_or_uniqueness_mismatch"})
    with csv_path.open(encoding="utf-8", newline="") as handle:
        csv_ids = [row["run_id"] for row in csv.DictReader(handle)]
    csv_matches = Counter(csv_ids) == Counter(run_ids)
    if not csv_matches:
        issues.append({"type": "json_csv_inventory_mismatch"})
    references = collect_references(repo)
    matcher = Matcher(references.passwords, references.usernames)
    if not references.passwords:
        issues.append({"type": "no_reference_credentials"})
    if references.unresolved_values:
        issues.append({"type": "unresolved_reference_values", "count": references.unresolved_values})
    base = repo / "piloto_kali/prototipo/corridas"
    run_paths = []
    for run in runs:
        path = base / run["run_id"]
        if not contained(base, path) or not path.is_dir():
            issues.append({"path": run["run_id"] if not Path(run["run_id"]).is_absolute() else "[unsafe_inventory_path]", "type": "missing_or_unsafe_run_directory"})
        else:
            run_paths.append((run, path))
    paths = sorted({file for _, path in run_paths for file in path.rglob("*") if file.is_file() and contained(path, file)})
    unsafe_count = sum(1 for _, path in run_paths for file in path.rglob("*") if file.is_symlink())
    if unsafe_count:
        issues.append({"type": "symlink_artifacts_excluded", "count": unsafe_count})
    protected_paths = sorted(set(paths) | references.sources | {inventory_path, csv_path})
    before = snapshot(protected_paths)
    file_types, extensions, db_coverage, prompt_coverage = Counter(), Counter(), Counter(), Counter()
    matches = []
    db_decisions: dict[Path, list[dict]] = {}
    decoded_documents = 0
    for path in paths:
        kind = artifact_type(path)
        file_types[kind] += 1
        extensions[path.suffix or "[none]"] += 1
        data = path.read_bytes()
        counts = matcher.scan_bytes(data)
        if counts:
            matches.append({"path": relative(path, repo), "artifact_type": kind, "surface": "raw_bytes", "types": dict(counts), "count": sum(counts.values())})
        if kind == "events_database":
            try:
                counts, coverage, db_issues, decisions = scan_sqlite(path, matcher)
                db_coverage.update(coverage)
                db_coverage["databases_read_only_immutable"] += 1
                db_decisions[path.parent] = decisions
                issues.extend({"path": relative(path, repo), **issue} for issue in db_issues)
                if counts:
                    matches.append({"path": relative(path, repo), "artifact_type": kind, "surface": "sqlite_decoded_cells", "types": dict(counts), "count": sum(counts.values())})
            except (sqlite3.Error, ValueError, TypeError):
                issues.append({"path": relative(path, repo), "type": "database_read_failed"})
            if any(Path(str(path) + suffix).exists() for suffix in ("-wal", "-journal")):
                issues.append({"path": relative(path, repo), "type": "sqlite_sidecar_not_in_immutable_logical_view"})
        elif path.suffix in {".json", ".txt"}:
            decoded_counts = Counter()
            for value in json_objects(data.decode("utf-8", errors="replace")):
                decoded_documents += 1
                decoded_counts["sensitive_field_nonempty"] += sensitive_fields(value)
                for text in text_values(value):
                    decoded_counts.update(matcher.scan_bytes(text.encode("utf-8")))
            if +decoded_counts:
                matches.append({"path": relative(path, repo), "artifact_type": kind, "surface": "decoded_json_values", "types": dict(+decoded_counts), "count": sum(decoded_counts.values())})
    per_run = []
    fixture_covered = 0
    for run, path in run_paths:
        missing = [name for name in REQUIRED_ARTIFACTS if not (path / name).is_file()]
        if missing:
            issues.append({"path": relative(path, repo), "type": "required_artifact_missing", "count": len(missing)})
        source_covered = run.get("fixture_sha256") in references.fixture_sources
        fixture_covered += int(source_covered)
        if not source_covered:
            issues.append({"path": relative(path, repo), "type": "reference_fixture_not_matched"})
        report_path = path / "report.json"
        calls = []
        if report_path.is_file():
            try:
                report = json.loads(report_path.read_text(encoding="utf-8"))
                calls = report.get("llm", {}).get("calls", [])
                if not isinstance(calls, list) or any(not isinstance(call, dict) for call in calls):
                    calls = []
                    issues.append({"path": relative(report_path, repo), "type": "invalid_llm_calls"})
            except (ValueError, TypeError):
                issues.append({"path": relative(report_path, repo), "type": "report_parse_failed"})
        local = Counter()
        for call in calls:
            outcome, prompt_issues = inspect_prompt(path, call, repo)
            local.update(outcome)
            issues.extend(prompt_issues)
            local["report_calls"] += 1
            local["generations_reported"] += int(call.get("generation_sent") is True)
            local["review_calls" if call.get("phase") == "specialist_review" else "planner_calls"] += 1
        decisions = db_decisions.get(path, [])
        decision_refs = Counter((call.get("prompt_ref"), call.get("prompt_sha256")) for call in decisions)
        report_refs = Counter((call.get("prompt_ref"), call.get("prompt_sha256")) for call in calls)
        linked = decision_refs == report_refs and bool(calls)
        if not linked:
            issues.append({"path": relative(path, repo), "type": "report_event_prompt_link_mismatch"})
        if local["generations_reported"] != run.get("api_generations"):
            issues.append({"path": relative(path, repo), "type": "inventory_generation_count_mismatch"})
        local["event_decisions"] = len(decisions)
        prompt_coverage.update(local)
        per_run.append({"path": relative(path, repo), "required_artifacts_present": len(REQUIRED_ARTIFACTS) - len(missing),
                        "reference_fixture_matched": source_covered, "report_event_references_match": linked,
                        "prompt_coverage": dict(local)})
    after = snapshot(protected_paths)
    changed = sum(before[path] != after[path] for path in protected_paths)
    if changed:
        issues.append({"type": "original_or_reference_file_changed_during_verification", "count": changed})
    match_files = len({match["path"] for match in matches})
    status = "coincidencias_requieren_revision" if matches else "cobertura_incompleta" if issues else "sin_coincidencias_en_corpus_conservado"
    return {
        "type": "post_evaluation_original_artifact_secret_verification",
        "schema_version": 1,
        "requirement": "RNF-07",
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "execution": {"offline": True, "network_or_api_calls": 0, "agent_or_graph_executions": 0,
                      "original_artifacts_modified": changed, "original_and_reference_files_checked_unchanged": len(protected_paths) - changed,
                      "sqlite_mode": "mode=ro&immutable=1; query_only=ON", "secrets_and_individual_secret_hashes_emitted": False},
        "inventory": {"json_path": relative(inventory_path, repo), "csv_path": relative(csv_path, repo),
                      "runs_expected": expected_runs, "runs_listed": len(runs), "runs_found": len(run_paths), "json_csv_run_ids_match": csv_matches},
        "references": {"source_files": len(references.sources), "source_paths": sorted(relative(path, repo) for path in references.sources),
                       "distinct_reference_passwords_in_memory": len(references.passwords), "distinct_reference_usernames_in_memory": len(references.usernames),
                       "run_fixture_hashes_matched_in_memory": fixture_covered, "unresolved_reference_values": references.unresolved_values},
        "coverage": {"original_files_scanned": len(paths), "bytes_scanned": sum(path.stat().st_size for path in paths),
                     "artifact_types": dict(file_types), "file_extensions": dict(extensions), "decoded_json_documents": decoded_documents,
                     "sqlite": dict(db_coverage), "provider_prompts": dict(prompt_coverage), "per_run": per_run},
        "detection": {"known_representations": ["UTF-8 plaintext", "UTF-16 LE/BE", "JSON escaping", "URL encoding", "base64 password", "base64 username:password"],
                      "additional_checks": ["populated sensitive JSON fields", "private key markers", "API-key shape", "authorization header values"],
                      "count_semantics": "Occurrences by representation and scan surface; decoded/raw surfaces may count the same occurrence. No individual credential identifiers or excerpts are retained.",
                      "files_with_matches": match_files, "match_records": len(matches), "occurrences_by_surface": sum(match["count"] for match in matches), "matches": matches},
        "limitations": [
            "The check covers only original artifacts preserved for the listed 50 runs; it does not recreate past execution or invoke the provider.",
            "Saved llm_*.txt evidence preserves prompt text and its JSON context, linked to report calls and event decisions by references and prompt integrity hashes checked only in memory.",
            "Complete HTTP request bodies, headers and provider-side captures are not preserved as independent evidence; absence in every transmitted byte cannot be established.",
            "No complete historical process-memory or LangGraph checkpoint snapshots were found as independent artifacts; only serialized task/report/plan/event state is available.",
            "Matching is bounded to local known fixture credentials and listed encodings, populated sensitive fields and token shapes; unknown secrets, arbitrary transformations or encrypted/compressed content are not exhaustively detectable.",
            "Reference and original artifact values, credential excerpts and individual password fingerprints are never written to the receipt or console.",
        ],
        "issues": issues,
        "result": {"status": status, "corpus_check_passed": not matches and not issues,
                   "rnf07_exhaustively_closed": False,
                   "basis": "Direct inspection of preserved original evidence; unit tests only validate the verifier. The result is limited to the retained corpus and does not prove unrecorded runtime state or every byte sent to the provider."},
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    repo = args.repo.resolve()
    output = args.output.resolve()
    allowed = repo / "docs/verificacion-postevaluacion"
    if not contained(allowed, output) or output.exists():
        parser.error("output must be a new JSON receipt inside docs/verificacion-postevaluacion")
    try:
        receipt = verify(repo)
    except Exception as exc:
        # No traceback/exception text: external data may contain credentials.
        print("Verification failed safely (" + type(exc).__name__ + "); no credential values emitted.")
        return 2
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("x", encoding="utf-8") as handle:
        json.dump(receipt, handle, indent=2, ensure_ascii=False)
        handle.write("\n")
    print("Receipt: " + str(output))
    print("Runs: " + str(receipt["inventory"]["runs_found"]) + "; files: " + str(receipt["coverage"]["original_files_scanned"]) + "; files with matches: " + str(receipt["detection"]["files_with_matches"]))
    return 0 if receipt["result"]["corpus_check_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
