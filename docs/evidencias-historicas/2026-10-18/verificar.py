"""Comprueba la evidencia recuperada; sólo usa Python estándar y lectura local."""
from __future__ import annotations

from collections import Counter
import hashlib
import json
from pathlib import Path
import random
import sqlite3
import statistics
import sys
import tempfile
import xml.etree.ElementTree as ET
import zipfile

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
sys.path.insert(0, str(REPO / "scripts"))
from tesis.exportacion_manual import verify_export


def require(condition, message):
    if not condition:
        raise ValueError(message)


def read_json(path):
    return json.loads(path.read_text(encoding="utf-8"))


def digest(data):
    return hashlib.sha256(data).hexdigest()


def main():
    publication = read_json(HERE / "integridad-publicacion.json")
    for relative, expected in publication["files"].items():
        path = REPO / relative
        require(path.resolve().is_relative_to(REPO), "Ruta fuera del repositorio")
        require(digest(path.read_bytes()) == expected, "Archivo publicado alterado: " + relative)

    history = read_json(HERE / "hashes-corridas-50.json")
    original_count = 0
    event_count = 0
    with zipfile.ZipFile(HERE / "auditorias-originales.zip") as archive:
        expected_names = set()
        with tempfile.TemporaryDirectory(prefix="centinela-evidencia-") as temporary:
            for run in history:
                prefix = "piloto_kali/prototipo/corridas/" + run["run_id"] + "/"
                for relative, expected in run["sha256"].items():
                    name = prefix + relative
                    expected_names.add(name)
                    data = archive.read(name)
                    require(digest(data) == expected, "Huella histórica diferente: " + name)
                    original_count += 1
                    if relative == "events.sqlite3":
                        database = Path(temporary) / (str(run["sequence"]) + ".sqlite3")
                        database.write_bytes(data)
                        connection = sqlite3.connect(
                            database.as_uri() + "?mode=ro&immutable=1", uri=True
                        )
                        try:
                            connection.execute("PRAGMA trusted_schema=OFF")
                            event_count += connection.execute("SELECT count(*) FROM events").fetchone()[0]
                        finally:
                            connection.close()
            require(len(archive.namelist()) == len(expected_names), "Entradas duplicadas o adicionales")
            require(set(archive.namelist()) == expected_names, "Inventario histórico incompleto")
    require(original_count == 3649 and event_count == 17692, "Totales históricos diferentes")

    evaluation = REPO / "docs/evaluacion-langgraph"
    verification = verify_export((evaluation / "evaluacion-langgraph.zip").read_bytes())
    require(verification["valid"], "Exportación experimental inválida")
    require(verification["counts"]["eligible_pairs"] == 23, "Parejas elegibles diferentes")
    runs = read_json(evaluation / "runs.json")
    require(Counter(run["status"] for run in runs) == {"complete": 48, "partial": 2}, "Estados diferentes")
    require(sum(run["total_tokens"] for run in runs) == 891821, "Consumo diferente")

    acceptance = read_json(evaluation / "aceptacion-sin-ia.json")
    acceptance_tasks = 0
    with zipfile.ZipFile(HERE / "aceptacion-original.zip") as archive:
        for scenario in acceptance["scenarios"]:
            prefix = "piloto_kali/prototipo/corridas/" + scenario["output"] + "/" + scenario["directory"] + "/"
            for name, expected in scenario["artifacts"].items():
                require(digest(archive.read(prefix + name)) == expected, "Aceptación alterada")
            result = json.loads(archive.read(prefix + "evaluation.json"))
            require(result["acceptance_passed"] and result["FP"] == result["FN"] == 0, "Aceptación no válida")
            require(result["tasks_checked"] == result["tasks_valid"], "Tareas de aceptación pendientes")
            acceptance_tasks += result["tasks_valid"]
    require(acceptance_tasks == 154, "Número de tareas diferente")

    test_path = "piloto_kali/prototipo/.verificacion/cierre-kali-20261019_182838/regresion-local-completa.xml"
    tests_receipt = read_json(REPO / "docs/verificacion-postevaluacion/pruebas-automatizadas-cierre-kali-20261019_182838.json")
    with zipfile.ZipFile(HERE / "verificaciones-originales.zip") as archive:
        data = archive.read(test_path)
    require(digest(data) == tests_receipt["sources"][test_path], "JUnit diferente del recibo original")
    xml = ET.fromstring(data)
    cases = list(xml.iter("testcase"))
    skipped = sum(case.find("skipped") is not None for case in cases)
    failed = sum(case.find("failure") is not None or case.find("error") is not None for case in cases)
    require(len(cases) - skipped == 708 and skipped == 2 and failed == 0, "Resultado de pruebas diferente")
    require(sum(int(suite.get("tests", "0")) for suite in xml.iter("testsuite")) - len(cases) == 59, "Subcasos diferentes")

    pairs = [pair["metrics"] for scenario in read_json(evaluation / "pairs.json") for pair in scenario["pairs"] if pair["eligible"]]
    statistics_out = {}
    for metric in ("TRTO_percent", "IDE_percent", "ETV_ratio"):
        values = [pair[metric] for pair in pairs]
        randomizer = random.Random(20261017)
        means = sorted(statistics.mean(randomizer.choices(values, k=len(values))) for _ in range(4000))
        statistics_out[metric] = {
            "mean": statistics.mean(values), "median": statistics.median(values),
            "bootstrap_95_percent": [means[100], means[3899]],
        }
    print(json.dumps({
        "valid": True, "published_files_checked": len(publication["files"]),
        "original_files_checked": original_count, "events": event_count,
        "audit_statuses": dict(Counter(run["status"] for run in runs)),
        "eligible_pairs": 23, "acceptance_tasks": acceptance_tasks,
        "original_tests": {"passed": 708, "skipped": skipped, "subtests_passed": 59},
        "statistics": statistics_out,
        "scope": "Verificación de archivos conservados; no ejecuta herramientas de auditoría ni llama a la API.",
    }, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, zipfile.BadZipFile, sqlite3.Error) as error:
        print("ERROR: " + str(error), file=sys.stderr)
        raise SystemExit(1)
