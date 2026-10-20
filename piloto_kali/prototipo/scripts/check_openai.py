#!/usr/bin/env python3
"""Comprueba GPT-6.1 Sol con una decisión mínima; registra tokens y costo estimado."""

import argparse
import time
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from auditoria.openai_provider import OpenAIScheduler, load_openai_config
from auditoria.store import RunStore, write_json


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, default=Path(".lab"))
    args = parser.parse_args()
    try:
        load_openai_config(args.config)
    except (OSError, ValueError):
        raise SystemExit("Revisa la configuración privada con scripts/configure_openai.py.")
    name = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S") + "_" + uuid4().hex[:6]
    store = RunStore(args.config / "openai_checks" / name, "openai-access-check")
    scheduler = OpenAIScheduler(
        store, architecture="single", budget=4096, deadline=time.monotonic() + 90
    )
    try:
        scheduler.decide(
            ["t000", "t001"], {"ready": [{"id": "t000"}, {"id": "t001"}]}, "single_agent"
        )
        summary = scheduler.summary()
        write_json(args.config / "openai_check.json", summary)
        print("Modelo:", summary["model"])
        print("Estado:", summary["status"])
        print("Tokens conocidos:", summary["known_tokens"])
        print("Costo estimado USD:", summary["cost_estimate_usd"])
        if summary["status"] != "accepted":
            print("Diagnóstico:", summary["calls"][-1].get("reason"))
            raise SystemExit(2)
    finally:
        store.close()


if __name__ == "__main__":
    main()
