"""Bitácora incremental y archivos de evidencia con huella."""

from __future__ import annotations

import hashlib
import json
import sqlite3
import time
import threading
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from .contracts import Event


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def write_json(path: Path, value: object) -> None:
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8"
    )


class RunStore:
    def __init__(self, root: Path, audit_id: str):
        self.root = root
        self.audit_id = audit_id
        self.root.mkdir(parents=True, exist_ok=False)
        (self.root / "evidence").mkdir()
        self._lock = threading.RLock()
        self.connection = sqlite3.connect(self.root / "events.sqlite3", check_same_thread=False)
        self.connection.execute(
            """CREATE TABLE events (
                event_id TEXT PRIMARY KEY,
                audit_id TEXT NOT NULL,
                task_id TEXT,
                component TEXT NOT NULL,
                kind TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                monotonic_ns INTEGER NOT NULL,
                payload_json TEXT NOT NULL
            )"""
        )
        self.connection.commit()

    def close(self) -> None:
        self.connection.close()

    def event(
        self, component: str, kind: str, *, task_id: str | None = None, payload: dict | None = None
    ) -> Event:
        event = Event(
            event_id=str(uuid4()),
            audit_id=self.audit_id,
            task_id=task_id,
            component=component,
            kind=kind,
            timestamp=datetime.now(timezone.utc),
            monotonic_ns=time.monotonic_ns(),
            payload=payload or {},
        )
        with self._lock, self.connection:
            self.connection.execute(
                "INSERT INTO events VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    event.event_id,
                    event.audit_id,
                    event.task_id,
                    event.component,
                    event.kind,
                    event.timestamp.isoformat(),
                    event.monotonic_ns,
                    json.dumps(event.payload, ensure_ascii=False, sort_keys=True),
                ),
            )
        return event

    def evidence(self, task_id: str, extension: str, data: bytes) -> tuple[str, str]:
        if not task_id.replace("-", "").replace("_", "").isalnum():
            raise ValueError("task_id no apto para ruta de evidencia")
        if extension not in {"xml", "txt", "json", "pcap"}:
            raise ValueError("extension de evidencia no admitida")
        relative = Path("evidence") / f"{task_id}.{extension}"
        with (self.root / relative).open("xb") as stream:
            stream.write(data)
        return relative.as_posix(), sha256_bytes(data)
