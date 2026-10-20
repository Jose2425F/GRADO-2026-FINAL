"""Contrato de lectura del observador con el panel y eventos reales aislados."""

import hashlib
import json
import os
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from archify_observer import DEFAULT_DIAGRAM, make_server
from auditoria.dashboard import make_server as make_panel, process_identity
from auditoria.store import RunStore, write_json


class ObserverTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name)
        self.store = RunStore(root / "test-run", "observer-test")
        write_json(self.store.root / "runtime.json", {"status": "running", "pid": os.getpid(), "identity": process_identity(os.getpid())})
        write_json(self.store.root / "manifest.json", {"mode": "dry_run"})
        write_json(self.store.root / "plan.json", [
            {"task_id": name, "agent_type": "ipv4_services", "target": {"asset_id": "test"}}
            for name in ("first", "second")
        ])
        self.panel = make_panel(root, 0)
        self.observer = make_server(DEFAULT_DIAGRAM, 0, self.panel.server_port)
        self.threads = []
        for server in (self.panel, self.observer):
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            self.threads.append(thread)
        self.url = f"http://127.0.0.1:{self.observer.server_port}"

    def tearDown(self):
        for server in (self.observer, self.panel):
            server.shutdown()
            server.server_close()
        for thread in self.threads:
            thread.join(timeout=2)
        self.store.close()
        self.temp.cleanup()

    def snapshot(self):
        # El panel cachea un segundo; reinicia el panel para leer inmediatamente.
        self.panel.shutdown()
        self.panel.server_close()
        self.threads[0].join(timeout=2)
        port = self.panel.server_port
        self.panel = make_panel(Path(self.temp.name), port)
        self.threads[0] = threading.Thread(target=self.panel.serve_forever, daemon=True)
        self.threads[0].start()
        return json.load(urlopen(self.url + "/api/state"))["runs"][0]

    def test_task_lifecycle_parallelism_and_read_only(self):
        self.store.event("controller", "task_admitted", task_id="first", payload={"password": "SECRET-MARKER"})
        self.store.event("controller", "task_admitted", task_id="second")
        db = self.store.root / "events.sqlite3"
        before = hashlib.sha256(db.read_bytes()).hexdigest()
        run = self.snapshot()
        self.assertEqual(sum(t["status"] == "running" for t in run["tasks"]), 2)
        self.assertEqual(run["mode"], "dry_run")
        self.assertNotIn("SECRET-MARKER", json.dumps(run))
        self.assertEqual(before, hashlib.sha256(db.read_bytes()).hexdigest())
        self.store.event("orchestration", "task_terminal", task_id="first", payload={"status": "completed"})
        self.assertEqual(sum(t["status"] == "running" for t in self.snapshot()["tasks"]), 1)
        self.store.event("orchestration", "task_terminal", task_id="second", payload={"status": "failed"})
        self.assertEqual(sum(t["status"] == "running" for t in self.snapshot()["tasks"]), 0)
        write_json(self.store.root / "runtime.json", {"status": "running", "pid": os.getpid(), "identity": "expired"})
        self.assertEqual(self.snapshot()["status"], "interrupted")

    def test_allowlisted_files_and_host(self):
        original = DEFAULT_DIAGRAM.read_bytes()
        self.assertEqual(urlopen(self.url + "/diagram").read(), original)
        self.assertIn(b"Arquitectura en vivo", urlopen(self.url + "/").read())
        for path in ("/../scripts/archify_observer.py", "/events.sqlite3", "/api/execute", "/.env"):
            with self.assertRaises(HTTPError) as caught:
                urlopen(self.url + path)
            self.assertEqual(caught.exception.code, 404)
        with self.assertRaises(HTTPError) as caught:
            urlopen(Request(self.url + "/api/state", headers={"Host": "external.invalid"}))
        self.assertEqual(caught.exception.code, 403)
        self.assertEqual(original, DEFAULT_DIAGRAM.read_bytes())

    def test_disconnected_panel_returns_503(self):
        self.panel.shutdown()
        self.panel.server_close()
        with self.assertRaises(HTTPError) as caught:
            urlopen(self.url + "/api/state")
        self.assertEqual(caught.exception.code, 503)
        self.assertEqual(json.load(caught.exception), {"error": "Panel local no disponible"})


if __name__ == "__main__":
    unittest.main()
