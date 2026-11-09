"""Entorno explícito para pruebas de controladores con herramientas simuladas."""
from pathlib import Path
from contextlib import contextmanager

import pytest


@pytest.fixture(autouse=True)
def isolated_segment_locks(tmp_path, monkeypatch):
    from tesis import segmentos
    monkeypatch.setattr(segmentos, "DEFAULT_ROOT", tmp_path / "segment-locks")


@pytest.fixture
def simulated_bank_restoration(monkeypatch):
    """The fake tools in controller tests also simulate a successful bank reset.

    Segment and adapter acceptance tests use the real guard/callback path instead.
    """
    from tesis import protocolo_ipv6

    @contextmanager
    def instrument(engine, bank, *, on_restored=None):
        original = engine.run_task
        def execute(task, store):
            result = original(task, store)
            if task.action_profile == "nmap_tcp_services_v1" and result.status.value in {"completed", "completed_no_findings"} and not result.services:
                from auditoria.contracts import Service
                aliases = {"postgres":"postgresql", "http-get":"http"}
                result = result.model_copy(update={"services":[Service(port=port,protocol="tcp",state="open",
                    name=aliases.get(name,name)) for name,port in bank.CREDENTIALS[task.target.asset_id]["services"]]})
            if on_restored is not None and task.agent_type in {"ipv6_ndp", "ipv6_fragmentation"}:
                on_restored(task, {"simulation_only": True, "baseline_checked": True})
            return result
        engine.run_task = execute
        try:
            yield
        finally:
            engine.run_task = original
    monkeypatch.setattr(protocolo_ipv6, "instrument_protocol", instrument)


@pytest.fixture
def healthy_kernel(monkeypatch):
    """Aísla solo /proc/.../tainted; no altera el kernel ni el código operativo.

    Los casos de rechazo por kernel tienen sus propias entradas y no usan esta
    fixture. El resto de lecturas de archivos conserva su comportamiento real.
    """
    original = Path.read_text

    def read_text(path, *args, **kwargs):
        if path == Path('/proc/sys/kernel/tainted'):
            return '0\n'
        return original(path, *args, **kwargs)

    monkeypatch.setattr(Path, 'read_text', read_text)
