"""Reservas entre procesos y cuarentena durable del segmento físico autorizado.

IPv4 e IPv6 comparten la clave de interfaz. Las sondas IPv6 toman reserva
exclusiva; el resto admite lectores concurrentes. Un marcador escrito antes del
despacho sobrevive a SIGKILL y sólo se retira tras una restauración comprobada.
"""
from __future__ import annotations

from contextlib import ExitStack
from datetime import datetime, timezone
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
from uuid import uuid4


IPV6 = {"ipv6_ndp", "ipv6_fragmentation"}
DEFAULT_ROOT = Path(__file__).resolve().parents[2] / "piloto_kali/prototipo/.segment-locks"


class SegmentBusy(Exception):
    pass


class SegmentQuarantined(Exception):
    pass


class SegmentGuard:
    def __init__(self, root, store=None):
        self.root = Path(root)
        self.store = store
        self.leases = {}
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        if self.root.is_symlink():
            raise ValueError("invalid_segment_lock_directory")

    def _path(self, segment, suffix):
        if not isinstance(segment, str) or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,64}", segment):
            raise ValueError("invalid_segment_interface")
        return self.root / (hashlib.sha256(segment.encode()).hexdigest() + suffix)

    def _open(self, segment, exclusive):
        fd = os.open(self._path(segment, ".lock"), os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        try:
            fcntl.flock(fd, (fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH) | fcntl.LOCK_NB)
        except BlockingIOError:
            os.close(fd)
            raise SegmentBusy("segment_busy") from None
        except BaseException:
            os.close(fd)
            raise
        return fd

    def _sync_directory(self):
        fd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)

    def _write(self, segment, record):
        target = self._path(segment, ".json")
        temporary = self.root / (uuid4().hex + ".tmp")
        try:
            with temporary.open("x", encoding="utf-8") as stream:
                os.chmod(temporary, 0o600)
                json.dump(record, stream, sort_keys=True)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, target)
            self._sync_directory()
        finally:
            temporary.unlink(missing_ok=True)

    def _clear(self, segment):
        self._path(segment, ".json").unlink(missing_ok=True)
        self._sync_directory()

    def _event(self, name, task_id=None, **payload):
        if self.store is not None:
            self.store.event("orchestration", name, task_id=task_id, payload=payload)

    def acquire(self, task):
        segment = task.target.interface
        exclusive = task.agent_type in IPV6
        fd = self._open(segment, exclusive)
        try:
            # Any marker, including malformed data, means restoration is unproven.
            if os.path.lexists(self._path(segment, ".json")):
                raise SegmentQuarantined("segment_quarantined")
            if exclusive:
                self._write(segment, {"schema_version": 1, "segment": segment,
                    "task_id": task.task_id, "state": "restoration_unverified",
                    "started_at": datetime.now(timezone.utc).isoformat()})
            self._event("segment_lock_acquired", task.task_id, segment=segment,
                        mode="exclusive" if exclusive else "shared")
            self.leases[task.task_id] = {"fd": fd, "segment": segment,
                                       "exclusive": exclusive, "verified": False}
        except BaseException:
            os.close(fd)
            raise

    def restored(self, task, state):
        """Called only by the adapter after wait_receiver/reset_receiver succeeds."""
        lease = self.leases[task.task_id]
        if not lease["exclusive"] or lease["segment"] != task.target.interface:
            raise ValueError("invalid_segment_restoration")
        if not isinstance(state, dict) or not state:
            raise ValueError("missing_restoration_state")
        payload = {"schema_version": 1, "segment": lease["segment"],
                   "task_id": task.task_id, "criterion": "bank_wait_receiver_baseline", "state": state}
        ref, digest = self.store.evidence(task.task_id + "_restoration", "json",
                                         json.dumps(payload, sort_keys=True).encode())
        self._event("segment_restoration_verified", task.task_id, segment=lease["segment"],
                    evidence_ref=ref, evidence_sha256=digest)
        lease["verified"] = True

    def release(self, task):
        lease = self.leases.pop(task.task_id, None)
        if lease is None:
            return
        try:
            if lease["exclusive"] and not lease["verified"]:
                self._event("segment_quarantined", task.task_id, segment=lease["segment"],
                            reason_code="restoration_unverified")
            else:
                self._event("segment_lock_released", task.task_id, segment=lease["segment"],
                            restoration_verified=lease["verified"])
                if lease["exclusive"]:
                    self._clear(lease["segment"])
        finally:
            os.close(lease["fd"])

    def recover(self, segments, restore_and_verify):
        """Hold all exclusive locks through recovery; no clearing on failed proof.

        The trusted bank callback restores the owned fixture and runs its full
        preflight. This method never treats a caller-supplied flag as proof.
        """
        segments = sorted(set(segments))
        if not segments:
            raise ValueError("empty_segment_recovery")
        with ExitStack() as stack:
            for segment in segments:
                fd = self._open(segment, True)
                stack.callback(os.close, fd)
            for segment in segments:
                self._write(segment, {"schema_version": 1, "segment": segment,
                                      "state": "recovery_in_progress"})
            proof = restore_and_verify()
            if not isinstance(proof, dict) or not proof:
                raise ValueError("missing_bank_recovery_proof")
            receipt = {"schema_version": 1, "segments": segments,
                       "verified_at": datetime.now(timezone.utc).isoformat(), "proof": proof}
            receipt_id = "recovery-" + uuid4().hex
            self._write(receipt_id, receipt)
            self._event("segment_recovery_verified", segments=segments,
                        receipt_sha256=hashlib.sha256(json.dumps(receipt, sort_keys=True).encode()).hexdigest())
            for segment in segments:
                self._clear(segment)
            return proof
