"""Límite externo para herramientas bloqueadas, incluido el grupo de procesos."""
import os
import signal
import subprocess


def terminate_group(process, *, grace_seconds=10):
    if process.poll() is not None:
        return
    # Callers create the owned child with start_new_session=True.
    for sig,wait_seconds in [(signal.SIGTERM,grace_seconds),(signal.SIGKILL,5)]:
        try:
            os.killpg(process.pid,sig)
        except ProcessLookupError:
            pass
        try:
            process.wait(timeout=wait_seconds)
            return
        except subprocess.TimeoutExpired:
            continue
    raise RuntimeError('process_termination_unconfirmed')


def wait_bounded(process, max_seconds, *, grace_seconds=10):
    if max_seconds<=0 or grace_seconds<=0:
        raise ValueError('invalid_process_deadline')
    try:
        return process.wait(timeout=max_seconds),False
    except subprocess.TimeoutExpired:
        terminate_group(process,grace_seconds=grace_seconds)
        return 124,True
