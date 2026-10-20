"""Corrobora autenticación con un cliente distinto; nunca ejecuta comandos remotos."""

from __future__ import annotations

import base64
import ftplib
import urllib.error
import urllib.request

from .contracts import CredentialProfile, Task
from .red import check_route


def corroborate(task: Task, profile: CredentialProfile, password: str, *, timeout: int) -> dict:
    check_route(task.target.address, task.target.interface)
    outcome = "indeterminate"
    tool = {
        "ssh": "paramiko",
        "ftp": "ftplib",
        "postgres": "psycopg",
        "http-get": "urllib-basic-auth",
    }[profile.service]
    try:
        if profile.service == "ssh":
            import paramiko

            client = paramiko.SSHClient()
            # Hosts efímeros del laboratorio; la huella observada queda en evidencia.
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            try:
                client.connect(
                    task.target.address,
                    port=profile.port,
                    username=profile.username,
                    password=password,
                    timeout=timeout,
                    auth_timeout=timeout,
                    banner_timeout=timeout,
                    allow_agent=False,
                    look_for_keys=False,
                )
                outcome = "accepted" if client.get_transport().is_authenticated() else "rejected"
            finally:
                client.close()
        elif profile.service == "ftp":
            with ftplib.FTP() as client:
                client.connect(task.target.address, profile.port, timeout=timeout)
                client.login(profile.username, password)
                outcome = "accepted"
        elif profile.service == "postgres":
            import psycopg

            with psycopg.connect(
                host=task.target.address,
                port=profile.port,
                user=profile.username,
                password=password,
                dbname="postgres",
                connect_timeout=timeout,
            ):
                outcome = "accepted"
        else:
            # Sin proxy del entorno ni redirecciones hacia objetivos distintos.
            class NoRedirect(urllib.request.HTTPRedirectHandler):
                def redirect_request(self, req, fp, code, msg, headers, newurl):
                    return None

            url = f"http://{task.target.address}:{profile.port}/manager/html"
            token = base64.b64encode(f"{profile.username}:{password}".encode()).decode()
            req = urllib.request.Request(url, headers={"Authorization": f"Basic {token}"})
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
            with opener.open(req, timeout=timeout) as response:
                outcome = "accepted" if response.status == 200 else "indeterminate"
    except Exception as exc:
        # No persistir str(exc): algunos clientes incluyen contraseñas o DSN.
        rejection = (
            isinstance(exc, ftplib.error_perm)
            or isinstance(exc, urllib.error.HTTPError)
            and exc.code == 401
            or type(exc).__name__ in {"AuthenticationException", "InvalidPassword"}
        )
        outcome = "rejected" if rejection else "indeterminate"
    return {
        "schema_version": "1",
        "tool": tool,
        "outcome": outcome,
        "target": task.target.address,
        "service": profile.service,
        "port": profile.port,
        "credential_ref": profile.ref,
        "attempts_max": 1,
    }


def http_basic_challenge(task: Task, profile: CredentialProfile, *, timeout: int) -> bool:
    """Un 403 o una página pública no demuestra autenticación HTTP Basic."""

    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            return None

    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    try:
        with opener.open(
            f"http://{task.target.address}:{profile.port}/manager/html", timeout=timeout
        ):
            return False
    except urllib.error.HTTPError as exc:
        return exc.code == 401 and (
            exc.headers.get("WWW-Authenticate", "").lower().startswith("basic ")
        )
    except OSError:
        return False
