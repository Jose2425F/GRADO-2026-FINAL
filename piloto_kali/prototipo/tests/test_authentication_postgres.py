"""Corroboración PostgreSQL sin depender de una base exclusiva del laboratorio."""

from contextlib import nullcontext

import psycopg
import pytest

from auditoria.authentication import corroborate
from auditoria.contracts import CredentialProfile, Target, Task


@pytest.mark.parametrize("failure,outcome", [
    (None, "accepted"),
    (psycopg.errors.InvalidPassword, "rejected"),
    (psycopg.errors.InvalidCatalogName, "indeterminate"),
    (psycopg.errors.InsufficientPrivilege, "indeterminate"),
])
def test_postgres_without_labdb_preserves_authentication_outcomes(monkeypatch, failure, outcome):
    target = Target(asset_id="postgres_test", address="192.0.2.10", interface="eth0", ports=[5432])
    task = Task(task_id="postgres_check", agent_type="ipv4_credentials", target=target,
                protocol="tcp", action_profile="hydra_postgres_single_v1", timeout_seconds=10)
    profile = CredentialProfile(ref="postgres_test", service="postgres", port=5432,
                                username="postgres", password_env="POSTGRES_TEST_PASSWORD")
    secret = "synthetic-secret-not-for-evidence"
    routes = []
    monkeypatch.setattr("auditoria.authentication.check_route", lambda *args: routes.append(args))

    def connect(**kwargs):
        assert routes == [(target.address, target.interface)]
        assert kwargs == dict(host=target.address, port=5432, user="postgres", password=secret,
                              dbname="postgres", connect_timeout=5)
        if failure:
            raise failure(secret)
        return nullcontext()

    monkeypatch.setattr(psycopg, "connect", connect)
    result = corroborate(task, profile, secret, timeout=5)
    assert result["outcome"] == outcome
    assert result["tool"] == "psycopg"
    assert result["attempts_max"] == 1
    assert secret not in str(result)
