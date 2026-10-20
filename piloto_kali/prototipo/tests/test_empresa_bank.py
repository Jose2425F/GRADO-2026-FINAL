"""Invariantes del banco NovaFlow que no requieren Docker."""
from __future__ import annotations

import json

import pytest

from auditoria import empresa_agent as agent
from auditoria import lab_empresa as lab
from auditoria.contracts import Category
from auditoria.policy import PolicyError


def test_catalog_within_request_limits():
    req = agent.request("LAB-PROPIO", llm=False)
    assert req.bank == "empresa"
    assert 1 <= len(req.targets) <= 16
    # Un activo como máximo una dirección por familia IP (validador del contrato).
    assert len({(t.asset_id, ":" in t.address) for t in req.targets}) == len(req.targets)


def test_plan_covers_the_five_capabilities():
    req = agent.request("LAB-PROPIO", llm=False)
    categories = {t.agent_type for t in agent.build_plan(req)}
    assert categories == {
        Category.IPV4_SERVICES, Category.IPV4_CREDENTIALS, Category.APPLICATION_ACCESS,
        Category.IPV6_NDP, Category.IPV6_FRAGMENTATION,
    }


def test_authorize_accepts_canonical_and_rejects_tampered():
    req = agent.request("LAB-PROPIO", llm=False)
    agent.authorize_empresa(req, agent.policy())
    tampered = req.model_copy(update={"token_budget": agent.policy().max_token_budget + 1})
    with pytest.raises(PolicyError):
        agent.authorize_empresa(tampered, agent.policy())


def test_ground_truth_balance(tmp_path):
    lab.prepare(tmp_path)
    ground = json.loads((tmp_path / "ground_truth.json").read_text())
    present = [e for e in ground["entries"] if e["present"]]
    absent = [e for e in ground["entries"] if not e["present"]]
    assert ground["bank"] == lab.VERSION
    assert len(present) == 13 and len(absent) == 11
    # El bastión es un control negativo de credenciales.
    assert all(not e["present"] for e in ground["entries"] if e["asset_id"] == "bastion")
    # receiver_a positivo, receiver_b negativo en las tres condiciones ND.
    assert all(e["present"] for e in ground["entries"] if e["asset_id"] == "receiver_a")
    assert all(not e["present"] for e in ground["entries"] if e["asset_id"] == "receiver_b")


def test_bastion_guess_differs_from_prepared_real(tmp_path):
    lab.prepare(tmp_path)
    env = dict(line.split("=", 1) for line in (tmp_path / "lab.env").read_text().splitlines() if "=" in line)
    assert env["LAB_NOVA_BASTION_REAL"] != lab.BASTION_GUESS
