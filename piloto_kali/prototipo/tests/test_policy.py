from pathlib import Path

import pytest

from auditoria.contracts import AuditRequest, LabPolicy
from auditoria.policy import PolicyError, authorize_request


BASE = Path(__file__).resolve().parents[1]


def inputs():
    request = AuditRequest.model_validate_json((BASE / "examples/solicitud.example.json").read_text())
    policy = LabPolicy.model_validate_json((BASE / "config/lab_policy.example.json").read_text())
    return request, policy


def test_valid_request():
    authorize_request(*inputs())


def test_llm_budget_is_not_claimed_by_inactive_integration():
    request, policy = inputs()
    request = request.model_copy(update={"token_budget": 100})
    with pytest.raises(PolicyError) as error:
        authorize_request(request, policy)
    assert error.value.reason_code == "budget_unavailable"


@pytest.mark.parametrize("field,value,reason", [
    ("address", "8.8.8.8", "target_out_of_scope"),
    ("interface", "eth0", "interface_denied"),
    ("ports", [9999], "port_denied"),
])
def test_target_denied(field, value, reason):
    request, policy = inputs()
    changed = request.targets[0].model_copy(update={field: value})
    request = request.model_copy(update={"targets": [changed]})
    with pytest.raises(PolicyError) as error:
        authorize_request(request, policy)
    assert error.value.reason_code == reason
