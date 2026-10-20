"""Contratos que cruzan las fronteras del monolito modular."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from ipaddress import ip_address, ip_network
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Category(StrEnum):
    APPLICATION_ACCESS = "application_access"
    IPV4_SERVICES = "ipv4_services"
    IPV4_CREDENTIALS = "ipv4_credentials"
    IPV6_NDP = "ipv6_ndp"
    IPV6_FRAGMENTATION = "ipv6_fragmentation"


class Target(StrictModel):
    asset_id: str = Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9_-]+$")
    address: str
    interface: str = Field(min_length=1, max_length=32, pattern=r"^[A-Za-z0-9_.:-]+$")
    ports: list[int] = Field(default_factory=list, max_length=32)
    credential_ref: str | None = Field(default=None, pattern=r"^[A-Za-z0-9_-]+$")
    credential_refs: list[str] = Field(default_factory=list, max_length=8)

    @field_validator("address")
    @classmethod
    def valid_address(cls, value: str) -> str:
        return str(ip_address(value))

    @field_validator("ports")
    @classmethod
    def valid_ports(cls, value: list[int]) -> list[int]:
        if any(port < 1 or port > 65535 for port in value):
            raise ValueError("los puertos deben estar entre 1 y 65535")
        if len(value) != len(set(value)):
            raise ValueError("los puertos no pueden repetirse")
        return sorted(value)


class AuditRequest(StrictModel):
    bank: Literal["v1", "v2", "empresa"] = "v1"
    audit_id: str = Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9_-]+$")
    operator: str = Field(min_length=1, max_length=120)
    authorization_ref: str = Field(min_length=1, max_length=200)
    scope_ipv4: list[str] = Field(default_factory=list)
    scope_ipv6: list[str] = Field(default_factory=list)
    categories: list[Category] = Field(min_length=1)
    case_ids: list[str] = Field(default_factory=list, max_length=8)
    targets: list[Target] = Field(min_length=1, max_length=16)
    not_before: datetime
    not_after: datetime
    max_runtime_seconds: int = Field(ge=5, le=3600)
    max_attempts: int = Field(ge=1, le=10)
    token_budget: int = Field(ge=0, le=10_000_000)
    architecture: Literal["multiagent", "single"] = "multiagent"
    llm_mode: Literal["disabled", "scheduler"] = "disabled"
    llm_provider: Literal["openai"] = "openai"
    execution_policy: Literal["predefined_profiles"] = "predefined_profiles"
    stop_on_verified_access: bool = Field(default=False, strict=True)

    @field_validator("scope_ipv4", "scope_ipv6")
    @classmethod
    def valid_networks(cls, value: list[str]) -> list[str]:
        return [str(ip_network(item, strict=True)) for item in value]

    @model_validator(mode="after")
    def valid_window_and_targets(self) -> AuditRequest:
        if self.not_before.tzinfo is None or self.not_after.tzinfo is None:
            raise ValueError("la ventana debe incluir zona horaria")
        if self.not_after <= self.not_before:
            raise ValueError("not_after debe ser posterior a not_before")
        if len(set(self.categories)) != len(self.categories):
            raise ValueError("las categorias no pueden repetirse")
        if len(set(self.case_ids)) != len(self.case_ids):
            raise ValueError("case_ids no pueden repetirse")
        if len(
            {(target.asset_id, ip_address(target.address).version) for target in self.targets}
        ) != len(self.targets):
            raise ValueError("un activo admite como máximo una dirección por familia IP")
        for target in self.targets:
            refs = target.credential_refs + (
                [target.credential_ref] if target.credential_ref else []
            )
            if len(refs) != len(set(refs)):
                raise ValueError("las referencias de un objetivo no pueden repetirse")
        return self


class LabSegment(StrictModel):
    name: str = Field(min_length=1, max_length=64)
    network: str
    interface: str = Field(min_length=1, max_length=32, pattern=r"^[A-Za-z0-9_.:-]+$")
    allowed_ports: list[int] = Field(default_factory=list)

    @field_validator("network")
    @classmethod
    def valid_network(cls, value: str) -> str:
        return str(ip_network(value, strict=True))


class CredentialProfile(StrictModel):
    ref: str = Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9_-]+$")
    service: str = Field(pattern=r"^(ssh|ftp|postgres|http-get)$")
    port: int = Field(ge=1, le=65535)
    username: str = Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9_.-]+$")
    password_env: str = Field(pattern=r"^[A-Z][A-Z0-9_]+$")
    condition: Literal["default_credential", "anonymous_access"] | None = None


class FindingRule(StrictModel):
    """Criterio público de validación; no contiene etiquetas experimentales."""

    rule_id: str
    case_id: str
    condition: str
    reference: str
    remediation: str
    severity: Literal["low", "medium", "high"] = "medium"


class LabPolicy(StrictModel):
    policy_id: str
    segments: list[LabSegment] = Field(min_length=1)
    allowed_categories: list[Category] = Field(min_length=1)
    allowed_case_ids: list[str] = Field(default_factory=list)
    max_token_budget: int = Field(default=0, ge=0, le=1_000_000)
    credential_profiles: list[CredentialProfile] = Field(default_factory=list)
    finding_rules: list[FindingRule] = Field(default_factory=list)

    @model_validator(mode="after")
    def unique_credential_refs(self) -> LabPolicy:
        refs = [profile.ref for profile in self.credential_profiles]
        if len(refs) != len(set(refs)):
            raise ValueError("las referencias de credenciales deben ser únicas")
        return self


class TaskStatus(StrEnum):
    COMPLETED = "completed"
    COMPLETED_NO_FINDINGS = "completed_no_findings"
    SKIPPED = "skipped"
    BLOCKED = "blocked"
    FAILED = "failed"
    CANCELLED = "cancelled"


class Task(StrictModel):
    task_id: str
    agent_type: str
    case_id: str | None = None
    target: Target
    protocol: str
    action_profile: Literal[
        "http_application_dualstack_v2",
        "ipv6_slaac_v2",
        "ipv6_ra_route_v2",
        "ipv6_ra_mtu_v2",
        "ipv6_na_neighbor_v2",
        "ipv6_dad_na_v2",
        "ipv6_overlap_v2",
        "ipv6_overlap_middle_v2",
        "ipv6_atomic_v2",
        "ipv6_incomplete_chain_v2",
        "nmap_tcp_services_v1",
        "hydra_ssh_single_v1",
        "hydra_ftp_single_v1",
        "hydra_postgres_single_v1",
        "hydra_http_get_single_v1",
        "ipv6_ra_route_v1",
        "ipv6_na_neighbor_v1",
        "ipv6_dad_v1",
        "ipv6_ra_mtu_v1",
        "ipv6_overlap_initial_v1",
        "ipv6_overlap_middle_v1",
        "ipv6_atomic_v1",
        "ipv6_incomplete_chain_v1",
    ]
    dependencies: list[str] = Field(default_factory=list)
    timeout_seconds: int = Field(ge=1, le=3600)


class Service(StrictModel):
    port: int
    protocol: str
    state: str
    name: str | None = None
    product: str | None = None
    version: str | None = None


class Authentication(StrictModel):
    credential_ref: str
    service: str
    port: int
    outcome: str = Field(pattern=r"^(accepted|rejected|transport_error|indeterminate)$")


class TaskResult(StrictModel):
    task_id: str
    status: TaskStatus
    reason_code: str | None = None
    services: list[Service] = Field(default_factory=list)
    authentication: Authentication | None = None
    observations: dict[str, Any] = Field(default_factory=dict)
    evidence_ref: str | None = None
    evidence_sha256: str | None = None
    diagnostic_ref: str | None = None
    diagnostic_sha256: str | None = None
    command: list[str] = Field(default_factory=list)


class Event(StrictModel):
    event_id: str
    audit_id: str
    task_id: str | None = None
    component: str
    kind: str
    timestamp: datetime
    monotonic_ns: int
    payload: dict[str, Any] = Field(default_factory=dict)
