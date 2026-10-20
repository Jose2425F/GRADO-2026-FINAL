"""Control determinista de alcance, perfil e interfaz."""

from __future__ import annotations

from datetime import datetime, timezone
from ipaddress import ip_address, ip_network

from .contracts import AuditRequest, Category, LabPolicy, LabSegment, Target
from .casos_ipv6 import CASES, selected_case_ids


class PolicyError(ValueError):
    def __init__(self, reason_code: str, message: str):
        super().__init__(message)
        self.reason_code = reason_code


def _segment_for(target: Target, policy: LabPolicy) -> LabSegment:
    address = ip_address(target.address)
    matches = [segment for segment in policy.segments if address in ip_network(segment.network)]
    if len(matches) != 1:
        raise PolicyError(
            "segment_not_unique", f"{target.address}: debe pertenecer a un unico segmento"
        )
    return matches[0]


def authorize_request(request: AuditRequest, policy: LabPolicy, *, live: bool = False) -> None:
    """Rechaza toda solicitud que amplíe la política del laboratorio."""
    if live:
        now = datetime.now(timezone.utc)
        if not request.not_before <= now <= request.not_after:
            raise PolicyError("outside_window", "fuera de la ventana autorizada")

    if not set(request.categories).issubset(set(policy.allowed_categories)):
        raise PolicyError("category_denied", "categoria no permitida por la politica local")
    categories = set(request.categories)
    if request.bank == "v2":
        from .v2_agent import authorize_v2

        authorize_v2(request, policy)
        return
    ipv4_categories = {Category.IPV4_SERVICES, Category.IPV4_CREDENTIALS}
    ipv6_categories = {Category.IPV6_NDP, Category.IPV6_FRAGMENTATION}
    if not categories <= ipv4_categories | ipv6_categories:
        raise PolicyError("profile_unavailable", "categorías no implementadas")
    if Category.IPV4_CREDENTIALS in categories and Category.IPV4_SERVICES not in categories:
        raise PolicyError("profile_unavailable", "credenciales requiere inventario IPv4")
    if categories & ipv6_categories:
        for case_id in selected_case_ids(request.case_ids):
            case = CASES.get(case_id)
            if (
                case is None
                or case.category not in categories
                or case_id not in policy.allowed_case_ids
            ):
                raise PolicyError("case_denied", f"{case_id}: caso no autorizado")
    elif request.case_ids:
        raise PolicyError("case_denied", "case_ids solo se usan en perfiles IPv6")
    if request.max_attempts != 1 or request.token_budget > policy.max_token_budget:
        raise PolicyError("budget_unavailable", "presupuesto fuera de la política local")
    if request.token_budget and (request.llm_provider != "openai" or request.llm_mode != "scheduler"):
        raise PolicyError("budget_unavailable", "la IA requiere el planificador acotado de OpenAI")

    for field, scope_version in ((request.scope_ipv4, 4), (request.scope_ipv6, 6)):
        for value in field:
            network = ip_network(value)
            if network.version != scope_version:
                raise PolicyError("scope_version", f"{value}: version IP incorrecta")
            if not any(
                network.version == ip_network(segment.network).version
                and network.subnet_of(ip_network(segment.network))
                for segment in policy.segments
            ):
                raise PolicyError("scope_denied", f"{value}: alcance fuera del laboratorio")

    requested_scopes = [ip_network(value) for value in request.scope_ipv4 + request.scope_ipv6]
    for target in request.targets:
        address = ip_address(target.address)
        if not categories & (ipv4_categories if address.version == 4 else ipv6_categories):
            raise PolicyError(
                "profile_unavailable", "versión IP del objetivo incompatible con las categorías"
            )
        if not any(address in network for network in requested_scopes):
            raise PolicyError(
                "target_out_of_scope", f"{target.address}: fuera del alcance solicitado"
            )
        segment = _segment_for(target, policy)
        if target.interface != segment.interface:
            raise PolicyError("interface_denied", f"{target.address}: interfaz no autorizada")
        if not set(target.ports).issubset(set(segment.allowed_ports)):
            raise PolicyError("port_denied", f"{target.address}: puerto fuera del perfil local")
        if (
            Category.IPV4_SERVICES in request.categories
            and address.version == 4
            and not target.ports
        ):
            raise PolicyError("ports_required", f"{target.address}: faltan puertos para inventario")
        refs = target.credential_refs + ([target.credential_ref] if target.credential_ref else [])
        if address.version == 4 and Category.IPV4_CREDENTIALS in categories:
            if not refs:
                raise PolicyError(
                    "credential_ref_denied", "faltan referencias de credenciales autorizadas"
                )
            for ref in refs:
                profiles = [profile for profile in policy.credential_profiles if profile.ref == ref]
                if len(profiles) != 1:
                    raise PolicyError(
                        "credential_ref_denied", "referencia de credenciales no autorizada"
                    )
                if profiles[0].port not in target.ports:
                    raise PolicyError(
                        "credential_port_denied", "puerto de credenciales fuera del objetivo"
                    )
        elif refs:
            raise PolicyError(
                "credential_ref_unneeded", "referencia de credenciales sin categoria autorizada"
            )
        if (
            address.version == 6
            and Category.IPV6_FRAGMENTATION in categories
            and target.ports != [53000]
        ):
            raise PolicyError(
                "port_denied", "fragmentación IPv6 requiere el puerto UDP 53000 del piloto"
            )


def segment_for(target: Target, policy: LabPolicy) -> LabSegment:
    return _segment_for(target, policy)
