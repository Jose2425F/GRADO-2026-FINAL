"""Prototipo multi-agente orquestado basado en LLMs para auditorías de
ciberseguridad en entornos dual-stack IPv4/IPv6.

Arquitectura de 6 componentes (véase capítulo 3 del anteproyecto):
  1. Agente Administrador  — orquestador LangGraph + validación cruzada
  2. Agente IPv4-Servicios  — Nmap + correlación CVE
  3. Agente IPv4-Credenciales — Hydra
  4. Agente IPv6-NDP/SLAAC   — Scapy (ICMPv6)
  5. Agente IPv6-Fragmentación — Scapy (RFC 5722 / RFC 8200)
  6. Módulo de Reportes      — informes de remediación priorizados por CVSS
"""

__version__ = "0.6.0"
