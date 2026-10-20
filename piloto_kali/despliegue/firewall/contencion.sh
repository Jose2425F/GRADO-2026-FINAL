#!/usr/bin/env bash
# Contencion de los dos enlaces de auditoria en la VM Kali (ASR-15).
# Aplicar despues de docker compose up -d. Requiere backend iptables de Docker.
# Ajustar IF_AUDIT_L2 al nombre real de la NIC VirtualBox antes de ejecutar.
# Estas reglas bloquean el REENVIO; Kali puede originar trafico autorizado.
set -euo pipefail

IF_AUDIT_L2="${IF_AUDIT_L2:-eth1}"
IF_DOCKER="br-lab-audit"

if [[ $EUID -ne 0 ]]; then
  echo "Ejecutar como root" >&2
  exit 1
fi
ip link show "$IF_AUDIT_L2" >/dev/null
ip link show "$IF_DOCKER" >/dev/null
iptables -nL DOCKER-USER >/dev/null || {
  echo "No existe DOCKER-USER: verificar el backend de firewall de Docker" >&2
  exit 1
}

ensure_rule() {
  local binary="$1" chain="$2"
  shift 2
  "$binary" -C "$chain" "$@" 2>/dev/null || "$binary" -I "$chain" 1 "$@"
}

# DOCKER-USER se evalua antes de las reglas de aceptacion de Docker.
# No se cambia la politica global FORWARD ni se desactiva ip_forward,
# porque Docker puede necesitarlos para administrar el puente.
ensure_rule iptables DOCKER-USER -i "$IF_AUDIT_L2" -j DROP
ensure_rule iptables DOCKER-USER -o "$IF_AUDIT_L2" -j DROP
ensure_rule iptables DOCKER-USER -i "$IF_DOCKER" -j DROP

# Un paquete dirigido a otra IP de Kali (por ejemplo, su IP de gestion)
# entra por INPUT, no por FORWARD. Solo se admiten las IP locales de auditoria.
ensure_rule iptables INPUT -i "$IF_AUDIT_L2" ! -d 192.168.56.2 -j DROP
ensure_rule iptables INPUT -i "$IF_DOCKER" ! -d 192.168.57.1 -j DROP

# El puente Docker no tiene IPv6. Estas reglas protegen el enlace L2 IPv6.
ensure_rule ip6tables FORWARD -i "$IF_AUDIT_L2" -j DROP
ensure_rule ip6tables FORWARD -o "$IF_AUDIT_L2" -j DROP

echo "Contencion de reenvio aplicada. Verificar ambos enlaces segun DESPLIEGUE.md."
