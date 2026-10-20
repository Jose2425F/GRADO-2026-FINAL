#!/usr/bin/env bash
# Basado en https://docs.docker.com/engine/install/debian/ (Kali: Debian trixie).
set -euo pipefail
if [ "$(id -u)" -ne 0 ]; then
  echo "Ejecuta: sudo bash $0" >&2
  exit 2
fi
operator_user="${SUDO_USER:-kali}"
if ! command -v docker >/dev/null; then
  apt-get update
  apt-get install -y ca-certificates curl
  install -m 0755 -d /etc/apt/keyrings
  curl -fsSL https://download.docker.com/linux/debian/gpg -o /etc/apt/keyrings/docker.asc
  chmod a+r /etc/apt/keyrings/docker.asc
  docker_arch="$(dpkg --print-architecture)"
  cat > /etc/apt/sources.list.d/docker.sources <<EOF
Types: deb
URIs: https://download.docker.com/linux/debian
Suites: trixie
Components: stable
Architectures: ${docker_arch}
Signed-By: /etc/apt/keyrings/docker.asc
EOF
  apt-get update
  apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
fi
systemctl enable --now docker
usermod -aG docker "$operator_user"
docker version
docker compose version
echo "Docker preparado. En tu terminal ejecuta: newgrp docker"
echo "Después comprueba: docker info"
