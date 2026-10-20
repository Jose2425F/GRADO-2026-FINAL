"""Comprobación de la topología Docker antes de una corrida real."""

from __future__ import annotations

import json
import socket
import subprocess

from .red import RouteDenied, check_route

NETWORK = "lab_auditoria_ipv4"
CONTAINER = "obj-tomcat"
ADDRESS = "192.168.57.13"
INTERFACE = "br-lab-audit"
PORT = 8080
SUBNET = "192.168.57.0/24"
SSH_CONTAINER = "obj-ssh"
SSH_ADDRESS = "192.168.57.11"
SSH_PORT = 2222


class LabError(RuntimeError):
    pass


def _docker_inspect(kind: str, name: str) -> dict:
    try:
        result = subprocess.run(
            ["docker", kind, "inspect", name], capture_output=True, text=True,
            timeout=15, check=True,
        )
        items = json.loads(result.stdout)
        if len(items) != 1 or not isinstance(items[0], dict):
            raise ValueError("respuesta inesperada de Docker")
        return items[0]
    except subprocess.CalledProcessError as exc:
        if "permission denied" in (exc.stderr or "").lower():
            raise LabError("Docker inaccesible: el usuario actual no puede usar el socket") from exc
        raise LabError(f"no se pudo inspeccionar {kind} {name}") from exc
    except (OSError, subprocess.SubprocessError, ValueError, IndexError) as exc:
        raise LabError(f"no se pudo inspeccionar {kind} {name}") from exc


def _container_has_default_route(container_name: str) -> bool:
    """Comprueba la tabla de rutas del objetivo sin depender de `ip` en la imagen."""
    try:
        result = subprocess.run(
            ["docker", "exec", container_name, "cat", "/proc/net/route"],
            capture_output=True, text=True, timeout=15, check=True,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise LabError("no se pudo comprobar la tabla de rutas del contenedor") from exc
    for line in result.stdout.splitlines()[1:]:
        fields = line.split()
        if len(fields) < 8:
            raise LabError("tabla de rutas del contenedor inválida")
        if fields[1] == "00000000" and fields[7] == "00000000":
            return True
    return False


def verify_container_lab(container_name: str, address: str, port: int) -> dict:
    """Verifica aislamiento y servicio real; devuelve solo metadatos sin secretos."""
    network = _docker_inspect("network", NETWORK)
    if network.get("Driver") != "bridge" or network.get("Internal") is not True:
        raise LabError("la red Docker no es un puente interno")
    if network.get("EnableIPv6") is not False:
        raise LabError("la red Docker debe tener IPv6 deshabilitado")
    configurations = network.get("IPAM", {}).get("Config", [])
    if not any(item.get("Subnet") == SUBNET for item in configurations):
        raise LabError("la subred Docker no coincide con la política")
    bridge = network.get("Options", {}).get("com.docker.network.bridge.name")
    if bridge != INTERFACE:
        raise LabError("la interfaz Docker no coincide con la política")

    container = _docker_inspect("container", container_name)
    if container.get("State", {}).get("Running") is not True:
        raise LabError(f"{container_name} no está en ejecución")
    attachments = container.get("NetworkSettings", {}).get("Networks", {})
    if set(attachments) != {NETWORK}:
        raise LabError(f"{container_name} debe estar conectado solo a la red de auditoría")
    attachment = attachments[NETWORK]
    if attachment.get("IPAddress") != address:
        raise LabError("la IP del contenedor no coincide con la política")
    if attachment.get("GlobalIPv6Address"):
        raise LabError(f"{container_name} tiene una dirección IPv6 fuera del perfil")
    published = container.get("NetworkSettings", {}).get("Ports", {})
    if any(bindings for bindings in published.values()):
        raise LabError("el contenedor tiene puertos publicados en el anfitrión")
    if _container_has_default_route(container_name):
        raise LabError(f"{container_name} tiene una ruta predeterminada de salida")

    try:
        check_route(address, INTERFACE)
    except RouteDenied as exc:
        raise LabError(str(exc)) from exc
    try:
        with socket.create_connection((address, port), timeout=3):
            pass
    except OSError as exc:
        raise LabError(f"{container_name} no escucha en {address}:{port}") from exc

    image_id = container.get("Image", "")
    image = _docker_inspect("image", image_id)
    return {
        "network": NETWORK,
        "network_id": network.get("Id"),
        "internal": True,
        "interface": INTERFACE,
        "subnet": SUBNET,
        "container": container_name,
        "container_id": container.get("Id"),
        "address": address,
        "port": port,
        "image_id": image_id,
        "image_repo_digests": image.get("RepoDigests", []),
    }


def verify_pilot_lab() -> dict:
    return verify_container_lab(CONTAINER, ADDRESS, PORT)


def verify_ssh_pilot_lab() -> dict:
    return verify_container_lab(SSH_CONTAINER, SSH_ADDRESS, SSH_PORT)
