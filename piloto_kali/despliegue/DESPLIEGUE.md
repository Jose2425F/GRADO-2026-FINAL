# Documentación de infraestructura y despliegue del laboratorio

**Trabajo de grado:** Desarrollo de un prototipo multiagente orquestado basado en LLM para la automatización de auditorías de ciberseguridad en entornos dual-stack IPv4/IPv6.

**Autores:** Héctor Yonaiker Antolínez Rojas · José Fernando Galván Payares
**Universidad Católica de Colombia — Facultad de Ingeniería**

Este documento describe la **capa de despliegue** del prototipo: la topología del laboratorio, el plan de direccionamiento, los servicios desplegados, el procedimiento de restauración y la verificación de contención. Complementa el numeral 3.7 del documento y el Anexo C.

**Estado del despliegue:** las secciones de VM, GNS3 y red de gestión separada describen una topología propuesta. El banco Docker v1 está implementado; el banco adicional v2 se define en `docker-compose.v2.yml` y se explica en la [guía v2](../prototipo/GUIA_LABORATORIO_V2.md). Este último ejecuta cuatro aplicaciones dual-stack y router/emisor/dos receptores en redes internas `.59` y `.60`, con SLAAC legítimo y certificación independiente. No atribuyas al despliegue actual las VM o el observador de gestión que siguen pendientes.

---

## 1. Estilo arquitectónico y decisiones de despliegue

| Decisión | Elección | Justificación (ASR) |
|---|---|---|
| Tipo de arquitectura | **Monolito modular** en Python | Un solo despliegue reproducible (ASR-10), contratos entre módulos (ASR-11) y la misma capa de ejecución para ambas arquitecturas (ASR-17). |
| Estilo de coordinación | **Orquestador central** (supervisor) con LangGraph | El Administrador coordina; los especialistas no se comunican entre sí (ASR-06). |
| Frontera con las herramientas | **Puertos y adaptadores** (hexagonal) | El núcleo no conoce Nmap/Hydra/Scapy; los usa por contrato (ASR-02, ASR-11). |
| Servicio separado | **Observador** en la red de gestión | El controlador consulta su API de lectura; los adaptadores no tienen perfiles de acción para la red de gestión y el ground truth permanece fuera de la API (ASR-18). |
| Despliegue | Máquinas virtuales con instantáneas + contenedores | Estado inicial conocido y restaurable en cada corrida (ASR-19). |

---

## 2. Topología del laboratorio (tres zonas, dos enlaces de auditoría)

```
Internet → control (NAT Network 192.168.10.0/24) → Kali
                                                 ├─ auditoría A: red interna de VM
                                                 │  192.168.56.0/24 + fd6a:9b21:4c70:1::/64
                                                 │  Metasploitable3, router RA, receptor IPv6
                                                 ├─ auditoría B: puente Docker interno IPv4
                                                 │  192.168.57.0/24
                                                 │  SSH, FTP, Tomcat, PostgreSQL
                                                 └─ gestión: red interna de VM
                                                    192.168.99.0/24
                                                    Observador FastAPI (consulta mediada)
```

El diagrama visual está en `diagrama_despliegue.svg` y su fuente editable para diagrams.net en `diagrama_despliegue.mmd`.

- **Control:** la VM Kali tiene una interfaz de salida en una NAT Network configurada como `192.168.10.0/24`. La lista de destinos externos permitidos se aplica en el punto de salida y se registra en el manifiesto.
- **Auditoría A:** red interna de VirtualBox `lab_auditoria_l2`, sin adaptador del anfitrión. Conecta Kali, Metasploitable3, el router RA y el receptor IPv6. Aquí se prueban NDP/SLAAC y fragmentación. `fd6a:9b21:4c70:1::/64` solo existe en este enlace.
- **Auditoría B:** puente Docker `lab_auditoria_ipv4` en la misma VM Kali. Usa `192.168.57.0/24`, `internal: true`, sin puertos publicados ni IPv6. Kali llega directamente a sus contenedores por la interfaz `br-lab-audit`; no se afirma que estos compartan el enlace L2 de las VM.
- **Gestión:** red interna separada `lab_gestion`. Kali usa esta red para que el controlador consulte el observador. Router y receptor ofrecen telemetría por esta red; Metasploitable3 puede conectarse para observación de estado. Los agentes solo reciben resultados filtrados de las consultas autorizadas, nunca etiquetas del ground truth.

Las tres **zonas** de seguridad son control, auditoría y gestión. Auditoría contiene dos enlaces distintos; tener el mismo propósito no los convierte en una única red IP. Ninguna VM objetivo debe reenviar paquetes entre sus interfaces. Antes del piloto se verificarán el cableado virtual y las reglas del anfitrión, además de las reglas de Kali (ASR-15).

---

## 3. Plan de direccionamiento

Valores propuestos; se verifican contra conflictos al desplegar y se congelan en el manifiesto (ASR-10). El prefijo IPv6 es ULA (`fd6a:9b21:4c70::/48`); el `/64` de prueba solo se anuncia en auditoría A. La red `192.168.10.0/24` requiere configurar una NAT Network de VirtualBox; no es la dirección predeterminada de una NIC NAT individual.

| Nodo | Control | Auditoría A, L2 de VM | Auditoría B, Docker IPv4 | Gestión |
|---|---|---|---|---|
| Kali, máquina de control | 192.168.10.2 | 192.168.56.2; `fd6a:9b21:4c70:1::2` | Puente `192.168.57.1` | 192.168.99.2 |
| Metasploitable3 | — | 192.168.56.20; IPv6 no supuesto | — | 192.168.99.20, si se instrumenta |
| Router RA, VM Linux | — | 192.168.56.254; `fd6a:9b21:4c70:1::1`; dirección de enlace local registrada al desplegar | — | 192.168.99.254 |
| Receptor IPv6, VM Linux | — | 192.168.56.30; IPv6 por SLAAC, registrado por `asset_id` | — | 192.168.99.30 |
| obj-ssh | — | — | 192.168.57.11 | — |
| obj-ftp | — | — | 192.168.57.12 | — |
| obj-tomcat | — | — | 192.168.57.13 | — |
| obj-postgres | — | — | 192.168.57.14 | — |
| Observador | — | — | — | 192.168.99.10 |

La dirección IPv6 SLAAC del receptor se obtiene en cada restauración y se registra antes de la corrida. No se atribuye una dirección SLAAC a Metasploitable3 ni a los contenedores sin verificar que la interfaz y el sistema la admiten.

---

## 4. Servicios desplegados (inventario)

| Nodo | Servicios / puertos | Plataforma | Categoría de prueba |
|---|---|---|---|
| Máquina de control (Kali) | Prototipo, agente único, Nmap, Hydra, Scapy, SQLite | VM VirtualBox | Orquestación (no es objetivo) |
| obj-ssh | SSH/2222 | Docker (`linuxserver/openssh-server`) | Credenciales IPv4 |
| obj-ftp | FTP/21; puertos pasivos por confirmar | Docker (`fauria/vsftpd`) | Credenciales IPv4 |
| obj-tomcat | HTTP/8080; Manager pendiente de aprovisionar | Docker (`tomcat:9.0`) | Servicios IPv4; credenciales solo tras verificar Manager |
| obj-postgres | PostgreSQL/5432 | Docker (`postgres:16`) | Credenciales IPv4 |
| Metasploitable3 | Servicios vulnerables compatibles | VM (Rapid7) con instantánea | Servicios IPv4 |
| Router IPv6 | Anuncios RA/SLAAC (radvd) | VM Linux integrada al proyecto GNS3 | NDP-SLAAC IPv6 |
| Receptor IPv6 | ICMPv6 y comportamiento de fragmentación; puertos de prueba por fijar | VM Linux con instantánea | NDP-SLAAC y fragmentación IPv6 |
| Observador | API de lectura: rutas, vecinos, MTU, capturas; puerto por fijar | FastAPI (red de gestión) | Instrumentación |

> Los objetivos de **fragmentación IPv6** (fragmentos solapados, atómicos, cadenas de encabezados) se ejercitan con Scapy desde Kali contra el receptor IPv6. Su comportamiento se observa por gestión. Las condiciones concretas y el resultado esperado se verifican antes de congelar el banco experimental.

---

## 5. Software base y versiones

Las versiones definitivas se registran con su hash en el manifiesto de corrida (ASR-10, ASR-13).

| Componente | Versión propuesta |
|---|---|
| Hipervisor | Oracle VirtualBox 7.x (NAT Network para control; redes internas separadas para auditoría A y gestión) |
| Máquina de control | Kali Linux 2026.x |
| Contenedores | Docker Engine 27.x + Compose v2 |
| Lenguaje | Python 3.13.12 en la VM Kali del piloto; versión y hash del entorno registrados por corrida |
| Orquestación | LangGraph |
| Contratos de datos | Pydantic v2 |
| Interfaz del operador | Typer (línea de comandos) |
| Observador | FastAPI + Uvicorn |
| Persistencia | SQLite + archivos de evidencia con huella SHA-256 |
| Informe | Jinja2 (JSON → HTML); conversor HTML a PDF por seleccionar y versionar |
| Herramientas | Nmap, Hydra, Scapy (versiones fijadas) |
| LLM | OpenAI mediante API (modelo identificado por versión) |

---

## 6. Procedimiento de restauración (antes de cada corrida) — ASR-19

1. Detener el prototipo y los contenedores: `docker compose down -v` dentro de `despliegue/`. Se descartan los datos de prueba de PostgreSQL para recrearlos desde la configuración base.
2. Restaurar las instantáneas base de Metasploitable3, router RA y receptor IPv6. La VM Kali conserva la bitácora, pero no el estado de los objetivos.
3. Cargar las variables `LAB_SSH_PASSWORD`, `LAB_FTP_PASSWORD` y `LAB_POSTGRES_PASSWORD` desde el almacén local protegido; no guardarlas en el repositorio ni en el estado del LLM. Levantar los contenedores con `docker compose up -d`.
4. Confirmar los dos enlaces de auditoría por separado: servicios `.57.x` desde Kali; RA, SLAAC y receptor `.56.x` en auditoría A. Registrar la IPv6 SLAAC del receptor, rutas, versiones y hashes de imágenes.
5. Aplicar y verificar las reglas de contención. Registrar las comprobaciones antes de iniciar la corrida multiagente o de agente único, según el orden aleatorio del bloque.

Cada corrida emparejada parte del mismo estado; los objetivos no se reutilizan sin restaurar (ASR-19, RO-12).

---

## 7. Verificación de contención — ASR-15 / RO-02

Antes de cada bloque se comprueba la contención **desde cada enlace**. La ausencia de respuesta a un `ping` no basta por sí sola: también se inspeccionan rutas, reglas y capturas de la interfaz de salida.

```bash
# En Kali: el puente debe figurar como interno y sin IPv6.
docker network inspect lab_auditoria_ipv4

# Desde obj-ssh: comprobar ausencia de ruta a Internet y gestión.
docker exec obj-ssh ip route
docker exec obj-ssh ip -6 route

# Desde el receptor IPv6 y Metasploitable3: comprobar ausencia de ruta
# a control y gestión usando sus consolas de VM, y observar la salida de Kali.
# Registrar además una prueba positiva de Kali hacia cada objetivo autorizado.
```

Resultado esperado: 0 rutas o conexiones no permitidas desde ambos enlaces de auditoría (ASR-15). La API del observador solo escucha en gestión y requiere autorización del controlador. Las reglas en Kali complementan el aislamiento de las redes internas de VirtualBox y del puente `internal` de Docker; no sustituyen la verificación del anfitrión. El script `firewall/contencion.sh` utiliza la cadena `DOCKER-USER` de Docker cuando el backend es `iptables`; debe adaptarse si el host usa `nftables`.

---

## 8. Archivos de esta carpeta

| Archivo | Contenido |
|---|---|
| `docker-compose.yml` | Objetivos IPv4 contenedorizados de la red de auditoría. |
| `docker-compose.piloto.yml` | Tomcat aislado para la primera corrida real, sin secretos requeridos. |
| `docker-compose.ipv6.yml` | Receptor y emisor del piloto IPv6 en puente Docker interno. |
| `Dockerfile.ipv6`, `ipv6_target.py`, `ipv6_sender.py` | Imagen Python 3.13/Scapy 2.7.0, observador y perfiles finitos de paquetes. |
| `DESPLIEGUE.md` | Este documento: topología, direccionamiento, servicios, restauración y contención. |
| `diagrama_despliegue.svg` | Diagrama de despliegue (nodos, redes y artefactos). |
| `diagrama_despliegue.mmd` | Código Mermaid para pegar en diagrams.net. |
| `firewall/contencion.sh` | Reglas de firewall de contención de la red de auditoría (plantilla). |

> Los valores son de referencia y se confirman al desplegar. Los contenedores no publican puertos en el anfitrión. El proyecto GNS3, el observador separado en red de gestión, el script de instantáneas y el manifiesto de hashes del banco final siguen pendientes; el observador local del piloto IPv6 se describe en la sección siguiente.

## 9. Piloto Docker IPv6 ejecutado

Mientras se arma la auditoría A en VM, `docker-compose.ipv6.yml` crea el enlace aislado `lab_auditoria_ipv6` en `br-lab-ipv6`, con prefijo `fd57:2026:9:28::/64`, emisor `::10` y receptor `::20`. Es `internal: true`; los contenedores no publican puertos ni poseen rutas predeterminadas IPv4/IPv6. La CLI comprueba estas condiciones antes de actuar.

```bash
cd piloto_kali/prototipo
set -a; source ./.env; set +a
docker compose -f ../despliegue/docker-compose.ipv6.yml up -d --build
./.venv/bin/auditoria piloto-ipv6 --completo --autorizacion REF-LAB
```

Los ocho casos GT-09 a GT-16 tienen perfiles finitos. GT-09 a GT-12 observan cambios de ruta, caché NDP, DAD y MTU; GT-13 a GT-16 comparan controles UDP con variantes de fragmentos. Cada tarea guarda PCAP, diagnóstico y huellas SHA-256; reinicia el receptor y comprueba que vuelva a la configuración inicial. `validar-corrida` recalcula integridad y clasifica efectos. Un `candidate` sigue pendiente de corroboración externa; el piloto no declara vulnerabilidades confirmadas.

## 10. Integración preparada para VM

`prototipo/config/lab_virtual.example.json` define los datos que se completan con la topología real: interfaz de auditoría IPv6 y gestión de Kali, direcciones, observador HTTPS, CA y variable del token. `observador_vm.py` ofrece una API de solo lectura en la interfaz de gestión del receptor. `preflight-lab-virtual` verifica rutas por interfaces separadas, la identidad y dirección del receptor y que no reenvíe IPv4 ni IPv6. La prueba en vivo de VM queda pendiente hasta que exista ese laboratorio y se congelen sus direcciones y autorización; la política del piloto Docker no permite usarlo como objetivo de forma automática.
