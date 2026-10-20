#!/usr/bin/env bash
# Monta 3 laboratorios de empresa de prueba por orden de dificultad (IPv4) para
# ejercitar el modo "por IP" del prototipo y su planificador con IA.
# Objetivos sintéticos con credenciales débiles (detectables) y señuelos endurecidos.
# Requiere las imágenes: novaflow-lab-credentials:local, novaflow-lab-http:local, postgres:16-alpine
set -u

CF=(--cap-drop=ALL --cap-add=CHOWN --cap-add=SETUID --cap-add=SETGID --cap-add=DAC_OVERRIDE --cap-add=SYS_CHROOT --security-opt=no-new-privileges --memory=128m --pids-limit=64)
PG=(--security-opt=no-new-privileges --memory=192m --tmpfs /var/lib/postgresql/data:rw,size=128m --tmpfs /run/postgresql:rw,size=8m)
HT=(--cap-drop=ALL --security-opt=no-new-privileges --read-only --memory=64m)
STRONG() { openssl rand -hex 20; }

creds() { # nombre red ip password
  docker rm -f "$1" >/dev/null 2>&1
  docker run -d --name "$1" --network "$2" --ip "$3" "${CF[@]}" -e LAB_TARGET_PASSWORD="$4" novaflow-lab-credentials:local >/dev/null && echo "  $1 ($3) ssh+ftp"
}
pg() { # nombre red ip user password
  docker rm -f "$1" >/dev/null 2>&1
  docker run -d --name "$1" --network "$2" --ip "$3" "${PG[@]}" -e POSTGRES_USER="$4" -e POSTGRES_PASSWORD="$5" postgres:16-alpine >/dev/null && echo "  $1 ($3) postgresql"
}
http() { # nombre red ip user password
  docker rm -f "$1" >/dev/null 2>&1
  docker run -d --name "$1" --network "$2" --ip "$3" "${HT[@]}" -e LAB_HTTP_USER="$4" -e LAB_HTTP_PASSWORD="$5" novaflow-lab-http:local >/dev/null && echo "  $1 ($3) http"
}
netw() { # nombre subnet bridge
  docker network rm "$1" >/dev/null 2>&1
  docker network create --driver bridge --internal --subnet "$2" --gateway "${2%.*}.1" -o com.docker.network.bridge.name="$3" "$1" >/dev/null && echo "red $1 $2"
}

echo "== LAB FÁCIL: MiniCorp (192.168.82.0/24) =="
netw labs_facil 192.168.82.0/24 br-facil
creds  facil-files   labs_facil 192.168.82.11 labuser      # DÉBIL ssh+ftp labuser/labuser
pg     facil-db      labs_facil 192.168.82.12 postgres postgres   # DÉBIL postgres/postgres
http   facil-web     labs_facil 192.168.82.13 admin admin         # DÉBIL admin/admin

echo "== LAB MEDIO: Intermodal S.A. (192.168.83.0/24) =="
netw labs_medio 192.168.83.0/24 br-medio
pg     medio-crm     labs_medio 192.168.83.22  admin admin        # DÉBIL admin/admin (2a del dicc.)
http   medio-portal  labs_medio 192.168.83.61  tomcat tomcat      # DÉBIL tomcat/tomcat (2a del dicc.)
creds  medio-files   labs_medio 192.168.83.140 labuser            # DÉBIL ssh+ftp labuser/labuser
creds  medio-vpn     labs_medio 192.168.83.45  "$(STRONG)"        # SEÑUELO ssh+ftp fuerte
http   medio-extranet labs_medio 192.168.83.199 ops "$(STRONG)"   # SEÑUELO http fuerte

echo "== LAB DIFÍCIL: Consorcio Global (192.168.84.0/24) =="
netw labs_dificil 192.168.84.0/24 br-dificil
pg     dif-archivo   labs_dificil 192.168.84.73  labuser labuser  # DÉBIL postgres labuser/labuser (3a del dicc.)
http   dif-consola   labs_dificil 192.168.84.158 manager manager  # DÉBIL http manager/manager (3a del dicc.)
creds  dif-respaldo  labs_dificil 192.168.84.211 labuser          # DÉBIL ssh+ftp labuser/labuser
creds  dif-vpn       labs_dificil 192.168.84.19  "$(STRONG)"      # SEÑUELO ssh+ftp fuerte
pg     dif-datos     labs_dificil 192.168.84.88  svc "$(STRONG)"  # SEÑUELO postgres fuerte
http   dif-web       labs_dificil 192.168.84.120 ops "$(STRONG)"  # SEÑUELO http fuerte
creds  dif-salto     labs_dificil 192.168.84.176 "$(STRONG)"      # SEÑUELO ssh+ftp fuerte

echo "Listo. Espere ~10 s a que arranquen los servicios (PostgreSQL y SSH)."
