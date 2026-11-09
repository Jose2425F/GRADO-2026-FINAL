# Centinela · auditoría dual-stack de Novaflow

Prototipo del trabajo de grado de Ingeniería de Sistemas y Computación de la Universidad Católica de Colombia. El panel usa LangGraph para coordinar un catálogo de comprobaciones IPv4 e IPv6 en laboratorios sintéticos. Los hallazgos se corroboran con validadores; un puerto abierto o una coincidencia de versión no equivalen por sí solos a una vulnerabilidad.

El aplicativo vigente está en `piloto_kali/prototipo/` y expone el paquete `auditoria`. La raíz conserva el paquete anterior `auditor_dualstack`, con su propio entorno y sus pruebas. Ambos proyectos declaran la versión de la entrega; no se deben mezclar sus entornos Python.

## Ejecución protegida del punto 11.3

Las auditorías reales de esta integración requieren la instalación del [ejecutor protegido del operador](docs/ajustes-profesor/2026-11-09-roles-origen/Operacion_ejecutor_protegido.txt). El controlador, Nmap e Hydra usan identidades separadas; el acceso a Docker queda limitado a perfiles del banco y la red filtra origen, destino y rol en IPv4 e IPv6. Sin el descriptor instalado y la identidad autorizada, las entradas de auditoría rechazan el despacho.

La [evidencia de 11.3](docs/evidencias-versionadas/2026-11-09-11-3/LEEME.txt) se conserva aparte de las campañas anteriores. Su aceptación comprende los cinco bancos cerrados sin API. La versión `0.6.0` incorpora una cola local entre el panel y el operador, un instalador privado y un intermediario de API separado. Los recibos de esta integración tienen un [paquete propio](docs/evidencias-versionadas/2026-11-09-v4/LEEME.txt); no amplían retroactivamente aquella aceptación ni las cohortes de KPI. Las extensiones por IP o VM requieren una aceptación propia. Abrir el panel con las instrucciones siguientes no instala los permisos del ejecutor. El grupo Docker de los requisitos corresponde al operador, no al proceso web ni al controlador o sus trabajadores.

Las acciones `preflight` y `recover` del operador y sus pruebas de cuarentena se documentan en la [continuación de recuperación](docs/ajustes-profesor/2026-11-09-recuperacion/Recuperacion_y_propiedad_de_leases.txt). Sus evidencias mantienen separado el código y el alcance de la aceptación anterior.

## 1. Requisitos en una instalación nueva de Kali

Ejecuta estos pasos como usuario normal con acceso a `sudo`, en un equipo dedicado al laboratorio. No los apliques a un servidor que ya está atendiendo usuarios.

```bash
sudo apt update
sudo apt install -y git curl ca-certificates python3 python3-venv python3-pip \
  docker.io docker-compose nmap hydra iproute2 nodejs npm
sudo systemctl enable --now docker
sudo usermod -aG docker "$USER"
```

Cierra la sesión y vuelve a entrar para activar el grupo. Comprueba:

```bash
docker info
docker compose version
nmap --version
hydra -h
ip -Version
node --version
npm --version
```

Se necesita Compose v2, accesible como `docker compose`, y Node.js 22 o posterior. Si `docker compose version` falla, completa la instalación de Compose antes de continuar. La [guía oficial de Kali](https://www.kali.org/docs/containers/installing-docker-on-kali/) describe la instalación de Docker y la renovación de la sesión después de añadir el grupo. Pertenecer al grupo Docker permite administrar su daemon; reserva ese acceso al operador del laboratorio.

## 2. Obtener el código e instalar las dependencias fijadas

```bash
git clone https://github.com/Jose2425F/GRADO-2026-FINAL.git
cd GRADO-2026-FINAL
python3 -m venv .venv-uv
.venv-uv/bin/python -m pip install 'uv==0.13.7'
.venv-uv/bin/uv python install 3.13.15
.venv-uv/bin/uv sync --project piloto_kali/prototipo --python 3.13.15 \
  --frozen --extra ipv6 --extra test
```

El panel requiere Python 3.13; no lo ejecutes con el Python de otro entorno. Esta receta y CI fijan la revisión 3.13.15. El comando crea `piloto_kali/prototipo/.venv` y utiliza `piloto_kali/prototipo/uv.lock`. `--frozen` evita resolver versiones nuevas; comprueba también la vigencia del lock con `.venv-uv/bin/uv lock --project piloto_kali/prototipo --check`. El [comportamiento de sincronización](https://docs.astral.sh/uv/concepts/projects/sync/) está documentado por uv.

No utilices `pip install -e ...` sin restricciones como sustituto de esta instalación reproducible. Las dependencias del aplicativo se conservan en el lock; una nueva resolución constituye otra configuración del entorno.

## 3. Crear el directorio de datos y la primera cuenta

El panel no crea una cuenta administrativa por sí solo. Su directorio de datos predeterminado es `/var/lib/centinela`.

```bash
sudo install -d -m 0700 -o "$(id -u)" -g "$(id -g)" /var/lib/centinela
export CENTINELA_DATA_DIR=/var/lib/centinela
piloto_kali/prototipo/.venv/bin/python scripts/administrar_centinela.py \
  --data-dir "$CENTINELA_DATA_DIR" crear-admin admin --nombre 'Administrador'
```

Introduce y confirma una contraseña propia de al menos ocho caracteres cuando la consola la solicite. No la escribas en el comando, en un archivo versionado ni en el README. No uses `--adoptar-historial` para una instalación vacía.

Inicia el panel desde la misma terminal:

```bash
./scripts/iniciar_panel.sh
```

Abre [el panel local](http://127.0.0.1:8765/) e inicia sesión con la cuenta creada. El servidor escucha en loopback. Si el puerto está ocupado, usa otro, por ejemplo `./scripts/iniciar_panel.sh --port 18765`; no detengas el proceso que ya lo ocupa.

La apertura del panel y las pruebas de software no requieren una clave de OpenAI. La configuración privada del proveedor se gestiona aparte y las auditorías con API pueden generar cargos.

En una instalación protegida, `CENTINELA_EXECUTOR_SOCKET` identifica el socket Unix preparado por el operador. El panel envía operaciones del catálogo instalado y recibe resultados sólo después del cierre de los roles. Cada trabajo se asocia a un usuario activo y a una credencial privada de acceso; los resultados se mantienen en su espacio de trabajo. El proceso web no necesita el grupo Docker. Consulta el [procedimiento del operador](docs/operacion/2026-11-09-v4/LEEME.txt) para preparar el ejecutor y sus servicios. La receta de arranque anterior sirve para revisar la interfaz; las auditorías reales requieren además esa instalación.

## 4. Construir las imágenes la primera vez

El panel puede abrirse sin construir los laboratorios. Para usar los cinco bancos se necesitan las imágenes locales y la descarga inicial de PostgreSQL. Ejecuta esta sección únicamente en el Docker del equipo de laboratorio preparado para estas pruebas.

```bash
piloto_kali/prototipo/.venv/bin/python scripts/laboratorio_empresa.py preparar
docker build -t auditoria-lab-v2-app:local \
  -f piloto_kali/despliegue/v2/Dockerfile.app piloto_kali/despliegue
docker pull postgres:16-alpine
piloto_kali/prototipo/.venv/bin/python scripts/laboratorio_empresa.py levantar --construir
piloto_kali/prototipo/.venv/bin/python scripts/laboratorio_empresa.py estado
```

La construcción inicial genera las imágenes de aplicaciones, servicios de credenciales, consola HTTP y protocolos IPv6. Después se fijan sus ID. La restauración posterior utiliza esas referencias y no vuelve a construir ni descargar imágenes. `--construir` se admite antes de que exista esa referencia; no borres una fijación para cambiar las imágenes de una evaluación ya iniciada.

El estado generado, incluidas las credenciales sintéticas, se guarda en carpetas `.lab*` excluidas de Git. Los cuatro escenarios adicionales reutilizan las imágenes locales. Sigue la [guía de preparación](docs/COMO_PREPARAR_TUS_LABORATORIOS.md) y el [protocolo de los cinco laboratorios](docs/PRUEBAS_LANGGRAPH.md) para preparar, cerrar y comprobar cada banco. No actives más de un escenario de la suite a la vez.

## 5. Pruebas de software y navegador

Desde la raíz del repositorio:

```bash
piloto_kali/prototipo/.venv/bin/python -m pytest -c piloto_kali/prototipo/pyproject.toml \
  -q scripts/tests piloto_kali/prototipo/tests
npm ci --prefix scripts/tests
./scripts/tests/node_modules/.bin/playwright install --with-deps chromium
npm test --prefix scripts/tests
npm run test:browser --prefix scripts/tests
```

La instalación de Chromium y sus bibliotecas puede solicitar permisos administrativos en una Kali nueva. Se usa la versión de Playwright declarada en `scripts/tests/package-lock.json`, sin instalar una versión global. La [documentación de Playwright](https://playwright.dev/docs/browsers) explica cómo instalar el navegador correspondiente a cada versión.

Las pruebas de DOM no ejecutan un navegador. La prueba de navegador crea su propia cuenta, carpeta de datos y panel temporal en otro puerto; no utiliza `/var/lib/centinela`, el puerto 8765, el Docker del operador ni llamadas al proveedor. Se comprueban el acceso, los recursos de interfaz y las respuestas del panel. Consulta [scripts/tests/README.md](scripts/tests/README.md) para distinguir estas pruebas de los guiones históricos y de una auditoría real.

El paquete legado se comprueba en un entorno separado:

```bash
.venv-uv/bin/uv sync --project . --python 3.13.15 --frozen --extra dev
.venv/bin/python -m pytest -q tests
```

Las pruebas usan proveedores y controladores simulados, además de servicios locales y una integración de Nmap restringida a loopback. No sustituyen la aceptación de los bancos. Una alerta real del kernel en los bits de taint 7 o 14 bloquea las pruebas de red; recupera el equipo y no elimines esa salvaguarda para obtener un resultado favorable.

La integridad de los paquetes públicos de 11.3 y recuperación se comprueba sin herramientas de auditoría:

```bash
piloto_kali/prototipo/.venv/bin/python docs/evidencias-versionadas/2026-11-09-11-3/verificar.py
piloto_kali/prototipo/.venv/bin/python docs/evidencias-versionadas/2026-11-09-11-3-recuperacion/verificar.py
piloto_kali/prototipo/.venv/bin/python docs/evidencias-versionadas/2026-11-09-v3/verificar.py
piloto_kali/prototipo/.venv/bin/python docs/evidencias-versionadas/2026-11-09-v4/verificar.py
```

Estos verificadores se incluyen en CI. Su opción `--historicos` describe el inventario original completo, con los Word retirados y el LEEME anterior; requiere la copia privada correspondiente y no se ejecuta sobre el árbol público actual. Los manifiestos conservan sus hashes originales. El alcance de esta fusión se registra en [INTEGRACION_11_3.txt](docs/mantenimiento/2026-11-09/INTEGRACION_11_3.txt).

## 6. Comprobar una copia sin usar los datos de otra instalación

Para una revisión manual del arranque, crea una carpeta temporal y una cuenta independiente:

```bash
centinela_prueba_dir=$(mktemp -d)
export CENTINELA_DATA_DIR="$centinela_prueba_dir/datos"
piloto_kali/prototipo/.venv/bin/python scripts/administrar_centinela.py \
  --data-dir "$CENTINELA_DATA_DIR" crear-admin revision --nombre 'Revisión local'
./scripts/iniciar_panel.sh --port 18765 --runs "$centinela_prueba_dir/corridas"
```

Abre `http://127.0.0.1:18765/`. Si ese puerto también está ocupado, elige otro disponible. Al terminar, detén únicamente este proceso desde su propia terminal. No emplees órdenes globales para matar procesos Python ni reinicies un panel ajeno. Los directorios temporales contienen cuentas y sesiones privadas; no se incorporan a Git.

## Datos, evidencias y documentos académicos

Los evaluadores de los laboratorios utilizan archivos `ground_truth.json` generados al preparar cada banco. La referencia se usa para evaluar resultados; no se envía al planificador LLM. El YAML histórico de la raíz se retiró por carecer de lectores en el código actual. No debe confundirse con las referencias JSON necesarias para los bancos.

Las [evidencias históricas de octubre](docs/evidencias-historicas/2026-10-18/README.md) y las [verificaciones de noviembre](docs/evidencias-versionadas/2026-11-09/LEEME.txt) conservan campañas y procedencias separadas. No se mezclan sus KPI ni se convierten verificaciones posteriores en nuevas parejas de la cohorte original.

La tesis en Word se distribuye de forma privada. `docs/entregas/2026-11-09/` conserva sólo su descripción y registros de revisión. La limpieza autorizada del 9 de noviembre retira los dos DOCX de las ramas y etiquetas publicadas, también en sus ancestros. Los manifiestos originales conservan sus huellas; su inventario completo requiere la copia privada original. Los fragmentos de revisión en JSON y ZIP se conservan como evidencia editorial.

La reescritura cambia identificadores Git, no los archivos originales de evidencia. Consulta el [registro de migración](docs/mantenimiento/2026-11-09/REESCRITURA_HISTORIAL.txt) y su [mapa de identificadores](docs/mantenimiento/2026-11-09/mapa-git.json). Si tenías un clon anterior, crea uno nuevo antes de publicar cambios; un merge o push desde la historia antigua puede volver a introducir los Word. Las copias descargadas y las cachés externas quedan fuera del control de esta limpieza.

## Versiones y licencia

Los cambios de publicación e instalación se registran en [CHANGELOG.md](CHANGELOG.md). Los commits, huellas de código y campañas experimentales deben identificarse por separado: el nombre de una etiqueta no demuestra qué ejecutable produjo una medición.

Consulta [LICENSE](LICENSE) para las condiciones indicadas por los titulares: publicación para consulta y evaluación académica y derechos reservados. El acceso público al repositorio no concede permisos adicionales a los expresados allí.

## Proteger `main` en GitHub

El propietario o una cuenta con administración del repositorio debe abrir **Settings → Branches → Add classic branch protection rule** y aplicar el patrón `main`:

1. Exigir pull request y al menos una aprobación antes de integrar.
2. Invalidar aprobaciones antiguas si cambian los commits y exigir resolver conversaciones.
3. Exigir que pasen los trabajos `legado` y `prototipo` del workflow **Pruebas reproducibles**, y que la rama esté actualizada con `main`.
4. Mantener deshabilitados los force push y la eliminación de la rama; aplicar las restricciones también a administradores cuando corresponda.

Los nombres exactos de los checks deben elegirse después de la primera ejecución del nuevo workflow. La cuenta conectada actualmente tiene escritura, pero no administración; esta revisión deja las instrucciones, no afirma que la protección esté activada. Consulta la [guía oficial de GitHub](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches/managing-a-branch-protection-rule).
