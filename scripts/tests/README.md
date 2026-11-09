# Verificación del panel

El acceso multiempresa y las publicaciones se comprueban con
`piloto_kali/prototipo/.venv/bin/python -m pytest -c piloto_kali/prototipo/pyproject.toml -q scripts/tests/test_centinela_accounts.py`.
Incluye servidores HTTP temporales, sesiones, permisos, comprobación y ejecución de
auditorías con un proceso simulado, entrega de informes y retirada de acceso.
No ejecuta herramientas de auditoría ni consume OpenAI.

Para comprobar el JavaScript vigente sin navegador ni red, instala las dependencias
de prueba con `npm ci --prefix scripts/tests --ignore-scripts --no-audit --no-fund` y ejecuta
`npm test --prefix scripts/tests` desde la raíz del repositorio.
El entorno de CI fija Node 24.19.0, npm 11.17.0 y Playwright 1.65.0; para estos
comandos se requiere Node 22 o posterior y el entorno Python del prototipo. Cubre el login,
navegación, historial, publicación y retirada por empresa, e informes sin datos.
Estas pruebas de DOM no sustituyen una revisión visual en navegador.

La prueba portable de arranque es `centinela.smoke.browser.mjs`. Primero instala
el navegador gestionado con
`scripts/tests/node_modules/.bin/playwright install chromium` y luego ejecuta
`npm run test:browser --prefix scripts/tests`. En Linux, Playwright necesita las
bibliotecas del sistema indicadas por su instalador; CI las prepara con
`playwright install --with-deps chromium` en su máquina temporal. No requiere
un Chromium en `/usr/bin`. `PLAYWRIGHT_BROWSERS_PATH` permite mantener la descarga
en una carpeta de trabajo; debe conservar el mismo valor al instalar y ejecutar.

Esta prueba crea su propio servidor, almacenamiento vacío y administrador
temporal con contraseña aleatoria. Comprueba el inicio y cierre de sesión,
la interfaz de administración, los recursos locales y el historial vacío.
Rechaza solicitudes externas y acciones de auditoría o proveedor; usa un
endpoint Docker inexistente. No necesita un panel ya publicado ni datos reales.
`CENTINELA_SMOKE_ARTIFACTS` permite guardar el resumen JSON y la captura en una
carpeta elegida. El servidor y los datos temporales se eliminan al terminar.

Prepara el entorno Python desde su lock, sin mezclarlo con el paquete legado
de la raíz: `uv sync --project piloto_kali/prototipo --frozen --extra test --extra ipv6`.
La batería del prototipo y los scripts usa su configuración explícita:
`piloto_kali/prototipo/.venv/bin/python -m pytest -c piloto_kali/prototipo/pyproject.toml -q scripts/tests piloto_kali/prototipo/tests`.
Incluye una integración real con Nmap contra dos servidores HTTP temporales,
exclusivamente en `127.0.0.1` y `::1`, por lo que necesita Nmap y loopback IPv6.
Las guardas de CI permiten únicamente ese perfil y bloquean herramientas de
auditoría y destinos externos. Las dependencias se instalan antes de activar
esas guardas; ninguna prueba solicita una auditoría contra AWS ni usa una API de IA.

Las plantillas cargan CSS, JavaScript e imágenes locales mediante
`{{ asset_url('archivo.js') }}` (por ejemplo, en el atributo `src` de un script;
para una hoja de estilos se usa en `href`). La URL recibe una huella SHA-256 del
contenido al renderizar la página: no se editan números de versión, no hay paso de
compilación y los cambios de interfaz se recogen al volver a abrir o recargar la
página, sin reiniciar el servicio. Los archivos viven en `scripts/dualstack_ui/`.
Para nuevos recursos, usa el mismo helper en la plantilla. El HTML conserva
`Cache-Control: no-store`. Una pestaña ya abierta necesita recargarse para ejecutar
el JavaScript nuevo; no se fuerza una recarga mientras el usuario trabaja.
Verifica este comportamiento con
`piloto_kali/prototipo/.venv/bin/python -m pytest -c piloto_kali/prototipo/pyproject.toml -q scripts/tests/test_panel_assets.py`.

Las pruebas Python `test_*.py` cubren contratos y módulos; se conservan después de limpiar el historial de auditorías. Ver el comando vigente en `docs/cierre-tesis/LEEME.md`.

La interfaz vigente se comprueba con `tesis_novaflow.browser.mjs` (estado HTTP controlado y todas las acciones de auditoría interceptadas). `archivo_tesis.browser.mjs` verifica la entrega inicial contra el archivo real conservado, el historial recién limpiado y el informe de aceptación del banco; solo hace GET y necesita los artefactos de esta instalación. No es una prueba portable con datos vacíos.

`panel_navigation.browser.mjs` cubre el bloqueo global, disponibilidad actual, ayudas por banco, navegación atrás/recarga, conservación del modo por IP y carga inicial de KPI históricos. Intercepta todas las acciones; el argumento opcional de salida captura aparte el estado real mediante GET.

Los otros archivos `.browser.mjs` documentan regresiones de las interfaces anteriores y sus fixtures; sus menús, datos y capturas corresponden a esos cortes. No constituyen el procedimiento de aceptación de la interfaz NovaFlow actual. No deben confundirse pruebas de interfaz, aceptación funcional del banco, comprobaciones API y corridas de la muestra experimental.


La batería integral incluye pruebas de conexión TCP a servidores locales de prueba y controladores que consultan el kernel real. Debe ejecutarse con el kernel limpio. Con tainted en bits 7/14 esas rutas se bloquean correctamente y sus expectativas de éxito fallan; no desactivar ni falsear esa salvaguarda para lograr un resultado verde. El 17/10/2026 hubo 164 aprobadas antes del fallo; una repetición posterior produjo 24 fallos por esa precondición ambiental. Las pruebas unitarias offline del conductor y de recuperación se verifican separadamente con `python -m unittest scripts.tests.test_interrupciones scripts.tests.test_estudio_novaflow -q`, sin tráfico de auditoría ni llamadas al proveedor.
