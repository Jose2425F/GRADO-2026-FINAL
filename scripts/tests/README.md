# Verificación del panel

El acceso multiempresa y las publicaciones se comprueban con
`piloto_kali/prototipo/.venv/bin/python -m pytest -q scripts/tests/test_centinela_accounts.py`.
Incluye servidores HTTP temporales, sesiones, permisos, comprobación y ejecución de
auditorías con un proceso simulado, entrega de informes y retirada de acceso.
No ejecuta herramientas de auditoría ni consume OpenAI.

Para comprobar el JavaScript vigente sin navegador ni red, instala las dependencias
de prueba con `npm ci --prefix scripts/tests` y ejecuta
`node --test scripts/tests/test_centinela_ui.cjs` desde la raíz del repositorio.
Requiere Node 18 o posterior y el entorno Python del prototipo. Cubre el login,
navegación, historial, publicación y retirada por empresa, e informes sin datos.
Estas pruebas de DOM no sustituyen una revisión visual en navegador.

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
`piloto_kali/prototipo/.venv/bin/python -m pytest -q scripts/tests/test_panel_assets.py`.

Las pruebas Python `test_*.py` cubren contratos y módulos; se conservan después de limpiar el historial de auditorías. Ver el comando vigente en `docs/cierre-tesis/LEEME.md`.

La interfaz vigente se comprueba con `tesis_novaflow.browser.mjs` (estado HTTP controlado y todas las acciones de auditoría interceptadas). `archivo_tesis.browser.mjs` verifica la entrega inicial contra el archivo real conservado, el historial recién limpiado y el informe de aceptación del banco; solo hace GET y necesita los artefactos de esta instalación. No es una prueba portable con datos vacíos.

`panel_navigation.browser.mjs` cubre el bloqueo global, disponibilidad actual, ayudas por banco, navegación atrás/recarga, conservación del modo por IP y carga inicial de KPI históricos. Intercepta todas las acciones; el argumento opcional de salida captura aparte el estado real mediante GET.

Los otros archivos `.browser.mjs` documentan regresiones de las interfaces anteriores y sus fixtures; sus menús, datos y capturas corresponden a esos cortes. No constituyen el procedimiento de aceptación de la interfaz NovaFlow actual. No deben confundirse pruebas de interfaz, aceptación funcional del banco, comprobaciones API y corridas de la muestra experimental.


La batería integral incluye pruebas de conexión TCP a servidores locales de prueba y controladores que consultan el kernel real. Debe ejecutarse con el kernel limpio. Con tainted en bits 7/14 esas rutas se bloquean correctamente y sus expectativas de éxito fallan; no desactivar ni falsear esa salvaguarda para lograr un resultado verde. El 17/10/2026 hubo 164 aprobadas antes del fallo; una repetición posterior produjo 24 fallos por esa precondición ambiental. Las pruebas unitarias offline del conductor y de recuperación se verifican separadamente con `python -m unittest scripts.tests.test_interrupciones scripts.tests.test_estudio_novaflow -q`, sin tráfico de auditoría ni llamadas al proveedor.
