# Registro de cambios

## 0.6.0 · integración protegida del panel y revisión de reportes

- Conecta el panel con una cola local del operador. Limita las solicitudes a los cinco bancos instalados y vincula cada trabajo a una cuenta activa y una credencial privada de acceso.
- Instala una copia fijada por huellas de código, intérprete, dependencias e imágenes en un daemon separado. Las operaciones de preparación, comprobación, recuperación y cierre conservan los bloqueos y las cuarentenas.
- Separa las consultas al proveedor del controlador y de los trabajadores. La clave permanece en la configuración privada del operador; el intermediario aplica límites de tiempo, peticiones y presupuesto.
- Conserva los cierres parciales y verifica los recibos antes de publicar un resultado. Corrige las proyecciones JSON, HTML y PDF y la relación entre solicitud, plan, intento, evidencia y hallazgo.
- Conserva el nombre y la fecha de la auditoría al publicar exportaciones con un nivel `runs` adicional, mediante búsquedas de metadatos limitadas al espacio autorizado.
- Unifica en `0.6.0` los dos proyectos y sus metadatos de ejecución, sin cambiar las versiones externas fijadas. Añade pruebas de contrato y verificadores de los nuevos paquetes públicos a CI.
- Conserva íntegramente las campañas y evidencias anteriores. Los paquetes `2026-11-09-v3` y `2026-11-09-v4` identifican sus propios cortes de código, pruebas y alcance; la tesis se distribuye por vía privada.

Los recibos de aceptación y despliegue se consultan en el paquete v4. Esta versión no recupera el código ni las imágenes exactas de octubre y no convierte una prueba funcional del proveedor en una nueva campaña comparable de KPI.

## Integración del punto 11.3 · corte previo 957972c

Integra `ajustes/11-3-cierre-20261109` sobre el mantenimiento de `main`, conservando la historia pública depurada y sus etiquetas.

- Incorpora la autorización registrada del alcance, la separación de controlador y trabajadores, el broker limitado a perfiles instalados y el filtrado por origen IPv4 e IPv6.
- Conserva el rechazo de auditorías reales sin descriptor e identidad protegidos, la cuarentena persistente y la comprobación de recuperación del operador.
- Añade los paquetes originales de evidencias de 11.3 y recuperación sin alterar sus bytes ni los de las campañas anteriores.
- Mantiene los locks, versiones, pruebas de navegador y CI de `main`; añade la verificación de los paquetes públicos desde la raíz del repositorio.

Los controles simulados y los verificadores de integridad no representan una nueva aceptación de bancos reales ni un despliegue en AWS. La integración del ejecutor con panel, API y extensiones por IP o VM mantiene los límites documentados en los cortes de 11.3.

## 2026-11-09 · mantenimiento del repositorio

Preparado inicialmente sobre `bc7f7d5`, corte de `main` correspondiente a `centinela-2026.11.09`, y reconstruido sobre `3896bde` después de retirar los Word del historial. No incorpora las ramas posteriores de separación de privilegios ni modifica la lógica del aplicativo.

- Retira los dos Word de `docs/entregas/2026-11-09/` de la versión actual y de los ancestros de las tres ramas y cuatro etiquetas públicas, con autorización expresa. Conserva los registros de revisión y un mapa de los identificadores Git anteriores y nuevos en `docs/mantenimiento/2026-11-09/`.
- Retira `ground_truth/ground_truth.yaml`, sin lectores en el código actual. Conserva las referencias `ground_truth.json` que generan y utilizan los laboratorios.
- Unifica los dos metadatos de paquete en `0.5.0`. Los paquetes legado y vigente mantienen sus entornos separados.
- Añade el lock del paquete legado y fija las herramientas de construcción. Conserva las versiones del lock del aplicativo y añade cobertura como dependencia de pruebas.
- Documenta la instalación en Kali, la primera cuenta, la construcción inicial de imágenes y la comprobación con datos temporales.
- Incluye las pruebas de `scripts/tests`, DOM y un arranque autenticado con navegador en CI. La prueba de navegador crea y elimina su propio panel y sus datos.
- Sustituye una ruta absoluta en `docs/PRUEBAS_LANGGRAPH.md` y añade las condiciones de publicación académica en `LICENSE`.

Los manifiestos y paquetes originales de evidencias conservan sus bytes y sus huellas. Los verificadores del inventario completo de una publicación anterior necesitan ese corte original; no deben utilizarse para certificar un árbol posterior con archivos retirados intencionalmente.

## 0.5.0 · corte `centinela-2026.11.09`

La etiqueta apuntaba originalmente a `bc7f7d58a1728e3d56ffbd4b3c18534283ad1755`; después de la limpieza apunta a `3896bdef475f3aa8b6902224a5c6b7cfec755064`. Sólo se retiraron de ese corte los dos Word. Incluye el aplicativo, los registros de revisión y las evidencias versionadas del 9 de noviembre. Los cambios de instalación y CI de este mantenimiento quedan en un commit posterior y no se atribuyen a esa etiqueta histórica.

### Procedencia experimental

La huella de fuentes `b71168c1be21f6c9270efe4cf0b743bf6bafb0cb29c514d6082de51bf1e43937` se reproduce con el algoritmo de `458675b` y figura en la campaña del 8 de noviembre. La evidencia de octubre registra `f9989505e528b788a5655b1acc3a990768489732b2af9fe0a2b634f7620e530d`; no se encontró un commit disponible que reproduzca esa huella. No se atribuye por ello el código de `458675b` a la ejecución de octubre ni se mezclan los KPI de ambas campañas.

La etiqueta propuesta `estudio-2026-10` queda pendiente de resolver esa correspondencia. Los cambios de empaquetado y de lock también pueden cambiar la huella calculada por versiones posteriores del algoritmo, aunque no cambien las funciones del aplicativo.
