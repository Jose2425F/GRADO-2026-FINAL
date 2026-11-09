# Registro de cambios

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
