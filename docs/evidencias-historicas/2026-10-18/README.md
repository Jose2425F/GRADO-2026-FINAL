# Evidencias de la evaluación del 18–19 de octubre de 2026

Este paquete conserva los registros originales de la evaluación citada en **TrabajoDeGrado_II_Completo_6.docx**. Se recuperó del respaldo de octubre en Google Drive y se verificó el 9 de noviembre de 2026. Esa fecha corresponde a la recuperación, no a nuevas auditorías.

## Resultados respaldados

| Comprobación | Resultado histórico |
|---|---:|
| Auditorías registradas | 50: 48 completas y 2 parciales |
| Parejas elegibles | 23 de 25 |
| TRTO medio | 19,36 % |
| IDE medio | 26,41 % |
| ETV medio | 1,51 |
| Tokens totales | 891.821 |
| Costo local estimado | USD 2,28 |
| Aceptación sin IA | 154/154 tareas; cinco laboratorios |
| Pruebas de software originales | 708 aprobadas, 2 omitidas; 59 subcasos aprobados |
| Eventos conservados | 17.692 en 50 bases SQLite |
| Requisitos | 48 validados y 31 parciales; siete pendientes críticos |

Los dos intentos parciales y las parejas excluidas se conservan. La meta temporal del 30 % no se alcanzó; el intervalo exploratorio de IDE incluye valores inferiores al 20 %. Los pendientes y las limitaciones del documento mantienen su estado.

## Archivos para revisar

- [Exportación, protocolo, corridas y KPI](../../evaluacion-langgraph/): archivos JSON/CSV y ZIP utilizados en el documento.
- [Recibos de verificación posterior](../../verificacion-postevaluacion/): pruebas, integridad, secretos, privilegios, aislamiento y denominadores.
- [auditorias-originales.zip](auditorias-originales.zip): los **3.649 archivos** de las 50 auditorías, con informes, planes, solicitudes, manifiestos, bases de eventos, capturas y contextos del proveedor. Sus bytes coinciden con el [inventario histórico de huellas](hashes-corridas-50.json).
- [aceptacion-original.zip](aceptacion-original.zip): **447 archivos** de la aceptación de los cinco laboratorios. Los 25 informes, planes, solicitudes, manifiestos y evaluaciones principales coinciden con las huellas del recibo antiguo.
- [verificaciones-originales.zip](verificaciones-originales.zip): **41 soportes**, incluidos los XML y registros de pruebas. Se conserva también el pase anterior con dos subcasos bloqueados por la guarda de Nmap; el recibo explica su resolución.
- [soportes-academicos.zip](soportes-academicos.zip): cinco libros originales de bibliometría, matrices, presupuesto y cronograma. Los [recibos documentales](../../soportes-academicos-2026-10-17/) se conservan por separado.
- [Procedencia y alcance](procedencia.json), [integridad de la publicación](integridad-publicacion.json) y [revisión de contenido del corpus](revision-publicacion-corpus-20261109.json).

## Comprobación local

Desde la raíz del repositorio, con Python 3.10 o posterior:

```bash
python3 docs/evidencias-historicas/2026-10-18/verificar.py
```

El comando comprueba las huellas de los archivos publicados y de los 3.649 originales, cuenta los eventos, verifica la aceptación y el XML de pruebas, y recalcula los KPI, medianas e intervalos exploratorios. Sólo lee archivos locales y usa un directorio temporal para abrir las bases SQLite; no ejecuta auditorías ni consulta la API.

Los ZIP conservan rutas de origen. Para inspeccionarlos, extráelos en una carpeta vacía de revisión. El paquete de auditorías contiene `piloto_kali/prototipo/corridas/`; el de verificaciones conserva `piloto_kali/prototipo/.verificacion/`.

La copia de Word revisada tiene SHA-256 `193e81204a2ef57284abe2d3c740d9b3417bdf6fb7d1a48baa66c3e7fedfed2e`. El documento se identifica por su huella y no se incluye en esta publicación.

## Conservación y límites

Este directorio corresponde exclusivamente al estudio de octubre. Las evaluaciones posteriores deben guardarse en directorios con su propia fecha, sin sustituir estos resultados. El identificador del protocolo por sí solo no distingue diferentes ejecuciones.

La recuperación verificó las 50 filas del documento, todos los archivos del inventario y las huellas de los recibos disponibles. La revisión de publicación comprobó secretos conocidos de los cinco laboratorios, representaciones codificadas y patrones de credenciales. Cinco marcas automáticas en `slot.json` se revisaron como el identificador público `LAB-PROPIO`; la [resolución](revision-publicacion-soportes-20261109.json) conserva el resultado automático y su justificación.

No se incluyen claves, credenciales de referencia, archivos `lab.env`, configuración privada ni imágenes Docker. Las comprobaciones se limitan a los registros conservados: no reconstruyen estados de memoria, tráfico no capturado ni respuestas del proveedor que no se hayan guardado. Preservar la evidencia no convierte los requisitos parciales en cumplidos ni acredita uso fuera del laboratorio.
