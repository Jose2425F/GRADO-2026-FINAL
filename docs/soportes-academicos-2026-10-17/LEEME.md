# Cotejo de los soportes académicos recuperados

Las cuatro hojas de cálculo aportadas por los autores ya están localizadas y se conservaron sin modificar. Esto resuelve su disponibilidad documental. La comparación con el manuscrito identifica también limitaciones de cálculo y diferencias entre el diseño inicial y lo ejecutado. Los resultados experimentales y los objetivos del proyecto permanecen intactos.

La revisión procede de copias locales en `/home/kali/Desktop/Trabajo de Grado`, idénticas por SHA-256 a las de `/home/kali/Downloads`. El enlace privado de OneDrive redirigió al inicio de sesión de Microsoft; no se afirma haber inventariado la carpeta remota. `recepcion.json` registra rutas, hashes y copias privadas. Los originales y el material docente no se publican automáticamente.

| Soporte | Qué permite comprobar | Reserva que permanece |
|---|---|---|
| Cronograma_Gantt_TG2026.xlsx | Fechas, actividades, responsables y fórmulas del calendario propuesto | Los estados dependen de TODAY(), no de evidencia de ejecución o aprobación. El plan contiene funciones y metas del diseño histórico. |
| Presupuesto_TG2026.xlsx | Rubros, parámetros, importes y distribución histórica por fases | No contiene fórmulas; no acredita recálculo automático ni gasto ejecutado. Cuatro subtotales por fase difieren del detalle. |
| Matriz_Comparativa_TG2026.xlsx | Siete antecedentes y el prototipo del diseño inicial | Contiene caracterizaciones y numeración de referencias anteriores a la revisión. Su existencia no valida todas sus afirmaciones. |
| Matriz_ASR_UtilityTree_UCatolica.xlsx | Veinticinco candidatos ASR y doce medidas del Utility Tree, concordantes con las tablas del diseño | La rúbrica no tiene calificaciones asignadas; no equivale a aval docente ni a aceptación individual de todos los requisitos del prototipo. |

## Presupuesto

El total general es **COP 27.476.047**, distribuido en COP 25.602.450 de aportes en especie y COP 1.873.597 de efectivo. Los importes proceden de `Presupuesto!A4:E25`. Las tres hojas contienen valores fijos y **cero fórmulas**, aunque `Parámetros!A2` anuncia recálculo automático. Los valores en `Distribución por fase!B5:H16` permiten reconstruir la distribución; las horas se multiplican por los parámetros de costo correspondientes. Se conserva el resultado derivado sin alterar la hoja original.

| Fase | Fila 17 del Excel, COP | Derivado del detalle, COP |
|---|---:|---:|
| F1 | 3.786.045 | 3.786.045 |
| F2 | 6.043.770 | 6.043.770 |
| F3 | 2.786.885 | 2.786.885 |
| F4 | 2.382.113 | 1.947.113 |
| F5 | 6.855.056 | 7.063.386 |
| F6 | 3.426.953 | 4.695.273 |
| F7 | 2.195.225 | 1.153.575 |
| Total | 27.476.047 | 27.476.047 |

Las diferencias se compensan en el total y no deben ocultarse por comprobar solo la suma global. Los importes derivados coinciden con la conciliación textual que ya figuraba en el Anexo F. Los modelos, tarifas y reservas de esta hoja corresponden al presupuesto histórico propuesto; no sustituyen el costo medido ni la factura de la campaña con API.

## Cronograma

Las columnas C y D de `Cronograma Gantt!B8:E45` contienen fechas propuestas. La columna E calcula sus estados a partir de `TODAY()`. En E38, por ejemplo, «Logrado» depende de alcanzar la fecha D38, sin consultar TRTO, IDE o ETV. El cierre experimental mantiene los resultados medidos: trece parejas formales de quince previstas y metas de tiempo y detección no alcanzadas.

La hoja programa revisión del director del 19 al 23 de octubre y entrega final para el 30 de octubre de 2026. Esas fechas no prueban entrega ni aprobación institucional. B30 incluye exploits y SMB relay; B32 menciona Phoenix; B35 usa N=16, y B37 propone Wilcoxon con potencia de al menos 0,80. Esos elementos se diferencian del alcance, la instrumentación y el análisis exploratorio realmente documentados.

## Matrices

La matriz comparativa conserva siete antecedentes más el prototipo en `'Matriz comparativa'!A1:H9` y una hoja de notas. Su clasificación de PentestAgent y VulnBot, la línea base descrita y las afirmaciones generales sobre IPv6 deben leerse con las correcciones del capítulo 2. Se preserva la numeración histórica del Excel y se advierte que no corresponde automáticamente a las 66 referencias actuales del manuscrito.

La matriz ASR tiene veinticinco identificadores y doce medidas coincidentes con el diseño documentado: veintiún candidatos aceptados, tres descartados como decisiones arquitectónicas y uno por validar. Ese estado es histórico. La hoja de rúbrica no contiene calificaciones asignadas: un total calculado o almacenado como cero no es una nota de aprobación. El libro también incluye material docente que se conserva privado.

## Pendientes que estos cuatro archivos no resuelven

No se ha localizado `Bibliometrix_TG2026.xlsx`, la exportación original de Scopus ni la bitácora de cribado. Las cifras históricas de 425 registros y 35 fuentes siguen requiriendo esos soportes. La matriz comparativa de siete sistemas no reemplaza ese corpus ni sus decisiones de inclusión y exclusión.

Tampoco se acredita una plantilla integral vigente para la tesis ni aprobación institucional mediante la rúbrica docente incluida en ASR. La presentación NTC 1486 y las referencias IEEE se conservan según la revisión anterior. Las reservas sobre muestra parcial, generalización, validación semántica independiente y VM independiente permanecen.

Los archivos JSON de esta carpeta detallan celdas, método de cotejo, huellas y discrepancias. La actualización del Word reconoce la disponibilidad recuperada sin convertir la planificación en evidencia de ejecución. No se ejecutaron laboratorios, llamadas API de pago ni operaciones de publicación en GitHub.
