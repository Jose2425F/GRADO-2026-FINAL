# Guía única de las 50 posiciones con LangGraph

**Antes de ejecutar, reinicia Kali y completa la aceptación sin IA.** El límite del 60 % ya fue autorizado e implementado: Original 19/32, Sucursal 15/25, Comercial 16/28, Mixto 19/32 y Reforzado 22/37. Incluye tareas previas y se consume al admitir cada tarea, también si falla. Se aplica por igual a ambas arquitecturas con API, incluidas prácticas. Dejar tareas fuera no garantiza dejar positivos sin detectar: en los cinco bancos todos los positivos pueden caber; IDE puede ser 0 %. No se modifica la referencia ni se buscan resultados favorables.

## Qué está preparado

Cinco laboratorios, cinco parejas por laboratorio, una corrida única y otra multiagente por pareja: 50 posiciones. Modelo gpt-6.1-sol, 60.000 tokens, 2 USD por corrida como tope conservador local y 2400 segundos por auditoría (incluye revisión, excluye restauración). El costo guardado se estima con uso informado y tarifas; la factura corresponde al proveedor. El agente de desarrollo no ejecuta auditorías con API.

La configuración y Compose de los cinco laboratorios están preparados. Su aceptación real requiere recuperar Kali y comprobar/restaurar cada uno; no se presentan como probados con tráfico por una validación de archivos.

## A. Abrir

Guarda tu trabajo y reinicia Kali. Después, en una terminal:

```bash
cd '/home/kali/Desktop/Trabajo de Grado/Trabajo-de-grado-2026'
./scripts/iniciar_panel.sh
```

Abre http://127.0.0.1:8765/. Mantén la terminal abierta. Si sigue el aviso «Auditorías bloqueadas en este equipo», no inicies pruebas. La restauración de Docker no limpia el indicador del kernel.

## B. Aceptación funcional de los cinco laboratorios, sin IA

Abre **Laboratorio** y pulsa **Aceptar los cinco laboratorios sin IA**. No pulses Iniciar detección real con IA para este paso. El proceso restaura, comprueba rutas y contenedores, ejecuta el catálogo completo y cierra cada banco antes de pasar al siguiente. Es una comprobación funcional distinta de las 50 corridas; no avanza sus posiciones y no llama al proveedor.

Espera al resultado **Aceptación completa · 5/5 laboratorios**: cada fila debe mostrar **Aceptado**, con tareas válidas Original 32/32, Sucursal 25/25, Comercial 28/28, Mixto 32/32 y Reforzado 37/37; además debe indicar 0 generaciones API y 0 tokens. Se exige evidencia íntegra y `acceptance_passed=true`, no sólo un proceso terminado. Si se detiene, revisa el banco y la fase indicados; si informa fallo del kernel, reinicia y repite. No empieces la muestra pagada antes de tener los cinco aceptados. Los recibos anteriores se conservan al repetir.

La aceptación ejecuta el grafo y las herramientas sin IA; no demuestra todavía la calidad de planificación/revisión del modelo. Al finalizar debes restaurar y comprobar de nuevo el banco de la primera posición.

## C. Elegir la siguiente posición y el laboratorio

Abre **Evaluación y KPI** y pulsa **Preparar siguiente posición**. También existe **Usar siguiente posición del protocolo** en la preparación. Estos botones sólo rellenan laboratorio, pareja y arquitectura; no ejecutan auditorías. Sigue el orden de la tabla, sin elegir otra arquitectura por preferencia.

En **Preparar auditoría**, paso **Tu red**, revisa **Laboratorio empresarial**. Las opciones son banco original, Sucursal Esencial, Operación Comercial, Empresa Mixta y Entorno Reforzado. Mantén **Registrar en la nueva evaluación** activado y el número de pareja indicado. Antes de cambiar de laboratorio, incluido el Original, pulsa **Bajar este escenario** mientras todavía esté seleccionado; espera el cierre y después prepara la siguiente posición.

## D. Restaurar y comprobar antes de CADA corrida

En el panel de preparación pulsa **Restaurar**. En la ventana de confirmación pulsa **Restaurar laboratorio**. Espera a que la operación termine. Después pulsa **Comprobar** y continúa sólo cuando el laboratorio esté listo y la restauración esté comprobada.

El Original utiliza un proyecto Docker aislado y una referencia de imágenes por ID. Restaurar recrea los contenedores con esas mismas imágenes, sin construir ni descargar. El recibo comprueba que la identidad coincida. Los demás laboratorios del equipo se conservan.

Se exige una restauración distinta para cada corrida, incluso entre las dos de una pareja. La comprobación sola no sustituye la restauración. El servidor guarda un recibo, lo consume al iniciar y no permite reutilizarlo. Un reinicio invalida recibos anteriores.

## E. Ejecutar agente único o multiagente

En **Tu red**, pulsa **Elegir pruebas →**. En **Qué revisar**, conserva el alcance del laboratorio y pulsa **Elegir agentes →**. En **Agentes e inicio**, revisa la arquitectura de la posición actual, **Con OpenAI**, **Revisión LLM de las observaciones** y 60.000 tokens. El modelo se configura privadamente como gpt-6.1-sol; no debe cambiar entre posiciones.

Pulsa **Iniciar detección real con IA →**. Éste es el paso que puede generar cargos. No pulses una segunda vez ni inicies otras auditorías. El registro conserva laboratorio, pareja, modo, versión/grafo, límites, prueba de restauración, tiempos, uso de entrada/salida, costo estimado, TP/FP/FN/TN y estado. Si el proveedor no informa un dato, queda desconocido; no se inventa un cero.

Para la segunda corrida de una pareja vuelve a **Evaluación y KPI**, prepara la siguiente posición y repite la restauración y comprobación. Nunca se comparte una restauración entre ambas.

## F. Saber cómo terminó y actuar si falla

En **Seguimiento**, consulta **Consola técnica**, **Pruebas y actividad**, **Agentes LLM** y **Arquitectura en vivo**. «Finalizada» indica cierre técnico; no garantiza que la pareja sea apta. «Finalizada con incidencias», «Fallida», «Bloqueada» o «Interrumpida» requieren revisar el motivo. Una omisión con motivo «no seleccionada por presupuesto» es cobertura parcial prevista; un fallo, bloqueo o cancelación sigue siendo una incidencia. El informe guarda catálogo, límite y tareas ejecutadas por separado. FN incluye positivos no detectados y TN sólo negativos comprobados; los negativos sin examinar aparecen aparte.

Si falla, conserva el intento y su mensaje. No borres el registro ni lo reemplaces con uno favorable. Corrige el entorno, restaura y comprueba antes de continuar con la siguiente posición. Si el fallo indica kernel, recuperación o reinicio primero. Una práctica adicional, con **Registrar en la nueva evaluación** desmarcado, se guarda separada y no reemplaza la posición fallida. Una práctica con API también utiliza el límite del 60 %, pero no sustituye un intento del estudio.

## G. Ver y exportar resultados

En **Resultados**, selecciona la corrida y abre **Informe técnico ↗** o **Informe ejecutivo ↗**. En **Evaluación y KPI**, la matriz muestra las 50 posiciones, los fallos y la aptitud de cada pareja. Los KPI pendientes no se presentan como cero.

Al terminar, abre **Evaluación y KPI** y pulsa **Descargar datos de evaluación (ZIP)**. Ese ZIP es el archivo principal que puedes compartir para revisión. También puedes usar **Descargar tabla de corridas (CSV)**. El ZIP incluye protocolo, 50 filas (incluidas fallidas/no iniciadas), datos de parejas, resumen y huellas de integridad; no incluye claves, prompts, cookies, PCAP ni evidencia cruda.

Se comprobará integridad, duplicados, posiciones faltantes, modelo, límites, código, restauraciones y comparabilidad. TRTO, IDE y ETV se recalculan por laboratorio y como agregado descriptivo de parejas compatibles. Los fallos y resultados desfavorables permanecen visibles. Un agregado no elimina las diferencias entre laboratorios ni demuestra causalidad.

## Orden reproducible

Semilla 20261018. Sorteo estratificado: 3/2 primeros modos por laboratorio y 13/12 en total. Se sortea una vez; el panel no vuelve a barajar. Las filas siguientes representan 50 corridas: primero la columna Primera y luego Segunda, restaurando entre ellas.

| Corridas | Laboratorio | Pareja | Primera | Segunda |
|---|---|---:|---|---|
| 1–2 | Original | 1 | Agente único | Multiagente |
| 3–4 | Original | 2 | Agente único | Multiagente |
| 5–6 | Original | 3 | Multiagente | Agente único |
| 7–8 | Original | 4 | Agente único | Multiagente |
| 9–10 | Original | 5 | Multiagente | Agente único |
| 11–12 | Sucursal | 1 | Multiagente | Agente único |
| 13–14 | Sucursal | 2 | Agente único | Multiagente |
| 15–16 | Sucursal | 3 | Agente único | Multiagente |
| 17–18 | Sucursal | 4 | Multiagente | Agente único |
| 19–20 | Sucursal | 5 | Multiagente | Agente único |
| 21–22 | Comercial | 1 | Agente único | Multiagente |
| 23–24 | Comercial | 2 | Multiagente | Agente único |
| 25–26 | Comercial | 3 | Multiagente | Agente único |
| 27–28 | Comercial | 4 | Agente único | Multiagente |
| 29–30 | Comercial | 5 | Multiagente | Agente único |
| 31–32 | Mixto | 1 | Agente único | Multiagente |
| 33–34 | Mixto | 2 | Multiagente | Agente único |
| 35–36 | Mixto | 3 | Agente único | Multiagente |
| 37–38 | Mixto | 4 | Multiagente | Agente único |
| 39–40 | Mixto | 5 | Agente único | Multiagente |
| 41–42 | Reforzado | 1 | Multiagente | Agente único |
| 43–44 | Reforzado | 2 | Agente único | Multiagente |
| 45–46 | Reforzado | 3 | Agente único | Multiagente |
| 47–48 | Reforzado | 4 | Agente único | Multiagente |
| 49–50 | Reforzado | 5 | Multiagente | Agente único |

Protocolo confirmado v3: `34e4066e28895a08d43438ec97f5fe20397e6800287251da165b9debe604e4ef`. Fuente:[PROTOCOLO_MANUAL_LANGGRAPH.json](PROTOCOLO_MANUAL_LANGGRAPH.json). Tabla completa de 50 filas:[PROTOCOLO_MANUAL_LANGGRAPH.csv](PROTOCOLO_MANUAL_LANGGRAPH.csv). El orden es fijo. La ejecución de red permanece bloqueada mientras Kali conserve indicadores de fallo del kernel.

## Incidencias de la primera pareja y corrección del entorno

Las dos posiciones iniciales del Original se conservan: agente único con fallo de ejecución IPv6 y multiagente completa, con identidad de imágenes distinta entre ambas. Esa pareja no es apta para KPI y sus registros no se reemplazan. Se corrigieron la restauración, el aislamiento del proyecto Docker y los diagnósticos. Las nuevas corridas deben acreditar la versión corregida y una nueva aceptación sin IA. La siguiente posición del protocolo sigue siendo la 3: Original, pareja 2, agente único.

Las pruebas IPv6 conservan las sondas originales. Si el receptor no alcanza el estado inicial conocido, puede recuperarse una sola vez antes de enviar la sonda. La recuperación, su duración y cualquier fallo se registran; no se repiten sondas fallidas. Los diagnósticos guardan fase y tipo de error, sin mensajes crudos, claves ni comandos privados.
