# Auditoría de una red entregada por el jurado

La entrada principal del panel es **Mi red · IP o rango**, organizada en **Tu red → Qué revisar → Agentes e inicio**. No exige que los equipos se llamen como NovaFlow, que usen sus IP ni que pertenezcan a Docker. NovaFlow y v2 permanecen como bancos de referencia para probar y comparar el prototipo.

## Alcance que acepta hoy

- IPv4: una dirección, lista por comas, un CIDR alineado `/24` a `/32`, o un rango inicio-fin como `192.168.56.10-192.168.56.80`. No se mezclan formatos en el mismo campo.
- IPv6: una dirección o lista de direcciones literales. No se barre un prefijo IPv6 `/64`.
- Máximo 256 direcciones combinadas por corrida. Los CIDR normales excluyen dirección de red y broadcast; los rangos explícitos incluyen sus extremos.
- Puertos automáticos: búsqueda TCP connect del **1 al 65535**, sin lista manual. El administrador recibe los abiertos y crea lotes de reconocimiento de hasta 32 puertos cada uno. No incluye UDP. Máximo 256 lotes de reconocimiento por corrida; excederlo deja el inventario afectado incompleto, sin truncar silenciosamente.
- Solo direcciones privadas, locales o de documentación incluidas en NETWORKS; no objetivos públicos. Cada IP debe tener ruta directa sin gateway en Kali. Una red detrás de router/VPN no cumple actualmente ese contrato.
- Presupuesto total de 240 segundos, concurrencia máxima 2 en multiagente o 1 en agente único, y límites por tarea. Si no alcanza, los pendientes se registran sin evaluar: no se promete completar 256 hosts bajo cualquier condición de red.

## Qué hace la corrida

1. El operador escribe el alcance autorizado del jurado y, si hace falta, selecciona la interfaz. La referencia de autorización identifica la práctica.
2. **Comprobar objetivos** revisa Nmap y rutas para todas las direcciones candidatas. No hace descubrimiento activo ni contacta la API.
3. Al iniciar un CIDR o rango, Nmap hace descubrimiento `-sn`. Solo los hosts que respondan pasan al inventario TCP y reconocimiento de servicios. Las IP de listas explícitas se revisan sin descubrimiento previo mediante `-Pn`.
4. Se crea una tarea de búsqueda TCP 1–65535 por dirección elegible; se revalida su ruta antes de ejecutarla. Su XML debe confirmar objetivo, integridad y conteo completo de los 65.535 puertos. Un timeout, XML incompleto o hash inválido no equivale a cero abiertos. El agente entrega los puertos abiertos al administrador (`open_ports_reported`), que programa reconocimiento de servicios solo sobre ellos, en lotes de hasta 32 (`open_service_plan_created`). Si el puerto se cierra entre ambas etapas no pasa a autenticación. Los hosts sin respuesta al descubrimiento se conservan como `down`, con puertos sin examinar; no se supone que estén apagados.
5. Si el operador seleccionó **Probar credenciales por defecto**, se aplican perfiles a los servicios reconocidos compatibles por IPv4. El servicio observado determina el perfil, incluso si SSH escucha en 2222 o PostgreSQL en 15432. El número de puerto por sí solo no demuestra el protocolo.
6. Las pruebas web configuradas se admiten tras descubrir abierto su endpoint y reconocer HTTP/HTTPS con el inventario completo de sus direcciones. Continúan necesitando sesión y recursos autorizados; el descubrimiento de puertos no obtiene esos datos.
7. Se conserva una entrada de inventario por host, con todas sus tareas fuente, estados, servicios y cobertura. La consola muestra la entrega al administrador y las órdenes registradas. El resultado prioriza exposición y hallazgos; el anexo técnico conserva diagnóstico e incidencias. No se modifican las evidencias ni los resultados históricos.

## Detecciones genéricas implementadas

El modo libre confirma credenciales por defecto en SSH, FTP, PostgreSQL y HTTP Basic de la ruta `/manager/html`, con diccionario finito y máximo 80 intentos globales. Requiere autenticación observada, evidencia íntegra y corroboración con un cliente independiente. No es un intento ilimitado ni un acceso a una consola remota. La opción no se activa por defecto. La corroboración PostgreSQL usa la base `postgres` en lugar de exigir `labdb`. Si la base no existe, la conexión falla o el usuario no puede acceder a ella, el resultado queda indeterminado; no se confirma acceso por ese fallo.

La compatibilidad HTTP es concreta: reconocer HTTP no convierte una aplicación con formulario de acceso en un servicio HTTP Basic compatible. Los perfiles actuales de credenciales no se aplican por IPv6 ni a TLS/HTTPS. Las comprobaciones fallidas, canceladas o sin corroboración válida no se presentan como ausencia de vulnerabilidades.

Un puerto abierto es exposición de un servicio, no una vulnerabilidad confirmada. Una versión detectada no confirma una CVE. No hay un motor general de CVE, SQLi, XSS, RCE o Active Directory en esta modalidad.

## Pruebas web configurables de la tesis

El adaptador externo `scripts/aplicaciones_personales.py` permite evaluar aplicaciones distintas de v2/NovaFlow, sobre las IP y puertos del alcance, sin conocer nombres de contenedores. Se habilita en **Pruebas web de la tesis · configurar aplicaciones**. Admite hasta 16 aplicaciones por corrida; cada endpoint IP/puerto pertenece a una sola configuración. No rastrea sitios ni descubre sesiones o recursos ajenos por sí solo.

Ejemplo: Ana puede leer `/documentos/10`, cuyo contenido ficticio incluye `DOCUMENTO_ANA_2026`; no debe leer `/documentos/20`, con `DOCUMENTO_PEDRO_2026`. El operador conoce esos permisos y confirma que son recursos de prueba autorizados. Un HTTP 200 sin el marcador esperado no basta para confirmar acceso al documento.

1. Guardar la sesión de la cuenta del laboratorio: nombre recordable, cabecera **Cookie** o **Authorization**, y valor correspondiente. No introducir la clave API de IA. El valor se guarda únicamente en `.lab/personal_web_sessions.json`, con permisos 0600 y excluido de Git; no aparece en opciones de auditoría, prompts, consola ni informes. Los cuerpos de respuesta tampoco se conservan: la evidencia contiene estado, hash y coincidencias de marcadores, contrastadas por dos clientes.
2. Activar las pruebas web y añadir cada aplicación. Indicar IPv4 y/o IPv6 literal del alcance, puerto de la aplicación, HTTP/HTTPS y nombre de sesión guardada. La asociación IPv4/IPv6 es explícita: no se supone que dos IP pertenezcan al mismo equipo.
3. Configurar el recurso privado propio y su marcador. Debe devolver 200 con la sesión y 401/403 sin ella; redirecciones de login o respuestas ambiguas requieren otro adaptador y quedan incompletas.
4. Configurar al menos una prueba de la tabla. Rutas relativas al servidor, nunca otra URL; marcadores ficticios distintos, de 8 a 160 caracteres, presentes en el contenido y ausentes de la URL.
5. Confirmar los permisos de esos recursos y **Comprobar objetivos**. Se validan alcance, rutas y presencia de la sesión guardada sin tráfico HTTP ni API. Cambiar aplicación, recursos o marcadores invalida la comprobación.
6. Iniciar. Cada aplicación genera una tarea dependiente del inventario de sus direcciones. Solo se admite si Nmap reconoce HTTP/HTTPS en el puerto configurado. Se revalida la ruta antes de cada solicitud. Los resultados se registran por dirección y puerto, con dos clientes (`urllib` y `http.client`).

| Prueba | Configuración y criterio |
| --- | --- |
| Autorización por objeto | Ruta del recurso ajeno y marcador conocido. La misma cuenta no debe poder leerlo; se confirma solo si ambos clientes observan su marcador en la misma familia IP. |
| Límite de descarga | Solicitud de laboratorio con recorrido `../` y canario ficticio interno conocido, que debe quedar fuera del directorio público. Dos clientes deben obtener su marcador. No se buscan archivos reales del sistema. |
| Diferencia de autorización IPv4/IPv6 | Ambas IP de la misma aplicación, mismo recurso propio y sesión, ruta administrativa y marcador. Una familia debe denegar (401/403), la otra entregar el marcador, y ambos clientes coincidir en la dirección de esa diferencia. |

Los perfiles solo realizan GET, no siguen redirecciones ni usan proxies. HTTPS conserva validación de certificado; un certificado no válido produce una incidencia. La modalidad web no admite IPv6 de enlace local fe80::; usar ULA o las direcciones locales admitidas del alcance. Los límites generales (240 s, concurrencia 2/1 y 256 direcciones) se comparten con descubrimiento, reconocimiento y credenciales. Cada lote de reconocimiento conserva el límite de 32 puertos únicos; la búsqueda inicial cubre TCP 1–65535. Al faltar tiempo, sesión, compatibilidad o corroboración, la cobertura queda incompleta y los positivos de otras pruebas válidas se conservan.

Sin configurar estas aplicaciones, sus pruebas no se ejecutan. La cobertura técnica conserva el estado pendiente, sin llenar el informe ejecutivo con módulos no solicitados. Un resultado negativo se limita a los recursos probados: no acredita seguridad de toda la aplicación. Las cuentas con login interactivo, MFA, contratos diferentes o redirecciones necesitan adaptación adicional. No se ha añadido un motor general de CVE.

## Pruebas de protocolo IPv6 que todavía requieren adaptación

RA, anuncios de vecino y DAD necesitan acceso al mismo enlace, emisor autorizado y observación del estado del receptor antes/después y tras restaurarlo. SLAAC y fragmentación necesitan controles de protocolo y observadores/capturas; no son vulnerabilidades positivas automáticamente. Funcionan en los bancos instrumentados; todavía no se aplican desde el modo libre a receptores arbitrarios. El informe conserva este límite, sin darlos por superados.

## IA y evaluación académica

La IA opcional selecciona perfiles autorizados; no escribe comandos, añade detectores ni decide por sí sola que exista una vulnerabilidad. Con una sola tarea lista puede no haber llamada API. Los fallos, respaldos y uso medido quedan registrados; el informe no consume tokens adicionales.

Como el jurado aún no ha entregado un listado de vulnerabilidades, se mantiene como referencia el catálogo comprometido en la tesis. Antes de afirmar que el prototipo supera un laboratorio desconocido, debe acordarse qué clases se evaluarán y qué acceso se proporcionará. Para medir falsos positivos, falsos negativos y detección, el evaluador necesita conocer las condiciones reales del laboratorio, separadas del contexto del agente.

El resultado entregable por equipo distingue inventario completado, sin respuesta o incompleto; credenciales no solicitadas, no compatibles, incompletas, confirmadas o sin detección en los intentos realizados. Ningún estado implica seguridad general del equipo. Los bancos de referencia y las prácticas por rango se conservan separados del estudio formal de KPI; no se cambian sus etiquetas para cumplir metas.

La [guía actual del panel](PANEL_UNIFICADO.md) explica la revisión LLM opcional y cómo registrar una referencia independiente del laboratorio para contrastar detecciones y calcular KPI sin entregar esas etiquetas a los agentes.


## Compatibilidad y límites del descubrimiento automático

El formulario ya no tiene lista de puertos; envía `port_mode=auto`. Las opciones explícitas de hasta 32 puertos siguen admitidas internamente para reproducir corridas históricas, sin aparecer como una configuración requerida del flujo nuevo. Los bancos v1/v2 y NovaFlow conservan su catálogo fijo y no se cambiaron.

La búsqueda utiliza `nmap --unprivileged -n -Pn -sT -p 1-65535`, reintentos finitos, timeout de host de 50 s y de proceso de hasta 65 s. No usa shell, NSE, UDP ni órdenes generadas por el LLM. El reconocimiento reutiliza el perfil existente `-sV --version-light`, únicamente para puertos abiertos entregados con evidencia válida. Los CIDR/rangos conservan descubrimiento de hosts con seis sondas TCP internas finitas y su comprobación de rutas. Un equipo que filtre esas sondas puede no responder; no se garantiza encontrar todos los equipos bajo cualquier filtrado.

Con 240 s no se garantiza completar el rango de puertos en 256 direcciones. Los pendientes se cancelan con causa y la cobertura queda incompleta. El modo sin IA automatiza igualmente la entrega y la creación de tareas; la IA opcional elige entre tareas autorizadas y revisa resultados dentro de su presupuesto. No decide qué puerto está abierto.

Las parejas KPI del modo automático comparan el mismo catálogo y dependencias aunque varíe el orden de recepción entre trabajadores. Cambiar los puertos encontrados, versiones o configuración sigue impidiendo declarar la pareja comparable. La referencia del evaluador puede declarar cualquier puerto TCP válido de una IP del alcance; una condición sin evidencia no se convierte en verdadero positivo ni en control protegido. Las corridas automáticas nuevas no se mezclan con el estudio v2.
