# Cómo preparar tus laboratorios para el prototipo

El prototipo no descubre que un equipo «es un laboratorio». Tú seleccionas el banco integrado o entregas direcciones autorizadas. Después se buscan equipos y servicios y se aplican únicamente los perfiles compatibles. Esta guía describe el código actual, no una promesa de detección universal.

## Dos formas de evaluar

| Modo del panel | Cómo elige objetivos | Qué permite |
|---|---|---|
| Tesis → Laboratorio → Banco NovaFlow | Catálogo fijo: 10 objetivos, 12 contenedores y 32 tareas | Servicios IPv4, credenciales conocidas del banco, acceso web dual-stack y protocolos IPv6 instrumentados |
| Laboratorio → Abrir mi laboratorio por IP, también en Desarrollo futuro | IP, lista o rango entregado por ti | Inventario TCP, credenciales comunes IPv4 opcionales y pruebas web configuradas; no las pruebas activas de enlace IPv6 sobre equipos desconocidos |

El banco fijo no se adapta automáticamente a otras IP. La exploración por IP está implementada, pero permanece separada del banco y de la muestra formal de tesis. Las 32 tareas del banco no equivalen a 32 vulnerabilidades.

## Qué puedes preparar y qué observará

| Área | Escenario que puedes preparar | Resultado que sí puede informar |
|---|---|---|
| Equipos y servicios | Un servidor TCP alcanzable por IPv4 o IPv6 | IP, puertos abiertos y servicio/producto/versión reconocidos. Esto es inventario, no un hallazgo por sí mismo |
| Credenciales SSH | Un SSH con autenticación por contraseña y una combinación del diccionario corto; otro equipo que la rechace | Credencial común aceptada, corroborada con un cliente independiente |
| Credenciales FTP | Un FTP compatible y un control que rechace esas credenciales | Acceso aceptado y corroborado; no incluye FTPS/SFTP como perfiles FTP |
| Credenciales PostgreSQL | Servicio PostgreSQL que permita autenticación TCP; cuenta de laboratorio común y control protegido | Credencial aceptada y conexión independiente a la base `postgres` |
| HTTP Basic | Un recurso `/manager/html` que presente el desafío HTTP Basic; control con contraseña distinta | Credencial común aceptada y corroborada. Un formulario de inicio de sesión o un 200 sin desafío no equivale a HTTP Basic válido |
| Documento ajeno | Una cuenta que lea su documento pero deba rechazar el documento de otro usuario | Acceso indebido a un recurso ficticio conocido, comprobado por dos clientes |
| Límite de descarga | Recurso interno ficticio que la cuenta no deba descargar mediante la ruta configurada | Ruptura del límite de descarga del recurso conocido; no es búsqueda libre de archivos |
| Permisos distintos IPv4/IPv6 | La misma aplicación y recurso administrativo, con IPv4 e IPv6 concretas | Diferencia de autorización corroborada entre las dos familias |
| RA, vecinos y DAD | Receptor instrumentado vulnerable y receptor protegido, emisor y control del enlace | Aceptación de anuncios no confiables, alteración del vecino o interferencia DAD según los perfiles del banco |
| SLAAC y fragmentación | Banco instrumentado con observación del receptor y restauración | Comportamiento de conformidad de SLAAC y fragmentos: solapados, atómicos y cadena incompleta. No todo comportamiento observado es una vulnerabilidad |

En el modo por IP, las pruebas de credenciales actuales son **por IPv4**. El reconocimiento del servicio decide qué perfil aplicar; no basta con abrir el puerto habitual. El diccionario es corto, con un máximo global de 80 intentos; no evalúa todas las contraseñas débiles. Para un primer laboratorio SSH sintético puedes preparar `labuser/labuser` en el objetivo positivo y una contraseña diferente en el control. No uses esas cuentas en equipos reales.

La correlación CVE es acotada: OpenSSH CVE-2024-6387 y PostgreSQL CVE-2023-5869 bajo reglas de producto/versión. Una coincidencia queda como **candidato**, requiere comprobar plataforma, configuración y parches; no se suma como vulnerabilidad confirmada. SQLi, XSS generales, todas las CVE, Windows/AD y explotación universal no son capacidades implementadas.

## Datos que necesitas entregar

Para inventario:

- IPv4 literal, lista por comas, CIDR alineado `/24` a `/32` o rango inicio-fin. No mezcles formatos.
- IPv6 opcional: direcciones concretas por comas. Nunca un prefijo `/64` para barrerlo. Una IPv4 no permite deducir de forma fiable la IPv6 del mismo equipo.
- Interfaz de Kali si no basta la ruta automática. Para `fe80::`, selecciónala explícitamente.
- Nombre de auditoría y referencia de autorización. No debes introducir puertos de inventario: se descubren automáticamente.

Kali necesita ruta directa **sin gateway** hacia cada objetivo. Se admiten rangos privados/locales/de documentación definidos en el código; las IP públicas se rechazan. Una red empresarial situada detrás de un router no es compatible con esta salvaguarda actual. Conecta Kali al segmento aislado correspondiente; no desactives la validación de rutas.

Para pruebas web necesitas además:

- IP del servicio, puerto y HTTP/HTTPS. Este puerto identifica la aplicación que configuraste y debe aparecer abierto durante el inventario.
- Sesión de una cuenta ficticia, mediante Cookie o Authorization, guardada privadamente en Kali.
- Ruta del documento propio y texto único dentro de él. Debe responder 200 con sesión y 401/403 sin ella.
- Rutas y textos únicos de los recursos opcionales: documento ajeno, descarga interna y recurso administrativo.
- Para comparar autorización entre familias, IPv4 e IPv6 de la misma aplicación.

Se realizan solicitudes GET acotadas, sin seguir redirecciones y conservando la validación de certificados HTTPS. Las sesiones no se envían al LLM. Una cuenta con un formulario de login, sin sesión válida ni recursos conocidos, no permite inferir pruebas de permisos fiables.

## Primer laboratorio recomendado

Empieza con pocos equipos, no con una red grande:

| Equipo | Preparación | Referencia antes de auditar |
|---|---|---|
| Acceso A | SSH con cuenta sintética del diccionario corto | Credencial común presente |
| Acceso B | SSH con una contraseña distinta de todas las probadas | Credencial común ausente |
| Web A | Cuenta Ana, documento propio y documento de Pedro con marcadores sintéticos; acceso ajeno permitido intencionalmente | Autorización de objeto rota presente |
| Web B | Mismos recursos y cuenta, con rechazo al documento ajeno | Autorización de objeto rota ausente |

Asigna IP privadas concretas y verifica que Kali alcance directamente a cada equipo. Para web, prepara un 401/403 sin sesión sobre el documento propio. Las aplicaciones deben implementar realmente las rutas y permisos: renombrar un contenedor no crea la condición vulnerable. Anota imágenes/versiones/configuración y conserva una forma de restaurar cada escenario.

Para pruebas IPv6 de enlace conserva inicialmente los bancos instrumentados existentes. Extenderlas a otros receptores requiere un adaptador, observadores y validación; añadir una IPv6 al formulario no lo sustituye.

## Flujo en el panel

1. Abre **Laboratorio → Abrir mi laboratorio por IP**. También está en Desarrollo futuro.
2. Escribe las direcciones y revisa la interfaz en el paso 1.
3. En el paso 2 activa credenciales y/o configura aplicaciones si preparaste esos escenarios. Solo inventario no confirmará esas vulnerabilidades.
4. En el paso 3 pulsa **Comprobar objetivos**, elige agente único o multiagente e IA, y revisa el límite de tokens. Comprobar no es ejecutar una auditoría.
5. Pulsa **Iniciar**. En Seguimiento abre **Pruebas y actividad** y **Consola técnica** para ver las herramientas, objetivos e incidencias registradas.
6. Abre **Informe técnico** para evidencia y cobertura, e **Informe ejecutivo** para problemas y acciones. Leerlos no consume más API.
7. En **Evaluación y KPI**, registra antes de ejecutar la referencia del evaluador: IP, puerto, condición presente o ausente. Compara versiones y alcances compatibles; las prácticas no entran automáticamente en la muestra formal.

## Límites que importan al diseñar la prueba

- Máximo 256 direcciones candidatas combinando ambas familias y 240 segundos por corrida por IP. No se garantiza evaluar todas dentro del tiempo.
- Para CIDR/rangos IPv4 se descubren hosts con `nmap -sn`, con sondas TCP acotadas. Un equipo que no responde puede quedar `down` aunque esté encendido. Usa listas de direcciones conocidas cuando debas distinguir este límite de descubrimiento.
- El inventario automático busca TCP 1–65535. Solo puertos abiertos pasan al reconocimiento, agrupados en trabajos de hasta 32 puertos. No incluye UDP ni NSE.
- Multiagente permite dos tareas independientes simultáneas; agente único una. Al agotarse tiempo/presupuesto se registran pendientes e incidencias, no aprobaciones ficticias.
- Un rechazo válido a la credencial probada no demuestra que el servidor no tenga ninguna otra vulnerabilidad. Un host sin respuesta no es un control protegido válido por sí mismo.
- El LLM ordena tareas autorizadas e interpreta evidencia; no inventa comandos, nuevas capacidades ni confirma hallazgos por su opinión.

## Bloqueo actual de Kali

En la revisión del 17/10/2026 se observó `/proc/sys/kernel/tainted = 16384`, indicador que la salvaguarda del prototipo trata como fallo del kernel. Por eso se bloquean auditorías, aunque el banco tenga una aceptación funcional anterior. No se ha determinado aquí qué proceso lo originó.

Guarda tu trabajo, reinicia Kali y vuelve a comprobar el banco. Restaurar Docker no limpia ese indicador. No se desactivó esta protección ni se ejecutaron nuevas auditorías o llamadas pagadas para comprobar la interfaz.
