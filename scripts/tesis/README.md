# Módulos de aplicación de la tesis

El despliegue sigue siendo un monolito modular en Kali. No se añaden microservicios ni servidores por agente. La API HTTP presenta la aplicación; los controladores ejecutan tareas en procesos locales; los adaptadores y validadores conservan su responsabilidad.

- `alcance.py`: contrato de capacidades, roles y preparación experimental.
- `workspace.py`: historial activo, archivo íntegro recuperable y acceso de solo lectura.
- `candidatos.py`: correlación local de dos avisos CVE con producto/versión como candidatos. No descarga bases externas ni confirma por banner.
- `llm_contexto.py`: contexto anónimo por activo/especialidad y acciones estructuradas permitidas.

`dualstack_panel.py` mantiene rutas y control de acceso. `llm_especialistas.py` gestiona transporte, presupuesto y respuestas del proveedor, separado del contexto y de los adaptadores. El agente único usa un contexto común; multiagente separa dominios. Ninguno recibe la verdad reservada al evaluador. Las pruebas web y el descubrimiento sobre redes arbitrarias siguen disponibles como ampliaciones, identificadas en Desarrollo futuro.
