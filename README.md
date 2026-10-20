# NovaFlow · auditoría dual-stack con LangGraph

Trabajo de grado de Ingeniería de Sistemas y Computación, Universidad Católica de Colombia (2026). NovaFlow es el nombre del prototipo académico; los laboratorios representan empresas ficticias.

El panel coordina herramientas autorizadas mediante **LangGraph**. El LLM de OpenAI selecciona tareas del catálogo e interpreta observaciones; los validadores deterministas corroboran los hallazgos. Un agente generalista ejecuta una tarea a la vez; la arquitectura multiagente usa roles especializados y hasta dos tareas independientes, con exclusión por activo y serialización de las pruebas IPv6.

## Abrir el prototipo

En Kali Linux, desde la raíz del repositorio y con el entorno ya instalado:

```bash
./scripts/iniciar_panel.sh
```

Abre [el panel local](http://127.0.0.1:8765/). La nueva guía está en [PRUEBAS_LANGGRAPH.md](docs/PRUEBAS_LANGGRAPH.md). La preparación no ejecuta auditorías con API.

Para instalar un entorno nuevo con Python 3.13:

```bash
python3.13 -m venv piloto_kali/prototipo/.venv
piloto_kali/prototipo/.venv/bin/python -m pip install -e './piloto_kali/prototipo[ipv6,test]'
```

Se requieren Docker con Compose, Nmap, Hydra e iproute2. El panel escucha únicamente en la interfaz local. La configuración de OpenAI se guarda fuera del control de versiones, mediante:

```bash
piloto_kali/prototipo/.venv/bin/python piloto_kali/prototipo/scripts/configure_openai.py
```

## Evaluación que ejecuta el usuario

Hay cinco laboratorios: integrado (32 tareas), sucursal (25), comercial (28), mixto (32) y reforzado (37). Las tareas son comprobaciones; su cantidad no equivale al número de vulnerabilidades.

El plan manual es **cinco parejas por laboratorio**: cinco corridas de agente único y cinco multiagente. Son 50 corridas previstas en total. Cada pareja usa el mismo laboratorio, alcance, código, imágenes, modelo y presupuesto. Se restaura y comprueba el banco antes de cada corrida. Los primeros intentos, incluidos los fallos, permanecen registrados; una práctica posterior no los sustituye.

El panel muestra tiempo, tokens, consola, informes técnico/ejecutivo y progreso por laboratorio. Los KPI de comparación requieren dos corridas compatibles, LangGraph acreditado, API medida y una referencia íntegra común. Sin esos datos quedan pendientes. Los resultados agregados son exploratorios; cinco laboratorios no constituyen cinco muestras independientes de empresas reales.

El valor inicial es 60.000 tokens totales por auditoría con revisión especializada, repartidos 60 % para planificación y 40 % para revisión. Es un límite, no consumo obligatorio ni garantía de costo. El saldo real se consulta con el proveedor. No se deben cambiar modelo, código o presupuesto en medio de una pareja.

## Componentes principales

- `scripts/dualstack_panel.py`: panel local, validación, operaciones e informes.
- `scripts/tesis/orquestacion_langgraph.py`: StateGraph de comprobación, admisión, ejecución, validación, aborto, revisión y cierre.
- `scripts/laboratorio_empresa.py`: integración del banco original con el grafo.
- `scripts/laboratorio_suite.py` y `scripts/tesis/laboratorios.py`: cuatro escenarios adicionales.
- `scripts/tesis/evaluacion_manual.py`: posiciones manuales y comparación por laboratorio.
- `piloto_kali/prototipo/src/auditoria/`: contratos, autorización, perfiles y proveedor OpenAI.
- `piloto_kali/despliegue/empresa/`: definiciones de los laboratorios.

El inventario por IP permanece como extensión. Los perfiles IPv6 instrumentados de los bancos cerrados no se transfieren automáticamente a cualquier red. Un puerto abierto o un candidato CVE no equivale a una vulnerabilidad confirmada.

## Verificación y documentación

```bash
piloto_kali/prototipo/.venv/bin/python -m pytest -q scripts/tests piloto_kali/prototipo/tests
node scripts/tests/manual_langgraph.browser.mjs
```

Las pruebas automatizadas usan dobles de herramientas y proveedor; no sustituyen las auditorías reales del usuario. Un fallo previo del kernel bloquea las pruebas de red y requiere recuperar/reiniciar Kali. No se elimina ni se ignora ese control.

Esta distribución publica el código fuente, la interfaz, los adaptadores, los laboratorios y las pruebas automatizadas. Las auditorías ejecutadas, sus evidencias privadas, las credenciales y el documento académico se conservan por separado y no forman parte de este repositorio.

El paquete que ejecuta el panel está en `piloto_kali/prototipo/`; utiliza el comando de instalación indicado arriba. Sus dependencias y versión de LangGraph se declaran en su propio `pyproject.toml` y `uv.lock`.
