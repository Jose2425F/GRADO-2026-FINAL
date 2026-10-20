#!/bin/sh
set -eu
project_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
export LANGSMITH_TRACING=false
export LANGCHAIN_TRACING_V2=false
exec "$project_dir/piloto_kali/prototipo/.venv/bin/python" "$project_dir/scripts/dualstack_panel.py" "$@"
