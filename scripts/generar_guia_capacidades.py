"""Publica la guía local del prototipo en HTML; generación offline, sin proveedor."""
from pathlib import Path
from markdown_it import MarkdownIt

ROOT = Path(__file__).resolve().parents[1]


def main():
    source = ROOT / 'docs/ALCANCE_Y_LABORATORIO_AMPLIADO.md'
    text = source.read_text()
    # El enlace del Markdown es de repositorio; la vista local no publica archivos arbitrarios.
    text = text.replace('[Guía del laboratorio v2](../piloto_kali/prototipo/GUIA_LABORATORIO_V2.md)',
                        'Guía del laboratorio v2, archivo piloto_kali/prototipo/GUIA_LABORATORIO_V2.md')
    text = text.replace('[Guía de entrada por IP](MI_LABORATORIO_POR_IP.md)', 'La guía de operación está en docs/MI_LABORATORIO_POR_IP.md; selecciona Auditoría de red por IP o rango en Nueva auditoría.')
    body = MarkdownIt('commonmark', {'html':False}).enable('table').render(text)
    html = '''<!doctype html><html lang="es"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Capacidades y ampliación del prototipo DualStack</title><style>
*{box-sizing:border-box}body{background:#f3f5f7;color:#26384b;font:15px/1.75 system-ui,sans-serif;margin:0}main{max-width:1100px;margin:25px auto;padding:35px;background:white;border:1px solid #e0e7ed;border-radius:12px}h1{font-size:30px;line-height:1.25}h2{margin-top:35px;font-size:21px}a{color:#176847}code{background:#eff3f5;padding:2px 4px;font-size:12px;overflow-wrap:anywhere}table{display:block;overflow:auto;border-collapse:collapse;font-size:12px;margin:20px 0}th,td{min-width:130px;max-width:330px;border:1px solid #dfe7e9;padding:12px;vertical-align:top;text-align:left}th{background:#edf4e9}li{margin:8px 0}.bar{display:flex;gap:20px;flex-wrap:wrap}button{padding:8px 12px;border:0;background:#bbe87c;border-radius:6px;cursor:pointer}@media(max-width:650px){main{margin:10px;padding:20px}h1{font-size:25px}}@media print{@page{size:A4;margin:17mm}body{font-size:10px;background:white}main{margin:0;padding:0;max-width:none;border:0}.bar{display:none}table{display:table;width:100%;font-size:8px}th,td{min-width:0;max-width:none;padding:6px}tr{break-inside:avoid}h2{break-after:avoid}}
</style><main><div class="bar"><a href="/#new">Volver al panel</a><button onclick="window.print()">Imprimir o guardar PDF</button></div>'''+body+'</main></html>'
    output = ROOT / 'scripts/dualstack_ui/capabilities.html'
    output.write_text(html)
    print(output)


if __name__ == '__main__':
    main()
