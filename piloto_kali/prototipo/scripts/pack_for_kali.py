"""Empaqueta solo fuentes y despliegue, sin entornos ni corridas locales."""

from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile


workspace = Path(__file__).resolve().parents[2]
destination = workspace / "prototipo_kali.zip"
roots = [workspace / "prototipo", workspace / "despliegue"]
excluded = {".venv", ".venv312", ".venv313", ".verificacion", ".pytest_cache", "__pycache__", "corridas"}

with ZipFile(destination, "w", compression=ZIP_DEFLATED) as archive:
    for root in roots:
        for path in root.rglob("*"):
            if not path.is_file():
                continue
            relative = path.relative_to(workspace)
            if any(part in excluded or part.endswith(".egg-info") for part in relative.parts):
                continue
            if path.suffix == ".pyc" or path.name == ".env":
                continue
            archive.write(path, relative.as_posix())

print(destination)
