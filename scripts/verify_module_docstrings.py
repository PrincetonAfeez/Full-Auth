"""Verify that every project .py file has a module-level docstring."""
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def has_module_docstring(text: str) -> bool:
    lines = text.splitlines()
    i = 0
    if lines and lines[0].startswith("#!"):
        i = 1
    while i < len(lines) and (not lines[i].strip() or lines[i].strip().startswith("#")):
        i += 1
    return i < len(lines) and lines[i].strip().startswith('"""')


missing = []
for p in sorted(ROOT.rglob("*.py")):
    if any(x in p.parts for x in (".venv", "__pycache__")):
        continue
    if not has_module_docstring(p.read_text(encoding="utf-8")):
        missing.append(p)

if missing:
    print("MISSING", len(missing))
    for p in missing:
        print(p)
    raise SystemExit(1)
print(f"OK: all {sum(1 for p in ROOT.rglob('*.py') if '.venv' not in p.parts)} python files have module docstrings.")
