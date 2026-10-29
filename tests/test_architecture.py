import ast
import pathlib

ROOT = pathlib.Path(__file__).resolve().parents[1] / "sbomreach"
ORDER = ["domain", "application", "adapters", "infrastructure"]
STDLIB_OK = {"__future__", "dataclasses", "enum", "typing", "re", "collections", "itertools", "math", "functools", "json"}


def imports(path):
    tree = ast.parse(path.read_text(encoding="utf-8"))
    out = []
    for n in ast.walk(tree):
        if isinstance(n, ast.Import):
            out += [a.name for a in n.names]
        elif isinstance(n, ast.ImportFrom):
            out.append(("." * n.level) + (n.module or ""))
    return out


def test_domain_imports_only_domain_and_pure_stdlib():
    for p in (ROOT / "domain").glob("*.py"):
        for m in imports(p):
            top = m.split(".")[0]
            if m.startswith("sbomreach"):
                assert m.startswith("sbomreach.domain"), f"{p.name} imports {m}"
            elif m.startswith("."):
                continue
            else:
                assert top in STDLIB_OK, f"{p.name} imports non-pure {m}"


def test_no_reverse_imports():
    for i, layer in enumerate(ORDER):
        higher = ORDER[i + 1:]
        for p in (ROOT / layer).glob("*.py"):
            for m in imports(p):
                for h in higher:
                    assert not m.startswith(f"sbomreach.{h}"), f"{layer}/{p.name} imports {m}"
