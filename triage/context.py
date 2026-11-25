"""Analyse de contexte par AST Python : fonction englobante, exposition HTTP
(route Flask/FastAPI), propagation simple de données issues de `request`
(taint intra-fonction), constance des arguments, imports du projet."""
from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set

HTTP_SOURCES = {"request"}                         # Flask / Starlette
ROUTE_DECORATORS = {"route", "get", "post", "put", "delete", "patch", "api_route"}


def is_test_path(path: str) -> bool:
    p = path.replace("\\", "/").lower()
    name = p.rsplit("/", 1)[-1]
    return ("/tests/" in f"/{p}" or "/test/" in f"/{p}" or name.startswith("test_")
            or name.endswith("_test.py") or name == "conftest.py")


def _names(node: ast.AST) -> Set[str]:
    return {n.id for n in ast.walk(node) if isinstance(n, ast.Name)}


@dataclass
class FuncInfo:
    name: str
    node: Optional[ast.AST]
    is_route: bool = False
    tainted: Set[str] = field(default_factory=set)
    const_names: Set[str] = field(default_factory=set)


class FileContext:
    def __init__(self, path: Path, rel: str):
        self.rel = rel
        self.source = path.read_text(encoding="utf-8", errors="replace")
        self.lines = self.source.splitlines()
        self.tree = ast.parse(self.source)
        self.imports: Set[str] = set()
        for n in ast.walk(self.tree):
            if isinstance(n, ast.Import):
                self.imports |= {a.name.split(".")[0] for a in n.names}
            elif isinstance(n, ast.ImportFrom) and n.module:
                self.imports.add(n.module.split(".")[0])
        self.funcs: List[FuncInfo] = [self._analyse(f) for f in ast.walk(self.tree)
                                      if isinstance(f, (ast.FunctionDef, ast.AsyncFunctionDef))]

    # -- analyse d'une fonction -------------------------------------------------
    def _analyse(self, fn) -> FuncInfo:
        is_route = False
        for d in fn.decorator_list:
            target = d.func if isinstance(d, ast.Call) else d
            if isinstance(target, ast.Attribute) and target.attr in ROUTE_DECORATORS:
                is_route = True
        info = FuncInfo(fn.name, fn, is_route)
        assigns = [n for n in ast.walk(fn) if isinstance(n, (ast.Assign, ast.AnnAssign))]
        changed = True
        while changed:                                  # point fixe : propagation du taint
            changed = False
            for a in assigns:
                targets = a.targets if isinstance(a, ast.Assign) else [a.target]
                tnames = set().union(*(_names(t) for t in targets))
                if a.value is None:
                    continue
                src = _names(a.value)
                if (src & HTTP_SOURCES) or (src & info.tainted):
                    if not tnames <= info.tainted:
                        info.tainted |= tnames
                        changed = True
        for a in assigns:                               # noms toujours affectés à une constante
            targets = a.targets if isinstance(a, ast.Assign) else [a.target]
            for t in targets:
                if isinstance(t, ast.Name) and a.value is not None and self.is_constant(a.value, None):
                    info.const_names.add(t.id)
        for a in assigns:                               # retire ceux réaffectés à du non constant
            targets = a.targets if isinstance(a, ast.Assign) else [a.target]
            for t in targets:
                if isinstance(t, ast.Name) and a.value is not None and not self.is_constant(a.value, None):
                    info.const_names.discard(t.id)
        return info

    # -- requêtes -----------------------------------------------------------------
    def function_at(self, line: int) -> FuncInfo:
        best = None
        for f in self.funcs:
            end = getattr(f.node, "end_lineno", f.node.lineno)
            if f.node.lineno <= line <= end and (best is None or f.node.lineno > best.node.lineno):
                best = f
        return best or FuncInfo("<module>", None)

    def calls_at(self, line: int) -> List[ast.Call]:
        calls = [n for n in ast.walk(self.tree) if isinstance(n, ast.Call)
                 and n.lineno <= line <= getattr(n, "end_lineno", n.lineno)]
        calls.sort(key=lambda c: (c.lineno != line, c.col_offset))
        return calls

    def call_at(self, line: int, sinks: Optional[Set[str]] = None,
                end_line: Optional[int] = None) -> Optional[ast.Call]:
        """Appel situé dans la région [line, end_line] signalée par l'outil.

        Si `sinks` est donné, on ne retourne QUE un appel dont le nom est un puits connu
        (ex. `execute`, `md5` dans `hashlib.md5(x).hexdigest()`) : jamais un appel voisin
        quelconque, sinon un `request.args.get("id", "")` sur la 1re ligne d'une région
        multi-lignes serait pris pour une requête paramétrée (faux négatif dangereux).
        """
        last = max(line, end_line or line)
        if sinks:
            for ln in range(line, last + 1):
                for c in self.calls_at(ln):
                    f = c.func
                    name = f.attr if isinstance(f, ast.Attribute) else getattr(f, "id", "")
                    if name in sinks:
                        return c
            return None
        calls = self.calls_at(line)
        return calls[0] if calls else None

    def is_constant(self, node: ast.AST, fn: Optional[FuncInfo]) -> bool:
        if isinstance(node, ast.Constant):
            return True
        if isinstance(node, ast.JoinedStr):
            return all(isinstance(v, ast.Constant) for v in node.values)
        if isinstance(node, ast.BinOp):
            return self.is_constant(node.left, fn) and self.is_constant(node.right, fn)
        if isinstance(node, (ast.Tuple, ast.List)):
            return all(self.is_constant(e, fn) for e in node.elts)
        if isinstance(node, ast.Name) and fn is not None:
            return node.id in fn.const_names or node.id.isupper()   # constante de module (BASE_DIR)
        return False

    def is_tainted(self, node: ast.AST, fn: FuncInfo) -> bool:
        names = _names(node)
        return bool(names & HTTP_SOURCES or names & fn.tainted)

    def window(self, line: int, radius: int = 6) -> str:
        lo, hi = max(1, line - radius), min(len(self.lines), line + radius)
        return "\n".join(f"{i:>4} | {self.lines[i - 1]}" for i in range(lo, hi + 1))


class CodeIndex:
    """Index léger du code source (fichiers .py) pour le contexte du triage."""

    def __init__(self, src_root: str | Path):
        self.root = Path(src_root)
        self.files: Dict[str, FileContext] = {}
        for p in sorted(self.root.rglob("*.py")):
            rel = p.relative_to(self.root).as_posix()
            try:
                self.files[rel] = FileContext(p, rel)
            except SyntaxError:
                continue

    def get(self, rel: Optional[str]) -> Optional[FileContext]:
        return self.files.get(rel) if rel else None

    @property
    def imports(self) -> Set[str]:
        out: Set[str] = set()
        for f in self.files.values():
            if not is_test_path(f.rel):
                out |= f.imports
        return out
