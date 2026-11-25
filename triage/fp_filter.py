"""Moteur déterministe de détection de faux positifs, avec justification.
Chaque règle s'appuie sur un fait vérifiable dans l'AST (pas sur le message)."""
from __future__ import annotations

import ast
from typing import Optional, Tuple

from .context import CodeIndex, FileContext, FuncInfo, is_test_path
from .models import Finding

SAFE_YAML_LOADERS = {"SafeLoader", "CSafeLoader", "BaseLoader"}
SINKS = {"CWE-89": {"execute", "executemany", "executescript", "raw", "text"},
         "CWE-78": {"system", "popen", "run", "call", "check_call", "check_output", "Popen"},
         "CWE-502": {"load", "safe_load", "loads", "load_all"},
         "CWE-327": {"md5", "sha1", "new"}, "CWE-328": {"md5", "sha1", "new"},
         "CWE-22": {"open", "send_file", "join"}}
PLACEHOLDERS = ("changeme", "example", "dummy", "placeholder", "xxx", "<", "${", "your-")

Verdict = Tuple[str, str]   # (TP|FP, justification)


def _kw(call: ast.Call, name: str):
    for k in call.keywords:
        if k.arg == name:
            return k.value
    return None


def _attr_name(node) -> str:
    if isinstance(node, ast.Attribute):
        return node.attr
    if isinstance(node, ast.Name):
        return node.id
    return ""


def _rule_injection(f: Finding, fc: FileContext, fn: FuncInfo, call: ast.Call) -> Optional[Verdict]:
    if not call.args:
        return None
    first = call.args[0]
    if fc.is_tainted(first, fn):
        src = "paramètre HTTP (request.*)" if fn.is_route else "donnée externe"
        return "TP", f"L'argument de `{_attr_name(call.func)}` dérive d'un {src} dans `{fn.name}()` sans neutralisation."
    if fc.is_constant(first, fn):
        if f.cwe == "CWE-89" and len(call.args) >= 2:
            return "FP", ("Requête SQL entièrement constante et valeurs passées en paramètres liés "
                          f"(`{_attr_name(call.func)}(query, params)`) : pas d'injection possible.")
        if f.cwe == "CWE-78":
            return "FP", "Commande shell littérale, aucune donnée externe n'atteint `shell=True`."
        return "FP", "Requête construite uniquement à partir de constantes."
    return None


def _rule_yaml(call: ast.Call) -> Optional[Verdict]:
    if _attr_name(call.func) == "safe_load":
        return "FP", "`yaml.safe_load` n'instancie pas d'objets Python arbitraires."
    loader = _kw(call, "Loader") or (call.args[1] if len(call.args) > 1 else None)
    if loader is not None and _attr_name(loader) in SAFE_YAML_LOADERS:
        return "FP", f"`yaml.load` appelé avec `Loader={_attr_name(loader)}` (chargeur sûr)."
    return None


def _rule_hash(call: ast.Call) -> Optional[Verdict]:
    v = _kw(call, "usedforsecurity")
    if isinstance(v, ast.Constant) and v.value is False:
        return "FP", "Hachage déclaré `usedforsecurity=False` (usage non cryptographique, ex. clé de cache)."
    return None


def _rule_secret(f: Finding) -> Optional[Verdict]:
    s = (f.snippet or "").lower()
    if any(p in s for p in PLACEHOLDERS):
        return "FP", "Valeur de remplacement (placeholder), pas un secret réel."
    return None


def classify(f: Finding, index: CodeIndex) -> Verdict:
    if f.kind == "sca":
        return "TP", "Version installée dans la plage vulnérable déclarée par la base de l'outil."
    if f.file and is_test_path(f.file):
        return "FP", f"Fichier de test (`{f.file}`) : non déployé, valeurs factices."
    fc = index.get(f.file)
    if fc is None or f.line is None:
        return "TP", "Code source indisponible : conservé par prudence."
    fn = fc.function_at(f.line)
    call = fc.call_at(f.line, SINKS.get(f.cwe or ""), f.end_line)
    f.exposed_http = fn.is_route
    verdict: Optional[Verdict] = None
    if call is not None:
        f.tainted = any(fc.is_tainted(a, fn) for a in call.args)
        if f.cwe in ("CWE-89", "CWE-78"):
            verdict = _rule_injection(f, fc, fn, call)
        elif f.cwe == "CWE-502" and _attr_name(call.func) in ("load", "safe_load"):
            verdict = _rule_yaml(call)
        elif f.cwe in ("CWE-327", "CWE-328"):
            verdict = _rule_hash(call)
    if verdict is None and f.cwe == "CWE-798":
        verdict = _rule_secret(f) or ("TP", "Littéral affecté à une clé de configuration sensible dans du code déployé.")
    if verdict is None and f.cwe in ("CWE-327", "CWE-328") and call is not None and call.args:
        names = " ".join(n.id.lower() for a in call.args for n in ast.walk(a) if isinstance(n, ast.Name))
        if any(k in names for k in ("pass", "pwd", "secret", "token")):
            f.tainted = True   # donnée sensible : on remonte la priorité
            verdict = "TP", "Algorithme de hachage rapide appliqué à un mot de passe/secret (cassable hors ligne)."
    if verdict is None:
        if f.tainted:
            verdict = "TP", f"Donnée issue de la requête HTTP atteignant le point sensible dans `{fn.name}()`."
        elif f.cwe == "CWE-489":
            verdict = "TP", "Mode debug actif dans le point d'entrée : console Werkzeug exposée."
        else:
            verdict = "TP", "Aucun élément de contexte ne permet d'écarter l'alerte."
    return verdict
