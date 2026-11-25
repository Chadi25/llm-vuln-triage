"""Pistes de remédiation par classe de faiblesse (mode déterministe)."""
from __future__ import annotations

from .models import Finding

FIXES = {
    "CWE-89": ("Utiliser une requête paramétrée.",
               'cur.execute("SELECT name, email FROM users WHERE id = ?", (user_id,))'),
    "CWE-78": ("Supprimer shell=True et passer une liste d'arguments ; valider l'hôte (ipaddress / regex DNS).",
               'subprocess.check_output(["ping", "-c", "1", host], shell=False, timeout=5)'),
    "CWE-22": ("Résoudre le chemin et vérifier qu'il reste sous le répertoire de base (ou flask.safe_join).",
               "p = (Path(BASE_DIR) / name).resolve()\nif not p.is_relative_to(Path(BASE_DIR).resolve()):\n    abort(400)"),
    "CWE-502": ("Ne jamais désérialiser une donnée non fiable : yaml.safe_load, JSON signé à la place de pickle.",
                "cfg = yaml.safe_load(request.data)"),
    "CWE-327": ("Mot de passe : utiliser un KDF lent (argon2id, scrypt, bcrypt) avec sel.",
                "hashlib.scrypt(pwd.encode(), salt=os.urandom(16), n=2**14, r=8, p=1)"),
    "CWE-798": ("Sortir le secret du code (variable d'environnement / coffre de secrets) puis le faire tourner.",
                'app.config["SECRET_KEY"] = os.environ["FLASK_SECRET_KEY"]'),
    "CWE-489": ("Désactiver le debug hors développement et servir via un serveur WSGI (gunicorn).",
                'app.run(debug=os.getenv("FLASK_DEBUG") == "1")'),
}


def suggest(f: Finding) -> None:
    if f.kind == "sca":
        if f.fixed_version:
            f.remediation = f"Mettre à jour `{f.package}` {f.version} → ≥ {f.fixed_version}."
            f.patch = f"{f.package}>={f.fixed_version}"
        else:
            f.remediation = f"Aucun correctif publié pour `{f.package}` : isoler ou remplacer la dépendance."
        return
    text, patch = FIXES.get(f.cwe or "", ("Revue manuelle requise.", ""))
    f.remediation, f.patch = text, patch
