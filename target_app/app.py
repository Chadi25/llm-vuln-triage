"""Application Flask VOLONTAIREMENT VULNÉRABLE — cible de démonstration.

NE PAS DÉPLOYER. Chaque faille est intentionnelle et documentée dans
fixtures/ground_truth.yaml. Certaines constructions sont sûres mais
ressemblent à des failles : elles servent à mesurer le filtre de faux positifs.
"""
import hashlib
import os
import pickle
import sqlite3
import subprocess

import yaml
from flask import Flask, request, send_file

app = Flask(__name__)
app.config["SECRET_KEY"] = "s3cr3t-pr0d-k3y-2019"  # secret en dur

BASE_DIR = "/srv/files"
DB_PATH = "users.db"


def get_db():
    return sqlite3.connect(DB_PATH)


@app.route("/user")
def user_lookup():
    user_id = request.args.get("id", "")
    cur = get_db().cursor()
    cur.execute(f"SELECT name, email FROM users WHERE id = '{user_id}'")
    return {"user": cur.fetchone()}


@app.route("/user/safe")
def user_lookup_safe():
    user_id = request.args.get("id", "")
    query = "SELECT name, email FROM users " + "WHERE id = ?"
    cur = get_db().cursor()
    cur.execute(query, (user_id,))
    return {"user": cur.fetchone()}


@app.route("/ping")
def ping():
    host = request.args.get("host", "127.0.0.1")
    out = subprocess.check_output("ping -c 1 " + host, shell=True)
    return out


def rotate_logs():
    # tâche de maintenance interne, aucune entrée utilisateur
    subprocess.run("ls -la /var/log/app", shell=True, check=False)


@app.route("/download")
def download():
    name = request.args.get("name")
    return send_file(os.path.join(BASE_DIR, name))


@app.route("/config", methods=["POST"])
def load_config():
    cfg = yaml.load(request.data)
    return {"keys": list(cfg)}


def load_defaults():
    with open("defaults.yml") as f:
        return yaml.load(f, Loader=yaml.SafeLoader)


@app.route("/session")
def restore_session():
    blob = request.cookies.get("state", "")
    state = pickle.loads(bytes.fromhex(blob))
    return {"state": str(state)}


def cache_key(payload: bytes) -> str:
    return hashlib.md5(payload, usedforsecurity=False).hexdigest()


def password_fingerprint(pwd: str) -> str:
    return hashlib.md5(pwd.encode()).hexdigest()


if __name__ == "__main__":
    app.run(host="0.0.0.0", debug=True)
