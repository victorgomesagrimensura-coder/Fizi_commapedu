import os
import secrets
from functools import wraps
from pathlib import Path

import psycopg
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb
from flask import Flask, jsonify, request, session, send_from_directory

BASE_DIR = Path(__file__).resolve().parent
app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY") or secrets.token_hex(32)
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE", "true").lower() == "true",
    MAX_CONTENT_LENGTH=25 * 1024 * 1024,
)


def db():
    url = os.environ.get("DATABASE_URL", "").strip()
    if not url:
        raise RuntimeError(
            "DATABASE_URL não configurada. Crie um PostgreSQL no Render e conecte-o ao Web Service."
        )
    if url.startswith("postgres://"):
        url = "postgresql://" + url[len("postgres://"):]
    return psycopg.connect(url, row_factory=dict_row, connect_timeout=10)


def init_db():
    with db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS datasets (
                name TEXT PRIMARY KEY,
                payload JSONB NOT NULL,
                updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS cms_content (
                element_id TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            )
        """)


def admin_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get("is_admin"):
            return jsonify(error="Sessão administrativa inválida. Entre novamente."), 401
        return fn(*args, **kwargs)
    return wrapper


@app.get("/")
def index():
    return send_from_directory(BASE_DIR, "index.html")


@app.get("/healthz")
def healthz():
    """
    Verificação simples de vida (liveness).
    Não consulta o PostgreSQL para que o Render consiga verificar
    se o processo Flask está respondendo, mesmo durante uma falha do banco.
    """
    return jsonify(status="ok"), 200


@app.get("/health")
def health():
    """
    Verificação completa: confirma também a conexão com o PostgreSQL.
    """
    try:
        with db() as conn:
            conn.execute("SELECT 1")
        return jsonify(status="ok", database="connected"), 200
    except Exception:
        app.logger.exception("Health check/PostgreSQL falhou")
        return jsonify(status="error", database="unavailable"), 503


@app.post("/api/login")
def login():
    body = request.get_json(silent=True) or {}
    username = os.environ.get("ADMIN_USER", "admin")
    # Credencial inicial provisória; ADMIN_PASSWORD no Render pode substituí-la.
    # Troque a senha provisória após o primeiro acesso.
    password = os.environ.get("ADMIN_PASSWORD", "provisoria1")
    supplied_user = str(body.get("username", ""))
    supplied_password = str(body.get("password", ""))
    if not secrets.compare_digest(supplied_user, username) or not secrets.compare_digest(supplied_password, password):
        return jsonify(error="Usuário ou senha incorretos."), 401
    session.clear()
    session["is_admin"] = True
    return jsonify(ok=True)


@app.post("/api/logout")
def logout():
    session.clear()
    return jsonify(ok=True)


@app.get("/api/datasets")
def list_datasets():
    try:
        with db() as conn:
            rows = conn.execute("SELECT payload FROM datasets ORDER BY name").fetchall()
        return jsonify(datasets=[row["payload"] for row in rows])
    except Exception:
        app.logger.exception("Não foi possível carregar as bases de dados")
        return jsonify(error="Não foi possível ler as bases de dados do PostgreSQL."), 500


@app.put("/api/datasets/<path:name>")
@admin_required
def put_dataset(name):
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return jsonify(error="Formato de base de dados inválido."), 400
    if not name or len(name) > 500:
        return jsonify(error="Nome da base inválido."), 400
    payload["name"] = name
    try:
        with db() as conn:
            conn.execute("""
                INSERT INTO datasets (name, payload) VALUES (%s, %s)
                ON CONFLICT (name) DO UPDATE
                SET payload = EXCLUDED.payload, updated_at = NOW()
            """, (name, Jsonb(payload)))
        return jsonify(ok=True, name=name)
    except Exception:
        app.logger.exception("Falha ao salvar base de dados")
        return jsonify(error="Não foi possível salvar a base no PostgreSQL."), 500


@app.delete("/api/datasets/<path:name>")
@admin_required
def delete_dataset(name):
    try:
        with db() as conn:
            conn.execute("DELETE FROM datasets WHERE name = %s", (name,))
        return jsonify(ok=True)
    except Exception:
        app.logger.exception("Falha ao excluir base de dados")
        return jsonify(error="Não foi possível excluir a base no PostgreSQL."), 500


@app.get("/api/cms")
def get_cms():
    try:
        with db() as conn:
            rows = conn.execute("SELECT element_id, value FROM cms_content").fetchall()
        return jsonify(content={row["element_id"]: row["value"] for row in rows})
    except Exception:
        app.logger.exception("Falha ao carregar conteúdo editorial")
        return jsonify(error="Falha ao carregar conteúdo do PostgreSQL."), 500


@app.put("/api/cms/<element_id>")
@admin_required
def put_cms(element_id):
    if not element_id or len(element_id) > 200:
        return jsonify(error="Identificador de conteúdo inválido."), 400
    body = request.get_json(silent=True) or {}
    value = body.get("value")
    if not isinstance(value, str) or len(value) > 100_000:
        return jsonify(error="Conteúdo inválido ou acima do limite permitido."), 400
    try:
        with db() as conn:
            conn.execute("""
                INSERT INTO cms_content (element_id, value) VALUES (%s, %s)
                ON CONFLICT (element_id) DO UPDATE
                SET value = EXCLUDED.value, updated_at = NOW()
            """, (element_id, value))
        return jsonify(ok=True)
    except Exception:
        app.logger.exception("Falha ao salvar conteúdo editorial")
        return jsonify(error="Não foi possível salvar a edição no PostgreSQL."), 500


@app.errorhandler(413)
def too_large(_error):
    return jsonify(error="O arquivo enviado excede o limite de 25 MB."), 413


# Cria as tabelas automaticamente quando o PostgreSQL já estiver conectado.
# O endpoint /health também tenta inicializá-las novamente caso o banco demore a ficar disponível.
try:
    init_db()
except Exception:
    app.logger.warning("PostgreSQL ainda indisponível na inicialização; será verificado novamente em /health.")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "10000")), debug=False)
