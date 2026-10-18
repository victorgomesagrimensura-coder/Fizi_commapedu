import os
import secrets
from functools import wraps
from pathlib import Path
from workers import env

import psycopg
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb
from flask import Flask, jsonify, request, session, send_from_directory, Response

BASE_DIR = Path(__file__).resolve().parent
app = Flask(__name__)
app.secret_key = env.SECRET_KEY
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE", "true").lower() == "true",
    MAX_CONTENT_LENGTH=25 * 1024 * 1024,
)


def worker_env():
    """Cloudflare exposes bindings through the WSGI request environment."""
    try:
        return request.environ.get("workers.env")
    except RuntimeError:
        return None


def setting(name, default=None):
    env = worker_env()
    if env is not None:
        value = getattr(env, name, None)
        return value if value not in (None, "") else default
    return os.environ.get(name, default)


def db():
    """Open a PostgreSQL connection via Hyperdrive on Cloudflare, or DATABASE_URL locally."""
    env = worker_env()
    if env is not None:
        hd = getattr(env, "HYPERDRIVE", None)
        if hd is None:
            raise RuntimeError("Binding HYPERDRIVE ausente. Configure-o no wrangler.jsonc.")
        conn = psycopg.connect(
            host=hd.host,
            port=int(hd.port),
            user=hd.user,
            password=hd.password,
            dbname=hd.database,
            sslmode="disable",
            connect_timeout=10,
            row_factory=dict_row,
        )
    else:
        url = os.environ.get("DATABASE_URL", "").strip()
        if not url:
            raise RuntimeError("Configure DATABASE_URL no ambiente local/Render ou HYPERDRIVE no Cloudflare.")
        if url.startswith("postgres://"):
            url = "postgresql://" + url[len("postgres://"):]
        conn = psycopg.connect(url, row_factory=dict_row, connect_timeout=10)

    # Schema initialization is lazy because Cloudflare bindings are request-scoped.
    # IF NOT EXISTS makes this safe on repeat calls and preserves all existing data.
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
    return conn


def admin_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get("is_admin"):
            return jsonify(error="Sessão administrativa inválida. Entre novamente."), 401
        return fn(*args, **kwargs)
    return wrapper


def cloudflare_assets_response(path):
    """Serve frontend files from the Workers Static Assets binding."""
    from pyodide.ffi import run_sync
    env = worker_env()
    if env is None:
        return None
    asset_path = path or "index.html"
    assets = env.ASSETS
    asset_response = run_sync(assets.fetch(f"https://assets.local/{asset_path}"))
    body = run_sync(asset_response.bytes())
    headers = dict(asset_response.headers)
    return Response(body, status=asset_response.status, headers=headers)


@app.get("/")
def index():
    response = cloudflare_assets_response("index.html")
    if response is not None:
        return response
    return send_from_directory(BASE_DIR, "index.html")


@app.get("/health")
def health():
    try:
        with db() as conn:
            conn.execute("SELECT 1")
        return jsonify(status="ok", database="connected")
    except Exception:
        app.logger.exception("Health check/PostgreSQL falhou")
        return jsonify(status="error", database="unavailable"), 503


@app.post("/api/login")
def login():
    body = request.get_json(silent=True) or {}
    username = setting("ADMIN_USER", "admin")
    # On Cloudflare, ADMIN_PASSWORD must be configured as a secret; never use a public default.
    password = setting("ADMIN_PASSWORD")
    if not password:
        return jsonify(error="Configure o segredo ADMIN_PASSWORD nas configurações do Worker."), 503
    supplied_user = str(body.get("username", ""))
    supplied_password = str(body.get("password", ""))
    if not secrets.compare_digest(supplied_user, str(username)) or not secrets.compare_digest(supplied_password, str(password)):
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


@app.get("/<path:path>")
def frontend_or_not_found(path):
    # Registered API routes take precedence. Everything else is a static asset request.
    response = cloudflare_assets_response(path)
    if response is not None:
        return response
    # Preserve local/Render behavior for the /static/ assets.
    if path.startswith("static/"):
        return send_from_directory(BASE_DIR, path)
    return jsonify(error="Recurso não encontrado."), 404


@app.errorhandler(413)
def too_large(_error):
    return jsonify(error="O arquivo enviado excede o limite de 25 MB."), 413


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "10000")), debug=False)
