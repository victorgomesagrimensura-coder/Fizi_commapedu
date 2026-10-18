from workers import env, wsgi
from app import app

# SECRET_KEY must be configured in Cloudflare Worker settings as a secret.
# A temporary random fallback lets the first deployment complete, but admin sessions
# will not be stable until SECRET_KEY is set. Set it before using the site in production.
secret_key = getattr(env, "SECRET_KEY", None)
if secret_key:
    app.secret_key = secret_key

Default = wsgi.entrypoint(app)
