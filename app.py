import hmac
import os
import re
import secrets
import string

import requests

try:  # opcional: carrega o .env em desenvolvimento local
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass
from flask import Flask, abort, render_template, request, session
from werkzeug.middleware.proxy_fix import ProxyFix

app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)
app.secret_key = os.environ["SECRET_KEY"]
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Strict",
    SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE", "false").lower() == "true",
)

CP_HOST = os.environ["CP_HOST"].rstrip("/")  # ex: https://vps.lomapv.com.br:2083
CP_USER = os.environ["CP_USER"]
CP_TOKEN = os.environ["CP_TOKEN"]
APP_USER = os.environ["APP_USER"]
APP_PASS = os.environ["APP_PASS"]
ALLOWED_DOMAINS = {
    d.strip().lower() for d in os.environ["ALLOWED_DOMAINS"].split(",") if d.strip()
}
VERIFY_TLS = os.environ.get("VERIFY_TLS", "true").lower() == "true"
MAX_LINHAS = int(os.environ.get("MAX_LINHAS", "50"))

LOCAL_RE = re.compile(r"^[a-z0-9._-]{1,64}$")


def gerar_senha(n=16):
    letras = string.ascii_letters + string.digits
    simbolos = "#@%!"
    while True:
        s = "".join(secrets.choice(letras + simbolos) for _ in range(n))
        if (any(c.islower() for c in s) and any(c.isupper() for c in s)
                and any(c.isdigit() for c in s) and any(c in simbolos for c in s)):
            return s


def criar_email(local, dominio, senha, quota):
    r = requests.post(
        f"{CP_HOST}/execute/Email/add_pop",
        headers={"Authorization": f"cpanel {CP_USER}:{CP_TOKEN}"},
        data={
            "email": local,
            "domain": dominio,
            "password": senha,
            "quota": quota,
            "skip_update_db": 1,
        },
        timeout=30,
        verify=VERIFY_TLS,
    )
    try:
        d = r.json()
    except ValueError:
        return False, f"resposta inválida do cPanel (HTTP {r.status_code})"
    if d.get("status") == 1:
        return True, ""
    return False, "; ".join(d.get("errors") or ["erro desconhecido"])


@app.route("/healthz")
def healthz():
    return "ok", 200


@app.before_request
def exigir_login():
    if request.path == "/healthz":
        return None
    a = request.authorization
    ok = (
        a
        and hmac.compare_digest(a.username or "", APP_USER)
        and hmac.compare_digest(a.password or "", APP_PASS)
    )
    if not ok:
        return ("Acesso negado", 401, {"WWW-Authenticate": 'Basic realm="Emails"'})


@app.after_request
def cabecalhos(resp):
    resp.headers["Cache-Control"] = "no-store"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    return resp


@app.route("/", methods=["GET", "POST"])
def index():
    resultados = []
    if request.method == "POST":
        token = session.get("csrf", "")
        if not token or not hmac.compare_digest(token, request.form.get("csrf", "")):
            abort(400)
        try:
            quota = max(0, min(int(request.form.get("quota", "1024")), 102400))
        except ValueError:
            quota = 1024

        linhas = [l.strip() for l in request.form.get("lista", "").splitlines() if l.strip()]
        for linha in linhas[:MAX_LINHAS]:
            endereco, _, senha = linha.partition(",")
            endereco = endereco.strip().lower()
            senha = senha.strip()
            if endereco.count("@") != 1:
                resultados.append({"email": endereco, "ok": False, "info": "formato inválido"})
                continue
            local, dominio = endereco.split("@")
            if not LOCAL_RE.match(local):
                resultados.append({"email": endereco, "ok": False, "info": "usuário inválido"})
                continue
            if dominio not in ALLOWED_DOMAINS:
                resultados.append({"email": endereco, "ok": False, "info": "domínio não permitido"})
                continue
            gerada = not senha
            if gerada:
                senha = gerar_senha()
            ok, erro = criar_email(local, dominio, senha, quota)
            resultados.append(
                {"email": endereco, "ok": ok, "info": senha if ok else erro}
            )
        if len(linhas) > MAX_LINHAS:
            resultados.append(
                {"email": "-", "ok": False,
                 "info": f"apenas as primeiras {MAX_LINHAS} linhas foram processadas"}
            )

    session["csrf"] = secrets.token_urlsafe(32)
    return render_template(
        "index.html",
        csrf=session["csrf"],
        resultados=resultados,
        dominios=sorted(ALLOWED_DOMAINS),
    )


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000)
