import hmac
import json
import os
import re
import secrets
import string
import time
from datetime import timedelta

import requests

try:  # opcional: carrega o .env em desenvolvimento local
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass
from flask import (Flask, abort, redirect, render_template, request, session,
                   url_for)
from werkzeug.middleware.proxy_fix import ProxyFix

app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)
app.secret_key = os.environ["SECRET_KEY"]
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Strict",
    SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE", "false").lower() == "true",
    PERMANENT_SESSION_LIFETIME=timedelta(
        hours=int(os.environ.get("SESSION_HORAS", "8"))
    ),
)

CP_HOST = os.environ["CP_HOST"].rstrip("/")  # ex: https://vps.lomapv.com.br:2083
APP_USER = os.environ["APP_USER"]
APP_PASS = os.environ["APP_PASS"]
VERIFY_TLS = os.environ.get("VERIFY_TLS", "true").lower() == "true"
MAX_LINHAS = int(os.environ.get("MAX_LINHAS", "50"))

LOCAL_RE = re.compile(r"^[a-z0-9._-]{1,64}$")

# limite de tentativas de login (por IP, em memória de cada worker)
MAX_FALHAS = 5
JANELA_FALHAS = 600  # segundos
FALHAS = {}


def carregar_contas():
    bruto = os.environ.get("ACCOUNTS", "").strip()
    if bruto:
        try:
            dados = json.loads(bruto)
        except json.JSONDecodeError as e:
            raise RuntimeError(f"ACCOUNTS não é um JSON válido: {e}")
        contas = {}
        for dominio, cred in dados.items():
            if not isinstance(cred, dict) or not cred.get("user") or not cred.get("token"):
                raise RuntimeError(f"ACCOUNTS: faltam 'user' ou 'token' em {dominio}")
            contas[dominio.strip().lower()] = {
                "user": cred["user"],
                "token": cred["token"],
            }
        return contas
    # compatibilidade com a configuração antiga (conta única)
    user = os.environ["CP_USER"]
    token = os.environ["CP_TOKEN"]
    dominios = {
        d.strip().lower()
        for d in os.environ["ALLOWED_DOMAINS"].split(",")
        if d.strip()
    }
    return {d: {"user": user, "token": token} for d in dominios}


ACCOUNTS = carregar_contas()
ALLOWED_DOMAINS = set(ACCOUNTS)


def igual(a, b):
    """Comparação em tempo constante, segura para qualquer texto (inclusive acentos)."""
    return hmac.compare_digest((a or "").encode("utf-8"), (b or "").encode("utf-8"))


def gerar_senha(n=16):
    letras = string.ascii_letters + string.digits
    simbolos = "#@%!"
    while True:
        s = "".join(secrets.choice(letras + simbolos) for _ in range(n))
        if (any(c.islower() for c in s) and any(c.isupper() for c in s)
                and any(c.isdigit() for c in s) and any(c in simbolos for c in s)):
            return s


def criar_email(local, dominio, senha, quota):
    conta = ACCOUNTS[dominio]
    try:
        r = requests.post(
            f"{CP_HOST}/execute/Email/add_pop",
            headers={"Authorization": f"cpanel {conta['user']}:{conta['token']}"},
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
    except requests.RequestException:
        return False, "falha de conexão com o cPanel"
    if r.status_code in (401, 403):
        return False, "token inválido ou sem permissão para esta conta"
    try:
        d = r.json()
    except ValueError:
        return False, f"resposta inválida do cPanel (HTTP {r.status_code})"
    if d.get("status") == 1:
        return True, ""
    return False, "; ".join(d.get("errors") or ["erro desconhecido"])


# ---------- proteção contra tentativas em excesso ----------
def bloqueado(ip):
    agora = time.time()
    recentes = [t for t in FALHAS.get(ip, []) if agora - t < JANELA_FALHAS]
    if recentes:
        FALHAS[ip] = recentes
    else:
        FALHAS.pop(ip, None)
    return len(recentes) >= MAX_FALHAS


def registrar_falha(ip):
    FALHAS.setdefault(ip, []).append(time.time())


# ---------- sessão / CSRF ----------
def garantir_csrf():
    if "csrf" not in session:
        session["csrf"] = secrets.token_urlsafe(32)
    return session["csrf"]


def checar_csrf():
    token = session.get("csrf", "")
    if not token or not igual(token, request.form.get("csrf", "")):
        abort(400, "Sessão expirada ou formulário antigo. Recarregue a página e tente de novo.")


ROTAS_ABERTAS = {"healthz", "login"}


@app.before_request
def exigir_login():
    if request.endpoint in ROTAS_ABERTAS:
        return None
    if not session.get("auth"):
        return redirect(url_for("login"))
    return None


@app.after_request
def cabecalhos(resp):
    resp.headers["Cache-Control"] = "no-store"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    return resp


@app.route("/healthz")
def healthz():
    return "ok", 200


@app.route("/login", methods=["GET", "POST"])
def login():
    if session.get("auth"):
        return redirect(url_for("index"))

    erro = ""
    status = 200
    if request.method == "POST":
        checar_csrf()
        ip = request.remote_addr or "?"
        if bloqueado(ip):
            erro = "Muitas tentativas. Aguarde alguns minutos e tente de novo."
            status = 429
        else:
            usuario_ok = igual(request.form.get("usuario", "").strip(), APP_USER)
            senha_ok = igual(request.form.get("senha", ""), APP_PASS)
            if usuario_ok and senha_ok:
                FALHAS.pop(ip, None)
                session.clear()
                session["auth"] = True
                session.permanent = True
                garantir_csrf()
                return redirect(url_for("index"))
            registrar_falha(ip)
            erro = "Usuário ou senha incorretos."
            status = 401

    return render_template("login.html", csrf=garantir_csrf(), erro=erro), status


@app.route("/logout", methods=["POST"])
def logout():
    checar_csrf()
    session.clear()
    return redirect(url_for("login"))


@app.route("/", methods=["GET", "POST"])
def index():
    resultados = []
    if request.method == "POST":
        checar_csrf()
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

    return render_template(
        "index.html",
        csrf=garantir_csrf(),
        resultados=resultados,
        dominios=sorted(ALLOWED_DOMAINS),
        max_linhas=MAX_LINHAS,
    )


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000)
