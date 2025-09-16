"""
app.py (reorganizado para templates em subpastas e layout admin)

Mudanças principais:
- render_template agora usa caminhos: auth/login.html, admin/index.html, admin/list.html etc.
- Layouts e parciais: layouts/base.html, layouts/admin_base.html, partials/_nav.html, partials/_flash.html.
- Pequeno ajuste: sessão também guarda user_id (fica útil para políticas futuras).
"""
from flask import Flask, render_template, request, redirect, url_for, session, send_from_directory, flash, make_response
import os
import logging
import requests
from functools import wraps
from urllib.parse import urlparse

import storage
import auth

# Configurações
MAX_BYTES = 50 * 1024 * 1024  # 50 MB
PORT = int(os.environ.get("PORT", 8080))
SECRET_KEY = os.environ.get("SECRET_KEY", None) or os.urandom(24).hex()
LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO").upper()

REMEMBER_COOKIE_NAME = os.environ.get("REMEMBER_COOKIE_NAME", "REMEMBER_TOKEN")
REMEMBER_DAYS = int(os.environ.get("REMEMBER_DAYS", "30"))
FORCE_SECURE_COOKIE = os.environ.get("FORCE_SECURE_COOKIE", "0") == "1"

# Logging
numeric_level = getattr(logging, LOG_LEVEL, logging.INFO)
logging.basicConfig(level=numeric_level, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
logger = logging.getLogger("app")
logger.setLevel(numeric_level)

app = Flask(__name__)
app.secret_key = SECRET_KEY
app.logger.setLevel(numeric_level)
app.config["REMEMBER_DAYS"] = REMEMBER_DAYS  # disponível nos templates

# Inicializa storage e auth
logger.debug("Inicializando storage")
store = storage.get_storage()
logger.debug("Inicializando auth")
auth.init_auth()


def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("username"):
            logger.debug("Acesso negado: usuário não autenticado para %s", request.path)
            return redirect(url_for("login", next=request.path))
        return f(*args, **kwargs)
    return decorated


def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("username"):
            logger.debug("Acesso negado (não autenticado) para %s", request.path)
            return redirect(url_for("login", next=request.path))
        if not session.get("admin"):
            logger.warning("Acesso negado: usuário '%s' sem privilégios admin tentou acessar %s", session.get("username"), request.path)
            flash("Acesso negado: permissões insuficientes.", "danger")
            return redirect(url_for("index"))
        return f(*args, **kwargs)
    return decorated


@app.before_request
def restore_session_from_token():
    """
    Se não existe sessão, tenta restaurar a partir do cookie REMEMBER_TOKEN.
    """
    if session.get("username"):
        return

    token = request.cookies.get(REMEMBER_COOKIE_NAME)
    if not token:
        return

    user = auth.get_user_by_token(token)
    if not user:
        logger.debug("Cookie de remember não válido/expirado")
        return

    session["user_id"] = user["id"]
    session["username"] = user["username"]
    session["admin"] = user.get("is_admin", False)
    logger.info("Sessão restaurada via token para %s (token_id=%s)", user["username"], user.get("token_id"))


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/admin/login", methods=["GET", "POST"])
def login():
    """
    Login com username + password e opção 'Lembrar sessão'.
    Se o usuário não existir, cria (bootstrap: primeiro usuário torna-se admin).
    """
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        remember = request.form.get("remember") == "on"

        logger.debug("Tentativa de login para '%s' remember=%s", username, remember)

        if not username or not password:
            flash("Informe usuário e senha.", "warning")
            return redirect(url_for("login"))

        existing = auth.get_user(username)
        if existing:
            user = auth.authenticate(username, password)
            if not user:
                logger.info("Falha de autenticação para %s", username)
                flash("Usuário ou senha incorretos.", "danger")
                return redirect(url_for("login"))
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["admin"] = user.get("is_admin", False)
            logger.info("Login bem-sucedido: %s (admin=%s)", username, session["admin"])

            resp = make_response(redirect(request.args.get("next") or url_for("admin")))
            if remember:
                token_id, raw_token = auth.create_token(user_id=user["id"], days=REMEMBER_DAYS, label=f"login-{username}")
                secure = FORCE_SECURE_COOKIE
                resp.set_cookie(REMEMBER_COOKIE_NAME, raw_token, max_age=REMEMBER_DAYS*24*3600, httponly=True, samesite="Lax", secure=secure)
                logger.debug("Cookie remember criado token_id=%s", token_id)
            return resp
        else:
            # criar usuário (bootstrap)
            cnt = auth.user_count()
            make_admin = (cnt == 0)
            try:
                user = auth.create_user(username, password, is_admin=make_admin)
            except Exception as e:
                logger.exception("Erro ao criar usuário '%s': %s", username, e)
                flash(f"Erro ao criar usuário: {e}", "danger")
                return redirect(url_for("login"))

            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["admin"] = bool(user.get("is_admin", False))
            logger.info("Usuário criado e logado: %s (admin=%s)", username, session["admin"])

            resp = make_response(redirect(request.args.get("next") or url_for("admin")))
            if remember:
                token_id, raw_token = auth.create_token(user_id=user["id"], days=REMEMBER_DAYS, label=f"signup-{username}")
                secure = FORCE_SECURE_COOKIE
                resp.set_cookie(REMEMBER_COOKIE_NAME, raw_token, max_age=REMEMBER_DAYS*24*3600, httponly=True, samesite="Lax", secure=secure)
                logger.debug("Cookie remember criado token_id=%s", token_id)
            return resp

    return render_template("auth/login.html")


@app.route("/admin/logout")
def logout():
    """
    Faz logout: remove sessão e remove cookie remember (revoga token correspondente).
    """
    username = session.get("username")
    logger.debug("Logout solicitado por %s", username)
    token = request.cookies.get(REMEMBER_COOKIE_NAME)
    resp = make_response(redirect(url_for("login")))
    if token:
        try:
            auth.revoke_token_by_raw(token)
        except Exception:
            logger.exception("Erro ao revogar token no logout")
        resp.set_cookie(REMEMBER_COOKIE_NAME, "", expires=0)
    session.pop("user_id", None)
    session.pop("username", None)
    session.pop("admin", None)
    flash("Logout realizado.", "info")
    return resp


# -------------------------
# Rotas de sincronização (mantidas)
# -------------------------
@app.route("/admin", methods=["GET", "POST"])
@admin_required
def admin():
    if request.method == "POST":
        url = request.form.get("url", "").strip()
        if not url:
            flash("Informe uma URL.", "warning")
            return redirect(url_for("admin"))

        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https"):
            flash("Somente URLs http/https são permitidas.", "warning")
            return redirect(url_for("admin"))

        try:
            with requests.get(url, stream=True, timeout=15) as r:
                r.raise_for_status()

                content_length = r.headers.get("Content-Length")
                if content_length:
                    try:
                        if int(content_length) > MAX_BYTES:
                            flash("Arquivo muito grande (pelo header Content-Length).", "danger")
                            return redirect(url_for("admin"))
                    except ValueError:
                        pass

                try:
                    link_id, filename = store.save_stream(url, r, MAX_BYTES)
                except IOError:
                    flash("Arquivo excedeu o limite durante o download.", "danger")
                    return redirect(url_for("admin"))
                except Exception as e:
                    logger.exception("Erro ao salvar conteúdo: %s", e)
                    flash(f"Erro ao salvar o conteúdo: {e}", "danger")
                    return redirect(url_for("admin"))

                flash(f"Conteúdo salvo como {filename}.", "success")
                return redirect(url_for("list_links"))

        except requests.RequestException as e:
            logger.exception("Erro ao baixar a URL: %s", e)
            flash(f"Erro ao baixar a URL: {e}", "danger")
            return redirect(url_for("admin"))

    return render_template("admin/index.html")


@app.route("/admin/list")
@admin_required
def list_links():
    rows = store.list_links()
    return render_template("admin/list.html", links=rows)


@app.route("/download/<int:link_id>")
@admin_required
def download(link_id):
    filename = store.get_filename(link_id)
    if not filename:
        flash("Arquivo não encontrado.", "warning")
        return redirect(url_for("list_links"))
    return send_from_directory(storage.SYNC_DIR, filename, as_attachment=True)


# -------------------------
# Área administrativa de usuários (CRUD + tokens)
# -------------------------
@app.route("/admin/users")
@admin_required
def users_list():
    users = auth.list_users()
    return render_template("admin/users.html", users=users)


@app.route("/admin/users/new", methods=["GET", "POST"])
@admin_required
def users_new():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        is_admin = request.form.get("is_admin") == "on"
        if not username or not password:
            flash("Informe usuário e senha.", "warning")
            return redirect(url_for("users_new"))
        try:
            auth.create_user(username, password, is_admin=is_admin)
            flash("Usuário criado.", "success")
            return redirect(url_for("users_list"))
        except Exception as e:
            logger.exception("Erro ao criar usuário: %s", e)
            flash(f"Erro ao criar usuário: {e}", "danger")
            return redirect(url_for("users_new"))
    return render_template("admin/user_form.html", user=None)


@app.route("/admin/users/<int:user_id>/edit", methods=["GET", "POST"])
@admin_required
def users_edit(user_id):
    user = auth.get_user_by_id(user_id)
    if not user:
        flash("Usuário não encontrado.", "warning")
        return redirect(url_for("users_list"))
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        is_admin = request.form.get("is_admin") == "on"
        if not username:
            flash("Informe um username.", "warning")
            return redirect(url_for("users_edit", user_id=user_id))
        try:
            auth.update_user(user_id, username=username, is_admin=is_admin)
            flash("Usuário atualizado.", "success")
            return redirect(url_for("users_list"))
        except Exception as e:
            logger.exception("Erro ao atualizar usuário: %s", e)
            flash(f"Erro ao atualizar usuário: {e}", "danger")
            return redirect(url_for("users_edit", user_id=user_id))
    return render_template("admin/user_form.html", user=user)


@app.route("/admin/users/<int:user_id>/password", methods=["GET", "POST"])
@admin_required
def users_password(user_id):
    user = auth.get_user_by_id(user_id)
    if not user:
        flash("Usuário não encontrado.", "warning")
        return redirect(url_for("users_list"))
    if request.method == "POST":
        password = request.form.get("password", "")
        password_confirm = request.form.get("password_confirm", "")
        if not password or password != password_confirm:
            flash("Senhas não informadas ou não conferem.", "warning")
            return redirect(url_for("users_password", user_id=user_id))
        try:
            auth.change_password(user_id, password, revoke_tokens=True)
            flash("Senha alterada e tokens revogados.", "success")
            return redirect(url_for("users_list"))
        except Exception as e:
            logger.exception("Erro ao alterar senha: %s", e)
            flash(f"Erro ao alterar senha: {e}", "danger")
            return redirect(url_for("users_password", user_id=user_id))
    return render_template("admin/user_password.html", user=user)


@app.route("/admin/users/<int:user_id>/delete", methods=["POST"])
@admin_required
def users_delete(user_id):
    # Evita auto-remoção acidental (opcional)
    if session.get("user_id") == user_id:
        flash("Não é permitido remover o usuário da sessão atual.", "warning")
        return redirect(url_for("users_list"))
    try:
        auth.delete_user(user_id)
        flash("Usuário removido.", "success")
    except Exception as e:
        logger.exception("Erro ao remover usuário: %s", e)
        flash(f"Erro ao remover usuário: {e}", "danger")
    return redirect(url_for("users_list"))


@app.route("/admin/users/<int:user_id>/tokens")
@admin_required
def users_tokens(user_id):
    user = auth.get_user_by_id(user_id)
    if not user:
        flash("Usuário não encontrado.", "warning")
        return redirect(url_for("users_list"))
    tokens = auth.list_tokens(user_id)
    return render_template("admin/user_tokens.html", user=user, tokens=tokens)


@app.route("/admin/users/<int:user_id>/tokens/revoke/<int:token_id>", methods=["POST"])
@admin_required
def users_tokens_revoke(user_id, token_id):
    try:
        auth.revoke_token(token_id)
        flash("Token revogado.", "success")
    except Exception as e:
        logger.exception("Erro ao revogar token: %s", e)
        flash(f"Erro ao revogar token: {e}", "danger")
    return redirect(url_for("users_tokens", user_id=user_id))


@app.route("/admin/users/<int:user_id>/tokens/revoke_all", methods=["POST"])
@admin_required
def users_tokens_revoke_all(user_id):
    try:
        auth.revoke_all_tokens_for_user(user_id)
        flash("Todos os tokens do usuário foram revogados.", "success")
    except Exception as e:
        logger.exception("Erro ao revogar tokens: %s", e)
        flash(f"Erro ao revogar tokens: {e}", "danger")
    return redirect(url_for("users_tokens", user_id=user_id))


if __name__ == "__main__":
    logger.info("Starting app on port %s with LOG_LEVEL=%s", PORT, LOG_LEVEL)
    app.run(host="0.0.0.0", port=PORT)