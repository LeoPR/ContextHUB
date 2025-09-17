"""
Blueprint de autenticação (/auth)
- /auth/login
- /auth/logout
- /auth/google/login
- /auth/google/callback
- /auth/google/unlink (POST)
- before_app_request: restaura sessão via cookie remember.
"""
import os
import logging
import json
import base64
import secrets
from datetime import datetime, timedelta
import requests
from flask import Blueprint, render_template, request, redirect, url_for, session, flash, make_response

import auth  # módulo de usuários/tokens

logger = logging.getLogger(__name__)

# Remember cookie config
REMEMBER_COOKIE_NAME = os.environ.get("REMEMBER_COOKIE_NAME", "REMEMBER_TOKEN")
REMEMBER_DAYS = int(os.environ.get("REMEMBER_DAYS", "30"))
FORCE_SECURE_COOKIE = os.environ.get("FORCE_SECURE_COOKIE", "0") == "1"

# Google OAuth config
GOOGLE_CLIENT_ID = os.environ.get("GOOGLE_CLIENT_ID", "")
GOOGLE_CLIENT_SECRET = os.environ.get("GOOGLE_CLIENT_SECRET", "")
GOOGLE_AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"
GOOGLE_ISS = {"https://accounts.google.com", "accounts.google.com"}

ALLOW_GOOGLE_SIGNUP = os.environ.get("ALLOW_GOOGLE_SIGNUP", "0") == "1"  # padrão: não cria usuário automaticamente

auth_bp = Blueprint("auth", __name__, template_folder="../templates")


def _base64url_decode(data: str) -> bytes:
    # Ajusta padding
    rem = len(data) % 4
    if rem:
        data += "=" * (4 - rem)
    return base64.urlsafe_b64decode(data.encode("utf-8"))


@auth_bp.app_context_processor
def inject_google_link_status():
    """
    Injeta variável 'google_linked' nos templates para o usuário atual.
    """
    linked = False
    glink = None
    uid = session.get("user_id")
    if uid:
        try:
            glink = auth.get_google_link_for_user(uid)
            linked = glink is not None
        except Exception:
            logger.exception("Erro ao consultar vínculo Google do usuário atual")
    return dict(google_linked=linked, google_link=glink)


@auth_bp.before_app_request
def restore_session_from_token():
    """
    Se não existe sessão, tenta restaurar a partir do cookie de remember.
    """
    if session.get("username"):
        return

    token = request.cookies.get(REMEMBER_COOKIE_NAME)
    if not token:
        return

    user = auth.get_user_by_token(token)
    if not user:
        logger.debug("Cookie remember inválido/expirado")
        return

    session["user_id"] = user["id"]
    session["username"] = user["username"]
    session["admin"] = user.get("is_admin", False)
    logger.info("Sessão restaurada via token para %s (token_id=%s)", user["username"], user.get("token_id"))


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    """
    Login com username+password e opção 'Lembrar sessão'.
    Bootstrap: primeiro usuário criado torna-se admin.
    """
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        remember = request.form.get("remember") == "on"

        logger.debug("Tentativa de login '%s' remember=%s", username, remember)

        if not username or not password:
            flash("Informe usuário e senha.", "warning")
            return redirect(url_for("auth.login"))

        existing = auth.get_user(username)
        if existing:
            user = auth.authenticate(username, password)
            if not user:
                logger.info("Falha de autenticação para %s", username)
                flash("Usuário ou senha incorretos.", "danger")
                return redirect(url_for("auth.login"))
        else:
            # criar usuário (bootstrap)
            cnt = auth.user_count()
            make_admin = (cnt == 0)
            try:
                user = auth.create_user(username, password, is_admin=make_admin)
            except Exception as e:
                logger.exception("Erro ao criar usuário '%s': %s", username, e)
                flash(f"Erro ao criar usuário: {e}", "danger")
                return redirect(url_for("auth.login"))

        # sessão ok
        session["user_id"] = user["id"]
        session["username"] = user["username"]
        session["admin"] = user.get("is_admin", False)

        resp = make_response(redirect(request.args.get("next") or url_for("admin.index")))
        if remember:
            token_id, raw_token = auth.create_token(user_id=user["id"], days=REMEMBER_DAYS, label=f"login-{username}")
            secure = FORCE_SECURE_COOKIE
            resp.set_cookie(REMEMBER_COOKIE_NAME, raw_token, max_age=REMEMBER_DAYS*24*3600, httponly=True, samesite="Lax", secure=secure)
            logger.debug("Cookie remember criado token_id=%s secure=%s", token_id, secure)
        flash("Login efetuado.", "success")
        return resp

    return render_template("auth/login.html")


@auth_bp.route("/logout")
def logout():
    """
    Faz logout: remove sessão e cookie remember (revoga token).
    """
    username = session.get("username")
    logger.debug("Logout solicitado por %s", username)
    token = request.cookies.get(REMEMBER_COOKIE_NAME)
    resp = make_response(redirect(url_for("auth.login")))
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


@auth_bp.route("/google/login")
def google_login():
    """
    Inicia o fluxo OAuth com o Google.
    - Se usuário está logado localmente: fluxo de VÍNCULO (link Google à conta atual).
    - Se não está logado: fluxo de LOGIN COM GOOGLE.
    """
    if not GOOGLE_CLIENT_ID or not GOOGLE_CLIENT_SECRET:
        flash("Login com Google não está configurado (defina GOOGLE_CLIENT_ID e GOOGLE_CLIENT_SECRET).", "warning")
        return redirect(url_for("auth.login"))

    intent = "link" if session.get("user_id") else "login"
    remember = request.args.get("remember", "0")

    # Gera state anti-CSRF
    state = secrets.token_urlsafe(16)
    session["oauth_state"] = state
    session["oauth_intent"] = intent
    session["oauth_remember"] = remember

    # Calcula redirect_uri
    redirect_uri = url_for("auth.google_callback", _external=True)

    # Monta URL de autorização
    params = {
        "client_id": GOOGLE_CLIENT_ID,
        "redirect_uri": redirect_uri,
        "response_type": "code",
        "scope": "openid email profile",
        "state": state,
        "access_type": "offline",  # tenta obter refresh_token no primeiro consent
        "include_granted_scopes": "true",
        # "prompt": "consent",  # se quiser forçar consent toda vez, descomente
    }

    from urllib.parse import urlencode
    url = f"{GOOGLE_AUTH_URL}?{urlencode(params)}"
    return redirect(url)


@auth_bp.route("/google/callback")
def google_callback():
    """
    Processa o retorno do Google: troca 'code' por tokens, valida id_token e
    executa login (se intent=login) ou vínculo (se intent=link).
    """
    err = request.args.get("error")
    if err:
        flash(f"Erro no login Google: {err}", "danger")
        return redirect(url_for("auth.login"))

    code = request.args.get("code", "")
    state = request.args.get("state", "")
    if not code or not state:
        flash("Resposta inválida do Google.", "danger")
        return redirect(url_for("auth.login"))

    if state != session.get("oauth_state"):
        flash("State inválido (possível CSRF).", "danger")
        return redirect(url_for("auth.login"))

    intent = session.get("oauth_intent") or "login"
    remember = session.get("oauth_remember") == "1"

    # Troca code por tokens
    data = {
        "code": code,
        "client_id": GOOGLE_CLIENT_ID,
        "client_secret": GOOGLE_CLIENT_SECRET,
        "redirect_uri": url_for("auth.google_callback", _external=True),
        "grant_type": "authorization_code",
    }

    try:
        resp = requests.post(GOOGLE_TOKEN_URL, data=data, timeout=15)
        resp.raise_for_status()
        token_json = resp.json()
    except Exception as e:
        logger.exception("Falha ao trocar code por tokens: %s", e)
        flash("Falha ao finalizar login com Google.", "danger")
        return redirect(url_for("auth.login"))

    id_token = token_json.get("id_token")
    access_token = token_json.get("access_token")
    refresh_token = token_json.get("refresh_token")  # pode vir ausente
    expires_in = token_json.get("expires_in")
    expires_at_iso = None
    if expires_in:
        try:
            expires_at_iso = (datetime.utcnow() + timedelta(seconds=int(expires_in))).isoformat()
        except Exception:
            pass

    if not id_token:
        flash("Resposta do Google sem id_token.", "danger")
        return redirect(url_for("auth.login"))

    # Decodifica id_token (sem verificar assinatura para simplicidade) e valida 'aud' e 'iss'
    try:
        parts = id_token.split(".")
        if len(parts) != 3:
            raise ValueError("id_token inválido")
        payload = json.loads(_base64url_decode(parts[1]).decode("utf-8"))
        sub = payload.get("sub")
        email = payload.get("email")
        name = payload.get("name")
        picture = payload.get("picture")
        aud = payload.get("aud")
        iss = payload.get("iss")
        if aud != GOOGLE_CLIENT_ID or iss not in GOOGLE_ISS:
            raise ValueError("id_token não corresponde ao client_id/issuer")
    except Exception as e:
        logger.exception("Falha ao decodificar/validar id_token: %s", e)
        flash("Token do Google inválido.", "danger")
        return redirect(url_for("auth.login"))

    # Intents
    if intent == "link":
        # Requer usuário local autenticado
        uid = session.get("user_id")
        if not uid:
            flash("Sessão local ausente para vincular Google. Faça login local e tente novamente.", "warning")
            return redirect(url_for("auth.login"))
        try:
            # Verifica se sub já pertence a outro usuário
            existing = auth.get_user_by_google_sub(sub)
            if existing and existing.get("id") != uid:
                flash("Esta conta Google já está vinculada a outro usuário.", "danger")
                return redirect(url_for("admin.index"))
            # Vincula (ou atualiza) com tokens
            auth.link_google_account(
                user_id=uid,
                google_sub=sub,
                email=email,
                name=name,
                picture=picture,
                access_token=access_token,
                refresh_token=refresh_token,
                expires_at_iso=expires_at_iso,
            )
            flash("Conta Google vinculada com sucesso.", "success")
            return redirect(url_for("admin.index"))
        except Exception as e:
            logger.exception("Erro ao vincular Google: %s", e)
            flash(f"Erro ao vincular conta Google: {e}", "danger")
            return redirect(url_for("admin.index"))

    # intent == "login"
    linked_user = auth.get_user_by_google_sub(sub)
    if not linked_user:
        if ALLOW_GOOGLE_SIGNUP:
            # Opcional: criar usuário local com base no e-mail do Google (desativado por padrão)
            try:
                username = email or f"google_{sub}"
                # senha aleatória (não usada para login via Google)
                temp_pass = secrets.token_urlsafe(12)
                user = auth.create_user(username, temp_pass, is_admin=False)
                auth.link_google_account(
                    user_id=user["id"],
                    google_sub=sub,
                    email=email,
                    name=name,
                    picture=picture,
                    access_token=access_token,
                    refresh_token=refresh_token,
                    expires_at_iso=expires_at_iso,
                )
                linked_user = user
            except Exception as e:
                logger.exception("Erro ao criar usuário por Google signup: %s", e)
                flash("Não foi possível criar usuário automaticamente. Faça login local e vincule o Google.", "warning")
                return redirect(url_for("auth.login"))
        else:
            flash("Nenhuma conta local vinculada a este Google. Faça login local e vincule em 'Vincular Google'.", "warning")
            return redirect(url_for("auth.login"))

    # Atualiza tokens do vínculo
    try:
        auth.update_google_tokens_by_sub(sub, access_token, refresh_token, expires_at_iso)
    except Exception:
        logger.exception("Falha ao atualizar tokens Google (sub=%s)", sub)

    # Autentica a sessão
    session["user_id"] = linked_user["id"]
    session["username"] = linked_user["username"]
    session["admin"] = bool(linked_user.get("is_admin", False))

    resp = make_response(redirect(url_for("admin.index")))
    if remember:
        token_id, raw_token = auth.create_token(user_id=linked_user["id"], days=REMEMBER_DAYS, label=f"google-{linked_user['username']}")
        resp.set_cookie(REMEMBER_COOKIE_NAME, raw_token, max_age=REMEMBER_DAYS*24*3600, httponly=True, samesite="Lax", secure=FORCE_SECURE_COOKIE)
        logger.debug("Cookie remember criado após login Google token_id=%s", token_id)
    flash("Login com Google concluído.", "success")
    return resp


@auth_bp.route("/google/unlink", methods=["POST"])
def google_unlink():
    """
    Desvincula a conta Google do usuário atual.
    """
    uid = session.get("user_id")
    if not uid:
        flash("Faça login para desvincular Google.", "warning")
        return redirect(url_for("auth.login"))
    try:
        auth.unlink_google_account(uid)
        flash("Conta Google desvinculada.", "success")
    except Exception as e:
        logger.exception("Erro ao desvincular Google: %s", e)
        flash(f"Erro ao desvincular Google: {e}", "danger")
    return redirect(url_for("admin.index"))