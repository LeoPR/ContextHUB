"""
Decorators de segurança compartilhados entre blueprints.
"""
from functools import wraps
from flask import session, redirect, url_for, request, flash
import logging

logger = logging.getLogger(__name__)


def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("username"):
            logger.debug("Acesso negado: usuário não autenticado para %s", request.path)
            return redirect(url_for("auth.login", next=request.path))
        return f(*args, **kwargs)
    return decorated


def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("username"):
            logger.debug("Acesso negado (não autenticado) para %s", request.path)
            return redirect(url_for("auth.login", next=request.path))
        if not session.get("admin"):
            logger.warning("Acesso negado: '%s' sem privilégios admin tentou acessar %s", session.get("username"), request.path)
            flash("Acesso negado: permissões insuficientes.", "danger")
            return redirect(url_for("index"))
        return f(*args, **kwargs)
    return decorated