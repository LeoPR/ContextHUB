"""
Blueprint administrativo (/admin)
- Dashboard de sincronização
- Lista/download de arquivos
- CRUD de usuários e gestão de tokens
"""
import os
import logging
from urllib.parse import urlparse
from flask import Blueprint, render_template, request, redirect, url_for, flash, send_from_directory, session
import requests

from security import admin_required
import storage
import auth

logger = logging.getLogger(__name__)

MAX_BYTES = int(os.environ.get("MAX_BYTES", str(50 * 1024 * 1024)))  # 50 MB
store = storage.get_storage()

admin_bp = Blueprint("admin", __name__, template_folder="../templates")


@admin_bp.route("/", methods=["GET", "POST"])
@admin_required
def index():
    if request.method == "POST":
        url = request.form.get("url", "").strip()
        if not url:
            flash("Informe uma URL.", "warning")
            return redirect(url_for("admin.index"))

        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https"):
            flash("Somente URLs http/https são permitidas.", "warning")
            return redirect(url_for("admin.index"))

        try:
            with requests.get(url, stream=True, timeout=15) as r:
                r.raise_for_status()

                content_length = r.headers.get("Content-Length")
                if content_length:
                    try:
                        if int(content_length) > MAX_BYTES:
                            flash("Arquivo muito grande (pelo header Content-Length).", "danger")
                            return redirect(url_for("admin.index"))
                    except ValueError:
                        pass

                try:
                    link_id, filename = store.save_stream(url, r, MAX_BYTES)
                except IOError:
                    flash("Arquivo excedeu o limite durante o download.", "danger")
                    return redirect(url_for("admin.index"))
                except Exception as e:
                    logger.exception("Erro ao salvar conteúdo: %s", e)
                    flash(f"Erro ao salvar o conteúdo: {e}", "danger")
                    return redirect(url_for("admin.index"))

                flash(f"Conteúdo salvo como {filename}.", "success")
                return redirect(url_for("admin.list_links"))

        except requests.RequestException as e:
            logger.exception("Erro ao baixar a URL: %s", e)
            flash(f"Erro ao baixar a URL: {e}", "danger")
            return redirect(url_for("admin.index"))

    return render_template("admin/index.html")


@admin_bp.route("/list")
@admin_required
def list_links():
    rows = store.list_links()
    return render_template("admin/list.html", links=rows)


@admin_bp.route("/download/<int:link_id>")
@admin_required
def download(link_id):
    filename = store.get_filename(link_id)
    if not filename:
        flash("Arquivo não encontrado.", "warning")
        return redirect(url_for("admin.list_links"))
    return send_from_directory(storage.SYNC_DIR, filename, as_attachment=True)


# ---------- Usuários ----------
@admin_bp.route("/users")
@admin_required
def users_list():
    users = auth.list_users()
    return render_template("admin/users.html", users=users)


@admin_bp.route("/users/new", methods=["GET", "POST"])
@admin_required
def users_new():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        is_admin = request.form.get("is_admin") == "on"
        if not username or not password:
            flash("Informe usuário e senha.", "warning")
            return redirect(url_for("admin.users_new"))
        try:
            auth.create_user(username, password, is_admin=is_admin)
            flash("Usuário criado.", "success")
            return redirect(url_for("admin.users_list"))
        except Exception as e:
            logger.exception("Erro ao criar usuário: %s", e)
            flash(f"Erro ao criar usuário: {e}", "danger")
            return redirect(url_for("admin.users_new"))
    return render_template("admin/user_form.html", user=None)


@admin_bp.route("/users/<int:user_id>/edit", methods=["GET", "POST"])
@admin_required
def users_edit(user_id):
    user = auth.get_user_by_id(user_id)
    if not user:
        flash("Usuário não encontrado.", "warning")
        return redirect(url_for("admin.users_list"))
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        is_admin = request.form.get("is_admin") == "on"
        if not username:
            flash("Informe um username.", "warning")
            return redirect(url_for("admin.users_edit", user_id=user_id))
        try:
            auth.update_user(user_id, username=username, is_admin=is_admin)
            flash("Usuário atualizado.", "success")
            return redirect(url_for("admin.users_list"))
        except Exception as e:
            logger.exception("Erro ao atualizar usuário: %s", e)
            flash(f"Erro ao atualizar usuário: {e}", "danger")
            return redirect(url_for("admin.users_edit", user_id=user_id))
    return render_template("admin/user_form.html", user=user)


@admin_bp.route("/users/<int:user_id>/password", methods=["GET", "POST"])
@admin_required
def users_password(user_id):
    user = auth.get_user_by_id(user_id)
    if not user:
        flash("Usuário não encontrado.", "warning")
        return redirect(url_for("admin.users_list"))
    if request.method == "POST":
        password = request.form.get("password", "")
        password_confirm = request.form.get("password_confirm", "")
        if not password or password != password_confirm:
            flash("Senhas não informadas ou não conferem.", "warning")
            return redirect(url_for("admin.users_password", user_id=user_id))
        try:
            auth.change_password(user_id, password, revoke_tokens=True)
            flash("Senha alterada e tokens revogados.", "success")
            return redirect(url_for("admin.users_list"))
        except Exception as e:
            logger.exception("Erro ao alterar senha: %s", e)
            flash(f"Erro ao alterar senha: {e}", "danger")
            return redirect(url_for("admin.users_password", user_id=user_id))
    return render_template("admin/user_password.html", user=user)


@admin_bp.route("/users/<int:user_id>/delete", methods=["POST"])
@admin_required
def users_delete(user_id):
    # Evita auto-remoção acidental
    if session.get("user_id") == user_id:
        flash("Não é permitido remover o usuário da sessão atual.", "warning")
        return redirect(url_for("admin.users_list"))
    try:
        auth.delete_user(user_id)
        flash("Usuário removido.", "success")
    except Exception as e:
        logger.exception("Erro ao remover usuário: %s", e)
        flash(f"Erro ao remover usuário: {e}", "danger")
    return redirect(url_for("admin.users_list"))


@admin_bp.route("/users/<int:user_id>/tokens")
@admin_required
def users_tokens(user_id):
    user = auth.get_user_by_id(user_id)
    if not user:
        flash("Usuário não encontrado.", "warning")
        return redirect(url_for("admin.users_list"))
    tokens = auth.list_tokens(user_id)
    return render_template("admin/user_tokens.html", user=user, tokens=tokens)


@admin_bp.route("/users/<int:user_id>/tokens/revoke/<int:token_id>", methods=["POST"])
@admin_required
def users_tokens_revoke(user_id, token_id):
    try:
        auth.revoke_token(token_id)
        flash("Token revogado.", "success")
    except Exception as e:
        logger.exception("Erro ao revogar token: %s", e)
        flash(f"Erro ao revogar token: {e}", "danger")
    return redirect(url_for("admin.users_tokens", user_id=user_id))


@admin_bp.route("/users/<int:user_id>/tokens/revoke_all", methods=["POST"])
@admin_required
def users_tokens_revoke_all(user_id):
    try:
        auth.revoke_all_tokens_for_user(user_id)
        flash("Todos os tokens do usuário foram revogados.", "success")
    except Exception as e:
        logger.exception("Erro ao revogar tokens: %s", e)
        flash(f"Erro ao revogar tokens: {e}", "danger")
    return redirect(url_for("admin.users_tokens", user_id=user_id))