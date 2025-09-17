from flask import Blueprint, render_template, request, redirect, url_for, flash
import os
from typing import Optional, Dict
from security import admin_required

# Usaremos o módulo utilitário criado previamente
try:
    from tools import google_credentials as gc
except Exception:  # fallback simples
    import importlib
    gc = importlib.import_module("tools.google_credentials")  # pode lançar erro se não existir

admin_google_bp = Blueprint("admin_google", __name__)
DB_PATH = os.environ.get("DB_PATH", "app.db")


def _parse_extra(extra_text: Optional[str]) -> Optional[Dict]:
    """Tenta fazer parse do campo extra (JSON)."""
    if not extra_text:
        return None
    import json
    extra_text = extra_text.strip()
    if not extra_text:
        return None
    try:
        return json.loads(extra_text)
    except Exception:
        flash("Campo 'extra' não é um JSON válido. Valor ignorado.", "warning")
        return None


@admin_google_bp.route("/google-credentials", methods=["GET", "POST"])
@admin_required
def google_credentials_page():
    """
    GET: exibe tutorial + formulário com dados atuais (se houver).
    POST: cria/atualiza a credencial.
    """
    if request.method == "POST":
        cred_id = request.form.get("cred_id", "").strip() or None
        client_id = request.form.get("client_id", "").strip()
        client_secret = request.form.get("client_secret", "").strip()
        refresh_token = request.form.get("refresh_token", "").strip() or None
        extra_raw = request.form.get("extra", "")
        extra = _parse_extra(extra_raw)

        if not client_id or not client_secret:
            flash("client_id e client_secret são obrigatórios.", "danger")
            return redirect(url_for("admin_google.google_credentials_page"))

        try:
            if cred_id:
                updated = gc.update_google_credentials(
                    DB_PATH,
                    int(cred_id),
                    client_id=client_id,
                    client_secret=client_secret,
                    refresh_token=refresh_token,
                    extra=extra,
                )
                if updated:
                    flash("Credencial atualizada com sucesso.", "success")
                else:
                    flash("Nada foi atualizado (verifique os dados).", "warning")
            else:
                new_id = gc.add_google_credentials(
                    DB_PATH,
                    client_id=client_id,
                    client_secret=client_secret,
                    refresh_token=refresh_token,
                    extra=extra,
                )
                flash(f"Credencial criada com sucesso (id={new_id}).", "success")
        except Exception as e:
            flash(f"Erro ao salvar credencial: {e}", "danger")

        return redirect(url_for("admin_google.google_credentials_page"))

    # GET
    creds = gc.get_google_credentials(DB_PATH)
    return render_template("admin/google_credentials.html", creds=creds)


@admin_google_bp.post("/google-credentials/delete")
@admin_required
def google_credentials_delete():
    cred_id = request.form.get("cred_id", "").strip()
    if not cred_id:
        flash("Nenhuma credencial selecionada para remover.", "warning")
        return redirect(url_for("admin_google.google_credentials_page"))
    try:
        ok = gc.delete_google_credentials(DB_PATH, int(cred_id))
        if ok:
            flash("Credencial removida.", "success")
        else:
            flash("Credencial não encontrada.", "warning")
    except Exception as e:
        flash(f"Erro ao remover credencial: {e}", "danger")
    return redirect(url_for("admin_google.google_credentials_page"))


@admin_google_bp.post("/google-credentials/export")
@admin_required
def google_credentials_export():
    cred_id = request.form.get("cred_id", "").strip() or None
    try:
        export_path = gc.export_google_credentials(DB_PATH, int(cred_id) if cred_id else None)
        if export_path:
            flash(f"Credencial exportada para: {export_path}", "info")
        else:
            flash("Nenhuma credencial encontrada para exportar.", "warning")
    except Exception as e:
        flash(f"Erro ao exportar credencial: {e}", "danger")
    return redirect(url_for("admin_google.google_credentials_page"))