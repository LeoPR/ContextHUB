"""
tools/google_credentials.py

Gerencia as credenciais administrativas do Google (tabela google_credentials).
Compatível com o schema definido em database/sql/010_google_credentials.sql.

Funções públicas:
- ensure_table_exists(db_path)
- add_google_credentials(db_path, client_id, client_secret, label=None, redirect_uris=None, scopes=None, refresh_token=None, access_token=None, token_expires_at=None, active=1)
- get_google_credentials(db_path, cred_id=None) -> dict | None
- get_all_google_credentials(db_path) -> list[dict]
- update_google_credentials(db_path, cred_id, **fields) -> bool
- delete_google_credentials(db_path, cred_id) -> bool
- export_google_credentials(db_path, cred_id=None) -> path | None
"""
from typing import Optional, Dict, List, Any
import os
import sqlite3
import json
from datetime import datetime
import tempfile

DEFAULT_DB = os.environ.get("DB_PATH", "app.db")


def _get_conn(db_path: str = DEFAULT_DB):
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn


def ensure_table_exists(db_path: str = DEFAULT_DB):
    """
    Garante que a tabela google_credentials exista (idempotente).
    """
    sql = """
    PRAGMA foreign_keys = ON;
    CREATE TABLE IF NOT EXISTS google_credentials (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        label TEXT,
        client_id TEXT NOT NULL,
        client_secret TEXT NOT NULL,
        redirect_uris TEXT,
        scopes TEXT,
        active INTEGER DEFAULT 1,
        access_token TEXT,
        refresh_token TEXT,
        token_expires_at TIMESTAMP,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    CREATE INDEX IF NOT EXISTS idx_google_credentials_active ON google_credentials(active);
    """
    conn = _get_conn(db_path)
    try:
        conn.executescript(sql)
        conn.commit()
    finally:
        conn.close()


def _row_to_dict(row: sqlite3.Row) -> Dict[str, Any]:
    if row is None:
        return None
    d = dict(row)
    # Parse redirect_uris JSON string -> list
    if d.get("redirect_uris"):
        try:
            d["redirect_uris"] = json.loads(d["redirect_uris"])
        except Exception:
            # se não for JSON válido, deixar a string original
            pass
    else:
        d["redirect_uris"] = None
    # Parse scopes string -> list
    if d.get("scopes"):
        if isinstance(d["scopes"], str):
            d["scopes"] = [s for s in d["scopes"].split() if s]
    else:
        d["scopes"] = None
    return d


def add_google_credentials(
    db_path: str = DEFAULT_DB,
    client_id: str = None,
    client_secret: str = None,
    label: Optional[str] = None,
    redirect_uris: Optional[List[str]] = None,
    scopes: Optional[List[str]] = None,
    refresh_token: Optional[str] = None,
    access_token: Optional[str] = None,
    token_expires_at: Optional[str] = None,
    active: int = 1,
) -> int:
    """
    Insere uma nova credencial. Retorna o id criado.
    redirect_uris: lista -> será armazenada como JSON string.
    scopes: lista -> será armazenada como espaço-separado string.
    """
    if not client_id or not client_secret:
        raise ValueError("client_id e client_secret são obrigatórios")

    ensure_table_exists(db_path=db_path)
    conn = _get_conn(db_path)
    cur = conn.cursor()
    ru = json.dumps(redirect_uris) if redirect_uris is not None else None
    sc = " ".join(scopes) if scopes else None
    cur.execute(
        """
        INSERT INTO google_credentials
        (label, client_id, client_secret, redirect_uris, scopes, active, access_token, refresh_token, token_expires_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
        """,
        (label, client_id, client_secret, ru, sc, 1 if active else 0, access_token, refresh_token, token_expires_at),
    )
    conn.commit()
    new_id = cur.lastrowid
    conn.close()
    return new_id


def get_all_google_credentials(db_path: str = DEFAULT_DB) -> List[Dict]:
    """
    Retorna todas as credenciais (lista de dicts).
    """
    ensure_table_exists(db_path=db_path)
    conn = _get_conn(db_path)
    cur = conn.cursor()
    cur.execute("SELECT * FROM google_credentials ORDER BY created_at DESC")
    rows = cur.fetchall()
    conn.close()
    return [_row_to_dict(r) for r in rows]


def get_google_credentials(db_path: str = DEFAULT_DB, cred_id: Optional[int] = None) -> Optional[Dict]:
    """
    Se cred_id for fornecido, retorna essa credencial.
    Se cred_id for None, retorna a primeira credencial ativa (active=1) ordenada por created_at DESC, ou None se não houver.
    """
    ensure_table_exists(db_path=db_path)
    conn = _get_conn(db_path)
    cur = conn.cursor()
    if cred_id is not None:
        cur.execute("SELECT * FROM google_credentials WHERE id = ?", (cred_id,))
        row = cur.fetchone()
        conn.close()
        return _row_to_dict(row)
    else:
        cur.execute("SELECT * FROM google_credentials WHERE active = 1 ORDER BY created_at DESC LIMIT 1")
        row = cur.fetchone()
        conn.close()
        return _row_to_dict(row)


def update_google_credentials(
    db_path: str = DEFAULT_DB,
    cred_id: int = None,
    label: Optional[str] = None,
    client_id: Optional[str] = None,
    client_secret: Optional[str] = None,
    redirect_uris: Optional[List[str]] = None,
    scopes: Optional[List[str]] = None,
    active: Optional[int] = None,
    access_token: Optional[str] = None,
    refresh_token: Optional[str] = None,
    token_expires_at: Optional[str] = None,
) -> bool:
    """
    Atualiza campos fornecidos para a credencial cred_id. Retorna True se atualizou.
    """
    if cred_id is None:
        raise ValueError("cred_id é obrigatório para update")

    ensure_table_exists(db_path=db_path)
    fields = []
    params = []
    if label is not None:
        fields.append("label = ?"); params.append(label)
    if client_id is not None:
        fields.append("client_id = ?"); params.append(client_id)
    if client_secret is not None:
        fields.append("client_secret = ?"); params.append(client_secret)
    if redirect_uris is not None:
        fields.append("redirect_uris = ?"); params.append(json.dumps(redirect_uris))
    if scopes is not None:
        fields.append("scopes = ?"); params.append(" ".join(scopes) if isinstance(scopes, (list, tuple)) else scopes)
    if active is not None:
        fields.append("active = ?"); params.append(1 if active else 0)
    if access_token is not None:
        fields.append("access_token = ?"); params.append(access_token)
    if refresh_token is not None:
        fields.append("refresh_token = ?"); params.append(refresh_token)
    if token_expires_at is not None:
        fields.append("token_expires_at = ?"); params.append(token_expires_at)

    if not fields:
        return False

    # atualiza updated_at
    fields.append("updated_at = CURRENT_TIMESTAMP")
    sql = f"UPDATE google_credentials SET {', '.join(fields)} WHERE id = ?"
    params.append(cred_id)

    conn = _get_conn(db_path)
    cur = conn.cursor()
    cur.execute(sql, params)
    conn.commit()
    changed = cur.rowcount
    conn.close()
    return changed > 0


def delete_google_credentials(db_path: str = DEFAULT_DB, cred_id: int = None) -> bool:
    """
    Remove a credencial pelo id. Retorna True se removida.
    """
    if cred_id is None:
        raise ValueError("cred_id é obrigatório para delete")
    ensure_table_exists(db_path=db_path)
    conn = _get_conn(db_path)
    cur = conn.cursor()
    cur.execute("DELETE FROM google_credentials WHERE id = ?", (cred_id,))
    conn.commit()
    changed = cur.rowcount
    conn.close()
    return changed > 0


def export_google_credentials(db_path: str = DEFAULT_DB, cred_id: Optional[int] = None) -> Optional[str]:
    """
    Exporta a credencial (ou a primeira ativa se cred_id for None) para um arquivo JSON em /tmp.
    Retorna o caminho do arquivo ou None se não houver credencial para exportar.
    """
    ensure_table_exists(db_path=db_path)
    cred = get_google_credentials(db_path=db_path, cred_id=cred_id)
    if not cred:
        return None

    # Normaliza para exportação
    out = {
        "id": cred.get("id"),
        "label": cred.get("label"),
        "client_id": cred.get("client_id"),
        "client_secret": cred.get("client_secret"),
        "redirect_uris": cred.get("redirect_uris") or [],
        "scopes": cred.get("scopes") or [],
        "active": bool(cred.get("active")),
        "access_token": cred.get("access_token"),
        "refresh_token": cred.get("refresh_token"),
        "token_expires_at": cred.get("token_expires_at"),
        "created_at": cred.get("created_at"),
        "updated_at": cred.get("updated_at"),
    }

    fd, path = tempfile.mkstemp(prefix=f"google_cred_{cred.get('id')}_", suffix=".json", dir="/tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(out, f, indent=2, ensure_ascii=False)
    except Exception:
        try:
            os.remove(path)
        except Exception:
            pass
        raise
    return path


# Quando importado, garante a tabela existir (útil em tempo de execução)
ensure_table_exists()