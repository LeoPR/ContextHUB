import sqlite3
import json
import os
from typing import Optional, Dict

def add_google_credentials(db_path: str, client_id: str, client_secret: str, refresh_token: Optional[str] = None, extra: Optional[Dict] = None) -> int:
    """
    Adiciona credenciais do Google na tabela google_credentials.
    Retorna o ID da credencial inserida.
    """
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    cur.execute(
        """
        INSERT INTO google_credentials (client_id, client_secret, refresh_token, extra)
        VALUES (?, ?, ?, ?)
        """,
        (client_id, client_secret, refresh_token, json.dumps(extra) if extra else None)
    )
    conn.commit()
    inserted_id = cur.lastrowid
    conn.close()
    return inserted_id

def get_google_credentials(db_path: str, cred_id: Optional[int] = None) -> Optional[Dict]:
    """
    Busca credenciais do Google pelo ID. Se não passar ID, retorna a primeira encontrada.
    """
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    if cred_id:
        cur.execute("SELECT id, client_id, client_secret, refresh_token, extra FROM google_credentials WHERE id = ?", (cred_id,))
    else:
        cur.execute("SELECT id, client_id, client_secret, refresh_token, extra FROM google_credentials LIMIT 1")
    row = cur.fetchone()
    conn.close()
    if row:
        id_, client_id, client_secret, refresh_token, extra = row
        return {
            "id": id_,
            "client_id": client_id,
            "client_secret": client_secret,
            "refresh_token": refresh_token,
            "extra": json.loads(extra) if extra else None
        }
    return None

def update_google_credentials(db_path: str, cred_id: int, client_id: Optional[str] = None, client_secret: Optional[str] = None, refresh_token: Optional[str] = None, extra: Optional[Dict] = None) -> bool:
    """
    Atualiza credenciais do Google pelo ID.
    """
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    # Monta o update dinâmico
    fields = []
    params = []
    if client_id is not None:
        fields.append("client_id = ?")
        params.append(client_id)
    if client_secret is not None:
        fields.append("client_secret = ?")
        params.append(client_secret)
    if refresh_token is not None:
        fields.append("refresh_token = ?")
        params.append(refresh_token)
    if extra is not None:
        fields.append("extra = ?")
        params.append(json.dumps(extra))
    if not fields:
        conn.close()
        return False
    params.append(cred_id)
    sql = "UPDATE google_credentials SET " + ", ".join(fields) + " WHERE id = ?"
    cur.execute(sql, params)
    conn.commit()
    updated = cur.rowcount > 0
    conn.close()
    return updated

def delete_google_credentials(db_path: str, cred_id: int) -> bool:
    """
    Remove credenciais do Google pelo ID.
    """
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    cur.execute("DELETE FROM google_credentials WHERE id = ?", (cred_id,))
    conn.commit()
    deleted = cur.rowcount > 0
    conn.close()
    return deleted

def export_google_credentials(db_path: str, cred_id: Optional[int] = None, export_path: Optional[str] = None) -> Optional[str]:
    """
    Exporta credenciais do Google para um arquivo JSON temporário.
    Retorna o caminho do arquivo criado.
    """
    creds = get_google_credentials(db_path, cred_id)
    if not creds:
        return None
    export_path = export_path or "/tmp/google_credentials.json"
    with open(export_path, "w", encoding="utf-8") as f:
        json.dump(creds, f, indent=2, ensure_ascii=False)
    return export_path

# Exemplo de uso (remova ou adapte conforme necessidade):
if __name__ == "__main__":
    DB_PATH = os.environ.get("DB_PATH", "app.db")
    # Adicionar credenciais
    # cred_id = add_google_credentials(DB_PATH, "123", "abc", "token", {"scopes": ["calendar"]})
    # Buscar credenciais
    # creds = get_google_credentials(DB_PATH)
    # Atualizar credenciais
    # update_google_credentials(DB_PATH, cred_id, client_secret="novo_secret")
    # Remover credenciais
    # delete_google_credentials(DB_PATH, cred_id)
    # Exportar credenciais
    # export_google_credentials(DB_PATH, cred_id)