"""
auth.py

Gerenciamento de usuários e tokens "remember me".
- Cria/usa a tabela users e tokens no mesmo DB SQLite (app.db por padrão).
- Funções:
  - init_auth()
  - create_user(username, password, is_admin=False)
  - authenticate(username, password)
  - get_user(username) / get_user_by_id(id)
  - user_count()
  - change_password(user_id, new_password, revoke_tokens=True)
  - delete_user(user_id)
  - create_token(user_id, days=30, label=None) -> (token_id, raw_token)
  - get_user_by_token(raw_token) -> user dict or None
  - list_tokens(user_id)
  - revoke_token(token_id) / revoke_token_by_raw(raw_token) / revoke_all_tokens_for_user(user_id)
"""

import os
import sqlite3
import logging
import hashlib
import secrets
from datetime import datetime, timedelta
from typing import Optional, Dict, List
from werkzeug.security import generate_password_hash, check_password_hash

logger = logging.getLogger(__name__)

DB_PATH = os.environ.get("DB_PATH", "app.db")
DEFAULT_REMEMBER_DAYS = int(os.environ.get("REMEMBER_DAYS", "30"))
# Quando mudar senha, revogar tokens por padrão
DEFAULT_REVOKE_ON_PASSWORD_CHANGE = os.environ.get("REVOKE_ON_PASSWORD_CHANGE", "1") != "0"


def _get_conn(db_path: str = DB_PATH):
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn


def init_auth(db_path: str = DB_PATH):
    """
    Inicializa as tabelas users e tokens.
    """
    logger.debug("Inicializando auth DB em %s", db_path)
    conn = _get_conn(db_path)
    cur = conn.cursor()
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            is_admin INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """
    )
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS tokens (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            token_hash TEXT NOT NULL,
            label TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            expires_at TIMESTAMP,
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
        )
        """
    )
    conn.commit()
    conn.close()
    logger.info("Tabelas users e tokens inicializadas (ou já existentes) em %s", db_path)


# -------------------------
# Usuários
# -------------------------
def create_user(username: str, password: str, is_admin: bool = False, db_path: str = DB_PATH) -> Dict:
    """
    Cria um usuário. Retorna dict com id, username, is_admin, created_at.
    Lança sqlite3.IntegrityError se username já existir.
    """
    logger.debug("Criando usuário '%s' (is_admin=%s)", username, is_admin)
    pw_hash = generate_password_hash(password)
    conn = _get_conn(db_path)
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO users (username, password_hash, is_admin) VALUES (?, ?, ?)",
        (username, pw_hash, 1 if is_admin else 0),
    )
    conn.commit()
    user_id = cur.lastrowid
    cur.execute("SELECT id, username, is_admin, created_at FROM users WHERE id = ?", (user_id,))
    row = cur.fetchone()
    conn.close()
    result = dict(row) if row else {}
    logger.info("Usuário criado: %s (id=%s, is_admin=%s)", result.get("username"), result.get("id"), result.get("is_admin"))
    return result


def authenticate(username: str, password: str, db_path: str = DB_PATH) -> Optional[Dict]:
    """
    Autentica usuário por username + password.
    Retorna dict do usuário (sem password_hash) se ok, ou None.
    """
    logger.debug("Autenticando usuário '%s'", username)
    conn = _get_conn(db_path)
    cur = conn.cursor()
    cur.execute("SELECT id, username, password_hash, is_admin, created_at FROM users WHERE username = ?", (username,))
    row = cur.fetchone()
    conn.close()
    if not row:
        logger.debug("Usuário '%s' não encontrado", username)
        return None
    pw_hash = row["password_hash"]
    if check_password_hash(pw_hash, password):
        logger.info("Autenticação bem-sucedida para '%s'", username)
        return {"id": row["id"], "username": row["username"], "is_admin": bool(row["is_admin"]), "created_at": row["created_at"]}
    logger.warning("Falha de autenticação para '%s': senha incorreta", username)
    return None


def get_user(username: str, db_path: str = DB_PATH) -> Optional[Dict]:
    conn = _get_conn(db_path)
    cur = conn.cursor()
    cur.execute("SELECT id, username, is_admin, created_at FROM users WHERE username = ?", (username,))
    row = cur.fetchone()
    conn.close()
    return dict(row) if row else None


def get_user_by_id(user_id: int, db_path: str = DB_PATH) -> Optional[Dict]:
    conn = _get_conn(db_path)
    cur = conn.cursor()
    cur.execute("SELECT id, username, is_admin, created_at FROM users WHERE id = ?", (user_id,))
    row = cur.fetchone()
    conn.close()
    return dict(row) if row else None


def user_count(db_path: str = DB_PATH) -> int:
    conn = _get_conn(db_path)
    cur = conn.cursor()
    cur.execute("SELECT COUNT(1) as cnt FROM users")
    row = cur.fetchone()
    conn.close()
    cnt = int(row["cnt"]) if row else 0
    logger.debug("Total de usuários no DB: %d", cnt)
    return cnt


def list_users(db_path: str = DB_PATH) -> List[Dict]:
    conn = _get_conn(db_path)
    cur = conn.cursor()
    cur.execute("SELECT id, username, is_admin, created_at FROM users ORDER BY created_at DESC")
    rows = cur.fetchall()
    conn.close()
    return [dict(r) for r in rows]


def change_password(user_id: int, new_password: str, revoke_tokens: bool = DEFAULT_REVOKE_ON_PASSWORD_CHANGE, db_path: str = DB_PATH) -> bool:
    """
    Altera senha de um usuário; opcionalmente revoga tokens existentes.
    Retorna True se alterado.
    """
    logger.debug("Alterando senha para user_id=%s revoke_tokens=%s", user_id, revoke_tokens)
    pw_hash = generate_password_hash(new_password)
    conn = _get_conn(db_path)
    cur = conn.cursor()
    cur.execute("UPDATE users SET password_hash = ? WHERE id = ?", (pw_hash, user_id))
    conn.commit()
    updated = cur.rowcount
    conn.close()
    if revoke_tokens:
        try:
            revoke_all_tokens_for_user(user_id, db_path=db_path)
        except Exception:
            logger.exception("Erro ao revogar tokens após alteração de senha para user_id=%s", user_id)
    return updated > 0


def update_user(user_id: int, username: Optional[str] = None, is_admin: Optional[bool] = None, db_path: str = DB_PATH) -> bool:
    """
    Atualiza username e/ou is_admin de um usuário. Retorna True se alterou.
    """
    logger.debug("Atualizando user_id=%s username=%s is_admin=%s", user_id, username, is_admin)
    if username is None and is_admin is None:
        return False
    conn = _get_conn(db_path)
    cur = conn.cursor()
    if username is not None and is_admin is not None:
        cur.execute("UPDATE users SET username = ?, is_admin = ? WHERE id = ?", (username, 1 if is_admin else 0, user_id))
    elif username is not None:
        cur.execute("UPDATE users SET username = ? WHERE id = ?", (username, user_id))
    else:
        cur.execute("UPDATE users SET is_admin = ? WHERE id = ?", (1 if is_admin else 0, user_id))
    conn.commit()
    changed = cur.rowcount
    conn.close()
    logger.info("Usuário atualizado user_id=%s changed=%s", user_id, changed)
    return changed > 0


def delete_user(user_id: int, db_path: str = DB_PATH) -> bool:
    """
    Remove usuário e tokens por cascade. Retorna True se deletou.
    """
    logger.debug("Deletando usuário id=%s", user_id)
    conn = _get_conn(db_path)
    cur = conn.cursor()
    cur.execute("DELETE FROM users WHERE id = ?", (user_id,))
    conn.commit()
    changed = cur.rowcount
    conn.close()
    logger.info("Usuário deletado id=%s changed=%s", user_id, changed)
    return changed > 0


# -------------------------
# Tokens "remember me"
# -------------------------
def _hash_token(raw_token: str) -> str:
    return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()


def create_token(user_id: int, days: int = DEFAULT_REMEMBER_DAYS, label: Optional[str] = None, db_path: str = DB_PATH) -> (int, str):
    """
    Cria um token, armazena o hash no DB e retorna (token_id, raw_token).
    raw_token deve ser entregue ao cliente (cookie).
    """
    raw = secrets.token_urlsafe(32)
    h = _hash_token(raw)
    expires = (datetime.utcnow() + timedelta(days=days)).isoformat()
    conn = _get_conn(db_path)
    cur = conn.cursor()
    cur.execute("INSERT INTO tokens (user_id, token_hash, label, expires_at) VALUES (?, ?, ?, ?)", (user_id, h, label, expires))
    conn.commit()
    token_id = cur.lastrowid
    conn.close()
    logger.info("Token criado id=%s user_id=%s expires=%s label=%s", token_id, user_id, expires, label)
    return token_id, raw


def get_user_by_token(raw_token: str, db_path: str = DB_PATH) -> Optional[Dict]:
    """
    Dado raw_token (do cookie), retorna o usuário se o token for válido e não expirado.
    """
    h = _hash_token(raw_token)
    conn = _get_conn(db_path)
    cur = conn.cursor()
    cur.execute("SELECT t.id as token_id, t.user_id, t.expires_at, u.id as uid, u.username, u.is_admin, u.created_at "
                "FROM tokens t JOIN users u ON t.user_id = u.id WHERE t.token_hash = ?", (h,))
    row = cur.fetchone()
    conn.close()
    if not row:
        logger.debug("Token não encontrado (hash=%s)", h)
        return None
    expires_at = row["expires_at"]
    if expires_at:
        try:
            exp = datetime.fromisoformat(expires_at)
            if datetime.utcnow() > exp:
                logger.info("Token expirado token_id=%s user_id=%s", row["token_id"], row["user_id"])
                # opcional: revogar token expirado
                try:
                    revoke_token(row["token_id"], db_path=db_path)
                except Exception:
                    logger.exception("Erro ao revogar token expirado id=%s", row["token_id"])
                return None
        except Exception:
            logger.exception("Formato inválido de expires_at para token_id=%s", row["token_id"])
            return None
    logger.info("Token válido para user_id=%s token_id=%s", row["user_id"], row["token_id"])
    return {"id": row["uid"], "username": row["username"], "is_admin": bool(row["is_admin"]), "created_at": row["created_at"], "token_id": row["token_id"]}


def list_tokens(user_id: int, db_path: str = DB_PATH) -> List[Dict]:
    conn = _get_conn(db_path)
    cur = conn.cursor()
    cur.execute("SELECT id, label, created_at, expires_at FROM tokens WHERE user_id = ? ORDER BY created_at DESC", (user_id,))
    rows = cur.fetchall()
    conn.close()
    return [dict(r) for r in rows]


def revoke_token(token_id: int, db_path: str = DB_PATH) -> bool:
    conn = _get_conn(db_path)
    cur = conn.cursor()
    cur.execute("DELETE FROM tokens WHERE id = ?", (token_id,))
    conn.commit()
    changed = cur.rowcount
    conn.close()
    logger.info("Token revoke_token id=%s changed=%s", token_id, changed)
    return changed > 0


def revoke_token_by_raw(raw_token: str, db_path: str = DB_PATH) -> bool:
    h = _hash_token(raw_token)
    conn = _get_conn(db_path)
    cur = conn.cursor()
    cur.execute("DELETE FROM tokens WHERE token_hash = ?", (h,))
    conn.commit()
    changed = cur.rowcount
    conn.close()
    logger.info("Token revoke_token_by_raw hash=%s changed=%s", h, changed)
    return changed > 0


def revoke_all_tokens_for_user(user_id: int, db_path: str = DB_PATH) -> int:
    conn = _get_conn(db_path)
    cur = conn.cursor()
    cur.execute("DELETE FROM tokens WHERE user_id = ?", (user_id,))
    conn.commit()
    changed = cur.rowcount
    conn.close()
    logger.info("Revoke all tokens for user_id=%s removed=%s", user_id, changed)
    return changed