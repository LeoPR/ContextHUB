"""
storage.py

Abstração de armazenamento para salvar conteúdo baixado e metadados.
Inclui uma implementação SQLite + armazenamento em disco (./synced).

API principal usada pelo app:
- get_storage() -> retorna instância de StorageBase (já inicializada)
- StorageBase.save_stream(url, response, max_bytes) -> (id, filename)
- StorageBase.list_links() -> list of dict rows (id, url, filename, content_type, created_at)
- StorageBase.get_filename(link_id) -> filename or None
- StorageBase.get_filepath(filename) -> caminho completo no disco
"""

import os
import sqlite3
import time
import uuid
import mimetypes
from typing import Optional, List, Dict

SYNC_DIR = "synced"
DB_PATH = "app.db"


class StorageBase:
    """Interface/base para implementações de armazenamento."""

    def init(self):
        """Cria diretórios, tabelas, etc."""
        raise NotImplementedError

    def save_stream(self, url: str, response, max_bytes: int) -> (int, str):
        """
        Salva o conteúdo vindo de uma resposta 'streaming' (requests.Response).
        Deve checar tamanho e gravar em disco, retornar (id, filename).
        """
        raise NotImplementedError

    def list_links(self) -> List[Dict]:
        """Retorna lista de registros com chaves: id, url, filename, content_type, created_at"""
        raise NotImplementedError

    def get_filename(self, link_id: int) -> Optional[str]:
        """Retorna o filename registrado para o id, ou None se não existir."""
        raise NotImplementedError

    def get_filepath(self, filename: str) -> str:
        """Retorna o caminho completo no disco para um filename."""
        return os.path.join(SYNC_DIR, filename)


class SqliteDiskStorage(StorageBase):
    """Implementação simples usando SQLite e arquivos em disco (SYNC_DIR)."""

    def __init__(self, db_path: str = DB_PATH, sync_dir: str = SYNC_DIR):
        self.db_path = db_path
        self.sync_dir = sync_dir

    def init(self):
        os.makedirs(self.sync_dir, exist_ok=True)
        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS links (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT NOT NULL,
                filename TEXT NOT NULL,
                content_type TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        conn.commit()
        conn.close()

    def _get_conn(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _guess_ext(self, content_type: str) -> str:
        if not content_type:
            return ".bin"
        ct = content_type.split(";")[0].strip()
        ext = mimetypes.guess_extension(ct) or ""
        if not ext:
            if ct.startswith("text/html"):
                return ".html"
            if ct.startswith("text/"):
                return ".txt"
            return ".bin"
        return ext

    def save_stream(self, url: str, response, max_bytes: int) -> (int, str):
        """
        response: objeto requests.Response com stream=True
        Retorna (id, filename) no DB após salvar.
        """
        content_type = response.headers.get("Content-Type", "application/octet-stream").split(";")[0].strip()
        ext = self._guess_ext(content_type)
        filename = f"{int(time.time())}_{uuid.uuid4().hex}{ext}"
        filepath = os.path.join(self.sync_dir, filename)

        bytes_written = 0
        try:
            with open(filepath, "wb") as f:
                for chunk in response.iter_content(chunk_size=8192):
                    if chunk:
                        bytes_written += len(chunk)
                        if bytes_written > max_bytes:
                            # remove parcial e aborta
                            f.close()
                            try:
                                os.remove(filepath)
                            except Exception:
                                pass
                            raise IOError("Exceeded max bytes")
                        f.write(chunk)
        except Exception:
            # certifique-se que arquivo parcial seja removido
            if os.path.exists(filepath):
                try:
                    os.remove(filepath)
                except Exception:
                    pass
            raise

        # grava metadados no DB
        conn = self._get_conn()
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO links (url, filename, content_type) VALUES (?, ?, ?)",
            (url, filename, content_type),
        )
        conn.commit()
        row_id = cur.lastrowid
        conn.close()
        return row_id, filename

    def list_links(self) -> List[Dict]:
        conn = self._get_conn()
        cur = conn.cursor()
        cur.execute("SELECT id, url, filename, content_type, created_at FROM links ORDER BY created_at DESC")
        rows = cur.fetchall()
        conn.close()
        return [dict(r) for r in rows]

    def get_filename(self, link_id: int) -> Optional[str]:
        conn = self._get_conn()
        cur = conn.cursor()
        cur.execute("SELECT filename FROM links WHERE id = ?", (link_id,))
        row = cur.fetchone()
        conn.close()
        if row:
            return row["filename"]
        return None


# Factory para obter a implementação ativa (pode ser alterada facilmente)
def get_storage() -> StorageBase:
    """
    Retorna a instância de StorageBase que o app usará.
    Para trocar implementação, altere aqui.
    """
    storage = SqliteDiskStorage()
    storage.init()
    return storage