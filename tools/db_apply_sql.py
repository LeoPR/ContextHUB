#!/usr/bin/env python3
"""
Aplica todos os scripts .sql em database/sql na ordem numérica (SQLite).

Uso:
  DB_PATH=/caminho/para/app.db python3 tools/db_apply_sql.py
  (ou sem DB_PATH, usa app.db no diretório atual)

Observações:
- Idempotente: os scripts usam CREATE TABLE IF NOT EXISTS.
- Saída no console indica a ordem e resultado.
"""

import os
import sqlite3
from glob import glob

DB_PATH = os.environ.get("DB_PATH", "app.db")

def apply_sql_file(conn, path):
    with open(path, "r", encoding="utf-8") as f:
        sql = f.read()
    conn.executescript(sql)

def main():
    base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    sql_dir = os.path.join(base, "database", "sql")
    files = sorted(glob(os.path.join(sql_dir, "*.sql")))
    if not files:
        print(f"Nenhum .sql encontrado em {sql_dir}")
        return

    print(f"Usando DB_PATH={DB_PATH}")
    conn = sqlite3.connect(DB_PATH)
    try:
        for f in files:
            name = os.path.basename(f)
            print(f">>> Aplicando {name} ...", end="", flush=True)
            apply_sql_file(conn, f)
            print(" OK")
        conn.commit()
        print("Concluído.")
    finally:
        conn.close()

if __name__ == "__main__":
    main()