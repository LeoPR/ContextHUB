# Scripts SQL de criação do schema (SQLite)

Esta pasta contém scripts `.sql` para criar os objetos de banco utilizados pelo serviço.

Ordem de execução recomendada (pela numeração do prefixo):
1. `001_users_tokens.sql`
2. `002_google_links.sql`
3. `010_google_credentials.sql`

## Executando manualmente (SQLite CLI)
Assumindo o arquivo do banco como `app.db`:
```bash
sqlite3 app.db < database/sql/001_users_tokens.sql
sqlite3 app.db < database/sql/002_google_links.sql
sqlite3 app.db < database/sql/010_google_credentials.sql
```

## Executando todos de uma vez (script Python opcional)
Você pode usar o utilitário `tools/db_apply_sql.py`:
```bash
# DB_PATH padrão é app.db; para alterar:
# export DB_PATH=/caminho/para/seu.db
python3 tools/db_apply_sql.py
```

Observações:
- Os scripts usam `CREATE TABLE IF NOT EXISTS`, então são idempotentes.
- Proteja o arquivo do banco dentro do container (permissões restritas) e, se possível, criptografe segredos sensíveis (como `client_secret` e `refresh_token`) em repouso.