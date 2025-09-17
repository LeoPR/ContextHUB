-- Credenciais administrativas/organizacionais do Google (OAuth)
-- Usadas para o servidor atuar como "proxy" via conta do admin/organização
-- Compatível com SQLite

PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS google_credentials (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    label TEXT,                       -- rótulo para identificar (ex: "Org Main")
    client_id TEXT NOT NULL,
    client_secret TEXT NOT NULL,      -- SENSÍVEL: proteger/criptografar em repouso
    redirect_uris TEXT,               -- JSON array com URIs
    scopes TEXT,                      -- escopos (space-separated)
    active INTEGER DEFAULT 1,         -- 1=ativo para uso
    access_token TEXT,                -- token atual
    refresh_token TEXT,               -- para renovar access_token
    token_expires_at TIMESTAMP,       -- ISO-8601, quando access_token expira
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_google_credentials_active ON google_credentials(active);