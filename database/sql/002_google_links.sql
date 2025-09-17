-- Vínculo de contas Google por usuário local (login social)
-- Usado quando o usuário vincula sua conta Google à conta local
-- Compatível com SQLite

PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS google_links (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL UNIQUE,
    google_sub TEXT NOT NULL UNIQUE,
    email TEXT,
    name TEXT,
    picture TEXT,
    access_token TEXT,
    refresh_token TEXT,
    expires_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_google_links_user ON google_links(user_id);
CREATE INDEX IF NOT EXISTS idx_google_links_sub  ON google_links(google_sub);