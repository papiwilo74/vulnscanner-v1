-- 002: Organizaciones, Usuarios RBAC y Cluster Distribuido
CREATE TABLE IF NOT EXISTS organizations (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    slug TEXT UNIQUE NOT NULL,
    tier TEXT NOT NULL DEFAULT 'enterprise',
    created_at TEXT NOT NULL,
    max_scans_monthly INTEGER NOT NULL DEFAULT 1000
);

CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    full_name TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'developer',
    is_active INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL,
    FOREIGN KEY (org_id) REFERENCES organizations (id)
);

CREATE TABLE IF NOT EXISTS cluster_workers (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    region TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'online',
    max_concurrency INTEGER NOT NULL DEFAULT 2,
    active_jobs INTEGER NOT NULL DEFAULT 0,
    tags TEXT NOT NULL DEFAULT '[]',
    last_heartbeat TEXT NOT NULL,
    registered_at TEXT NOT NULL
);
