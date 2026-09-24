-- 003: Resiliencia de workers (retries, progreso, cancelación) y lista negra de tokens JWT
CREATE TABLE IF NOT EXISTS cluster_jobs (
    task_id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    url TEXT NOT NULL,
    profile TEXT NOT NULL DEFAULT 'normal',
    status TEXT NOT NULL DEFAULT 'queued',
    config_json TEXT NOT NULL DEFAULT '{}',
    assigned_worker_id TEXT,
    region_preference TEXT,
    results_json TEXT,
    created_at TEXT NOT NULL,
    started_at TEXT,
    completed_at TEXT,
    retry_count INTEGER NOT NULL DEFAULT 0,
    max_retries INTEGER NOT NULL DEFAULT 3,
    progress_percent INTEGER NOT NULL DEFAULT 0,
    current_stage TEXT NOT NULL DEFAULT 'queued',
    is_cancelled INTEGER NOT NULL DEFAULT 0,
    FOREIGN KEY (assigned_worker_id) REFERENCES cluster_workers (id)
);

CREATE TABLE IF NOT EXISTS revoked_tokens (
    jti TEXT PRIMARY KEY,
    revoked_at TEXT NOT NULL,
    expires_at INTEGER NOT NULL
);
