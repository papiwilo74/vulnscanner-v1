-- 001: Esquema base de tareas y reportes de auditoría DAST
CREATE TABLE IF NOT EXISTS tasks (
    task_id TEXT PRIMARY KEY,
    url TEXT NOT NULL,
    profile TEXT NOT NULL,
    status TEXT NOT NULL,
    created_at TEXT NOT NULL,
    completed_at TEXT,
    results_json TEXT,
    html_report_path TEXT,
    json_report_path TEXT,
    sarif_report_path TEXT,
    pdf_report_path TEXT
);
