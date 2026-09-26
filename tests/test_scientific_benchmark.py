"""
Suite de Pruebas Automatizadas para el Motor de Benchmark Científico y Evaluación Empírica.
Verifica:
1. Ciclo de vida del servidor sintético local.
2. Respuestas exactas de endpoints vulnerables y controles seguros.
3. Precisión de las fórmulas estadísticas (Matriz de Confusión, MCC, F1-Score).
4. Generación de artefactos de tesis (LaTeX, Markdown y JSON).
5. Endpoints REST en FastAPI.
"""
from __future__ import annotations

import json
from pathlib import Path
from tempfile import TemporaryDirectory

import requests
from fastapi.testclient import TestClient

from api import app
from scanner.scientific_benchmark import (
    ScientificBenchmarkResult,
    run_scientific_benchmark,
)
from scanner.synthetic_benchmark import (
    GROUND_TRUTH_CATALOG,
    SyntheticBenchmarkServer,
)


def test_synthetic_benchmark_server_lifecycle_and_endpoints() -> None:
    """Valida el inicio, consulta de endpoints de prueba y detención del servidor sintético."""
    server = SyntheticBenchmarkServer(host="127.0.0.1", port=0)
    base_url = server.start()
    assert server.actual_port > 0

    session = requests.Session()
    try:
        # 1. SQLi: caso vulnerable debe devolver error de SQLite
        r_sqli_vuln = session.get(f"{base_url}/vulnerable/sqli?id=1'", timeout=3)
        assert r_sqli_vuln.status_code == 500
        assert "sqlite3.OperationalError" in r_sqli_vuln.text

        # 1. SQLi: caso control no debe fallar
        r_sqli_ctrl = session.get(f"{base_url}/hardened/sqli?id=1'", timeout=3)
        assert r_sqli_ctrl.status_code == 200
        assert "safe_result" in r_sqli_ctrl.text

        # 2. XSS: caso vulnerable refleja sin escapar
        r_xss_vuln = session.get(f"{base_url}/vulnerable/xss?q=<script>alert(1)</script>", timeout=3)
        assert "<script>alert(1)</script>" in r_xss_vuln.text

        # 2. XSS: caso control escapa con entidades HTML
        r_xss_ctrl = session.get(f"{base_url}/hardened/xss?q=<script>alert(1)</script>", timeout=3)
        assert "&lt;script&gt;" in r_xss_ctrl.text

        # 3. Headers: caso control tiene CSP y HSTS
        r_hdr_ctrl = session.get(f"{base_url}/hardened/headers", timeout=3)
        assert "Content-Security-Policy" in r_hdr_ctrl.headers
        assert "Strict-Transport-Security" in r_hdr_ctrl.headers

        # 4. Fuzzer: .env expuesto
        r_env = session.get(f"{base_url}/.env", timeout=3)
        assert r_env.status_code == 200
        assert "DB_PASSWORD" in r_env.text

    finally:
        server.stop()
        assert server.server is None


def test_run_scientific_benchmark_accuracy_and_metrics() -> None:
    """Valida que la ejecución del benchmark genere métricas consistentes contra el ground truth."""
    with TemporaryDirectory() as tmpdir:
        result = run_scientific_benchmark(
            target_url=None,
            save_reports=True,
            reports_dir=tmpdir,
        )

        assert isinstance(result, ScientificBenchmarkResult)
        assert result.total_cases == len(GROUND_TRUTH_CATALOG)
        assert result.total_cases == 20

        # Exactitud esperada >= 95%
        assert result.accuracy >= 0.95
        assert result.precision >= 0.95
        assert result.recall >= 0.90
        assert result.f1_score >= 0.90
        assert result.matthews_corr_coef >= 0.85
        assert result.false_positive_rate <= 0.05

        # Verificar que se generaron los 3 reportes formales
        out_path = Path(tmpdir)
        json_file = out_path / "scientific_benchmark_report.json"
        md_file = out_path / "scientific_benchmark_report.md"
        tex_file = out_path / "scientific_benchmark_table.tex"

        assert json_file.exists()
        assert md_file.exists()
        assert tex_file.exists()

        # Validar contenido JSON
        with open(json_file, encoding="utf-8") as f:
            data = json.load(f)
            assert data["total_cases"] == 20
            assert "categories" in data

        # Validar contenido Markdown
        md_text = md_file.read_text(encoding="utf-8")
        assert "Matriz de Confusión Global" in md_text
        assert "Indicadores Estadísticos Clave" in md_text
        assert "Coef. Matthews (MCC)" in md_text

        # Validar contenido LaTeX
        tex_text = tex_file.read_text(encoding="utf-8")
        assert r"\begin{table}" in tex_text
        assert r"\end{table}" in tex_text
        assert "Exactitud (Accuracy)" in tex_text


def test_api_benchmark_endpoints() -> None:
    """Verifica los endpoints REST de benchmarking en FastAPI."""
    client = TestClient(app)

    # 1. Ejecución del benchmark vía POST
    post_resp = client.post("/api/v1/benchmark/run")
    assert post_resp.status_code == 200
    data = post_resp.json()
    assert data["total_cases"] == 20
    assert "accuracy" in data
    assert "f1_score" in data
    assert "matthews_corr_coef" in data

    # 2. Consulta de los últimos resultados vía GET
    get_resp = client.get("/api/v1/benchmark/latest")
    assert get_resp.status_code == 200
    get_data = get_resp.json()
    assert get_data["status"] == "success"
    assert "benchmark" in get_data
    assert get_data["benchmark"]["total_cases"] == 20
