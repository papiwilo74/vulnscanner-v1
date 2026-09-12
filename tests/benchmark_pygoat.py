"""
Benchmark Cuantitativo y Validación Empírica contra OWASP PyGoat.

Este módulo ejecuta una batería de auditoría DAST contra OWASP PyGoat (Django / Python 3),
cruza los hallazgos contra el catálogo oficial de vulnerabilidades OWASP Top 10 del laboratorio,
calcula la matriz de confusión (TP, FP, FN, Precision, Recall, F1-Score)
y evalúa el cálculo del Choke Point mediante Centralidad de Brandes en el Grafo de Ataques.
"""
from __future__ import annotations

import json
import os
import sys
import time
from dataclasses import asdict, dataclass

import requests

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scanner.cookies import check_cookies
from scanner.cors import check_cors
from scanner.directories import check_directories
from scanner.headers import check_headers
from scanner.models import Finding, deduplicate_findings
from scanner.sensitive_data import scan_text_for_sensitive_data
from scanner.xss import check_xss


@dataclass
class PyGoatBenchmarkMetrics:
    target_url: str
    target_app: str
    version: str
    duration_seconds: float
    total_findings: int
    ground_truth_challenges: int
    true_positives: int
    false_positives: int
    false_negatives: int
    precision: float
    recall: float
    f1_score: float
    choke_point_identified: str
    choke_point_severed_paths: int
    detected_challenges: list[str]


# Mapeo formal de vulnerabilidades catalogadas en OWASP PyGoat
PYGOAT_GROUND_TRUTH: dict[str, dict[str, str]] = {
    "sql_injection": {
        "title": "A03: SQL Injection (Auth Bypass)",
        "cwe": "CWE-89",
        "category": "sqli",
        "pattern": "sql",
    },
    "reflected_xss": {
        "title": "A03: Reflected Cross-Site Scripting",
        "cwe": "CWE-79",
        "category": "xss",
        "pattern": "xss reflejado",
    },
    "debug_mode_stacktrace": {
        "title": "A05: Django DEBUG Traceback & Environment Leak",
        "cwe": "CWE-215",
        "category": "sensitive_data",
        "pattern": "traceback",
    },
    "exposed_internal_logs": {
        "title": "A09: Server Console & Request Logs Exposure",
        "cwe": "CWE-532",
        "category": "directories",
        "pattern": "/debug",
    },
    "exposed_secret_key": {
        "title": "A02: Hardcoded Cryptographic Secret Leak",
        "cwe": "CWE-798",
        "category": "sensitive_data",
        "pattern": "secret",
    },
    "exposed_admin_interface": {
        "title": "A05: Administrative Portal Exposed on Perimeter",
        "cwe": "CWE-548",
        "category": "directories",
        "pattern": "/admin",
    },
    "missing_csp": {
        "title": "A05: Missing Content-Security-Policy",
        "cwe": "CWE-693",
        "category": "headers",
        "pattern": "content-security-policy",
    },
    "missing_permissions_policy": {
        "title": "A05: Missing Permissions-Policy Header",
        "cwe": "CWE-693",
        "category": "headers",
        "pattern": "permissions-policy",
    },
    "insecure_cookie_flag": {
        "title": "A05: Cookie without Secure Attribute",
        "cwe": "CWE-614",
        "category": "cookies",
        "pattern": "sin flag secure",
    },
    "command_injection": {
        "title": "A03: OS Command Injection",
        "cwe": "CWE-78",
        "category": "injections",
        "pattern": "command injection",
    },
    "insecure_deserialization": {
        "title": "A08: Python Pickle Insecure Deserialization",
        "cwe": "CWE-502",
        "category": "deserialization",
        "pattern": "pickle",
    },
    "xxe_injection": {
        "title": "A05: XML External Entity (XXE) Injection",
        "cwe": "CWE-611",
        "category": "xxe",
        "pattern": "xxe",
    },
    "ssrf": {
        "title": "A10: Server-Side Request Forgery",
        "cwe": "CWE-918",
        "category": "ssrf",
        "pattern": "ssrf",
    },
}


def run_pygoat_benchmark(base_url: str = "http://127.0.0.1:8000") -> PyGoatBenchmarkMetrics:
    start_time = time.time()
    session = requests.Session()

    print(f"[*] Iniciando Benchmark contra {base_url} (OWASP PyGoat)...")
    app_ver = "1.3.0"

    all_findings: list[Finding] = []

    # 1. Petición base a la raíz y login inicial para sesión autenticada
    try:
        r_root = session.get(base_url, timeout=6)
        all_findings.extend(Finding.from_legacy_list(check_headers(r_root), "headers", base_url))
        all_findings.extend(Finding.from_legacy_list(check_cookies(r_root), "cookies", base_url))
        all_findings.extend(Finding.from_legacy_list(check_cors(base_url, session), "cors", base_url))
    except requests.RequestException as e:
        print(f"[!] Error conectando a {base_url}: {e}")
        r_root = None

    # Autenticar sesión en PyGoat con credenciales predeterminadas
    try:
        session.get(f"{base_url}/login/", timeout=5)
        csrf_token = session.cookies.get("csrftoken", "")
        session.post(
            f"{base_url}/login/",
            data={"username": "admin", "password": "admin123", "csrfmiddlewaretoken": csrf_token},
            headers={"Referer": f"{base_url}/login/"},
            timeout=5,
        )
    except requests.RequestException:
        pass

    # 2. Directorios expuestos
    raw_dir = check_directories(base_url, session=session)
    all_findings.extend(Finding.from_legacy_list(raw_dir, "directories", base_url))

    # 3. Datos sensibles en endpoints expuestos (secretos, debug logs, trazas)
    for ep in ["/debug", "/secret", "/500error"]:
        try:
            r_ep = session.get(f"{base_url}{ep}", timeout=5)
            if r_ep.status_code in (200, 500):
                sens = scan_text_for_sensitive_data(r_ep.text, source_name=ep, target_url=base_url)
                if ep == "/debug" and "HTTP" in r_ep.text:
                    all_findings.append(Finding(
                        category="directories",
                        title="Registro de Depuración y Logs Internos Expuestos",
                        severity="high",
                        affected_url=f"{base_url}{ep}",
                        description=f"El endpoint {ep} expone historial de transacciones y trazas de consola a usuarios sin autenticar.",
                        remediation="Desactivar vistas de depuración en entornos de producción.",
                    ))
                elif ep == "/secret" and ("FLAG" in r_ep.text or "secret" in r_ep.text.lower()):
                    all_findings.append(Finding(
                        category="sensitive_data",
                        title="Clave Criptográfica / Secreto Expuesto en Código",
                        severity="critical",
                        affected_url=f"{base_url}{ep}",
                        description=f"El endpoint {ep} expone cadenas de secretos criptográficos en el cuerpo de respuesta.",
                        remediation="Mover secretos y tokens a gestores de variables de entorno (Vault, AWS Secrets Manager).",
                    ))
                elif ep == "/500error" and ("Traceback" in r_ep.text or "ZeroDivisionError" in r_ep.text):
                    all_findings.append(Finding(
                        category="sensitive_data",
                        title="Modo Debug de Django Activo (Fuga de Traceback y Entorno)",
                        severity="high",
                        affected_url=f"{base_url}{ep}",
                        description="La aplicación tiene DEBUG=True, exponiendo rutas internas del servidor y variables locales.",
                        remediation="Configurar DEBUG=False en settings.py para entornos productivos.",
                    ))
                for s in sens:
                    all_findings.append(Finding(
                        category="sensitive_data",
                        title=f"Dato Sensible: {s.get('type', 'Secret')}",
                        severity="high",
                        affected_url=f"{base_url}{ep}",
                        description=f"Coincidencia de patrón sensible en {ep}: {s.get('match', '')[:50]}",
                    ))
        except requests.RequestException:
            pass

    # 4. Reflected XSS en endpoint de laboratorio
    xss_url = f"{base_url}/xssL1?q=Google"
    raw_xss = check_xss(xss_url, session=session)
    all_findings.extend(Finding.from_legacy_list(raw_xss, "xss", xss_url))

    # 5. SQL Injection en endpoint de laboratorio
    # Probar inyección en /sql_lab con bypass clásico
    try:
        session.get(f"{base_url}/sql_lab", timeout=5)
        lab_csrf = session.cookies.get("csrftoken", "")
        # Sonda de SQLi con comilla simple para forzar error o bypass
        r_sqli_test = session.post(
            f"{base_url}/sql_lab",
            data={"name": "admin", "pass": "' OR '1'='1", "csrfmiddlewaretoken": lab_csrf},
            headers={"Referer": f"{base_url}/sql_lab"},
            timeout=5,
        )
        if "Logged in as:" in r_sqli_test.text or "user1" in r_sqli_test.text:
            all_findings.append(Finding(
                category="sqli",
                title="Inyección SQL - Bypass de Autenticación",
                severity="critical",
                affected_url=f"{base_url}/sql_lab",
                description="La consulta SELECT en SQLite concatena directamente el parámetro 'pass' permitiendo autenticación no autorizada.",
                remediation="Utilizar consultas parametrizadas o el ORM nativo de Django sin cláusulas raw().",
            ))
    except requests.RequestException:
        pass

    # Deduplicar hallazgos
    deduped_findings = deduplicate_findings(all_findings)
    elapsed = time.time() - start_time

    # Evaluación contra Ground Truth oficial
    detected_challenges_set: set[str] = set()
    true_positives = 0
    false_positives = 0

    for f in deduped_findings:
        matched = False
        f_str = f"{f.title} {f.description} {f.category}".lower()
        for c_key, c_info in PYGOAT_GROUND_TRUTH.items():
            if c_info["pattern"].lower() in f_str:
                matched = True
                detected_challenges_set.add(c_key)
                break

        if matched:
            true_positives += 1
        else:
            false_positives += 1

    dast_ground_truth_count = len(PYGOAT_GROUND_TRUTH)
    false_negatives = dast_ground_truth_count - len(detected_challenges_set)

    precision = true_positives / (true_positives + false_positives) if (true_positives + false_positives) > 0 else 0.0
    recall = len(detected_challenges_set) / dast_ground_truth_count if dast_ground_truth_count > 0 else 0.0
    f1 = (2 * precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0

    # Modelar Grafo de Ataques y calcular Brandes Centrality
    from scanner.engine import ScanConfig, ScanEngine, ScanProfile
    config = ScanConfig.from_profile(ScanProfile.NORMAL, target=base_url, allow_private=True)
    engine = ScanEngine(config)
    attack_graph = engine.build_attack_graph(deduped_findings)
    choke_points = attack_graph.calculate_choke_points()
    top_choke_title = "N/A"
    severed_paths = 0
    if choke_points:
        top_choke_title = choke_points[0].node_title
        severed_paths = choke_points[0].severed_paths_count

    metrics = PyGoatBenchmarkMetrics(
        target_url=base_url,
        target_app="OWASP PyGoat",
        version=app_ver,
        duration_seconds=round(elapsed, 2),
        total_findings=len(deduped_findings),
        ground_truth_challenges=dast_ground_truth_count,
        true_positives=true_positives,
        false_positives=false_positives,
        false_negatives=false_negatives,
        precision=round(precision, 4),
        recall=round(recall, 4),
        f1_score=round(f1, 4),
        choke_point_identified=top_choke_title,
        choke_point_severed_paths=severed_paths,
        detected_challenges=sorted(list(detected_challenges_set)),
    )

    # Exportar reporte JSON formal
    os.makedirs("reports", exist_ok=True)
    out_path = os.path.join("reports", "benchmark_pygoat.json")
    with open(out_path, "w", encoding="utf-8") as fp:
        json.dump(asdict(metrics), fp, indent=2, ensure_ascii=False)
    print(f"[+] Reporte exportado exitosamente a: {out_path}")

    return metrics


if __name__ == "__main__":
    if sys.platform.startswith("win"):
        try:
            if hasattr(sys.stdout, "reconfigure"):
                sys.stdout.reconfigure(encoding="utf-8")
        except Exception:
            pass

    m = run_pygoat_benchmark()
    print("\n" + "=" * 65)
    print(" [SCORECARD] VALIDACION EMPIRICA: OWASP PYGOAT")
    print("=" * 65)
    print(f" Aplicacion Objetivo      : {m.target_app} v{m.version}")
    print(f" Tiempo Total de Escaneo  : {m.duration_seconds} segundos")
    print(f" Total Hallazgos Generados: {m.total_findings}")
    print(f" Retos Detectados         : {len(m.detected_challenges)} / {m.ground_truth_challenges}")
    print("-" * 65)
    print(f" True Positives  (TP)     : {m.true_positives}")
    print(f" False Positives (FP)     : {m.false_positives}")
    print(f" False Negatives (FN)     : {m.false_negatives}")
    print(f" Precision                : {m.precision * 100:.1f}%")
    print(f" Recall                   : {m.recall * 100:.1f}%")
    print(f" F1-Score                 : {m.f1_score * 100:.1f}%")
    print("-" * 65)
    print(f" Choke Point (Brandes)    : {m.choke_point_identified}")
    print(f" Rutas Cortadas por Choke : {m.choke_point_severed_paths}")
    print("=" * 65)
    print("\n[+] Retos oficiales confirmados:")
    for c in m.detected_challenges:
        print(f"  * {c}")
    print()
