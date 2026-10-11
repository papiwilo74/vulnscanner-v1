"""
Despachador modular de comandos y modos de ejecución CLI para OmniBreach v3.9.
"""
from __future__ import annotations

import argparse
import contextlib
import logging
import sys
from pathlib import Path
from typing import Callable

logger = logging.getLogger("OmniBreach.CLI")

OMNIBREACH_BANNER = (
    "\n"
    r"   ____                  _ ____                       _    " + "\n"
    r"  / __ \____ ___  ____  (_) __ )________  ____ ______/ /_  " + "\n"
    r" / / / / __ `__ \/ __ \/ / __  / ___/ _ \/ __ `/ ___/ __ \ " + "\n"
    r"/ /_/ / / / / / / / / / / /_/ / /  /  __/ /_/ / /__/ / / / " + "\n"
    r"\____/_/ /_/ /_/_/ /_/_/_____/_/   \___/\__,_/\___/_/ /_/  " + "\n"
    "                             v3.10\n"
)


def dispatch_cli(args: argparse.Namespace, scan_runner: Callable | None = None) -> None:
    """
    Despacha y orquesta la ejecución del comando correspondiente según los argumentos provistos.
    """
    import os

    import requests

    # Propagar flags de integración a variables de entorno para NotificationDispatcher
    if getattr(args, "slack_webhook", None):
        os.environ["SLACK_WEBHOOK_URL"] = args.slack_webhook
    if getattr(args, "teams_webhook", None):
        os.environ["TEAMS_WEBHOOK_URL"] = args.teams_webhook
    if getattr(args, "jira_url", None):
        os.environ["JIRA_URL"] = args.jira_url
    if getattr(args, "jira_project", None):
        os.environ["JIRA_PROJECT_KEY"] = args.jira_project

    if not getattr(args, "worker", False) and not getattr(args, "oast_standalone", False):
        print(OMNIBREACH_BANNER)

    # 1. Modo OAST Standalone
    if getattr(args, "oast_standalone", False):
        from scanner.oast import DedicatedOASTServer
        standalone_server = DedicatedOASTServer(
            host="0.0.0.0",  # nosec B104
            domain=args.oast_server or "oast.local",
            dns_port=args.oast_dns_port or 53,
            http_port=args.oast_http_port or 80,
        )
        print("\n" + "=" * 75)
        print(" [🌐 INFRAESTRUCTURA OAST DEDICADA] INICIANDO SERVIDORES AUTORITATIVOS")
        print("=" * 75)
        print(f" Dominio OAST: {standalone_server.domain}")
        res_info = standalone_server.start()
        print(f" Servidor DNS (UDP): Puerto {res_info['dns_port']} (Resolución autoritativa de registros A)")
        print(f" Servidor HTTP (TCP): Puerto {res_info['http_port']} (Callbacks web y correlación)")
        print(" Esperando interacciones fuera de banda (Blind SSRF, Blind RCE, SQLi, Log4j)...")
        print(" Presione Ctrl+C para detener el servicio.")
        print("=" * 75 + "\n")
        try:
            import time
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            standalone_server.stop()
            print("\n[OAST] Infraestructura detenida limpiamente.")
            sys.exit(0)

    # 2. Modo Benchmark Científico
    if getattr(args, "benchmark", False):
        from scanner.scientific_benchmark import run_scientific_benchmark
        print("\n" + "=" * 76)
        print(" [📊 BENCHMARK CIENTÍFICO] INICIANDO SUITE DE EVALUACIÓN EMPÍRICA DAST")
        print("=" * 76)
        sci_res = run_scientific_benchmark(target_url=getattr(args, "benchmark_target", None))
        sci_res.print_ascii_scorecard()
        print("[+] Reporte formal exportado en: reports/scientific_benchmark_report.md")
        print("[+] Tabla para Tesis en LaTeX: reports/scientific_benchmark_table.tex")
        print("[+] Dataset cuantitativo en: reports/scientific_benchmark_report.json\n")
        sys.exit(0)

    # 3. Modo Worker Distribuido
    if getattr(args, "worker", False):
        from scanner.cluster import ScanningWorkerDaemon
        worker = ScanningWorkerDaemon(
            coordinator_url=getattr(args, "coordinator", "http://localhost:8000"),
            region=getattr(args, "region", "us-east-1"),
        )
        print("\n" + "=" * 70)
        print(" [🌐 CLUSTER DISTRIBUIDO] INICIANDO NODO WORKER DE ESCANEO")
        print("=" * 70)
        print(f" ID Worker: {worker.worker_id} | Región: {worker.region}")
        print(f" Coordinador: {worker.coordinator_url}")
        print(" Esperando y procesando tareas de escaneo en segundo plano (Ctrl+C para salir)...")
        print("=" * 70 + "\n")
        worker.start()
        try:
            import time
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            worker.stop()
            print("\n[WORKER] Nodo detenido limpiamente.")
            sys.exit(0)

    # 4. Modo Verificación Criptográfica de Audit Ledger
    if getattr(args, "verify_ledger", None):
        from scanner.audit_ledger import AuditLedger
        ledger = AuditLedger(ledger_file=args.verify_ledger)
        is_valid, msg = ledger.verify_integrity()
        print("\n" + "=" * 75)
        print(" [🛡️ AUDIT LEDGER] VERIFICACIÓN DE INTEGRIDAD CRIPTOGRÁFICA (SOC 2 / ISO 27001)")
        print("=" * 75)
        print(f" Archivo: {args.verify_ledger}")
        print(f" Total de bloques: {len(ledger.events)}")
        print(f" Estado: {'✅ VÁLIDO (INMUTABLE)' if is_valid else '❌ COMPROMETIDO / ALTERADO'}")
        print(f" Dictamen: {msg}")
        print("=" * 75 + "\n")
        sys.exit(0 if is_valid else 1)

    # 5. Modo Listar Plantillas Declarativas YAML DSL
    if getattr(args, "list_templates", False):
        from scanner.template_engine import TemplateEngine
        tdir = Path(getattr(args, "templates_dir", None) or (Path(__file__).resolve().parent.parent / "templates_dsl"))
        templates = TemplateEngine.load_from_dir(tdir)
        print("\n" + "=" * 80)
        print(" [📜 CATÁLOGO DE PLANTILLAS DECLARATIVAS DSL - OMNIBREACH v3.10]")
        print("=" * 80)
        print(f" Directorio: {tdir}")
        print(f" Total de plantillas disponibles: {len(templates)}\n")
        print(f" {'ID':<28} {'SEVERIDAD':<10} {'CWE':<10} {'NOMBRE'}")
        print(" " + "-" * 78)
        for t in templates:
            cwe = t.info.cwe_id or "N/A"
            print(f" {t.id:<28} {t.info.severity.upper():<10} {cwe:<10} {t.info.name}")
        print("=" * 80 + "\n")
        sys.exit(0)

    # 6. Modo Escaneo Incremental Quirúrgico por Git Diff (CI/CD Quality Gate)
    if getattr(args, "git_diff", None) is not None or getattr(args, "diff_file", None):
        if not getattr(args, "url", None):
            logger.error("Debe especificar una URL objetivo para el escaneo incremental por Git Diff.")
            sys.exit(1)

        from scanner.git_diff_scanner import dispatch_ci_incremental_scan
        base_ref = getattr(args, "git_diff", "origin/main") or "origin/main"
        diff_content = None
        if getattr(args, "diff_file", None):
            with open(args.diff_file, encoding="utf-8") as df:
                diff_content = df.read()

        print("\n" + "=" * 80)
        print(" [⚡ ESCANEO INCREMENTAL QUIRÚRGICO EN CI/CD] EVALUANDO CAMBIOS EN GIT DIFF")
        print("=" * 80)
        print(f" Objetivo: {args.url}")
        print(f" Rama Base: {base_ref}")
        print(f" Quality Gate Umbral: {getattr(args, 'gate_severity', 'high').upper()}")
        print(" Analizando archivos modificados y abstrayendo endpoints afectados...")

        res_dict = dispatch_ci_incremental_scan(
            url=args.url,
            base_ref=base_ref,
            diff_content=diff_content,
            repo_dir=getattr(args, "repo_dir", "."),
            gate_severity=getattr(args, "gate_severity", "high"),
        )
        scan_res = res_dict.get("result", {})
        routes_tested = scan_res.get("routes_tested", [])
        findings = scan_res.get("findings", [])
        gate_passed = scan_res.get("gate_passed", True)

        print(f"\n[+] Rutas modificadas analizadas: {len(routes_tested)}")
        for r in routes_tested:
            print(f"    -> [{r.get('method', 'GET')}] {r.get('path')} (desde {r.get('source_file')})")

        print(f"[+] Total de vulnerabilidades detectadas: {len(findings)}")
        print(f"[+] Quality Gate: {'✅ APROBADO (PASSED)' if gate_passed else '❌ BLOQUEADO (FAILED - VULNERABILIDAD DETECTADA)'}")

        # Exportar comentario Markdown para PR
        if getattr(args, "pr_comment_out", None):
            pr_md = scan_res.get("pr_comment_markdown", "")
            with open(args.pr_comment_out, "w", encoding="utf-8") as f:
                f.write(pr_md)
            print(f"[+] Comentario para Pull Request exportado en: {args.pr_comment_out}")

        # Exportar SARIF incremental
        if getattr(args, "incremental_sarif", None):
            from scanner.models import Finding
            from scanner.sarif import export_findings_to_sarif, save_sarif_file
            finding_objs = [Finding(**f) if isinstance(f, dict) else f for f in findings]
            sarif_doc = export_findings_to_sarif(finding_objs, scan_url=args.url)
            save_sarif_file(sarif_doc, args.incremental_sarif)
            print(f"[+] Reporte SARIF incremental exportado en: {args.incremental_sarif}")

        print("=" * 80 + "\n")
        sys.exit(0 if gate_passed else 1)

    # 7. Modo Re-test Quirúrgico
    if getattr(args, "retest", None):
        import json

        from scanner.retest import retest_multiple_findings
        print("\n" + "=" * 75)
        print(" [🔬 RE-TEST QUIRÚRGICO] VERIFICACIÓN RÁPIDA DE HALLAZGOS (VERIFY FIX)")
        print("=" * 75)
        print(f" Cargando hallazgos desde: {args.retest}")
        with open(args.retest, encoding="utf-8") as f:
            raw_findings = json.load(f)
        if isinstance(raw_findings, dict) and "findings" in raw_findings:
            raw_findings = raw_findings["findings"]
        if not isinstance(raw_findings, list):
            raw_findings = [raw_findings]
        res = retest_multiple_findings(raw_findings)
        print(f" Total evaluados: {res['total_retested']} | Resueltos (Fixed): {res['fixed']} | Aún vulnerables: {res['still_vulnerable']} | Inconclusos: {res['inconclusive']}")
        print("-" * 75)
        for r in res["results"]:
            icon = "✅" if r["status"] == "fixed" else ("❌" if r["status"] == "still_vulnerable" else "⚠️")
            print(f" {icon} [{r['status'].upper()}] {r['vuln_type']} ({r['duration_ms']} ms)")
            print(f"    URL: {r['url']}")
            print(f"    Detalle: {r['details']}")
        print("=" * 75 + "\n")
        sys.exit(0 if res["still_vulnerable"] == 0 else 2)

    # 6. Modo Importación HAR
    if getattr(args, "import_har", None):
        args.har = args.import_har

    # 7. Modo Proxy Interceptor
    if getattr(args, "proxy_capture", None):
        import time

        from scanner.proxy_capture import ProxyCaptureServer
        proxy = ProxyCaptureServer(port=args.proxy_capture)
        print("\n" + "=" * 75)
        print(f" [🕵️ PROXY INTERCEPTOR PASIVO] ESCUCHANDO EN http://127.0.0.1:{args.proxy_capture}")
        print("=" * 75)
        print(" Configure su navegador o suite de QA (Selenium/Cypress) apuntando al proxy.")
        proxy.start()
        capture_time = getattr(args, "proxy_duration", None) or 10
        print(f" Capturando tráfico durante {capture_time} segundos (o presione Ctrl+C)...")
        try:
            time.sleep(capture_time)
        except KeyboardInterrupt:
            pass
        finally:
            proxy.stop()

        print(f"\n[+] Sesión de captura finalizada. Flujos interceptados: {len(proxy.flows)}")
        endpoints = proxy.get_captured_endpoints()
        print(f"[+] Endpoints únicos descubiertos: {len(endpoints)}")
        for ep in endpoints[:10]:
            print(f"    * {ep}")
        if len(endpoints) > 10:
            print(f"    ... y {len(endpoints) - 10} más.")

        if not args.url and endpoints:
            args.url = endpoints[0]
            print(f"[+] Fijando objetivo principal para escaneo: {args.url}\n")
        elif not args.url:
            print("[!] No se detectó tráfico ni se especificó URL objetivo. Finalizando.")
            sys.exit(0)

    # 8. Modo Plantillas Declarativas DSL
    if getattr(args, "template", None) or getattr(args, "templates_dir", None):
        from scanner.template_engine import TemplateEngine
        print("\n" + "=" * 75)
        print(" [📜 MOTOR DECLARATIVO DSL] EJECUCIÓN DE PLANTILLAS DE AUDITORÍA")
        print("=" * 75)
        if not getattr(args, "url", None):
            print("[!] Debes especificar la URL objetivo con --url (ej: python main.py --template templates_dsl/exposed_env.yaml --url http://target.com)")
            sys.exit(1)

        templates_to_run = []
        if getattr(args, "template", None):
            templates_to_run.append(TemplateEngine.load_from_file(args.template))
        if getattr(args, "templates_dir", None):
            templates_to_run.extend(TemplateEngine.load_from_dir(args.templates_dir))

        print(f" Objetivo: {args.url}")
        print(f" Plantillas a ejecutar: {len(templates_to_run)}")
        for t in templates_to_run:
            print(f"   * [{t.id}] {t.info.name} (Severidad: {t.info.severity})")
        print("-" * 75)

        engine_dsl = TemplateEngine()
        findings = engine_dsl.execute_all(templates_to_run, args.url)
        print(f"\n[+] Auditoría DSL finalizada. Total hallazgos: {len(findings)}")
        for f in findings:
            print(f"   * 🚨 [{f.severity.upper()}] {f.title}")
            print(f"     URL: {f.affected_url}")
            if f.evidence:
                print(f"     Evidencia: {f.evidence.response_fragment[:120]}")
            print(f"     Remediación: {f.remediation}")
        print("=" * 75 + "\n")
        sys.exit(0 if len(findings) == 0 else 2)

    # 9. Modo Git-Diff Incremental CI/CD
    if getattr(args, "git_diff", None) or getattr(args, "diff_file", None):
        from scanner.git_diff_scanner import (
            GitDiffAnalyzer,
            SurgicalIncrementalScanner,
            export_incremental_sarif,
            format_github_pr_comment,
        )
        print("\n" + "=" * 75)
        print(" [🚀 CI/CD DEVSECOPS] ESCANEO DIFERENCIAL QUIRÚRGICO (SMART INCREMENTAL DAST)")
        print("=" * 75)
        if not getattr(args, "url", None):
            print("[!] Debes especificar la URL objetivo (ej: python main.py http://staging.app --git-diff main)")
            sys.exit(1)

        base_ref = getattr(args, "git_diff", None) or "origin/main"
        if getattr(args, "diff_file", None):
            print(f" Analizando archivo de diff: {args.diff_file}")
            diff_text = Path(args.diff_file).read_text(encoding="utf-8", errors="ignore")
            modified_files = GitDiffAnalyzer.parse_diff_text(diff_text)
        else:
            repo_dir = getattr(args, "repo_dir", ".")
            print(f" Analizando cambios de Git en '{repo_dir}' contra '{base_ref}'...")
            modified_files = GitDiffAnalyzer.extract_files_from_git(repo_path=repo_dir, base_ref=base_ref)

        print(f" Archivos modificados detectados: {len(modified_files)}")
        for mf in modified_files[:10]:
            print(f"   * {mf}")
        if len(modified_files) > 10:
            print(f"   ... y {len(modified_files) - 10} más.")

        routes = GitDiffAnalyzer.extract_routes_from_files(modified_files, base_dir=getattr(args, "repo_dir", "."))

        if getattr(args, "openapi", None):
            try:
                import json
                oa_path = Path(args.openapi)
                if oa_path.is_file():
                    oa_data = json.loads(oa_path.read_text(encoding="utf-8"))
                    oa_routes = GitDiffAnalyzer.map_routes_from_openapi(modified_files, oa_data)
                    routes.extend(oa_routes)
            except Exception as exc:
                logger.debug("Error cruzando OpenAPI en escaneo incremental: %s", exc)

        print(f" Endpoints quirúrgicos identificados: {len(routes)}")
        for r in routes[:10]:
            print(f"   * [{r.method}] {r.path} (fuente: {r.file_source})")
        if len(routes) > 10:
            print(f"   ... y {len(routes) - 10} más.")

        if not routes:
            print("[!] No se detectaron endpoints HTTP en los archivos modificados.")
            print("    Quality Gate Aprobado por omisión (sin cambios en superficie web).")
            print("=" * 75 + "\n")
            sys.exit(0)

        from main import build_session
        session = build_session(getattr(args, "cookie", None), getattr(args, "auth", None))
        gate_sev = getattr(args, "gate_severity", "high")
        scanner_inst = SurgicalIncrementalScanner(session=session, max_severity_gate=gate_sev)
        res = scanner_inst.run_incremental_scan(
            target_base_url=args.url,
            routes=routes,
            modified_files=modified_files,
            base_ref=base_ref,
        )

        print("-" * 75)
        print(f" Resumen: {res.summary}")
        print(f" Hallazgos: {len(res.findings)}")
        for f in res.findings:
            print(f"   * [{f.severity.upper()}] {f.title} -> {f.affected_url}")
        print(f" Quality Gate: {'✅ APROBADO (PASS)' if res.gate_passed else '❌ BLOQUEADO (FAIL)'}")

        if getattr(args, "pr_comment_out", None):
            comment_md = format_github_pr_comment(res)
            Path(args.pr_comment_out).write_text(comment_md, encoding="utf-8")
            print(f"[+] Comentario para PR generado en: {args.pr_comment_out}")

        if getattr(args, "incremental_sarif", None):
            export_incremental_sarif(res, args.incremental_sarif)
            print(f"[+] Reporte SARIF exportado en: {args.incremental_sarif}")

        print("=" * 75 + "\n")
        sys.exit(0 if res.gate_passed else 2)

    # 10. Modo Agente Satélite Inverso
    if getattr(args, "satellite", False):
        import time

        from scanner.satellite import SatelliteAgent
        sat = SatelliteAgent(coordinator_url=getattr(args, "satellite_coordinator", "http://localhost:8000"))
        print("\n" + "=" * 75)
        print(" [🛰️ AGENTE SATÉLITE INVERSO] INICIANDO SONDEO SALIENTE DE RED INTERNA")
        print("=" * 75)
        print(f" ID Satélite: {sat.satellite_id} | Nombre: {sat.satellite_name}")
        print(f" Coordinador Central: {sat.coordinator_url}")
        print(" Alcance Intranet: " + ", ".join(sat.intranet_scope))
        print(" Conectando y esperando órdenes de escaneo interno (Ctrl+C para salir)...")
        print("=" * 75 + "\n")
        if sat.register():
            print("[+] Agente registrado exitosamente ante el coordinador.")
        else:
            print("[!] Advertencia: no se pudo confirmar registro inicial, reintentando en bucle...")
        try:
            while True:
                sat.run_single_cycle()
                time.sleep(sat.poll_interval)
        except KeyboardInterrupt:
            print("\n[🛰️ Satélite] Agente detenido limpiamente.")
            sys.exit(0)

    # 11. Modo EASM (External Attack Surface Management)
    if getattr(args, "easm", None):
        clean_target = args.easm.strip()
        if not clean_target or " " in clean_target:
            print("\n[EASM ERROR] Debes proporcionar un dominio corporativo válido (ej: python main.py --easm empresa.com.co)")
            sys.exit(1)

        try:
            from scanner.easm.engine import EASMEngine
            easm_engine = EASMEngine()
            print("\n" + "=" * 75)
            print(f" [🌐 EASM SCOUT] CARTOGRAFÍA & SUPERFICIE DE ATAQUE EXTERNA: {clean_target}")
            print("=" * 75)
            report = easm_engine.run_full_surface_assessment(
                clean_target,
                include_bruteforce=not getattr(args, "no_bruteforce", False),
            )
            print(f"\n Calificación de Exposición: {report.exposure_grade} ({report.exposure_score}/100)")
            print(f" Activos Totales Descubiertos: {report.total_assets}")
            print(f" Servicios Expuestos: {report.total_exposed_services}")
            print(f" Vectores de Ransomware (RDP, SMB, DBs): {report.critical_ransomware_vectors}")
            print(f" Alertas CISA KEV (Exploits Activos): {report.cisa_kev_alerts}")
            print(f" Secuestros de Subdominio (Takeover): {len(report.takeovers)}")
            print(f" Fugas de Secretos en Repositorios (OSINT): {len(report.secret_leaks)}")
            print("-" * 75)
            if report.services:
                print(" SERVICIOS Y PUERTOS CRÍTICOS EXPUESTOS:")
                for s in report.services:
                    crit_flag = "🚨 [CRÍTICO]" if s["severity"] == "CRITICAL" else f"[{s['severity']}]"
                    print(f"   * {crit_flag} {s['host']} ({s['ip']}) -> Puerto {s['port']} ({s['service_name']})")
                    if s["unauthenticated_access"]:
                        print(f"     ⚠️ ACCESO NO AUTENTICADO DETECTADO: {s['evidence']}")
                    elif s["banner"]:
                        print(f"     Banner: {s['banner'][:80]}")
                print("-" * 75)
            if report.takeovers:
                print(" 🚨 ALERTA: SUBDOMAIN TAKEOVER CONFIRMADOS:")
                for to_item in report.takeovers:
                    print(f"   * 💥 {to_item['subdomain']} -> CNAME: {to_item['cname']} ({to_item['service_name']})")
                    print(f"     Firma detectada: {to_item['fingerprint_detected']}")
                    print(f"     Mitigación: {to_item['remediation']}")
                print("-" * 75)
            if report.secret_leaks:
                print(" 🔑 ALERTA: FUGAS DE SECRETOS EN REPOSITORIOS PÚBLICOS:")
                for sec in report.secret_leaks:
                    print(f"   * ⚠️ {sec['secret_type']} ({sec['masked_value']}) en {sec['source_repository']}")
                    print(f"     Acción: {sec['remediation']}")
                print("-" * 75)
            if report.cves:
                print(" ALERTA CISA KEV — VULNERABILIDADES ACTIVAMENTE EXPLOTADAS:")
                for c in report.cves:
                    print(f"   * 💥 {c['cve_id']} - {c['vulnerability_name']}")
                    print(f"     Afecta: {c['affected_product']} (Campaña: {c['ransomware_campaign']})")
                    print(f"     Remediación: {c['remediation_steps']}")
                print("-" * 75)
            if report.identity_risk.get("typosquatting_detected"):
                print(" RIESGO DE IDENTIDAD & TYPOSQUATTING (Phishing):")
                for typo in report.identity_risk["typosquatting_detected"]:
                    print(f"   * ⚠️ Dominio suplantador activo: {typo['domain']} ({typo['ip']})")
                print("-" * 75)

            if getattr(args, "runbook", False) or report.critical_ransomware_vectors > 0 or report.takeovers:
                rb = report.remediation_runbook
                print(" 🛡️ ASESOR DE IA: RUNBOOK TÉCNICO DE REMEDIACIÓN A MEDIDA:")
                print(f"   Motor: {rb.get('generated_by', 'OmniBreach AI')}")
                print(f"   Resumen: {rb.get('executive_summary', '')}")
                if rb.get("immediate_actions"):
                    print("   Acciones Inmediatas (P0):")
                    for act in rb["immediate_actions"]:
                        print(f"     - [!] {act}")
                if rb.get("executable_scripts"):
                    print("   Comandos de Mitigación Listos para Ejecutar:")
                    for sname, scode in rb["executable_scripts"].items():
                        print(f"     [{sname}]:\n       " + scode.replace("\n", "\n       "))
                print("-" * 75)
            print()
            sys.exit(0)
        except KeyboardInterrupt:
            print("\n\n[EASM] Auditoría cancelada por el usuario.")
            sys.exit(130)
        except Exception as err:
            print(f"\n[EASM ERROR] Fallo inesperado durante la auditoría: {err}")
            sys.exit(1)

    # 12. Modo Deception / Canaries
    if getattr(args, "deception_generate", False):
        from scanner.deception import DeceptionManager, SnippetGenerator
        mgr = DeceptionManager()
        t1 = mgr.create_trap("url", "Ruta Secreta Admin Vault")
        t2 = mgr.create_trap("api_key", "Stripe Production Live Secret")
        t3 = mgr.create_trap("jwt_token", "JWT Superadmin Token")
        print("\n" + "=" * 70)
        print(" [🛡️ DECEPTION ENGINE] PACK DE SEÑUELOS GENERADO EXITOSAMENTE")
        print("=" * 70)
        for t in [t1, t2, t3]:
            s = SnippetGenerator.generate_snippet(t)
            print(f"\n📌 Tipo: {t.trap_type.upper()} | Etiqueta: {t.label}")
            print(f"   ID Trampa: {t.id}")
            print(f"   Valor Señuelo: {t.token_value}")
            print(f"   Dónde colocar: {s['placement']}")
            print(f"   Código a insertar:\n{s['code']}")
            print("-" * 70)
        print("\n💡 Cualquier acceso a estos señuelos generará alertas inmediatas en tiempo real.")
        print(f"   Base de datos de trampas: {mgr.db_path}\n")
        sys.exit(0)

    if getattr(args, "deception_alerts", False):
        from scanner.deception import DeceptionManager
        mgr = DeceptionManager()
        events = mgr.list_events(limit=50)
        stats = mgr.get_stats()
        print("\n" + "=" * 70)
        print(" [🚨 DECEPTION ENGINE] HISTORIAL DE INTRUSIONES & CANARIOS DETONADOS")
        print("=" * 70)
        print(f" Trampas Activas: {stats['active_traps']}/{stats['total_traps']} | Intrusiones Totales: {stats['total_intrusions_detected']} | IPs Únicas: {stats['unique_attackers']}")
        print("-" * 70)
        if not events:
            print(" ✅ No se han detectado intrusiones ni accesos a señuelos todavía.")
        else:
            for ev in events:
                print(f" [!] {ev.timestamp} | {ev.http_method} {ev.requested_path}")
                print(f"     IP Atacante: {ev.attacker_ip} | Trampa: {ev.trap_label} ({ev.trap_type})")
                print(f"     User-Agent: {ev.user_agent}")
                if ev.payload_sample:
                    print(f"     Payload: {ev.payload_sample[:120]}")
                print("-" * 70)
        print()
        sys.exit(0)

    # 13. Modo SBOM (Supply Chain)
    if getattr(args, "sbom", None):
        from scanner.sbom import SBOMGenerator
        gen = SBOMGenerator()
        fmt = args.sbom.lower()
        out_file = f"reports/sbom_{fmt}.json"
        saved = gen.export_to_file(out_file, format_type=fmt)
        print("\n" + "=" * 70)
        print(f" [📦 SUPPLY CHAIN SECURITY] SBOM GENERADO EXITOSAMENTE ({fmt.upper()})")
        print("=" * 70)
        print(f" Estándar: {'CycloneDX v1.5 JSON' if fmt == 'cyclonedx' else 'SPDX v2.3 JSON'}")
        print(" Normativas: Conforme a EU Cyber Resilience Act (CRA) y US EO 14028")
        print(f" Archivo persistido en: {saved}")
        print(f" Componentes inventariados: {len(gen.collect_components())}")
        print("=" * 70 + "\n")
        sys.exit(0)

    # 14. Modo Container Security (Dockerfile)
    if getattr(args, "dockerfile", None):
        from scanner.container_security import DockerfileScanner
        c_scanner = DockerfileScanner()
        findings_cont = c_scanner.scan_file(args.dockerfile)
        print("\n" + "=" * 70)
        print(f" [🐳 CONTAINER SECURITY] AUDITORÍA ESTÁTICA DOCKERFILE: {args.dockerfile}")
        print("=" * 70)
        if not findings_cont:
            print(" ✅ No se detectaron malas prácticas ni directivas inseguras en el Dockerfile.")
        else:
            print(f" Se encontraron {len(findings_cont)} observaciones de seguridad:")
            for f_cont in findings_cont:
                sev_icon = "💥" if f_cont.severity in ("critical", "high") else "⚠️"
                print(f"\n {sev_icon} [{f_cont.severity.upper()}] {f_cont.title} (Línea {f_cont.line_number})")
                print(f"    Directiva: {f_cont.line_content}")
                print(f"    Riesgo: {f_cont.description}")
                print(f"    Remediación: {f_cont.remediation}")
        print("=" * 70 + "\n")
        sys.exit(0)

    # 15. Modo Feedback de Analista (Active Learning)
    if getattr(args, "ai_feedback", None):
        from scanner.ai_check import record_analyst_feedback
        f_payload, f_label_str = args.ai_feedback
        is_mal = f_label_str.lower() in ("malicious", "vulnerable", "1", "true", "si", "sí")
        ok = record_analyst_feedback(f_payload, is_malicious=is_mal, category="analyst_cli")
        if ok:
            print(f"\n[AI ACTIVE LEARNING] Feedback registrado: '{f_payload}' -> {'MALICIOSO' if is_mal else 'BENIGNO'}")
            print("El clasificador incorporará este ejemplo en el próximo re-entrenamiento (train_ai.py).\n")
        else:
            print("\n[AI ERROR] No se pudo persistir el feedback de analista.\n")
        sys.exit(0)

    # 16. Modo Dashboard Web / SOC GUI
    if getattr(args, "web_mode", False):
        import webbrowser

        import uvicorn
        web_url = "http://localhost:8000/dashboard"
        logger.info("[WEB] Iniciando Servidor Web y Panel SOC en %s ...", web_url)
        with contextlib.suppress(Exception):
            webbrowser.open(web_url)
        uvicorn.run("api:app", host="127.0.0.1", port=8000, reload=False, ws="auto")
        sys.exit(0)

    # 17. Modo Lab Hermético
    lab_server = None
    if getattr(args, "lab_mode", False):
        from scanner.lab_server import LabServer
        lab_server = LabServer()
        args.url = lab_server.start()
        args.allow_private = True
        logger.info("[LAB MODE] Servidor de pruebas hermético iniciado en %s", args.url)

    # Validación de URL
    if not getattr(args, "url", None):
        from cli.parser import build_cli_parser
        parser = build_cli_parser()
        parser.print_help()
        sys.exit(1)

    # 18. Modo Completo (--full)
    if getattr(args, "full", False):
        from main import build_session
        from utils.renderer import is_playwright_available

        logger.info("[TODO-EN-UNO] Modo --full activado: Ejecutando suite completa de auditoría empresarial...")
        if getattr(args, "crawl", 1) == 1:
            args.crawl = 10
        args.subdomains = True
        args.stealth = True
        args.param_fuzz = True
        if is_playwright_available():
            args.headless_crawl = True

        # Auto-descubrir OpenAPI si el servidor expone contrato
        if not getattr(args, "openapi", None):
            session_check = build_session(getattr(args, "cookie", None), getattr(args, "auth", None)) or requests.Session()
            for cand in ["/openapi.json", "/swagger.json", "/api/openapi.json"]:
                cand_url = f"{args.url.rstrip('/')}{cand}"
                try:
                    r = session_check.get(cand_url, timeout=3)
                    if r.status_code == 200 and ("openapi" in r.text.lower() or "swagger" in r.text.lower()):
                        args.openapi = cand_url
                        logger.info("[AUTO-DISCOVERY] Especificación OpenAPI encontrada en: %s", cand_url)
                        break
                except requests.RequestException:
                    continue

        # Auto-descubrir si el servidor tiene agente IAST/RASP activo
        if not getattr(args, "iast_url", None):
            session_check = build_session(getattr(args, "cookie", None), getattr(args, "auth", None)) or requests.Session()
            try:
                r = session_check.get(f"{args.url.rstrip('/')}/__vulnscanner_iast__", timeout=2)
                if r.status_code == 200 and "telemetry" in r.text:
                    args.iast_url = args.url
                    logger.info("[AUTO-DISCOVERY] Agente IAST/RASP en memoria detectado en el objetivo.")
            except requests.RequestException:
                pass

    # Resolver runner de escaneo
    if scan_runner is None:
        from main import scan
        scan_runner = scan

    try:
        scan_runner(
            args.url,
            no_open=getattr(args, "no_open", False),
            cookie_str=getattr(args, "cookie", None),
            auth_header=getattr(args, "auth", None),
            crawl_pages=getattr(args, "crawl", 1),
            run_subdomains=getattr(args, "subdomains", False),
            delay=getattr(args, "delay", 0.0),
            stealth=getattr(args, "stealth", False),
            passive=getattr(args, "passive", False),
            enable_oast=not getattr(args, "no_oast", False),
            login_url=getattr(args, "login_url", None),
            login_creds=getattr(args, "login_creds", None),
            profile=getattr(args, "profile", "normal"),
            allow_private=getattr(args, "allow_private", False),
            har_file=getattr(args, "har", None),
            headless_crawl=getattr(args, "headless_crawl", False),
            active_crawl=getattr(args, "active_crawl", False),
            monkey_actions=getattr(args, "monkey_actions", 25),
            headless_login=getattr(args, "headless_login", False),
            openapi_spec=getattr(args, "openapi", None),
            use_async_engine=getattr(args, "async_engine", False),
            no_waf_detect=getattr(args, "no_waf_detect", False),
            iast_url=getattr(args, "iast_url", None),
            attack_chain=not getattr(args, "no_attack_chain", False),
            generate_pdf=getattr(args, "pdf", False) or getattr(args, "full", False),
            auto_pr=getattr(args, "auto_pr", False),
            github_repo=getattr(args, "github_repo", None),
            github_token=getattr(args, "github_token", None),
            base_branch=getattr(args, "base_branch", "main"),
            what_if_nodes=getattr(args, "what_if", None),
            param_fuzz=getattr(args, "param_fuzz", False),
            session_macro_file=getattr(args, "session_macro", None),
            sentinel_url=getattr(args, "sentinel_url", None),
            totp_secret=getattr(args, "totp_secret", None),
            copilot=getattr(args, "copilot", False),
            autofix=getattr(args, "autofix", False),
            source_dir=getattr(args, "source_dir", None),
            dry_run=getattr(args, "dry_run", False),
            prefer_local_ai=getattr(args, "prefer_local_ai", False),
            oast_server=getattr(args, "oast_server", None),
            oast_dns_port=getattr(args, "oast_dns_port", None),
            oast_http_port=getattr(args, "oast_http_port", None),
            sarif_output=getattr(args, "sarif", None),
            eval_compliance=getattr(args, "compliance", False),
            export_waf=getattr(args, "export_waf", None),
            waf_output=getattr(args, "waf_output", None),
            oauth2_token_url=getattr(args, "oauth2_token_url", None),
            oauth2_refresh_token=getattr(args, "oauth2_refresh_token", None),
            oauth2_client_id=getattr(args, "oauth2_client_id", None),
            oauth2_client_secret=getattr(args, "oauth2_client_secret", None),
        )
    finally:
        if lab_server:
            lab_server.stop()
            logger.info("[LAB MODE] Servidor de pruebas hermético detenido.")
