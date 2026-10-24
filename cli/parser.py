"""
Constructor y definición modular de argumentos CLI para OmniBreach v3.10.
"""
from __future__ import annotations

import argparse
import os


def build_cli_parser() -> argparse.ArgumentParser:
    """Construye y devuelve el analizador de argumentos de línea de comandos de OmniBreach."""
    parser = argparse.ArgumentParser(
        description="OmniBreach v3.10 — Escáner DAST, EASM, Motor DSL Declarativo y Agente IAST/RASP Universal",
        epilog="Ejemplo: python main.py --easm empresa.com.co",
    )
    parser.add_argument("--version", "-V", action="version", version="OmniBreach v3.10")
    parser.add_argument("url", nargs="?", default=None, help="URL del sitio web a escanear")
    parser.add_argument("--easm", type=str, default=None, metavar="DOMINIO",
                        help="Auditoría de Superficie Externa (EASM): Cartografía de subdominios, puertos de ransomware y CISA KEV")
    parser.add_argument("--no-bruteforce", action="store_true",
                        help="Omite la fuerza bruta DNS en el modo EASM (solo consultas pasivas CT logs)")
    parser.add_argument("--runbook", action="store_true",
                        help="Exporta el Runbook Técnico de Remediación a Medida generado por el Asesor de IA")
    parser.add_argument("--web", "--dashboard", "--gui", dest="web_mode", action="store_true",
                        help="Inicia la interfaz web interactiva en tiempo real (SOC Dashboard) en el navegador")
    parser.add_argument("--lab", "--offline", dest="lab_mode", action="store_true",
                        help="Modo Laboratorio Aislado: ejecuta un servidor de prueba local hermético para escaneo sin conexión")
    parser.add_argument("--no-open", action="store_true",
                        help="Evita abrir el reporte HTML automáticamente")
    parser.add_argument("--pdf", action="store_true",
                        help="Genera un Reporte Ejecutivo formal en PDF para comités CISO/Dirección")
    parser.add_argument("--auto-pr", action="store_true",
                        help="Genera automáticamente un Pull Request de remediación en GitHub con los parches aplicados")
    parser.add_argument("--github-repo", type=str, default=os.environ.get("GITHUB_REPOSITORY"),
                        help="Repositorio de GitHub en formato 'owner/repo' para Auto-PR")
    parser.add_argument("--github-token", type=str, default=os.environ.get("GITHUB_TOKEN"),
                        help="Token de acceso personal (PAT) de GitHub para Auto-PR")
    parser.add_argument("--base-branch", type=str, default="main",
                        help="Rama base en GitHub sobre la cual abrir el Pull Request (defecto: main)")
    parser.add_argument("--copilot", action="store_true",
                        help="Activa el Copiloto de Seguridad IA Híbrido (Groq + Ollama) para triaje y resumen ejecutivo CISO")
    parser.add_argument("--autofix", action="store_true",
                        help="Activa el motor de auto-corrección de código seguro en archivos fuente locales")
    parser.add_argument("--source-dir", type=str, default=None,
                        help="Ruta al directorio de código fuente del proyecto local para aplicar auto-correcciones")
    parser.add_argument("--dry-run", action="store_true",
                        help="Muestra el diff de las correcciones de código sin modificar los archivos originales")
    parser.add_argument("--prefer-local-ai", action="store_true",
                        help="Fuerza el uso de Ollama local (RTX 4060) en lugar de Groq Cloud")
    parser.add_argument("--cookie", type=str, default=None,
                        help="Cookies de sesión en formato 'nombre=valor; nombre2=valor2'")
    parser.add_argument("--auth", type=str, default=None,
                        help="Cabecera Authorization (ej. 'Bearer mi_token')")
    parser.add_argument("--crawl", type=int, default=1,
                        help="Número máximo de páginas a rastrear")
    parser.add_argument("--subdomains", action="store_true",
                        help="Habilita búsqueda de subdominios activos")
    parser.add_argument("--delay", type=float, default=0.0,
                        help="Retardo fijo en segundos entre peticiones")
    parser.add_argument("--stealth", action="store_true",
                        help="Rate-limiting con User-Agent rotativo y retardos aleatorios")
    parser.add_argument("--passive", action="store_true",
                        help="Modo pasivo: solo análisis sin envío de payloads")
    parser.add_argument("--no-oast", action="store_true",
                        help="Deshabilita las pruebas Out-of-Band (OAST)")
    parser.add_argument("--profile", type=str, default="normal",
                        choices=["passive", "normal", "aggressive"],
                        help="Perfil de escaneo: passive, normal, aggressive (defecto: normal)")
    parser.add_argument("--allow-private", action="store_true",
                        help="Permite escanear IPs privadas (10.x, 192.168.x, etc.)")
    parser.add_argument("--login-url", type=str, default=None,
                        help="URL del endpoint de login para autenticación dinámica")
    parser.add_argument("--login-creds", type=str, default=None,
                        help="Credenciales en formato 'campo=valor;campo2=valor2'")
    parser.add_argument("--har", type=str, default=None,
                        help="Ruta a archivo .har (HTTP Archive) para reproducir sesión autenticada")
    parser.add_argument("--headless-crawl", action="store_true",
                        help="Habilita rastreador headless dinámico con Playwright para SPAs")
    parser.add_argument("--active-crawl", "--monkey-crawl", dest="active_crawl", action="store_true",
                        help="Habilita rastreo activo con Monkey Testing y CDP Network Interception para SPAs complejas")
    parser.add_argument("--monkey-actions", type=int, default=25,
                        help="Número máximo de acciones interactivas de Monkey Testing a ejecutar (defecto: 25)")
    parser.add_argument("--param-fuzz", action="store_true",
                        help="Habilita descubrimiento activo y fuzzing diferencial de parámetros de consulta ocultos")
    parser.add_argument("--headless-login", action="store_true",
                        help="Usa navegador headless interactivo para resolver el login")
    parser.add_argument("--openapi", type=str, default=None,
                        help="Ruta o URL a especificación OpenAPI/Swagger para auditar endpoints de API")
    parser.add_argument("--async-engine", action="store_true",
                        help="Habilita motor asíncrono httpx/asyncio de ultra alto rendimiento")
    parser.add_argument("--no-waf-detect", action="store_true",
                        help="Deshabilita la detección automática de WAF")
    parser.add_argument("--iast-url", type=str, default=None,
                        help="URL base del servidor instrumentado con agente IAST/RASP para correlación en memoria")
    parser.add_argument("--no-attack-chain", action="store_true",
                        help="Deshabilita el modelado de Grafos de Ataque y análisis de Choke Points defensivos")
    parser.add_argument("--full", "--all", dest="full", action="store_true",
                        help="Modo Todo-en-Uno: activa crawling (10 páginas), subdominios, stealth, detección WAF, grafos de ataque y auto-detección de OpenAPI e IAST")
    parser.add_argument("--deception-generate", action="store_true",
                        help="Genera un pack de señuelos HoneyTokens / Canaries activos (URLs, API Keys, JWT)")
    parser.add_argument("--deception-alerts", action="store_true",
                        help="Consulta y lista las alertas de intrusión y detonaciones de trampas activas")
    parser.add_argument("--worker", action="store_true",
                        help="Inicia la instancia como un nodo worker de escaneo distribuido")
    parser.add_argument("--coordinator", type=str, default="http://localhost:8000",
                        help="URL del servidor API coordinador para workers (defecto: http://localhost:8000)")
    parser.add_argument("--region", type=str, default="us-east-1",
                        help="Región geográfica del nodo worker (defecto: us-east-1)")
    parser.add_argument("--tenant", type=str, default="org_default",
                        help="ID de organización tenant para el escaneo (defecto: org_default)")
    parser.add_argument("--sbom", type=str, nargs="?", const="cyclonedx", choices=["cyclonedx", "spdx"],
                        help="Genera un Software Bill of Materials (SBOM) del software en formato CycloneDX v1.5 o SPDX v2.3")
    parser.add_argument("--dockerfile", type=str, default=None,
                        help="Ruta al archivo Dockerfile para ejecutar auditoría de Container Security y malas prácticas")
    parser.add_argument("--what-if", type=str, nargs="+", default=None,
                        help="Simula la remediación de uno o más IDs de vulnerabilidad/nodos en el Grafo de Ataque")
    parser.add_argument("--ai-feedback", type=str, nargs=2, metavar=("PAYLOAD", "LABEL"),
                        help="Registra feedback de analista para Active Learning (ej: --ai-feedback '<script>' malicious)")

    parser.add_argument("--session-macro", type=str, default=None,
                        help="Ruta a archivo JSON con la definición del macro de autenticación interactiva")
    parser.add_argument("--sentinel-url", type=str, default=None,
                        help="URL centinela para comprobar sesión viva y forzar re-autenticación automática")
    parser.add_argument("--totp-secret", type=str, default=None,
                        help="Secreto Base32 para generación autónoma de códigos MFA/TOTP (RFC 6238)")
    parser.add_argument("--oast-server", type=str, default=None,
                        help="Dominio o IP del servidor OAST dedicado autoritativo (ej: oast.miempresa.com)")
    parser.add_argument("--oast-dns-port", type=int, default=None,
                        help="Puerto de escucha UDP para el servidor DNS autoritativo OAST (defecto: 1053 o aleatorio)")
    parser.add_argument("--oast-http-port", type=int, default=None,
                        help="Puerto de escucha HTTP para el servidor OAST (defecto: 8088 o aleatorio)")
    parser.add_argument("--oast-standalone", action="store_true",
                        help="Inicia la infraestructura OAST dedicada (DNS + HTTP) como daemon autónomo de red")
    parser.add_argument("--benchmark", action="store_true",
                        help="Ejecuta la suite de benchmark científico y evaluación empírica con matriz de confusión y métricas formales")
    parser.add_argument("--benchmark-target", type=str, default=None,
                        help="URL objetivo externa para benchmark (si se omite, usa el testbed sintético OWASP embebido)")
    parser.add_argument("--slack-webhook", type=str, default=None,
                        help="URL de Webhook entrante de Slack para alertas automáticas")
    parser.add_argument("--teams-webhook", type=str, default=None,
                        help="URL de Webhook entrante de Microsoft Teams para tarjetas de incidente")
    parser.add_argument("--jira-url", type=str, default=None,
                        help="URL base de Jira Cloud (ej: https://miempresa.atlassian.net)")
    parser.add_argument("--jira-project", type=str, default=None,
                        help="Clave del proyecto Jira donde radicar los tickets (ej: SEC)")
    parser.add_argument("--notify-min-severity", type=str, default="high",
                        choices=["critical", "high", "medium", "low", "info"],
                        help="Severidad mínima para despachar alertas y tickets (defecto: high)")
    parser.add_argument("--satellite", action="store_true",
                        help="Inicia OmniBreach como Agente Satélite Inverso para auditar redes privadas/intranets")
    parser.add_argument("--satellite-coordinator", type=str, default="http://localhost:8000",
                        help="URL del coordinador central para el Agente Satélite")
    parser.add_argument("--retest", type=str, default=None, metavar="JSON_FILE",
                        help="Re-verificación quirúrgica rápida (Verify Fix) de hallazgos desde archivo JSON")
    parser.add_argument("--verify-ledger", type=str, default=None, metavar="JSONL_FILE",
                        help="Verifica la integridad criptográfica de un registro de auditoría inmutable (Audit Ledger)")
    parser.add_argument("--sarif", type=str, default=None, metavar="SARIF_FILE",
                        help="Ruta donde exportar el reporte en estándar OASIS SARIF v2.1.0 para GitHub Code Scanning")
    parser.add_argument("--compliance", action="store_true",
                        help="Evalúa el cumplimiento normativo automático contra PCI-DSS v4.0, HIPAA, NIST SP 800-53 e ISO 27001")
    parser.add_argument("--export-waf", "--waf-export", dest="export_waf", type=str, default=None, choices=["modsecurity", "aws_waf", "cloudflare", "nginx", "all"],
                        help="Exporta reglas defensivas de mitigación inmediata (Virtual Patching) para WAF")
    parser.add_argument("--waf-output", type=str, default=None, metavar="FILE",
                        help="Ruta de archivo donde guardar las reglas WAF generadas")
    parser.add_argument("--oauth2-token-url", type=str, default=None,
                        help="Endpoint OAuth2 para auto-refresco de tokens de acceso")
    parser.add_argument("--oauth2-refresh-token", type=str, default=None,
                        help="Refresh token OAuth2 para mantener sesiones autenticadas de larga duración")
    parser.add_argument("--oauth2-client-id", type=str, default=None,
                        help="Client ID para auto-refresco OAuth2")
    parser.add_argument("--oauth2-client-secret", type=str, default=None,
                        help="Client Secret para auto-refresco OAuth2")
    parser.add_argument("--proxy-capture", type=int, default=None, metavar="PORT",
                        help="Inicia proxy interceptor en el puerto dado para capturar tráfico y endpoints antes de auditar")
    parser.add_argument("--proxy-duration", type=int, default=None, metavar="SECONDS",
                        help="Segundos a escuchar en el proxy interceptor antes de auditar los endpoints descubiertos")
    parser.add_argument("--import-har", type=str, default=None, metavar="HAR_FILE",
                        help="Importa y audita endpoints y sesiones autenticadas directamente desde un archivo HAR")
    parser.add_argument("--templates-dir", type=str, default=None, metavar="DIR",
                        help="Ruta al directorio de plantillas declarativas YAML/JSON para ejecutar")
    parser.add_argument("--template", type=str, default=None, metavar="FILE",
                        help="Ruta a una plantilla declarativa YAML/JSON específica para ejecutar")
    parser.add_argument("--list-templates", action="store_true",
                        help="Lista las plantillas declarativas YAML/JSON disponibles en el catálogo de OmniBreach")
    parser.add_argument("--git-diff", type=str, nargs="?", const="origin/main", default=None, metavar="BASE_REF",
                        help="Ejecuta escaneo diferencial quirúrgico en CI/CD analizando cambios contra la rama base (defecto: origin/main)")
    parser.add_argument("--diff-file", type=str, default=None, metavar="DIFF_FILE",
                        help="Ruta a un archivo de diff unificado (patch) para escaneo incremental sin requerir git")
    parser.add_argument("--gate-severity", type=str, default="high", choices=["critical", "high", "medium", "low"],
                        help="Umbral de severidad para el Quality Gate en CI/CD (defecto: high)")
    parser.add_argument("--repo-dir", type=str, default=".", metavar="DIR",
                        help="Directorio del repositorio para análisis de cambios Git (defecto: .)")
    parser.add_argument("--pr-comment-out", type=str, default=None, metavar="FILE",
                        help="Ruta donde escribir el reporte Markdown formateado para Pull Request de GitHub")
    parser.add_argument("--incremental-sarif", type=str, default=None, metavar="SARIF_FILE",
                        help="Ruta donde guardar el reporte SARIF v2.1.0 del escaneo diferencial para GitHub Code Scanning")

    return parser
