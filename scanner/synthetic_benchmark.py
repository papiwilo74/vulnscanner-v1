"""
Servidor de Laboratorio Sintético Embebido para Evaluación Empírica de DAST.
Implementa un servidor HTTP multihilo ultraligero que expone endpoints con vulnerabilidades
controladas (OWASP Top 10) y endpoints no vulnerables (controles negativos anti-falsos positivos).
Incluye el catálogo formal de Ground Truth certificado.
"""
from __future__ import annotations

import html
import http.server
import logging
import socketserver
import threading
from dataclasses import dataclass
from typing import Any
from urllib.parse import parse_qs, urlparse

logger = logging.getLogger("OmniBreach.SyntheticBenchmark")


@dataclass(frozen=True)
class GroundTruthTestCase:
    test_id: str
    category: str
    cwe_id: str
    path: str
    is_vulnerable: bool
    description: str
    expected_pattern: str


GROUND_TRUTH_CATALOG: list[GroundTruthTestCase] = [
    # 1. SQL Injection
    GroundTruthTestCase(
        test_id="TC-SQLI-VULN",
        category="sqli",
        cwe_id="CWE-89",
        path="/vulnerable/sqli?id=1",
        is_vulnerable=True,
        description="Parámetro id vulnerable a inyección SQL con fuga de errores SQLite",
        expected_pattern="sqlite3.OperationalError",
    ),
    GroundTruthTestCase(
        test_id="TC-SQLI-CTRL",
        category="sqli",
        cwe_id="CWE-89",
        path="/hardened/sqli?id=1",
        is_vulnerable=False,
        description="Consulta parametrizada segura insensible a comillas y sintaxis SQL",
        expected_pattern="safe_result",
    ),
    # 2. Cross-Site Scripting (XSS Reflejado)
    GroundTruthTestCase(
        test_id="TC-XSS-VULN",
        category="xss",
        cwe_id="CWE-79",
        path="/vulnerable/xss?q=test",
        is_vulnerable=True,
        description="Parámetro q reflejado directamente en HTML sin sanitización",
        expected_pattern="<script>",
    ),
    GroundTruthTestCase(
        test_id="TC-XSS-CTRL",
        category="xss",
        cwe_id="CWE-79",
        path="/hardened/xss?q=test",
        is_vulnerable=False,
        description="Parámetro q escapado con html.escape en el cuerpo de respuesta",
        expected_pattern="&lt;script&gt;",
    ),
    # 3. DOM XSS
    GroundTruthTestCase(
        test_id="TC-DOMXSS-VULN",
        category="dom_xss",
        cwe_id="CWE-79",
        path="/vulnerable/dom-xss.html",
        is_vulnerable=True,
        description="Uso inseguro de sink document.write alimentado por location.hash",
        expected_pattern="document.write(location.hash",
    ),
    GroundTruthTestCase(
        test_id="TC-DOMXSS-CTRL",
        category="dom_xss",
        cwe_id="CWE-79",
        path="/hardened/dom-xss.html",
        is_vulnerable=False,
        description="Asignación segura a textContent sin interpretar marcado HTML",
        expected_pattern="textContent = location.hash",
    ),
    # 4. CORS Misconfiguration
    GroundTruthTestCase(
        test_id="TC-CORS-VULN",
        category="cors",
        cwe_id="CWE-942",
        path="/vulnerable/cors",
        is_vulnerable=True,
        description="CORS excesivamente permisivo con Wildcard (*) y credenciales",
        expected_pattern="Access-Control-Allow-Origin: *",
    ),
    GroundTruthTestCase(
        test_id="TC-CORS-CTRL",
        category="cors",
        cwe_id="CWE-942",
        path="/hardened/cors",
        is_vulnerable=False,
        description="CORS estricto sin wildcard ni orígenes arbitrarios reflejados",
        expected_pattern="Access-Control-Allow-Origin: https://trusted.enterprise.local",
    ),
    # 5. Cabeceras de Seguridad Faltantes
    GroundTruthTestCase(
        test_id="TC-HDR-VULN",
        category="headers",
        cwe_id="CWE-693",
        path="/vulnerable/headers",
        is_vulnerable=True,
        description="Ausencia total de cabeceras CSP, HSTS, X-Content-Type-Options y X-Frame-Options",
        expected_pattern="no_security_headers",
    ),
    GroundTruthTestCase(
        test_id="TC-HDR-CTRL",
        category="headers",
        cwe_id="CWE-693",
        path="/hardened/headers",
        is_vulnerable=False,
        description="Cabeceras perimetrales endurecidas y CSP estricto configurado",
        expected_pattern="Content-Security-Policy: default-src 'self'",
    ),
    # 6. Open Redirect
    GroundTruthTestCase(
        test_id="TC-REDIR-VULN",
        category="open_redirect",
        cwe_id="CWE-601",
        path="/vulnerable/redirect?url=https://attacker.evil.com",
        is_vulnerable=True,
        description="Redirección HTTP 302 sin validar dominio de destino",
        expected_pattern="Location: https://attacker.evil.com",
    ),
    GroundTruthTestCase(
        test_id="TC-REDIR-CTRL",
        category="open_redirect",
        cwe_id="CWE-601",
        path="/hardened/redirect?url=https://attacker.evil.com",
        is_vulnerable=False,
        description="Redirección validada contra lista blanca estricta de rutas relativas",
        expected_pattern="Location: /dashboard",
    ),
    # 7. Exposición de Secretos y Credenciales (Sensitive Data)
    GroundTruthTestCase(
        test_id="TC-DATA-VULN",
        category="sensitive_data",
        cwe_id="CWE-200",
        path="/vulnerable/credentials.js",
        is_vulnerable=True,
        description="Claves de API de AWS y cadenas de conexión a base de datos expuestas",
        expected_pattern="AKIAIOSFODNN7EXAMPLE",
    ),
    GroundTruthTestCase(
        test_id="TC-DATA-CTRL",
        category="sensitive_data",
        cwe_id="CWE-200",
        path="/hardened/bundle.js",
        is_vulnerable=False,
        description="Código JavaScript cliente minificado sin secretos embebidos",
        expected_pattern="function app(){return true;}",
    ),
    # 8. Cookies Inseguras
    GroundTruthTestCase(
        test_id="TC-COOKIE-VULN",
        category="cookies",
        cwe_id="CWE-614",
        path="/vulnerable/cookies",
        is_vulnerable=True,
        description="Cookie de sesión sin atributos HttpOnly, Secure ni SameSite",
        expected_pattern="session_id=insecure_token_12345",
    ),
    GroundTruthTestCase(
        test_id="TC-COOKIE-CTRL",
        category="cookies",
        cwe_id="CWE-614",
        path="/hardened/cookies",
        is_vulnerable=False,
        description="Cookie de sesión protegida con HttpOnly, Secure y SameSite=Strict",
        expected_pattern="HttpOnly; Secure; SameSite=Strict",
    ),
    # 9. Archivos Sensibles Expuestos (Fuzzer / Directories)
    GroundTruthTestCase(
        test_id="TC-ENV-VULN",
        category="fuzzer",
        cwe_id="CWE-552",
        path="/.env",
        is_vulnerable=True,
        description="Archivo .env con variables de entorno y secretos de producción expuesto",
        expected_pattern="DB_PASSWORD=SuperSecret99",
    ),
    GroundTruthTestCase(
        test_id="TC-ENV-CTRL",
        category="fuzzer",
        cwe_id="CWE-552",
        path="/hardened/.env",
        is_vulnerable=False,
        description="Acceso a archivos ocultos bloqueado con respuesta 404 Not Found",
        expected_pattern="Not Found",
    ),
    # 10. Prototype Pollution
    GroundTruthTestCase(
        test_id="TC-PROTO-VULN",
        category="prototype_pollution",
        cwe_id="CWE-1321",
        path="/vulnerable/proto.html",
        is_vulnerable=True,
        description="Fusión recursiva de objetos insegura vulnerable a Prototype Pollution",
        expected_pattern="Object.prototype.__proto__",
    ),
    GroundTruthTestCase(
        test_id="TC-PROTO-CTRL",
        category="prototype_pollution",
        cwe_id="CWE-1321",
        path="/hardened/proto.html",
        is_vulnerable=False,
        description="Uso de Object.create(null) y congelamiento de prototipos inmune a polución",
        expected_pattern="Object.freeze(Object.prototype)",
    ),
]


class SyntheticBenchmarkHandler(http.server.BaseHTTPRequestHandler):
    """Manejador HTTP que simula las respuestas vulnerables y de control."""

    def log_message(self, format: str, *args: Any) -> None:
        # Suprimir logs ruidosos en stdout durante la ejecución del benchmark
        pass

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path
        query = parse_qs(parsed.query)

        # 1. SQLi Endpoints
        if path == "/vulnerable/sqli":
            id_val = query.get("id", ["1"])[0]
            if any(token in id_val for token in ("'", "UNION", "OR 1=1", "--")):
                self.send_response(500)
                self.send_header("Content-Type", "text/plain; charset=utf-8")
                self.end_headers()
                self.wfile.write(b"sqlite3.OperationalError: unrecognized token: \"'\" in SELECT * FROM items WHERE id='1''")
            else:
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"item_id": 1, "name": "Standard Laptop"}')
            return

        if path == "/hardened/sqli":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"status": "success", "result": "safe_result"}')
            return

        # 2. XSS Endpoints
        if path == "/vulnerable/xss":
            q_val = query.get("q", [""])[0]
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            resp = f"<html><body><h1>Resultados de busqueda</h1><p>Buscaste: {q_val}</p></body></html>"
            self.wfile.write(resp.encode("utf-8"))
            return

        if path == "/hardened/xss":
            q_val = query.get("q", [""])[0]
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            escaped = html.escape(q_val)
            resp = f"<html><body><h1>Resultados de busqueda</h1><p>Buscaste: {escaped}</p></body></html>"
            self.wfile.write(resp.encode("utf-8"))
            return

        # 3. DOM XSS Endpoints
        if path == "/vulnerable/dom-xss.html":
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            content = """<!DOCTYPE html>
<html>
<head><title>DOM XSS Test</title></head>
<body>
  <h1>DOM XSS Vulnerable Sink</h1>
  <script>
    var hash = location.hash.substring(1);
    document.write(location.hash);
  </script>
</body>
</html>"""
            self.wfile.write(content.encode("utf-8"))
            return

        if path == "/hardened/dom-xss.html":
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            content = """<!DOCTYPE html>
<html>
<head><title>DOM XSS Hardened</title></head>
<body>
  <div id="output"></div>
  <script>
    document.getElementById("output").textContent = location.hash;
  </script>
</body>
</html>"""
            self.wfile.write(content.encode("utf-8"))
            return

        # 4. CORS Endpoints
        if path == "/vulnerable/cors":
            origin = self.headers.get("Origin", "*")
            self.send_response(200)
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Access-Control-Allow-Credentials", "true")
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"account": "1234-5678-9012", "balance": 99999.00}')
            return

        if path == "/hardened/cors":
            self.send_response(200)
            self.send_header("Access-Control-Allow-Origin", "https://trusted.enterprise.local")
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"status": "protected"}')
            return

        # 5. Security Headers Endpoints
        if path == "/vulnerable/headers":
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(b"<html><body><h1>Servidor sin cabeceras perimetrales</h1></body></html>")
            return

        if path == "/hardened/headers":
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Security-Policy", "default-src 'self'")
            self.send_header("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Referrer-Policy", "strict-origin-when-cross-origin")
            self.send_header("Permissions-Policy", "camera=(), microphone=()")
            self.end_headers()
            self.wfile.write(b"<html><body><h1>Servidor con cabeceras estrictas</h1></body></html>")
            return

        # 6. Open Redirect Endpoints
        if path == "/vulnerable/redirect":
            dest = query.get("url", ["/"])[0]
            self.send_response(302)
            self.send_header("Location", dest)
            self.end_headers()
            return

        if path == "/hardened/redirect":
            dest = query.get("url", ["/"])[0]
            safe_dest = dest if dest.startswith("/") and not dest.startswith("//") else "/dashboard"
            self.send_response(302)
            self.send_header("Location", safe_dest)
            self.end_headers()
            return

        # 7. Sensitive Data Endpoints
        if path == "/vulnerable/credentials.js":
            self.send_response(200)
            self.send_header("Content-Type", "application/javascript")
            self.end_headers()
            js_code = """
            // Configuracion cliente frontend
            const AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE";
            const DB_URL = "postgres://root:ProdSecretPass123@db.internal:5432/finance";
            console.log("Servicios iniciados");
            """
            self.wfile.write(js_code.encode("utf-8"))
            return

        if path == "/hardened/bundle.js":
            self.send_response(200)
            self.send_header("Content-Type", "application/javascript")
            self.end_headers()
            self.wfile.write(b"function app(){return true;}")
            return

        # 8. Cookies Endpoints
        if path == "/vulnerable/cookies":
            self.send_response(200)
            self.send_header("Set-Cookie", "session_id=insecure_token_12345; Path=/")
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"Cookie insegura establecida")
            return

        if path == "/hardened/cookies":
            self.send_response(200)
            self.send_header("Set-Cookie", "session_id=secure_token_99999; Path=/; HttpOnly; Secure; SameSite=Strict")
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"Cookie endurecida establecida")
            return

        # 9. Fuzzer / Exposed Files Endpoints
        if path == "/.env":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            env_content = "APP_ENV=production\nDB_PASSWORD=SuperSecret99\nJWT_SECRET=ultra-secret-key-xyz\n"
            self.wfile.write(env_content.encode("utf-8"))
            return

        if path == "/hardened/.env":
            self.send_response(404)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"Not Found")
            return

        # 10. Prototype Pollution Endpoints
        if path == "/vulnerable/proto.html":
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            html_doc = """<!DOCTYPE html>
<html><body>
<script>
function merge(target, source) {
    for (var key in source) {
        target.__proto__[key] = source[key];
    }
}
</script>
</body></html>"""
            self.wfile.write(html_doc.encode("utf-8"))
            return

        if path == "/hardened/proto.html":
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            html_doc = """<!DOCTYPE html>
<html><body>
<script>
Object.freeze(Object.prototype);
</script>
</body></html>"""
            self.wfile.write(html_doc.encode("utf-8"))
            return

        # Default raíz
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        root_html = """<!DOCTYPE html>
<html>
<head><title>OmniBreach Synthetic Benchmark Lab</title></head>
<body>
  <h1>OmniBreach Testbed de Calibración DAST</h1>
  <p>Entorno local de evaluación empírica con controles Ground Truth certificados.</p>
</body>
</html>"""
        self.wfile.write(root_html.encode("utf-8"))


class SyntheticBenchmarkServer:
    """Orquestador del ciclo de vida del servidor de benchmark sintético."""

    def __init__(self, host: str = "127.0.0.1", port: int = 0) -> None:
        self.host = host
        self.port = port
        self.server: socketserver.TCPServer | None = None
        self.thread: threading.Thread | None = None
        self.actual_port: int = 0

    def start(self) -> str:
        """Inicia el servidor en un hilo secundario y retorna la URL base."""
        socketserver.TCPServer.allow_reuse_address = True
        self.server = socketserver.TCPServer((self.host, self.port), SyntheticBenchmarkHandler)
        self.actual_port = self.server.server_address[1]

        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

        base_url = f"http://{self.host}:{self.actual_port}"
        logger.info("Servidor de Benchmark Sintético activo en %s", base_url)
        return base_url

    def stop(self) -> None:
        """Detiene y libera los recursos del servidor."""
        if self.server:
            try:
                self.server.shutdown()
                self.server.server_close()
            except Exception as e:
                logger.warning("Error cerrando servidor sintético: %s", e)
            finally:
                self.server = None
        logger.info("Servidor de Benchmark Sintético detenido limpiamente.")
