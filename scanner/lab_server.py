"""
Servidor de Laboratorio Aislado (Lab Mode / Hermetic CI) para VulnScanner Enterprise.
Levanta una aplicación web simulada con vulnerabilidades controladas para permitir:
1. Pruebas y auditorías locales sin conexión a internet ni dependencias externas.
2. Demostraciones rápidas y validación en pipelines CI/CD cerrados.
3. Pruebas herméticas End-to-End.
"""
import http.server
import threading
from typing import Optional


class LabRequestHandler(http.server.BaseHTTPRequestHandler):
    """Manejador HTTP con vulnerabilidades intencionales para pruebas herméticas."""

    server_version = "VulnScannerLab/1.0"
    sys_version = ""

    def log_message(self, format: str, *args: object) -> None:
        # Silenciar logs en consola para mantener limpia la salida de escaneo
        pass

    def do_GET(self) -> None:
        path = self.path
        parsed_path = path.split("?")[0]

        # 1. Robots.txt
        if parsed_path == "/robots.txt":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"User-agent: *\nDisallow: /admin\nDisallow: /backup\n")
            return

        # 2. Archivos expuestos (.env, backup.zip)
        if parsed_path == "/.env":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"DB_PASSWORD=supersecret_lab_pass_2026\nAWS_SECRET_KEY=AKIAIOSFODNN7EXAMPLE\n")
            return

        if parsed_path in ("/backup", "/backup/"):
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(b"<html><body><h1>Index of /backup</h1><a href='dump.sql'>dump.sql</a></body></html>")
            return

        # 3. SQL Injection en /products?id=
        if parsed_path == "/products":
            query = path.split("?")[1] if "?" in path else ""
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            # Sin cabeceras de seguridad para activar hallazgos
            self.end_headers()
            if any(sqli in query.lower() for sqli in ["' or '1'='1", "union select", "1' or '1'='1' --", "sleep("]):
                body = (
                    "<html><body><h1>Catálogo de Productos</h1>"
                    "<div class='item'>ID: 1 - Admin Secret Gadget</div>"
                    "<p>SQL Error: syntax error near 'OR' (Simulated SQLite)</p>"
                    "</body></html>"
                )
            else:
                body = "<html><body><h1>Catálogo de Productos</h1><div class='item'>ID: 1 - Laptop</div></body></html>"
            self.wfile.write(body.encode("utf-8"))
            return

        # 4. Reflected XSS en /search?q=
        if parsed_path == "/search":
            query = path.split("?")[1] if "?" in path else ""
            q_val = ""
            if "q=" in query:
                for part in query.split("&"):
                    if part.startswith("q="):
                        q_val = part.split("q=", 1)[1]
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            # Vulnerabilidad XSS reflejado directo (sin escapar)
            body = f"<html><body><h1>Resultados de búsqueda</h1><p>Búsqueda para: {q_val}</p></body></html>"
            self.wfile.write(body.encode("utf-8"))
            return

        # 5. GraphQL Endpoint
        if parsed_path == "/graphql":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"data": {"__schema": {"queryType": {"name": "Query"}}}}')
            return

        # 6. Página principal (Falta de cabeceras de seguridad, formulario sin CSRF, enlaces)
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        # Cookie sin Secure ni HttpOnly
        self.send_header("Set-Cookie", "session_token=lab_token_12345; Path=/")
        self.end_headers()

        html = """<!DOCTYPE html>
<html>
<head>
    <title>VulnScanner Test Lab</title>
</head>
<body>
    <h1>Bienvenido al Laboratorio de Pruebas</h1>
    <p>Entorno controlado para auditoría hermética.</p>
    <nav>
        <a href="/products?id=1">Productos</a>
        <a href="/search?q=test">Búsqueda</a>
        <a href="/backup/">Backups</a>
    </nav>
    <form action="/login" method="POST">
        <input type="text" name="username" placeholder="Usuario">
        <input type="password" name="password" placeholder="Clave">
        <button type="submit">Iniciar Sesión</button>
    </form>
    <script>
        // DOM XSS Sink intencional
        const param = new URLSearchParams(window.location.search).get("msg");
        if (param) {
            document.getElementById("output").innerHTML = param;
        }
    </script>
    <div id="output"></div>
</body>
</html>
"""
        self.wfile.write(html.encode("utf-8"))

    def do_POST(self) -> None:
        parsed_path = self.path.split("?")[0]
        if parsed_path == "/graphql":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"data": {"__schema": {"queryType": {"name": "Query"}}}}')
            return

        # Simulación de respuesta estándar de login
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(b"<html><body>Login recibido</body></html>")


class LabServer:
    """Administrador del ciclo de vida del servidor de laboratorio local."""

    def __init__(self, host: str = "127.0.0.1", port: int = 0) -> None:
        self.host = host
        self.port = port
        self._server: Optional[http.server.HTTPServer] = None
        self._thread: Optional[threading.Thread] = None

    def start(self) -> str:
        """Inicia el servidor en un hilo secundario y devuelve su URL base."""
        # Si port es 0, el SO asigna automáticamente un puerto libre
        self._server = http.server.HTTPServer((self.host, self.port), LabRequestHandler)
        actual_port = self._server.server_port
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        return f"http://{self.host}:{actual_port}"

    def stop(self) -> None:
        """Detiene el servidor HTTP de forma limpia."""
        if self._server:
            self._server.shutdown()
            self._server.server_close()
            self._server = None
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2.0)
            self._thread = None
