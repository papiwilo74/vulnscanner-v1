"""
Suite de Pruebas de Alta Precisión y Resistencia a Falsos Positivos.
Verifica que los filtros avanzados de OmniBreach supriman eficazmente el ruido:
1. Rechazo de falsos positivos de SQLi ante páginas de bloqueo WAF (Cloudflare, AWS WAF, ModSecurity).
2. Rechazo de falsos positivos de XSS cuando el payload queda confinado en comentarios HTML o atributos sin breakout.
3. Rechazo de falsos positivos de secretos ante cadenas de prueba de baja entropía de Shannon.
4. Detección certera ante verdaderos positivos con evidencia ejecutable.
"""
from __future__ import annotations

from unittest.mock import Mock
from urllib.parse import urlparse

from scanner.sensitive_data import (
    scan_text_for_sensitive_data,
    shannon_entropy,
)
from scanner.sqli import (
    is_waf_blocking_page,
)
from scanner.sqli import (
    test_boolean_sqli as exec_boolean_sqli,
)
from scanner.sqli import (
    test_error_sqli as exec_error_sqli,
)
from scanner.xss import (
    _is_reflection_in_html_comment,
    _is_reflection_in_unbroken_attribute,
)
from scanner.xss import (
    test_xss_payload as exec_xss_payload,
)


class TestWAFBlockSuppression:
    """Verifica que las respuestas de WAFs bloqueando ataques no sean confundidas con vulnerabilidades."""

    def test_waf_blocking_detection(self) -> None:
        cf_body = "<html><title>Attention Required! | Cloudflare</title><h2>Error 1020: Access Denied</h2><p>Request blocked by SQL injection firewall rule.</p></html>"
        assert is_waf_blocking_page(403, cf_body) is True

        aws_body = "<html><body><h1>403 Forbidden</h1><p>Request blocked by CloudFront</p></body></html>"
        assert is_waf_blocking_page(403, aws_body) is True

        modsec_body = "<html><body>ModSecurity: Access denied with code 403 (Phase 2). Pattern match 'syntax error at or near'</body></html>"
        assert is_waf_blocking_page(403, modsec_body) is True

        real_db_error = "<html><body>Database Error: sqlite3.OperationalError: unrecognized token: \"'\" in SELECT * FROM users</body></html>"
        assert is_waf_blocking_page(500, real_db_error) is False

    def test_error_sqli_ignores_waf_block_page(self) -> None:
        parsed = urlparse("https://target.local/search?q=apple")
        params = {"q": ["apple"]}

        mock_session = Mock()
        mock_response = Mock()
        mock_response.status_code = 403
        mock_response.headers = {"server": "cloudflare"}
        mock_response.text = (
            "<title>Attention Required! | Cloudflare</title>"
            "<h2>Error 1020: Access Denied</h2>"
            "<p>Request blocked by SQL injection firewall rule: you have an error in your sql syntax</p>"
        )
        mock_session.get.return_value = mock_response

        # A pesar de contener 'you have an error in your sql syntax', el WAF 403 debe descartarlo
        finding = exec_error_sqli(
            parsed=parsed,
            params=params,
            param="q",
            payload="' OR '1'='1",
            baseline_body="<html><body>Normal search</body></html>",
            session=mock_session,
        )
        assert finding is None

    def test_boolean_sqli_ignores_waf_block_on_false_condition(self) -> None:
        parsed = urlparse("https://target.local/items?id=1")
        params = {"id": ["1"]}

        mock_session = Mock()

        # Respuesta True: 200 OK
        resp_true = Mock()
        resp_true.status_code = 200
        resp_true.text = "<html><body>Item details: Laptop ABC</body></html>"

        # Respuesta False: WAF bloquea con 403
        resp_false = Mock()
        resp_false.status_code = 403
        resp_false.text = "<html><title>Access Denied</title><p>Request blocked by firewall</p></html>"

        mock_session.get.side_effect = [resp_true, resp_false]

        finding = exec_boolean_sqli(
            parsed=parsed,
            params=params,
            param="id",
            true_payload="1 AND 1=1",
            false_payload="1 AND 1=2",
            baseline_body="<html><body>Item details: Laptop ABC</body></html>",
            session=mock_session,
        )
        assert finding is None


class TestXSSContextAwareness:
    """Verifica que el análisis contextual de reflexión en el DOM descarte falsos positivos."""

    def test_xss_in_comment_is_not_executable(self) -> None:
        payload = "<script>alert(1)</script>"
        html_with_comment = f"""
        <html>
        <body>
            <!-- El usuario buscó el término: {payload} -->
            <p>Resultados no encontrados.</p>
        </body>
        </html>
        """
        assert _is_reflection_in_html_comment(html_with_comment, payload) is True

    def test_xss_in_unbroken_attribute_is_not_executable(self) -> None:
        payload = "<script>alert(1)</script>"
        html_in_attr = f"""
        <html>
        <body>
            <input type="text" name="query" value="{payload}">
        </body>
        </html>
        """
        assert _is_reflection_in_unbroken_attribute(html_in_attr, payload) is True

    def test_xss_breaking_attribute_is_executable(self) -> None:
        payload = '"><img src=x onerror=alert(1)>'
        # El payload rompió las comillas del atributo
        html_broken = f'<input type="text" name="query" value="{payload}">'
        assert _is_reflection_in_unbroken_attribute(html_broken, payload) is False

    def test_test_xss_payload_discards_reflection_in_comment(self) -> None:
        parsed = urlparse("https://target.local/search?q=test")
        params = {"q": ["test"]}

        mock_session = Mock()
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.headers = {"Content-Type": "text/html; charset=utf-8"}
        payload = "<script>alert(1)</script>"
        mock_response.text = f"<html><body><!-- Historial de búsqueda: {payload} --><h1>Buscar</h1></body></html>"
        mock_session.get.return_value = mock_response

        finding = exec_xss_payload(
            parsed=parsed,
            params=params,
            param="q",
            payload=payload,
            baseline_text="<html><body><h1>Buscar</h1></body></html>",
            session=mock_session,
        )
        assert finding is None


class TestShannonEntropySecretFilter:
    """Verifica el cálculo de entropía de Shannon para filtrar falsos positivos de secretos."""

    def test_shannon_entropy_calculation(self) -> None:
        # Cadena con todos los caracteres iguales: entropía = 0
        assert shannon_entropy("AAAAAAAAAA") == 0.0

        # Cadena con baja entropía
        assert shannon_entropy("ABABABABAB") == 1.0

        # Clave criptográfica aleatoria real: alta entropía (> 3.0 bits/char)
        real_key_entropy = shannon_entropy("AKIAIOSFODNN7WXYZ99Q")
        assert real_key_entropy > 3.0

    def test_filter_discards_dummy_low_entropy_aws_keys(self) -> None:
        dummy_code = """
        const DUMMY_AWS_1 = "AKIAAAAAAAAAAAAAAAAA";
        const DUMMY_AWS_2 = "AKIA0000000000000000";
        const DUMMY_AWS_3 = "AKIA1111111111111111";
        """
        findings = scan_text_for_sensitive_data(dummy_code, "test.js")
        assert len(findings) == 0

    def test_filter_detects_real_high_entropy_secrets(self) -> None:
        real_code = """
        const AWS_KEY = "AKIAIOSFODNN7WXYZ99Q";
        const GITHUB_PAT = "ghp_1234567890abcdefghijklmnopqrstuvwxyz";
        """
        findings = scan_text_for_sensitive_data(real_code, "config.js")
        assert len(findings) >= 2
        categories = [f["vuln"] for f in findings]
        assert any("AWS" in c for c in categories)
        assert any("GitHub" in c for c in categories)
