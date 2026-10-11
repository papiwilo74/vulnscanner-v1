"""
Suite de pruebas exhaustivas para el Motor de Reglas Declarativas (YAML/JSON DSL Engine).
"""
import json
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from scanner.template_engine import (
    Extractor,
    ExtractorType,
    Matcher,
    MatcherCondition,
    MatcherPart,
    MatcherType,
    RequestSpec,
    SecurityTemplate,
    TemplateEngine,
    TemplateInfo,
    _coerce_yaml_scalar,
)


class TestTemplateParserAndModels(unittest.TestCase):
    """Pruebas de deserialización, tipado y modelos de plantillas."""

    def test_coerce_yaml_scalars(self) -> None:
        self.assertEqual(_coerce_yaml_scalar("true"), True)
        self.assertEqual(_coerce_yaml_scalar("false"), False)
        self.assertEqual(_coerce_yaml_scalar("null"), None)
        self.assertEqual(_coerce_yaml_scalar("123"), 123)
        self.assertEqual(_coerce_yaml_scalar("45.67"), 45.67)
        self.assertEqual(_coerce_yaml_scalar('"quoted"'), "quoted")
        self.assertEqual(_coerce_yaml_scalar("'single'"), "single")
        self.assertEqual(_coerce_yaml_scalar("[200, 301]"), [200, 301])

    def test_parse_json_template(self) -> None:
        raw_json = json.dumps({
            "id": "test-json-rule",
            "info": {
                "name": "Test Rule JSON",
                "severity": "high",
                "cwe_id": "CWE-89",
                "cvss_score": 9.8,
            },
            "requests": [
                {
                    "method": "GET",
                    "path": ["/api/test"],
                    "matchers": [
                        {"type": "status", "status": [200]},
                        {"type": "word", "words": ["admin", "root"], "condition": "or"}
                    ]
                }
            ]
        })
        tmpl = TemplateEngine.load_from_string(raw_json)
        self.assertEqual(tmpl.id, "test-json-rule")
        self.assertEqual(tmpl.info.name, "Test Rule JSON")
        self.assertEqual(tmpl.info.severity, "high")
        self.assertEqual(tmpl.info.cwe_id, "CWE-89")
        self.assertEqual(tmpl.info.cvss_score, 9.8)
        self.assertEqual(len(tmpl.requests), 1)
        self.assertEqual(tmpl.requests[0].method, "GET")
        self.assertEqual(len(tmpl.requests[0].matchers), 2)

    def test_parse_yaml_template(self) -> None:
        yaml_content = """
id: custom-cve-test
info:
  name: Custom Vulnerability Check
  author: Security Lab
  severity: critical
  cwe_id: CWE-78
  cvss_score: 9.8
requests:
  - method: POST
    path:
      - "{{BaseURL}}/exec"
    body: "cmd=whoami"
    matchers:
      - type: status
        status:
          - 200
      - type: word
        part: body
        words:
          - "root"
          - "daemon"
        condition: or
"""
        tmpl = TemplateEngine.load_from_string(yaml_content)
        self.assertEqual(tmpl.id, "custom-cve-test")
        self.assertEqual(tmpl.info.name, "Custom Vulnerability Check")
        self.assertEqual(tmpl.info.severity, "critical")
        self.assertEqual(tmpl.info.cwe_id, "CWE-78")
        self.assertEqual(len(tmpl.requests), 1)
        req = tmpl.requests[0]
        self.assertEqual(req.method, "POST")
        self.assertEqual(req.body, "cmd=whoami")
        self.assertEqual(len(req.matchers), 2)


class TestMatcherEvaluation(unittest.TestCase):
    """Pruebas unitarias de operadores de evaluación de respuestas."""

    def setUp(self) -> None:
        self.engine = TemplateEngine()

    def test_status_matcher(self) -> None:
        matcher = Matcher(type=MatcherType.STATUS, status=[200, 201])
        mock_resp_200 = MagicMock()
        mock_resp_200.status_code = 200
        mock_resp_404 = MagicMock()
        mock_resp_404.status_code = 404

        res_200, _ = self.engine._evaluate_single_matcher(matcher, mock_resp_200)
        res_404, _ = self.engine._evaluate_single_matcher(matcher, mock_resp_404)
        self.assertTrue(res_200)
        self.assertFalse(res_404)

    def test_word_matcher_or_and(self) -> None:
        mock_resp = MagicMock()
        mock_resp.text = "Error in SQL syntax; database query failed"
        mock_resp.headers = {}

        # Condición OR
        matcher_or = Matcher(type=MatcherType.WORD, words=["SQL syntax", "nonexistent"], condition=MatcherCondition.OR)
        matched, frag = self.engine._evaluate_single_matcher(matcher_or, mock_resp)
        self.assertTrue(matched)
        self.assertIn("SQL syntax", frag)

        # Condición AND exitosa
        matcher_and = Matcher(type=MatcherType.WORD, words=["syntax", "database"], condition=MatcherCondition.AND)
        matched, _ = self.engine._evaluate_single_matcher(matcher_and, mock_resp)
        self.assertTrue(matched)

        # Condición AND fallida
        matcher_and_fail = Matcher(type=MatcherType.WORD, words=["syntax", "missing_word"], condition=MatcherCondition.AND)
        matched, _ = self.engine._evaluate_single_matcher(matcher_and_fail, mock_resp)
        self.assertFalse(matched)

    def test_regex_matcher(self) -> None:
        mock_resp = MagicMock()
        mock_resp.text = "Server version: Apache/2.4.41 (Ubuntu)"
        mock_resp.headers = {}

        matcher = Matcher(type=MatcherType.REGEX, regex=[r"Apache\/[0-9]+\.[0-9]+"])
        matched, frag = self.engine._evaluate_single_matcher(matcher, mock_resp)
        self.assertTrue(matched)
        self.assertIn("Apache/2.4", frag)

    def test_negative_matcher(self) -> None:
        mock_resp = MagicMock()
        mock_resp.text = "Valid plain text token"
        mock_resp.headers = {}

        # El cuerpo NO debe contener "<html"
        matcher_neg = Matcher(type=MatcherType.WORD, words=["<html"], negative=True)
        matched, _ = self.engine._evaluate_single_matcher(matcher_neg, mock_resp)
        self.assertTrue(matched)

        # Si el cuerpo SÍ contiene "<html", debe fallar
        mock_resp_html = MagicMock()
        mock_resp_html.text = "<html><body>Error</body></html>"
        mock_resp_html.headers = {}
        matched_html, _ = self.engine._evaluate_single_matcher(matcher_neg, mock_resp_html)
        self.assertFalse(matched_html)

    def test_header_matcher(self) -> None:
        mock_resp = MagicMock()
        mock_resp.text = "Hello"
        mock_resp.headers = {"X-Powered-By": "Express", "Server": "Cloudflare"}

        matcher = Matcher(type=MatcherType.WORD, part=MatcherPart.HEADER, words=["Express"])
        matched, _ = self.engine._evaluate_single_matcher(matcher, mock_resp)
        self.assertTrue(matched)


class TestTemplateExecutionAndExtractors(unittest.TestCase):
    """Pruebas de ciclo completo de ejecución con mocks HTTP y propagación de extractores."""

    @patch("requests.Session.request")
    def test_execute_template_positive(self, mock_request: MagicMock) -> None:
        # Simular respuesta vulnerable con credenciales expuestas
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = "DB_PASSWORD=SuperSecret123!\nAPP_KEY=base64:xyz"
        mock_resp.headers = {"Content-Type": "text/plain"}
        mock_request.return_value = mock_resp

        tmpl = SecurityTemplate(
            id="test-env-leak",
            info=TemplateInfo(
                name="Prueba de Fuga de Variables",
                severity="critical",
                cwe_id="CWE-200",
                cvss_score=8.5,
            ),
            requests=[
                RequestSpec(
                    method="GET",
                    path=["{{BaseURL}}/.env"],
                    matchers=[
                        Matcher(type=MatcherType.STATUS, status=[200]),
                        Matcher(type=MatcherType.WORD, words=["DB_PASSWORD="]),
                    ],
                    matchers_condition=MatcherCondition.AND,
                )
            ]
        )

        engine = TemplateEngine()
        findings = engine.execute_template(tmpl, "http://localhost:8000")

        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertEqual(f.category, "template_dsl")
        self.assertEqual(f.severity, "critical")
        self.assertEqual(f.cwe_id, "CWE-200")
        self.assertEqual(f.cvss_score, 8.5)
        self.assertIn("http://localhost:8000/.env", f.affected_url)
        self.assertIsNotNone(f.evidence)
        self.assertEqual(f.evidence.response_status, 200)

    @patch("requests.Session.request")
    def test_multi_step_extractor_chaining(self, mock_request: MagicMock) -> None:
        # Paso 1: Devuelve un token en JSON
        resp1 = MagicMock()
        resp1.status_code = 200
        resp1.text = '{"auth": {"csrf_token": "token-xyz-999"}}'
        resp1.headers = {"Content-Type": "application/json"}
        resp1.json.return_value = {"auth": {"csrf_token": "token-xyz-999"}}

        # Paso 2: Endpoint protegido que acepta el token
        resp2 = MagicMock()
        resp2.status_code = 200
        resp2.text = "WELCOME_ADMIN_DASHBOARD"
        resp2.headers = {}

        mock_request.side_effect = [resp1, resp2]

        tmpl = SecurityTemplate(
            id="chained-token-exploit",
            info=TemplateInfo(name="Prueba Chained Token", severity="high"),
            requests=[
                RequestSpec(
                    method="GET",
                    path=["{{BaseURL}}/get-token"],
                    extractors=[
                        Extractor(name="csrf", type=ExtractorType.JSON, json_path="auth.csrf_token")
                    ]
                ),
                RequestSpec(
                    method="POST",
                    path=["{{BaseURL}}/admin"],
                    headers={"X-CSRF-Token": "{{csrf}}"},
                    body="action=login&token={{csrf}}",
                    matchers=[
                        Matcher(type=MatcherType.WORD, words=["WELCOME_ADMIN_DASHBOARD"])
                    ]
                )
            ]
        )

        engine = TemplateEngine()
        findings = engine.execute_template(tmpl, "http://example.com")

        # Verificar que el segundo request utilizó el token extraído del primer request
        self.assertEqual(mock_request.call_count, 2)
        second_call = mock_request.call_args_list[1]
        self.assertEqual(second_call.kwargs["headers"]["X-CSRF-Token"], "token-xyz-999")
        self.assertEqual(second_call.kwargs["data"], "action=login&token=token-xyz-999")
        self.assertEqual(len(findings), 1)

    def test_built_in_templates_directory(self) -> None:
        templates_dir = Path(__file__).resolve().parent.parent / "templates_dsl"
        self.assertTrue(templates_dir.is_dir())
        loaded = TemplateEngine.load_from_dir(templates_dir)
        self.assertGreaterEqual(len(loaded), 5)

        ids = [t.id for t in loaded]
        self.assertIn("exposed-env-file", ids)
        self.assertIn("exposed-git-repository", ids)
        self.assertIn("spring-boot-actuator-exposed", ids)
        self.assertIn("graphql-introspection-enabled", ids)
        self.assertIn("swagger-ui-exposed", ids)


if __name__ == "__main__":
    unittest.main()
