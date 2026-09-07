"""
Tests unitarios y de integración para las nuevas funcionalidades avanzadas:
1. Headless Crawler & Dynamic SPA Discovery
2. DOM-based XSS Detection
3. HAR Session Parser & Replay
4. AuthSessionManager & Auto-refresh
"""
import json
import unittest
from unittest.mock import MagicMock, patch

import requests

from scanner.auth_helper import AuthSessionManager, parse_credentials
from scanner.dom_xss import (
    analyze_scripts_for_dom_xss,
    check_dom_xss,
)
from scanner.har_parser import HARSessionParser
from scanner.headless_crawler import HeadlessCrawler
from scanner.models import Finding


class TestHARSessionParser(unittest.TestCase):
    """Pruebas para el parser de archivos .har (HTTP Archive)."""

    def setUp(self):
        self.sample_har = {
            "log": {
                "version": "1.2",
                "entries": [
                    {
                        "request": {
                            "method": "GET",
                            "url": "https://app.test.local/dashboard#overview",
                            "headers": [
                                {"name": "Authorization", "value": "Bearer test_jwt_token_123"},
                                {"name": "User-Agent", "value": "TestBrowser"}
                            ],
                            "cookies": [
                                {"name": "session_id", "value": "sess_abc123"},
                                {"name": "csrf_token", "value": "csrf_xyz789"}
                            ]
                        },
                        "response": {
                            "status": 200,
                            "cookies": [
                                {"name": "remember_me", "value": "true"}
                            ]
                        }
                    },
                    {
                        "request": {
                            "method": "POST",
                            "url": "https://app.test.local/api/v1/users",
                            "headers": [
                                {"name": "X-API-Key", "value": "key_secure_456"}
                            ],
                            "cookies": []
                        },
                        "response": {
                            "status": 201,
                            "cookies": []
                        }
                    }
                ]
            }
        }

    def test_har_parsing_cookies_and_headers(self):
        parser = HARSessionParser(self.sample_har)
        summary = parser.get_summary()

        self.assertEqual(parser.cookies.get("session_id"), "sess_abc123")
        self.assertEqual(parser.cookies.get("csrf_token"), "csrf_xyz789")
        self.assertEqual(parser.cookies.get("remember_me"), "true")
        self.assertEqual(parser.headers.get("Authorization"), "Bearer test_jwt_token_123")
        self.assertEqual(parser.headers.get("X-API-Key"), "key_secure_456")

        self.assertIn("https://app.test.local/dashboard", parser.discovered_urls)
        self.assertIn("https://app.test.local/api/v1/users", parser.api_endpoints)
        self.assertEqual(summary["total_urls"], 2)

    def test_har_create_session(self):
        parser = HARSessionParser(self.sample_har)
        session = parser.create_session()

        self.assertIsInstance(session, requests.Session)
        self.assertEqual(session.headers.get("Authorization"), "Bearer test_jwt_token_123")
        self.assertEqual(session.cookies.get("session_id"), "sess_abc123")
        self.assertEqual(session.cookies.get("remember_me"), "true")

    def test_har_from_json_string(self):
        har_str = json.dumps(self.sample_har)
        parser = HARSessionParser.from_string(har_str)
        self.assertEqual(len(parser.discovered_urls), 2)
        self.assertIn("session_id", parser.cookies)


class TestDOMXSSDetection(unittest.TestCase):
    """Pruebas para el módulo de detección de DOM-based XSS."""

    def test_detect_vulnerable_dom_flow_innerhtml(self):
        vulnerable_html = """
        <!DOCTYPE html>
        <html>
        <head><title>Test App</title></head>
        <body>
            <div id="content"></div>
            <script>
                var hash = location.hash.substring(1);
                document.getElementById('content').innerHTML = hash;
            </script>
        </body>
        </html>
        """
        findings = analyze_scripts_for_dom_xss(vulnerable_html, "https://app.test.local")
        self.assertGreaterEqual(len(findings), 1)
        self.assertEqual(findings[0]["severity"], "Alto")
        self.assertIn("innerHTML", findings[0]["evidence"])

    def test_detect_vulnerable_dom_flow_document_write(self):
        vulnerable_html = """
        <script>
            var q = location.search;
            document.write("Result: " + q);
        </script>
        """
        findings = analyze_scripts_for_dom_xss(vulnerable_html, "https://app.test.local")
        self.assertEqual(len(findings), 1)
        self.assertIn("document.write", findings[0]["evidence"])

    def test_safe_script_no_false_positive(self):
        safe_html = """
        <script>
            console.log("Safe application loaded");
            var name = "VulnScanner";
            document.getElementById('title').textContent = name;
        </script>
        """
        findings = analyze_scripts_for_dom_xss(safe_html, "https://app.test.local")
        self.assertEqual(len(findings), 0)

    def test_check_dom_xss_wrapper_and_standards(self):
        html = "<script>document.getElementById('out').innerHTML = location.hash;</script>"
        raw_findings = check_dom_xss("https://app.test.local", html)
        findings = Finding.from_legacy_list(raw_findings, "dom_xss", "https://app.test.local")

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].cwe_id, "CWE-79")
        self.assertEqual(findings[0].mitre_attack_id, "T1059.007")
        self.assertGreaterEqual(findings[0].cvss_score, 6.0)


class TestHeadlessCrawlerAndAuth(unittest.TestCase):
    """Pruebas para HeadlessCrawler y AuthSessionManager."""

    def test_parse_credentials(self):
        creds_str = "user=admin; password=secret123; role=auditor"
        creds = parse_credentials(creds_str)
        self.assertEqual(creds.get("user"), "admin")
        self.assertEqual(creds.get("password"), "secret123")
        self.assertEqual(creds.get("role"), "auditor")

    def test_headless_crawler_graceful_fallback(self):
        with patch("scanner.headless_crawler.is_playwright_available", return_value=False):
            crawler = HeadlessCrawler()
            links, apis, html = crawler.crawl_dynamic_page("https://app.test.local")
            self.assertEqual(links, [])
            self.assertEqual(apis, set())
            self.assertEqual(html, "")

    def test_auth_session_manager_auto_refresh(self):
        mock_session = MagicMock(spec=requests.Session)
        mock_response_401 = MagicMock(spec=requests.Response)
        mock_response_401.status_code = 401

        mock_response_200 = MagicMock(spec=requests.Response)
        mock_response_200.status_code = 200

        mock_refreshed_session = MagicMock(spec=requests.Session)
        mock_refreshed_session.request.return_value = mock_response_200

        mock_session.request.return_value = mock_response_401

        refresh_called = [False]

        def fake_refresh():
            refresh_called[0] = True
            return mock_refreshed_session

        manager = AuthSessionManager(session=mock_session, refresh_callback=fake_refresh)
        resp = manager.get("https://app.test.local/api/profile")

        self.assertTrue(refresh_called[0])
        self.assertEqual(resp.status_code, 200)


if __name__ == "__main__":
    unittest.main()
