"""
Suite de pruebas exhaustivas para el Crawler Activo con Monkey Testing & CDP Network Interception.
"""
from __future__ import annotations

import unittest
from unittest.mock import MagicMock, patch

from scanner.active_crawler import (
    ActiveCrawler,
    ActiveCrawlResult,
    HTTPTransaction,
    MonkeyAction,
    StaticBundleExtractor,
    extract_active_crawl_targets,
)
from scanner.headless_crawler import crawl_site_dynamic


class TestActiveCrawler(unittest.TestCase):
    """Pruebas unitarias para modelos, extractor estático, monkey safety y crawler interactivo."""

    def test_http_transaction_and_result_models(self) -> None:
        tx = HTTPTransaction(
            url="http://app.local/api/v1/users",
            method="POST",
            headers={"Authorization": "Bearer test-jwt"},
            post_data='{"username": "alice"}',
            resource_type="fetch",
            response_status=201,
            source_event="monkey_click",
        )
        tx_dict = tx.to_dict()
        self.assertEqual(tx_dict["url"], "http://app.local/api/v1/users")
        self.assertEqual(tx_dict["method"], "POST")
        self.assertEqual(tx_dict["response_status"], 201)
        self.assertEqual(tx_dict["source_event"], "monkey_click")

        action = MonkeyAction(
            action_type="fill",
            selector="input#email",
            tag_name="input",
            value_entered="test@example.com",
        )
        action_dict = action.to_dict()
        self.assertEqual(action_dict["action_type"], "fill")
        self.assertEqual(action_dict["value_entered"], "test@example.com")

        res = ActiveCrawlResult(
            target_url="http://app.local",
            discovered_pages=["http://app.local/dashboard"],
            api_transactions=[tx],
            spa_routes=["http://app.local/profile"],
            websocket_endpoints=["ws://app.local/ws"],
            monkey_actions=[action],
            dom_mutations=15,
            duration_seconds=1.23,
        )
        res_dict = res.to_dict()
        self.assertEqual(res_dict["api_endpoints_count"], 1)
        self.assertEqual(res_dict["monkey_actions_count"], 1)
        self.assertEqual(res_dict["dom_mutations"], 15)
        self.assertEqual(res_dict["duration_seconds"], 1.23)

    def test_safe_action_heuristics(self) -> None:
        crawler = ActiveCrawler()

        # Acciones peligrosas (deben ser rechazadas para preservar la sesión)
        self.assertFalse(crawler.is_safe_action({"text": "Logout"}))
        self.assertFalse(crawler.is_safe_action({"text": "Cerrar Sesión"}))
        self.assertFalse(crawler.is_safe_action({"id": "btn-signout"}))
        self.assertFalse(crawler.is_safe_action({"aria": "delete account"}))
        self.assertFalse(crawler.is_safe_action({"name": "destroy"}))

        # Acciones seguras (deben ser aceptadas para exploración)
        self.assertTrue(crawler.is_safe_action({"text": "Search"}))
        self.assertTrue(crawler.is_safe_action({"text": "Ver Perfil"}))
        self.assertTrue(crawler.is_safe_action({"id": "tab-billing"}))
        self.assertTrue(crawler.is_safe_action({"aria": "Expand menu"}))
        self.assertTrue(crawler.is_safe_action({"name": "save-draft"}))

    def test_static_bundle_extractor(self) -> None:
        sample_js = """
        const API_URL = '/api/v1/orders?limit=10';
        fetch('/graphql', { method: 'POST' });
        axios.get('/api/v2/inventory');
        const socket = new WebSocket('ws://realtime.app.local/feed');
        const secureWs = 'wss://push.app.local/notifications';
        """
        apis, websockets = StaticBundleExtractor.extract_from_text(sample_js, "http://app.local")

        self.assertIn("http://app.local/api/v1/orders?limit=10", apis)
        self.assertIn("http://app.local/graphql", apis)
        self.assertIn("http://app.local/api/v2/inventory", apis)
        self.assertIn("ws://realtime.app.local/feed", websockets)
        self.assertIn("wss://push.app.local/notifications", websockets)

    def test_fallback_crawler_execution(self) -> None:
        mock_session = MagicMock()

        # Respuesta HTML inicial
        html_resp = MagicMock()
        html_resp.status_code = 200
        html_resp.text = """
        <!DOCTYPE html>
        <html>
        <head>
            <script src="/static/app.bundle.js"></script>
        </head>
        <body>
            <form action="/login-post" method="POST">
                <input type="text" name="user">
            </form>
            <div data-url="/api/internal/config"></div>
        </body>
        </html>
        """

        # Respuesta bundle JS
        js_resp = MagicMock()
        js_resp.status_code = 200
        js_resp.text = """
        axios.get('/api/v1/dashboard/metrics');
        """

        def mock_get(url: str, **kwargs: object) -> MagicMock:
            if "app.bundle.js" in url:
                return js_resp
            return html_resp

        mock_session.get.side_effect = mock_get

        crawler = ActiveCrawler()
        result = crawler.crawl("http://app.local", session=mock_session, force_fallback=True)

        self.assertIn("http://app.local/login-post", result.discovered_pages)
        self.assertIn("http://app.local/api/v1/dashboard/metrics", result.discovered_pages)

        # Transacción de formulario detectada
        methods = [tx.method for tx in result.api_transactions]
        self.assertIn("POST", methods)
        self.assertIn("GET", methods)

        targets = extract_active_crawl_targets(result)
        self.assertIn("http://app.local/login-post", targets)
        self.assertIn("http://app.local/api/v1/dashboard/metrics", targets)

    def test_extract_active_crawl_targets_deduplication(self) -> None:
        res = ActiveCrawlResult(
            target_url="http://app.local",
            discovered_pages=["http://app.local/a", "http://app.local/b#anchor"],
            api_transactions=[
                HTTPTransaction(url="http://app.local/api/c#frag"),
                HTTPTransaction(url="http://app.local/a"),
            ],
            spa_routes=["http://app.local/d"],
        )
        targets = extract_active_crawl_targets(res)
        self.assertEqual(len(targets), 4)
        self.assertIn("http://app.local/a", targets)
        self.assertIn("http://app.local/b", targets)
        self.assertIn("http://app.local/api/c", targets)
        self.assertIn("http://app.local/d", targets)

    def test_mocked_playwright_active_crawl(self) -> None:
        # Simular Playwright disponible y verificar orquestación de Monkey Testing
        import sys
        mock_sync_api = MagicMock()
        mock_playwright_mod = MagicMock()
        mock_playwright_mod.sync_api = mock_sync_api
        mock_playwright_cm = MagicMock()
        mock_sync_api.sync_playwright = mock_playwright_cm

        with (
            patch.dict(sys.modules, {"playwright": mock_playwright_mod, "playwright.sync_api": mock_sync_api}),
            patch("scanner.active_crawler.is_playwright_available", return_value=True),
        ):
            mock_p = MagicMock()
            mock_playwright_cm.return_value.__enter__.return_value = mock_p

            mock_browser = MagicMock()
            mock_p.chromium.launch.return_value = mock_browser

            mock_context = MagicMock()
            mock_browser.new_context.return_value = mock_context

            mock_page = MagicMock()
            mock_context.new_page.return_value = mock_page

            # Mock locators para monkey testing
            mock_page.locator.return_value.count.return_value = 0
            mock_page.eval_on_selector_all.return_value = ["/about", "/contact"]
            mock_page.evaluate.return_value = {
                "routes": [{"type": "pushState", "url": "/spa/view"}],
                "mutations": 42,
                "current_url": "http://app.local/spa/view",
            }

            crawler = ActiveCrawler(max_monkey_actions=10)
            res = crawler._crawl_with_playwright("http://app.local")

            # Verificar inyección del script de instrumentación
            mock_context.add_init_script.assert_called_once()
            self.assertIn("http://app.local/about", res.discovered_pages)
            self.assertIn("http://app.local/spa/view", res.discovered_pages)
            self.assertIn("http://app.local/spa/view", res.spa_routes)
            self.assertEqual(res.dom_mutations, 42)

    def test_crawl_site_dynamic_integration_with_active_crawler(self) -> None:
        mock_active_res = ActiveCrawlResult(
            target_url="http://app.local",
            discovered_pages=["http://app.local/home", "http://app.local/dashboard"],
            api_transactions=[HTTPTransaction(url="http://app.local/api/feed")],
        )

        with patch.object(ActiveCrawler, "crawl", return_value=mock_active_res):
            pages, apis = crawl_site_dynamic("http://app.local", max_pages=10, enable_monkey=True)
            self.assertIn("http://app.local/home", pages)
            self.assertIn("http://app.local/dashboard", pages)
            self.assertIn("http://app.local/api/feed", apis)


if __name__ == "__main__":
    unittest.main()
