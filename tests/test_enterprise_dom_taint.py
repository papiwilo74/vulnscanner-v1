from unittest.mock import MagicMock

from scanner.dom_xss import dynamic_check_dom_xss


def test_dynamic_dom_xss_taint_tracking_confirmed(monkeypatch):
    """Verifica que el taint tracking en Playwright capture el sumidero y la traza de pila."""
    # Simular disponibilidad de Playwright
    monkeypatch.setattr("scanner.dom_xss.is_playwright_available", lambda: True)

    mock_page = MagicMock()
    # Simular que evaluate retorna un evento de taint capturado por el hook inyectado
    mock_taint_event = [{
        "sink": "Element.innerHTML",
        "value": "<img src=x onerror=alert(1)>",
        "stack": "Error\n    at renderUserContent (https://victim.test/app.js:45:12)\n    at initPage (https://victim.test/app.js:12:5)",
        "timestamp": 1710000000000
    }]
    mock_page.evaluate.return_value = mock_taint_event

    mock_browser = MagicMock()
    mock_browser.new_page.return_value = mock_page

    mock_playwright_context = MagicMock()
    mock_playwright_context.chromium.launch.return_value = mock_browser
    mock_playwright_context.__enter__.return_value = mock_playwright_context
    mock_playwright_context.__exit__.return_value = None

    import sys
    mock_pw_module = MagicMock()
    mock_pw_module.sync_playwright.return_value = mock_playwright_context
    monkeypatch.setitem(sys.modules, "playwright.sync_api", mock_pw_module)

    findings = dynamic_check_dom_xss("https://victim.test/profile")

    assert len(findings) == 1
    f = findings[0]
    assert "Taint Analysis (Element.innerHTML)" in f["vuln"]
    assert f["confidence"] == "confirmed"
    assert f["severity"] == "Alto"
    assert "renderUserContent" in f["evidence"]

    # Verificar que el arnés de instrumentación fue inyectado antes de navegar
    mock_page.add_init_script.assert_called_once()
    init_script_arg = mock_page.add_init_script.call_args[0][0]
    assert "window.__omni_taint_findings" in init_script_arg
    assert "Element.innerHTML" in init_script_arg


def test_dynamic_dom_xss_unavailable_graceful(monkeypatch):
    """Verifica degradación limpia si Playwright no está instalado o deshabilitado."""
    monkeypatch.setattr("scanner.dom_xss.is_playwright_available", lambda: False)
    findings = dynamic_check_dom_xss("https://victim.test/search")
    assert findings == []
