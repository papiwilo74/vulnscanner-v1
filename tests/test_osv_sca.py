from unittest.mock import Mock

import responses

from scanner.sca import (
    _OSV_CACHE,
    check_library_vulnerabilities,
    query_osv_vulnerabilities,
)


def test_osv_query_success_parses_cves_and_severities():
    """Valida que la respuesta de OSV.dev se procese correctamente, extrayendo CVEs y mapeando severidad."""
    _OSV_CACHE.clear()

    mock_resp = {
        "vulns": [
            {
                "id": "GHSA-j827-mfrf-vhw4",
                "aliases": ["CVE-2020-11022"],
                "summary": "Cross-site Scripting in jQuery",
                "database_specific": {"severity": "HIGH"},
                "details": "In jQuery versions greater than or equal to 1.2 and prior to 3.5.0, passing HTML from untrusted sources to jQuery's DOM manipulation methods may execute untrusted code.",
            },
            {
                "id": "GHSA-gxr4-xjj5-5px2",
                "aliases": ["CVE-2020-11023"],
                "summary": "Cross-site Scripting in jQuery .htmlPrefilter",
                "database_specific": {"severity": "CRITICAL"},
            },
        ]
    }

    mock_session = Mock()
    mock_http_response = Mock()
    mock_http_response.status_code = 200
    mock_http_response.json.return_value = mock_resp
    mock_session.post.return_value = mock_http_response

    findings = query_osv_vulnerabilities("jquery", "1.12.4", session=mock_session)

    assert len(findings) == 2
    assert any("CVE-2020-11022" in f["vuln"] and f["risk"] == "Alto" for f in findings)
    assert any("CVE-2020-11023" in f["vuln"] and f["risk"] == "Crítico" for f in findings)
    assert all(f["confidence"] == "confirmed" for f in findings)


def test_osv_cache_prevents_duplicate_network_calls():
    """Valida que consultas sucesivas a la misma librería y versión usen la caché en memoria."""
    _OSV_CACHE.clear()

    mock_session = Mock()
    mock_http_response = Mock()
    mock_http_response.status_code = 200
    mock_http_response.json.return_value = {"vulns": [{"id": "CVE-2021-9999", "summary": "Test Vuln"}]}
    mock_session.post.return_value = mock_http_response

    f1 = query_osv_vulnerabilities("lodash", "4.17.15", session=mock_session)
    assert len(f1) == 1
    assert mock_session.post.call_count == 1

    # Segunda llamada debe usar caché sin llamar a post de nuevo
    f2 = query_osv_vulnerabilities("lodash", "4.17.15", session=mock_session)
    assert len(f2) == 1
    assert mock_session.post.call_count == 1


@responses.activate
def test_osv_fallback_to_local_vulnerable_libs_on_error():
    """Si la API de OSV falla o está offline, el escáner recurre a la base local VULNERABLE_LIBS."""
    _OSV_CACHE.clear()

    # Simular caída de OSV.dev con 500 Internal Server Error
    responses.add(
        responses.POST,
        "https://api.osv.dev/v1/query",
        status=500,
        body="Internal Server Error",
    )

    findings = check_library_vulnerabilities("bootstrap", "3.3.7", use_osv=True)

    # Debe haber obtenido la vulnerabilidad desde VULNERABLE_LIBS local
    assert len(findings) >= 1
    assert "Componente Vulnerable Detectado" in findings[0]["vuln"]
    assert "CVE-2019-8331" in findings[0]["detail"]
    assert findings[0]["confidence"] == "confirmed"


def test_osv_unknown_library_returns_empty():
    """Una librería desconocida y no vulnerable no debe generar hallazgos."""
    _OSV_CACHE.clear()

    mock_session = Mock()
    mock_http_response = Mock()
    mock_http_response.status_code = 200
    mock_http_response.json.return_value = {"vulns": []}
    mock_session.post.return_value = mock_http_response

    findings = check_library_vulnerabilities("safe-internal-lib", "1.0.0", session=mock_session)
    assert len(findings) == 0
