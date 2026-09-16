import responses

from scanner.param_fuzzer import (
    ParameterFuzzer,
    check_param_fuzzer,
    discover_parameters,
    generate_canary,
)


def test_generate_canary():
    canary = generate_canary(10)
    assert canary.startswith("ob_")
    assert len(canary) == 13
    assert canary != generate_canary(10)


@responses.activate
def test_parameter_fuzzer_reflected():
    base_url = "https://app.test/search"
    # Base response
    responses.add(
        responses.GET,
        base_url,
        body="<html><body><h1>Search Page</h1></body></html>",
        status=200
    )

    # Param probe with reflection
    def request_callback(request):
        if "q=" in request.url:
            val = request.url.split("q=")[1]
            return (200, {}, f"<html><body>Result for: {val}</body></html>")
        return (200, {}, "<html><body><h1>Search Page</h1></body></html>")

    responses.add_callback(
        responses.GET,
        base_url,
        callback=request_callback,
    )

    fuzzer = ParameterFuzzer(timeout=2)
    discovered_urls, findings = fuzzer.probe_url(base_url, candidate_params=["q", "other"])

    assert len(discovered_urls) >= 1
    assert any("q=" in u for u in discovered_urls)
    assert any(f["vuln"].startswith("Parámetro Oculto Aceptado") for f in findings)


@responses.activate
def test_parameter_fuzzer_status_divergence():
    base_url = "https://app.test/api/endpoint"
    # Base returns 404
    responses.add(
        responses.GET,
        base_url,
        body="Not found",
        status=404
    )

    # When id=1 is provided, it returns 200
    def callback(request):
        if "id=" in request.url:
            return (200, {}, '{"id": 1, "name": "Item"}')
        return (404, {}, "Not found")

    responses.add_callback(
        responses.GET,
        base_url,
        callback=callback,
    )

    fuzzer = ParameterFuzzer(timeout=2)
    discovered_urls, findings = fuzzer.probe_url(base_url, candidate_params=["id"])

    assert len(discovered_urls) == 1
    assert "id=" in discovered_urls[0]


@responses.activate
def test_parameter_fuzzer_debug_param():
    base_url = "https://app.test/login"

    def callback(request):
        if "debug=" in request.url:
            return (200, {}, "DEBUG CONSOLE ACTIVE: Memory Dump, Environment Variables...")
        return (200, {}, "Login Form")

    responses.add_callback(
        responses.GET,
        base_url,
        callback=callback,
    )

    findings = check_param_fuzzer(base_url)
    debug_findings = [f for f in findings if "debug" in f["vuln"].lower()]
    assert len(debug_findings) == 1
    assert debug_findings[0]["risk"] == "Medio"
    assert debug_findings[0]["cwe"] == "CWE-489"


@responses.activate
def test_discover_parameters_convenience():
    base_url = "https://app.test/view"
    responses.add(responses.GET, base_url, body="View content", status=200)

    def callback(request):
        if "redirect=" in request.url:
            return (302, {"Location": "https://evil.com"}, "Redirecting")
        return (200, {}, "View content")

    responses.add_callback(responses.GET, base_url, callback=callback)

    urls = discover_parameters(base_url, candidate_params=["redirect", "dummy"])
    assert len(urls) >= 1
    assert any("redirect=" in u for u in urls)
