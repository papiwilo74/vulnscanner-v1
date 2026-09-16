import responses

from utils.adaptive_client import AdaptiveRateLimiter, create_adaptive_session


def test_adaptive_rate_limiter_aimd():
    """Verifica que el algoritmo AIMD aumente gradualmente y disminuya a la mitad ante 429."""
    limiter = AdaptiveRateLimiter(base_rps=10.0, min_rps=1.0, max_rps=20.0, success_step=3)
    assert limiter.current_rps == 10.0

    # 3 éxitos consecutivos aumentan 1.0 RPS
    limiter.on_success()
    limiter.on_success()
    limiter.on_success()
    assert limiter.current_rps == 11.0

    # Rate-limit 429 divide la tasa a la mitad
    wait_time = limiter.on_rate_limit(retry_after=1.5)
    assert limiter.current_rps == 5.5
    assert wait_time == 1.5

    # Bloqueo WAF reduce al mínimo
    limiter.on_waf_block()
    assert limiter.current_rps == 1.0


@responses.activate
def test_adaptive_session_retries_on_429():
    """Verifica que AdaptiveSession reaccione a un 429 con Retry-After y reintente con éxito."""
    url = "https://victim.test/api/probe"

    # Primer intento 429 con Retry-After de 0.05s, segundo intento 200 OK
    responses.add(
        responses.GET,
        url,
        status=429,
        headers={"Retry-After": "0.05"},
    )
    responses.add(
        responses.GET,
        url,
        status=200,
        body="Success after rate-limit backoff",
    )

    session = create_adaptive_session(base_rps=20.0, stealth=True)
    resp = session.get(url)

    assert resp.status_code == 200
    assert "Success after rate-limit backoff" in resp.text
    assert len(responses.calls) == 2

    # Verificar que los encabezados de evasión fueron inyectados
    first_req = responses.calls[0].request
    assert "X-Forwarded-For" in first_req.headers
    assert "X-Real-IP" in first_req.headers


@responses.activate
def test_adaptive_session_evasion_headers_injected():
    """Verifica la inyección de cabeceras de proxy de cliente spoofeadas para eludir WAF."""
    url = "https://victim.test/resource"
    responses.add(responses.GET, url, status=200, body="OK")

    session = create_adaptive_session(stealth=True)
    session.get(url)

    req = responses.calls[0].request
    assert "X-Forwarded-For" in req.headers
    assert "X-Originating-IP" in req.headers
