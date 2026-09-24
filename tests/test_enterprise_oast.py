import requests

from scanner.oast import OASTClient, OASTLocalServer
from scanner.xxe import check_xxe


def test_oast_local_server_lifecycle():
    """Verifica que OASTLocalServer arranque, reciba peticiones HTTP reales y se detenga limpiamente."""
    server = OASTLocalServer(host="127.0.0.1", port=0)
    assigned_port = server.start()
    assert assigned_port > 0
    assert server.port == assigned_port

    token = "vuln-local-test-token-123"
    target_url = f"http://127.0.0.1:{assigned_port}/{token}/test.dtd"

    # Enviar una petición real al servidor de escucha local
    resp = requests.get(target_url, timeout=3)
    assert resp.status_code == 200
    assert resp.headers.get("X-OAST-Engine") == "OmniBreach-OAST"
    assert "<!-- OAST Correlated -->" in resp.text

    hits = server.get_interactions_for_token(token)
    assert len(hits) >= 1
    assert hits[0]["type"] == "HTTP"
    assert hits[0]["method"] == "GET"

    server.stop()
    assert server.httpd is None


def test_oast_client_with_local_server():
    """Verifica que OASTClient use automáticamente la URL del servidor local si está presente."""
    server = OASTLocalServer(host="127.0.0.1", port=0)
    server.start()

    client = OASTClient(local_server=server)
    token = client.generate_token(prefix="probe")
    cb_url = client.get_callback_url(token)

    assert f":{server.port}/{token}" in cb_url

    # Disparar callback
    requests.post(cb_url, data="oast payload callback", timeout=3)

    interactions = client.poll_interactions(token)
    assert len(interactions) >= 1
    assert interactions[0]["method"] == "POST"

    server.stop()


def test_blind_xxe_detected_via_oast():
    """Verifica que check_xxe identifique y confirme Blind XXE mediante correlación OAST."""
    client = OASTClient(mock_mode=True)

    class MockXXESession:
        def get(self, url: str, timeout: float = 5.0) -> requests.Response:
            resp = requests.Response()
            resp.status_code = 200
            resp._content = b"<html>Normal Page</html>"
            return resp

        def post(self, url: str, data: str = "", headers: dict[str, str] | None = None, timeout: float = 6.0) -> requests.Response:
            # Simular que el procesador XML del backend procesó la entidad externa asíncrona
            for token in list(client._registered_interactions.keys()):
                if token in data:
                    client.record_mock_interaction(token, interaction_type="HTTP", client_ip="192.168.1.100")
            resp = requests.Response()
            resp.status_code = 200
            # No refleja contenido alguno en el cuerpo (Blind)
            resp._content = b"<response><status>received</status></response>"
            return resp

    session = MockXXESession()
    findings = check_xxe(
        url="https://victim.test/api/xml",
        html_content="",
        session=session,
        oast_client=client,
    )

    blind_findings = [f for f in findings if "Blind XML External Entity" in f["vuln"]]
    assert len(blind_findings) == 1
    assert blind_findings[0]["risk"] == "Critico"
    assert blind_findings[0]["confidence"] == "confirmed"
