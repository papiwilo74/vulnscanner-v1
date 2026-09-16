from typing import Optional
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

import requests

REDIRECT_PARAMS = [
    "redirect", "redirect_uri", "redirect_url", "url", "next", "goto",
    "return", "return_to", "return_url", "continue", "callback",
    "target", "rurl", "dest", "destination", "redir", "origin",
    "fallback", "back", "forward", "location", "link", "uri",
]

EVIL_URL = "https://evil-phishing-site.com"
CONTROL_URL = "https://control-verify-target.org"


def check_open_redirect(url: str, session: Optional[requests.Session] = None) -> list[dict[str, str]]:
    results: list[dict[str, str]] = []
    client = session if session is not None else requests

    parsed = urlparse(url)
    query_params = parse_qs(parsed.query)
    if not query_params:
        return results

    redirect_candidates = [p for p in query_params if p.lower() in REDIRECT_PARAMS]
    if not redirect_candidates:
        return results

    for param in redirect_candidates:
        # Sonda 1: Inyección del primer dominio externo
        modified = query_params.copy()
        modified[param] = [EVIL_URL]

        query_str = urlencode(modified, doseq=True)
        test_url = urlunparse((
            parsed.scheme, parsed.netloc, parsed.path,
            parsed.params, query_str, parsed.fragment,
        ))

        try:
            r = client.get(test_url, timeout=6, allow_redirects=False)
        except requests.RequestException:
            continue

        location = r.headers.get("Location", "")
        if location:
            loc_parsed = urlparse(location)
            evil_parsed = urlparse(EVIL_URL)

            is_external_evil = bool(
                (loc_parsed.netloc and loc_parsed.netloc.lower() == evil_parsed.netloc.lower())
                or location.startswith(f"//{evil_parsed.netloc}")
                or location.startswith(EVIL_URL)
            )

            if is_external_evil:
                # Sonda 2 (Control Diferencial): Verificar que acepte cualquier destino arbitrario
                modified_ctrl = query_params.copy()
                modified_ctrl[param] = [CONTROL_URL]
                ctrl_url = urlunparse((
                    parsed.scheme, parsed.netloc, parsed.path,
                    parsed.params, urlencode(modified_ctrl, doseq=True), parsed.fragment,
                ))
                try:
                    r_ctrl = client.get(ctrl_url, timeout=6, allow_redirects=False)
                    loc_ctrl = r_ctrl.headers.get("Location", "")
                    ctrl_parsed = urlparse(loc_ctrl)
                    is_ctrl_valid = bool(
                        (ctrl_parsed.netloc and ctrl_parsed.netloc.lower() == urlparse(CONTROL_URL).netloc.lower())
                        or loc_ctrl.startswith(CONTROL_URL)
                        or loc_ctrl.startswith(f"//{urlparse(CONTROL_URL).netloc}")
                    )
                except requests.RequestException:
                    is_ctrl_valid = False

                if is_ctrl_valid:
                    results.append({
                        "vuln": "Open Redirect",
                        "risk": "Medio",
                        "detail": f"El parámetro '{param}' redirige a una URL externa arbitraria: {location}",
                        "confidence": "confirmed",
                    })
                    continue

        body_lower = r.text.lower()
        evil_lower = EVIL_URL.lower()
        if (f"url={evil_lower}" in body_lower or f'window.location="{evil_lower}"' in body_lower or f"window.location='{evil_lower}'" in body_lower):
            results.append({
                "vuln": "Open Redirect (Meta Refresh / JS)",
                "risk": "Medio",
                "detail": f"El parámetro '{param}' genera una redirección a URL externa en el cuerpo de la respuesta (status {r.status_code}).",
                "confidence": "probable",
            })

    return results
