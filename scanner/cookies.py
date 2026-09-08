
from typing import Any

import requests

CSRF_COOKIE_PATTERNS = {"csrf", "xsrf", "_token", "authenticity_token", "middlewaretoken"}


def check_cookies(response: requests.Response | Any) -> list[dict[str, str]]:
    results: list[dict[str, str]] = []

    for cookie in response.cookies:
        name_lower = cookie.name.lower()
        is_csrf = any(p in name_lower for p in CSRF_COOKIE_PATTERNS)

        if not cookie.secure:
            results.append({
                "vuln": f"Cookie '{cookie.name}' sin flag Secure",
                "risk": "Alto",
                "detail": "Puede transmitirse por HTTP"
            })

        if is_csrf:
            continue

        if not cookie.has_nonstandard_attr("HttpOnly"):
            results.append({
                "vuln": f"Cookie '{cookie.name}' sin flag HttpOnly",
                "risk": "Alto",
                "detail": "Accesible desde JavaScript (riesgo XSS)"
            })

    return results
