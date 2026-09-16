
from typing import Any

import requests

CSRF_COOKIE_PATTERNS = {"csrf", "xsrf", "_token", "authenticity_token", "middlewaretoken"}

SESSION_COOKIE_PATTERNS = {
    "session", "sess", "token", "auth", "jwt", "id", "sid",
    "connect.sid", "phpsessid", "jsessionid", "aspsessionid",
    "remember", "user", "login",
}

CLIENT_SIDE_COOKIES = {
    "_ga", "_gid", "_gat", "_gac", "_fbp", "_hj",
    "theme", "dark_mode", "mode", "lang", "locale", "i18n",
    "cookie_consent", "consent", "notice_dismissed", "cart_count",
    "timezone", "currency",
}


def check_cookies(response: requests.Response | Any) -> list[dict[str, str]]:
    results: list[dict[str, str]] = []

    for cookie in response.cookies:
        name_lower = cookie.name.lower()
        is_csrf = any(p in name_lower for p in CSRF_COOKIE_PATTERNS)
        is_session = any(p in name_lower for p in SESSION_COOKIE_PATTERNS)
        is_client_side = (
            name_lower in CLIENT_SIDE_COOKIES
            or any(c in name_lower for c in ["_ga", "consent", "theme", "lang"])
        )

        # 1. Flag Secure
        if not cookie.secure:
            risk = "Alto" if is_session else "Medio"
            results.append({
                "vuln": f"Cookie '{cookie.name}' sin flag Secure",
                "risk": risk,
                "detail": f"La cookie '{cookie.name}' puede transmitirse por HTTP en texto plano.",
                "confidence": "confirmed",
            })

        # Las cookies de CSRF suelen requerir lectura por JavaScript para enviarse en cabeceras AJAX
        if is_csrf:
            continue

        # 2. Flag HttpOnly
        # Cookies de analítica/interfaz del cliente están diseñadas para ser leídas por frontend
        if not cookie.has_nonstandard_attr("HttpOnly"):
            if is_session:
                results.append({
                    "vuln": f"Cookie '{cookie.name}' sin flag HttpOnly",
                    "risk": "Alto",
                    "detail": "Cookie de autenticación/sesión accesible desde JavaScript (riesgo de robo vía XSS).",
                    "confidence": "confirmed",
                })
            elif not is_client_side:
                results.append({
                    "vuln": f"Cookie '{cookie.name}' sin flag HttpOnly",
                    "risk": "Bajo",
                    "detail": "Cookie accesible desde JavaScript. Si maneja datos sensibles, evaluar habilitar HttpOnly.",
                    "confidence": "probable",
                })

        # 3. Atributo SameSite (para cookies de sesión reales)
        if is_session and hasattr(cookie, "_rest"):
            samesite = cookie.get_nonstandard_attr("SameSite") if hasattr(cookie, "get_nonstandard_attr") else None
            if not samesite:
                results.append({
                    "vuln": f"Cookie '{cookie.name}' sin atributo SameSite",
                    "risk": "Medio",
                    "detail": f"La cookie de sesión '{cookie.name}' no define 'SameSite=Lax' o 'SameSite=Strict'.",
                    "confidence": "confirmed",
                })
            elif str(samesite).lower() == "none" and not cookie.secure:
                results.append({
                    "vuln": f"Cookie '{cookie.name}' con SameSite=None Inseguro",
                    "risk": "Alto",
                    "detail": f"La cookie '{cookie.name}' especifica SameSite=None sin requerir flag Secure.",
                    "confidence": "confirmed",
                })

    return results
