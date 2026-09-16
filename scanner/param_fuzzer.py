"""
Motor de Fuzzing Dinámico y Descubrimiento de Parámetros Ocultos.
Identifica parámetros de consulta no enlazados (?id=, ?redirect=, ?file=, ?debug=)
utilizando análisis diferencial de respuestas HTTP (código de estado, longitud,
reflexión de payloads canarios y cabeceras).
"""
import logging
import random
import string
from typing import Any, Optional
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

import requests

logger = logging.getLogger("OmniBreach.ParamFuzzer")

# Parámetros de consulta de alto impacto priorizados por criticidad de seguridad
COMMON_QUERY_PARAMS: list[str] = [
    # Lógica de depuración / Administración / Bypasses (prioridad crítica)
    "debug", "test", "admin", "source", "show", "preview", "mode", "auth", "token", "key",
    # Redirección abierta / SSRF / Navegación
    "redirect", "url", "redirect_url", "redirect_uri", "next", "to", "dest",
    "destination", "return", "return_to", "r", "goto", "link", "target", "out",
    # SQLi / IDOR / Identificadores de recursos
    "id", "user_id", "uid", "account", "item", "cat", "category", "order",
    "sort", "limit", "offset", "role", "group", "type",
    # Path Traversal / Inclusión de Archivos (LFI/RFI)
    "file", "path", "page", "doc", "document", "template", "view", "include", "dir",
    # XSS / Entrada reflejada / Búsqueda
    "q", "query", "search", "keyword", "filter", "text", "callback", "jsonp", "msg",
]


def generate_canary(length: int = 8) -> str:
    """Genera un token canario pseudoaleatorio para rastreo de reflexión."""
    token = "".join(random.choices(string.ascii_lowercase + string.digits, k=length))
    return f"ob_{token}"


class ParameterFuzzer:
    """
    Descubridor diferencial de parámetros HTTP GET.
    Realiza sondeos comparando la respuesta base vs respuestas con parámetros inyectados.
    """

    def __init__(self, session: Optional[requests.Session] = None, timeout: int = 5):
        self.session = session if session is not None else requests.Session()
        self.timeout = timeout

    def probe_url(
        self,
        url: str,
        candidate_params: Optional[list[str]] = None,
        max_params: int = 50
    ) -> tuple[list[str], list[dict[str, Any]]]:
        """
        Descubre parámetros ocultos en la URL especificada.

        Returns:
            tuple: (lista_de_urls_con_parametros_descubiertos, lista_de_hallazgos)
        """
        discovered_urls: list[str] = []
        findings: list[dict[str, Any]] = []

        params_to_test = (candidate_params or COMMON_QUERY_PARAMS)[:max_params]

        parsed = urlparse(url)
        existing_query = parse_qs(parsed.query)

        # Filtrar candidatos que ya estén presentes en la URL
        filtered_candidates = [p for p in params_to_test if p not in existing_query]
        if not filtered_candidates:
            return discovered_urls, findings

        # Petición base de referencia
        try:
            base_res = self.session.get(url, timeout=self.timeout, allow_redirects=False)
            base_status = base_res.status_code
            base_len = len(base_res.text)
            base_has_location = "Location" in base_res.headers
        except requests.RequestException:
            return discovered_urls, findings

        for param in filtered_candidates:
            canary = generate_canary()
            test_query = dict(existing_query)
            test_query[param] = [canary]

            encoded_query = urlencode(test_query, doseq=True)
            probe_url = urlunparse((
                parsed.scheme, parsed.netloc, parsed.path,
                parsed.params, encoded_query, parsed.fragment
            ))

            try:
                probe_res = self.session.get(probe_url, timeout=self.timeout, allow_redirects=False)
            except requests.RequestException:
                continue

            # Heurística 1: Reflexión del token canario en la respuesta
            is_reflected = canary in probe_res.text

            # Heurística 2: Cambio significativo en el código de estado HTTP
            status_changed = (
                probe_res.status_code != base_status
                and probe_res.status_code not in (429, 502, 503, 504)
            )

            # Heurística 3: Nueva cabecera Location (redirección activada por parámetro)
            location_triggered = (
                "Location" in probe_res.headers
                and not base_has_location
            )

            # Heurística 4: Variación sustancial en el tamaño del cuerpo (más allá del canario inyectado)
            len_diff = abs(len(probe_res.text) - base_len)
            length_diverged = len_diff > (len(param) + len(canary) + 15) or (len_diff >= 30 and not is_reflected)

            if is_reflected or status_changed or location_triggered or length_diverged:
                logger.info(
                    "  [PARAM-DISCOVERY] Parámetro oculto descubierto: '%s' en %s "
                    "(reflejado=%s, status=%d->%d, len_diff=%d)",
                    param, url, is_reflected, base_status, probe_res.status_code, len_diff
                )
                # Formatear URL lista para pruebas de vulnerabilidad
                # Usar valor típico según la naturaleza del parámetro
                test_val = "1" if param in ("id", "user_id", "uid", "cat", "item") else "test"
                rec_query = dict(existing_query)
                rec_query[param] = [test_val]
                discovered_urls.append(urlunparse((
                    parsed.scheme, parsed.netloc, parsed.path,
                    parsed.params, urlencode(rec_query, doseq=True), parsed.fragment
                )))

                # Generar hallazgo si es un parámetro sensible de depuración o reflejado
                if param in ("debug", "admin", "test", "source", "dev") and (status_changed or length_diverged):
                    findings.append({
                        "vuln": f"Parámetro de Depuración/Admin Activo ('{param}')",
                        "risk": "Medio",
                        "detail": (
                            f"El endpoint responde y altera su comportamiento ante el parámetro oculto '{param}'. "
                            f"(Estado: {base_status} -> {probe_res.status_code}, Variación: {len_diff} bytes). "
                            "Puede exponer lógica interna o eludir controles de acceso."
                        ),
                        "confidence": "confirmed",
                        "cwe": "CWE-489",
                        "cvss": 5.3,
                        "url": probe_url,
                    })
                elif is_reflected:
                    findings.append({
                        "vuln": f"Parámetro Oculto Aceptado y Reflejado ('{param}')",
                        "risk": "Bajo",
                        "detail": (
                            f"El backend procesa y refleja directamente el parámetro de consulta no documentado '{param}'. "
                            "Superficie candidata para pruebas de XSS, Inyección o Manipulación de Estado."
                        ),
                        "confidence": "confirmed",
                        "cwe": "CWE-20",
                        "cvss": 3.7,
                        "url": probe_url,
                    })


        return discovered_urls, findings


def discover_parameters(
    url: str,
    session: Optional[requests.Session] = None,
    candidate_params: Optional[list[str]] = None,
    max_params: int = 30
) -> list[str]:
    """
    Descubre parámetros ocultos en una URL y devuelve la lista de URLs enriquecidas con dichos parámetros.
    """
    fuzzer = ParameterFuzzer(session=session)
    discovered_urls, _ = fuzzer.probe_url(url, candidate_params=candidate_params, max_params=max_params)
    return discovered_urls


def check_param_fuzzer(
    url: str,
    session: Optional[requests.Session] = None
) -> list[dict[str, Any]]:
    """
    Función de compatibilidad con el motor de auditoría para reportar parámetros ocultos/sensibles descubiertos.
    """
    fuzzer = ParameterFuzzer(session=session)
    _, findings = fuzzer.probe_url(url)
    return findings
