"""
Módulo de Seguridad en APIs REST y Microservicios (OWASP API Security Top 10 2023).
Implementa análisis heurístico y comparativo para:
- API1:2023 - Broken Object Level Authorization (BOLA / IDOR)
- API3:2023 - Broken Object Property Level Authorization / Mass Assignment
- API4:2023 - Unrestricted Resource Consumption
- API5:2023 - Broken Function Level Authorization (BFLA)
"""
from __future__ import annotations

import json
import logging
import re
from typing import Any
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

import requests

from scanner.models import Evidence, Finding

logger = logging.getLogger("OmniBreach.APISecurity")

# Atributos sensibles y roles comúnmente abusados en Mass Assignment
PRIVILEGED_PROPERTIES: dict[str, Any] = {
    "role": "admin",
    "is_admin": True,
    "isAdmin": True,
    "is_superuser": True,
    "tier": "enterprise",
    "verified": True,
    "is_verified": True,
    "account_balance": 999999,
    "permissions": ["admin", "root"],
}

# Palabras clave asociadas a funciones administrativas o de alto privilegio
ADMIN_PATH_INDICATORS: tuple[str, ...] = (
    "/admin",
    "/manage",
    "/system",
    "/internal",
    "/export/all",
    "/metrics/raw",
    "/config/server",
)


def _safe_json_parse(text: str) -> Any | None:
    try:
        return json.loads(text)
    except (ValueError, TypeError):
        return None


def check_bola_idor(
    url: str,
    method: str = "GET",
    session_user_a: requests.Session | None = None,
    session_user_b: requests.Session | None = None,
    test_entity_ids: tuple[str, str] | None = None,
    unauth_check: bool = True,
    timeout: float = 6.0,
) -> Finding | None:
    """
    Verifica BOLA / IDOR (API1:2023).
    Comprueba si el Usuario A puede acceder a la entidad del Usuario B sustituyendo identificadores en URL o parámetros.
    """
    client_a = session_user_a or requests.Session()
    client_unauth = requests.Session()

    parsed = urlparse(url)
    target_path = parsed.path

    # 1. Identificar candidato de ID en la ruta (ej. /api/v1/users/1001 o /orders/1234)
    # Busca segmentos numéricos o UUIDs en el path
    id_match = re.search(r"/(?:users|accounts|orders|profiles|invoices|documents|items)/([0-9a-fA-F-]+|\d+)", target_path)

    entity_a: str | None = None
    entity_b: str | None = None

    if test_entity_ids:
        entity_a, entity_b = test_entity_ids
    elif id_match:
        entity_a = id_match.group(1)
        # Generar un ID B candidato si es numérico
        if entity_a.isdigit():
            val = int(entity_a)
            entity_b = str(val + 1 if val % 2 == 1 else val - 1)

    if not entity_a or not entity_b:
        return None

    # Construir URLs para Entidad A y Entidad B
    url_a = url.replace(f"/{entity_a}", f"/{entity_a}")
    url_b = url.replace(f"/{entity_a}", f"/{entity_b}")

    try:
        # A) Petición con Usuario A a su propio recurso A (debe responder 200 OK)
        resp_a = client_a.request(method, url_a, timeout=timeout)
        if resp_a.status_code != 200:
            return None

        # B) Comprobar control sin autenticación sobre recurso B (para descartar endpoints 100% públicos)
        if unauth_check:
            resp_unauth = client_unauth.request(method, url_b, timeout=timeout)
            # Si un visitante no autenticado puede verlo con 200, el endpoint es intencionalmente público
            if resp_unauth.status_code == 200 and len(resp_unauth.text) > 20:
                return None

        # C) Prueba Crítica: Usuario A solicita el recurso ajeno B
        resp_a_on_b = client_a.request(method, url_b, timeout=timeout)

        # Si responde 401 Unauthorized o 403 Forbidden o 404 Not Found legítimo, hay control de acceso
        if resp_a_on_b.status_code in (401, 403, 404):
            return None

        # Si responde 200 OK con contenido válido distinto al error
        if resp_a_on_b.status_code == 200 and len(resp_a_on_b.text) > 20:
            # Comprobar que no sea una página de error genérica devuelta con 200
            b_lower = resp_a_on_b.text.lower()
            if any(err in b_lower for err in ("not found", "no encontrado", "error", "unauthorized", "access denied")):
                return None

            return Finding(
                category="api_bola",
                title=f"BOLA / IDOR Confirmado en '{target_path}'",
                severity="high",
                confidence="confirmed",
                description=(
                    f"El endpoint '{target_path}' es vulnerable a Broken Object Level Authorization (API1:2023). "
                    f"La sesión autenticada del Usuario A pudo acceder con éxito (HTTP 200) al recurso del Usuario B "
                    f"sustituyendo el identificador '{entity_a}' por '{entity_b}'."
                ),
                affected_url=url_b,
                parameter=entity_a,
                evidence=Evidence(
                    request_method=method,
                    request_url=url_b,
                    payload=f"Target ID: {entity_b}",
                    response_status=resp_a_on_b.status_code,
                    response_fragment=resp_a_on_b.text[:300],
                ),
                remediation=(
                    "Implementar control de acceso a nivel de objeto basado en la identidad validada en el token "
                    "de sesión (ej. JWT 'sub') y verificar que el usuario autenticado sea el propietario del registro solicitado."
                ),
            )
    except Exception as exc:
        logger.debug("[BOLA] Error durante prueba IDOR en %s: %s", url, exc)

    return None


def check_mass_assignment(
    url: str,
    method: str = "POST",
    session: requests.Session | None = None,
    base_json: dict[str, Any] | None = None,
    timeout: float = 6.0,
) -> Finding | None:
    """
    Verifica Mass Assignment / Property Tampering (API3:2023).
    Intenta inyectar parámetros de control de acceso privilegiados en el cuerpo JSON de peticiones POST/PUT/PATCH.
    """
    if method.upper() not in ("POST", "PUT", "PATCH"):
        return None

    client = session or requests.Session()
    payload_base = dict(base_json) if base_json else {"name": "test_audit", "email": "audit@example.local"}

    # Payload con inyección de múltiples atributos de elevación de privilegios
    tampered_payload = dict(payload_base)
    tampered_payload.update(PRIVILEGED_PROPERTIES)

    try:
        headers = {"Content-Type": "application/json"}
        resp = client.request(method, url, json=tampered_payload, headers=headers, timeout=timeout)

        # Si el servidor responde 200 OK o 201 Created
        if resp.status_code in (200, 201):
            resp_data = _safe_json_parse(resp.text)
            if isinstance(resp_data, dict):
                # Verificar si alguno de los campos privilegiados inyectados fue aceptado y reflejado en el estado
                compromised_keys = [
                    k for k in PRIVILEGED_PROPERTIES
                    if k in resp_data and resp_data[k] == PRIVILEGED_PROPERTIES[k]
                ]

                if compromised_keys:
                    return Finding(
                        category="api_mass_assignment",
                        title=f"Mass Assignment / Mutación Privilegiada en '{urlparse(url).path}'",
                        severity="high",
                        confidence="confirmed",
                        description=(
                            f"La API acepta propiedades de objeto no autorizadas (API3:2023). "
                            f"Se inyectaron campos privilegiados que fueron procesados y persistidos o reflejados en la respuesta: "
                            f"{compromised_keys}."
                        ),
                        affected_url=url,
                        evidence=Evidence(
                            request_method=method,
                            request_url=url,
                            payload=json.dumps({k: PRIVILEGED_PROPERTIES[k] for k in compromised_keys}),
                            response_status=resp.status_code,
                            response_fragment=resp.text[:300],
                        ),
                        remediation=(
                            "Implementar esquemas estrictos de entrada (Data Transfer Objects / Pydantic / DTOs) con listas "
                            "blancas de propiedades permitidas ('whitelisting'). No enlazar directamente el cuerpo JSON de entrada "
                            "al modelo de base de datos o entidad interna."
                        ),
                    )
    except Exception as exc:
        logger.debug("[MassAssignment] Error durante prueba en %s: %s", url, exc)

    return None


def check_bfla(
    url: str,
    unprivileged_session: requests.Session | None = None,
    timeout: float = 6.0,
) -> Finding | None:
    """
    Verifica Broken Function Level Authorization (API5:2023).
    Evalúa si un endpoint con funciones administrativas responde satisfactoriamente a usuarios sin privilegios.
    """
    path_lower = urlparse(url).path.lower()
    if not any(indicator in path_lower for indicator in ADMIN_PATH_INDICATORS):
        return None

    client = unprivileged_session or requests.Session()

    try:
        # 1. Probar método GET estándar
        resp = client.get(url, timeout=timeout)

        # Si responde con 200 OK y entrega datos estructurados
        if resp.status_code == 200 and len(resp.text) > 30:
            resp_lower = resp.text.lower()
            # Descartar pantallas de login o accesos denegados disfrazados con 200
            if not any(w in resp_lower for w in ("iniciar sesión", "login", "unauthorized", "access denied", "forbidden")):
                return Finding(
                    category="api_bfla",
                    title=f"Broken Function Level Authorization (BFLA) en '{path_lower}'",
                    severity="critical" if "/admin" in path_lower else "high",
                    confidence="confirmed",
                    description=(
                        f"El endpoint de función administrativa '{path_lower}' es accesible "
                        f"sin la debida autorización de rol (API5:2023). La petición devolvió HTTP 200 con datos sensibles."
                    ),
                    affected_url=url,
                    evidence=Evidence(
                        request_method="GET",
                        request_url=url,
                        response_status=resp.status_code,
                        response_fragment=resp.text[:300],
                    ),
                    remediation=(
                        "Aplicar un mecanismo estricto de autorización basado en roles (RBAC) en el gateway o controlador "
                        "antes de procesar cualquier función administrativa."
                    ),
                )
    except Exception as exc:
        logger.debug("[BFLA] Error durante prueba en %s: %s", url, exc)

    return None


def check_resource_consumption(
    url: str,
    session: requests.Session | None = None,
    param_name: str = "limit",
    abusive_value: int = 1000000,
    timeout: float = 8.0,
) -> Finding | None:
    """
    Verifica Unrestricted Resource Consumption (API4:2023).
    Envía valores de paginación abusivos para comprobar si el servidor aplica límites máximos estrictos.
    """
    client = session or requests.Session()
    parsed = urlparse(url)
    qs = parse_qs(parsed.query)

    # Inyectar parámetro abusivo
    qs[param_name] = [str(abusive_value)]
    new_query = urlencode(qs, doseq=True)
    test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment))

    try:
        resp = client.get(test_url, timeout=timeout)

        # Si el servidor responde 200 y devuelve un payload masivo (> 1.5MB)
        content_length = len(resp.content)
        if resp.status_code == 200 and content_length > 1_500_000:
            return Finding(
                category="api_resource_consumption",
                title=f"Consumo de Recursos No Restringido en '{parsed.path}'",
                severity="medium",
                confidence="confirmed",
                description=(
                    f"El parámetro '{param_name}={abusive_value}' permitió solicitar un volumen excesivo de datos "
                    f"({content_length // 1024} KB) sin aplicar límites máximos de paginación (API4:2023)."
                ),
                affected_url=test_url,
                parameter=param_name,
                evidence=Evidence(
                    request_method="GET",
                    request_url=test_url,
                    payload=f"{param_name}={abusive_value}",
                    response_status=resp.status_code,
                    response_fragment=f"Tamaño devuelto: {content_length} bytes",
                ),
                remediation=(
                    "Imponer topes máximos estrictos en el tamaño de página (ej. 'max_limit = 100') "
                    "en todos los endpoints de listado y paginación."
                ),
            )
        # O si el servidor colapsa con error 500 / 504 ante la paginación masiva
        if resp.status_code in (500, 504):
            return Finding(
                category="api_resource_consumption",
                title=f"Degradación / Error 500 ante Paginación Abusiva en '{parsed.path}'",
                severity="medium",
                confidence="possible",
                description=(
                    f"La API respondió con error de servidor HTTP {resp.status_code} al solicitar '{param_name}={abusive_value}'. "
                    f"Indica falta de validación de límites numéricos y potencial agotamiento de memoria o DoS."
                ),
                affected_url=test_url,
                parameter=param_name,
                evidence=Evidence(
                    request_method="GET",
                    request_url=test_url,
                    payload=f"{param_name}={abusive_value}",
                    response_status=resp.status_code,
                    response_fragment=resp.text[:300],
                ),
                remediation="Validar rangos numéricos de entrada y retornar HTTP 400 Bad Request si el límite supera el máximo permitido.",
            )
    except requests.exceptions.Timeout:
        return Finding(
            category="api_resource_consumption",
            title=f"Tiempo de Espera Agotado (DoS) ante Paginación Abusiva en '{parsed.path}'",
            severity="medium",
            confidence="possible",
            description=(
                f"La API sufrió una caída por timeout (> {timeout}s) al procesar '{param_name}={abusive_value}'. "
                f"Indica consulta pesada no indexada o vulnerabilidad a agotamiento de recursos."
            ),
            affected_url=test_url,
            parameter=param_name,
            remediation="Implementar límites rígidos en las consultas y paginación a nivel de base de datos.",
        )
    except Exception as exc:
        logger.debug("[ResourceConsumption] Error en %s: %s", test_url, exc)

    return None


# Aliases para compatibilidad
test_bola_idor = check_bola_idor
test_mass_assignment = check_mass_assignment
test_bfla = check_bfla
test_resource_consumption = check_resource_consumption
