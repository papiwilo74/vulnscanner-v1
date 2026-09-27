"""
Módulo de Detección y Fuzzing Avanzado de APIs GraphQL.
Detecta endpoints expuestos, consolas interactivas (GraphiQL/Playground),
evalúa exposición de introspección de esquema, y ejecuta pruebas de seguridad avanzadas:
1. Abuso de Profundidad de Consulta / Complejidad Recursiva (Query Depth Limiting DoS).
2. Ataque de Batching / Amplificación de Peticiones (Rate Limit Bypass / Brute Force).
"""
from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any
from urllib.parse import urljoin, urlparse

import requests

GQL_ENDPOINTS = [
    "/graphql",
    "/gql",
    "/api/graphql",
    "/api/gql",
    "/v1/graphql",
    "/v2/graphql",
    "/graphql/api",
    "/query",
    "/graphiql",
    "/playground",
]

INTROSPECTION_QUERY = """
{
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types {
      name
      kind
      description
      fields {
        name
        type { name kind }
      }
    }
  }
}
"""

GQL_SCHEMA_KEYWORDS = [
    "__schema", "queryType", "mutationType", "subscriptionType",
    "GraphQL", "IntrospectionQuery", "__typename",
]

# Consulta anidada de profundidad 10+ para evaluar límite de profundidad (Query Depth Limit)
DEEP_QUERY_PROBE = """
query DepthLimitProbe {
  __schema {
    types {
      fields {
        type {
          ofType {
            ofType {
              ofType {
                ofType {
                  ofType {
                    name
                    kind
                  }
                }
              }
            }
          }
        }
      }
    }
  }
}
"""


def _check_query_depth_limit(endpoint: str, client: Any) -> dict[str, str] | None:
    """Evalúa si el endpoint restringe consultas GraphQL con anidamiento profundo (CWE-400)."""
    headers = {"Content-Type": "application/json"}
    try:
        r = client.post(endpoint, json={"query": DEEP_QUERY_PROBE}, headers=headers, timeout=5)
        if r.status_code == 200 and "application/json" in r.headers.get("Content-Type", ""):
            body = r.text
            # Si el servidor responde con datos y NO bloquea con error de max depth
            if '"data"' in body and not any(err in body.lower() for err in ["depth", "complexity", "too deep", "cost", "limit"]):
                return {
                    "vuln": "GraphQL — Sin Límite de Profundidad de Consulta (DoS / Resource Exhaustion)",
                    "risk": "Medio",
                    "detail": f"El endpoint GraphQL en '{endpoint}' resolvió una consulta con más de 8 niveles de anidamiento sin rechazarla por límite de profundidad (Depth Limit / Query Cost). Atacantes pueden forzar denegación de servicio por consumo de CPU y memoria.",
                    "confidence": "confirmed",
                    "_endpoint": endpoint,
                }
    except requests.RequestException:
        pass
    return None


def _check_batching_abuse(endpoint: str, client: Any) -> dict[str, str] | None:
    """Evalúa si el endpoint permite ejecución por lotes (Batching) en una sola petición HTTP (CWE-799)."""
    headers = {"Content-Type": "application/json"}
    batch_payload = [{"query": "{ __typename }"} for _ in range(10)]
    try:
        r = client.post(endpoint, json=batch_payload, headers=headers, timeout=5)
        if r.status_code == 200 and "application/json" in r.headers.get("Content-Type", ""):
            try:
                parsed = r.json()
                if isinstance(parsed, list) and len(parsed) >= 10:
                    return {
                        "vuln": "GraphQL — Ataque de Batching / Amplificación Habilitado",
                        "risk": "Medio",
                        "detail": f"El endpoint GraphQL en '{endpoint}' procesó exitosamente 10 consultas en lote dentro de una sola petición HTTP (Query Batching). Esto permite eludir rate-limiters de WAF y ejecutar ataques de fuerza bruta masivos.",
                        "confidence": "confirmed",
                        "_endpoint": endpoint,
                    }
            except json.JSONDecodeError:
                pass
    except requests.RequestException:
        pass
    return None


def _probe_endpoint(endpoint: str, client: Any) -> dict[str, str] | None:
    headers = {"Content-Type": "application/json"}
    try:
        r = client.post(endpoint, json={"query": INTROSPECTION_QUERY}, headers=headers, timeout=5)
        if r.status_code == 200:
            body = r.text
            match_count = sum(1 for kw in GQL_SCHEMA_KEYWORDS if kw in body)
            if match_count >= 3:
                data = r.json() if "application/json" in r.headers.get("Content-Type", "") else {}
                types_count = 0
                if data and "data" in data and "__schema" in data["data"]:
                    types_count = len(data["data"]["__schema"].get("types", []))
                return {
                    "vuln": "GraphQL — Introspeccion Habilitada",
                    "risk": "Medio",
                    "detail": f"La introspeccion GraphQL esta expuesta en '{endpoint}'. Se filtraron {types_count} tipos del esquema. Deshabilitar introspeccion en produccion.",
                    "confidence": "confirmed",
                    "_endpoint": endpoint,
                }
            elif match_count >= 2 and "application/json" in r.headers.get("Content-Type", ""):
                return {
                    "vuln": "GraphQL Endpoint Detectado",
                    "risk": "Bajo",
                    "detail": f"Se detecto un endpoint GraphQL en '{endpoint}'. Verificar que la introspeccion y el playground esten deshabilitados en produccion.",
                    "confidence": "probable",
                    "_endpoint": endpoint,
                }
    except requests.RequestException:
        pass
    return None


def _check_get(endpoint: str, client: Any) -> dict[str, str] | None:
    try:
        r = client.get(endpoint, timeout=4)
        if r.status_code == 200:
            content_type = r.headers.get("Content-Type", "").lower()
            text_lower = r.text.lower()

            # Caso 1: Consola interactiva para desarrolladores (GraphiQL o GraphQL Playground)
            if any(m in text_lower for m in ["<title>graphiql", "graphql playground", "window.__env__", "graphiql.min.js"]):
                return {
                    "vuln": "Consola GraphQL Interactiva Expuesta",
                    "risk": "Medio",
                    "detail": f"Consola interactiva GraphQL (Playground/GraphiQL) expuesta en '{endpoint}'. Permite consultar y mutar datos sin restricciones.",
                    "confidence": "confirmed",
                    "_endpoint": endpoint,
                }

            # Caso 2: API GraphQL que responde a consultas JSON vía GET
            if "application/json" in content_type and any(k in r.text for k in ['"data"', '"errors"', '"locations"']):
                return {
                    "vuln": "GraphQL Endpoint Detectado (GET)",
                    "risk": "Bajo",
                    "detail": f"Respuesta GraphQL en '{endpoint}'. Verificar configuracion de seguridad.",
                    "confidence": "confirmed",
                    "_endpoint": endpoint,
                }
    except requests.RequestException:
        pass
    return None


def fuzz_graphql(url: str, session: requests.Session | None = None) -> list[dict[str, str]]:
    """
    Ejecuta auditoría activa y fuzzing de seguridad avanzado en endpoints GraphQL:
    1. Abuso de límite de profundidad (Depth Limit DoS / Query Complexity).
    2. Abuso de Batching / Amplificación de consultas (Rate Limit Bypass).
    """
    results: list[dict[str, str]] = []
    client = session if session is not None else requests

    base = urlparse(url)
    base_url = f"{base.scheme}://{base.netloc}"
    targets = [urljoin(base_url, ep) for ep in GQL_ENDPOINTS]

    with ThreadPoolExecutor(max_workers=6) as executor:
        futures = []
        for ep in targets:
            futures.append(executor.submit(_check_query_depth_limit, ep, client))
            futures.append(executor.submit(_check_batching_abuse, ep, client))

        for future in as_completed(futures):
            res = future.result()
            if res:
                res.pop("_endpoint", None)
                results.append(res)

    return results


def check_graphql(
    url: str,
    session: requests.Session | None = None,
    enable_fuzzing: bool = False,
) -> list[dict[str, str]]:
    results: list[dict[str, str]] = []
    client = session if session is not None else requests

    base = urlparse(url)
    base_url = f"{base.scheme}://{base.netloc}"

    targets = [urljoin(base_url, ep) for ep in GQL_ENDPOINTS]

    with ThreadPoolExecutor(max_workers=6) as executor:
        futures = []
        for ep in targets:
            futures.append(executor.submit(_probe_endpoint, ep, client))
            futures.append(executor.submit(_check_get, ep, client))

        for future in as_completed(futures):
            res = future.result()
            if res:
                results.append(res)

    # Deduplicar y priorizar el hallazgo más crítico por endpoint
    endpoint_findings: dict[str, list[dict[str, str]]] = {}
    for r in results:
        ep = r.pop("_endpoint", r.get("detail", ""))
        endpoint_findings.setdefault(ep, []).append(r)

    deduped_results: list[dict[str, str]] = []
    for f_list in endpoint_findings.values():
        has_intro = any("Introspeccion" in f["vuln"] for f in f_list)
        if has_intro:
            for f in f_list:
                if "Introspeccion" in f["vuln"] and f not in deduped_results:
                    deduped_results.append(f)
        else:
            for f in f_list:
                if f not in deduped_results:
                    deduped_results.append(f)

    if enable_fuzzing:
        fuzz_findings = fuzz_graphql(url, session=session)
        deduped_results.extend(fuzz_findings)

    return deduped_results
