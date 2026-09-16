from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Optional
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


def _probe_endpoint(endpoint: str, client: Any) -> Optional[dict[str, str]]:
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


def _check_get(endpoint: str, client: Any) -> Optional[dict[str, str]]:
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


def check_graphql(url: str, session: Optional[requests.Session] = None) -> list[dict[str, str]]:
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

    return deduped_results

