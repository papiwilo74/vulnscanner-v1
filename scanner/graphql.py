from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional
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


def _probe_endpoint(endpoint: str, client) -> Optional[dict[str, str]]:
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
                    "detail": f"La introspeccion GraphQL esta expuesta en '{endpoint}'. Se filtraron {types_count} tipos del esquema. Deshabilitar introspeccion en produccion."
                }
            elif match_count >= 1:
                return {
                    "vuln": "GraphQL Endpoint Detectado",
                    "risk": "Bajo",
                    "detail": f"Se detecto un endpoint GraphQL en '{endpoint}'. Verificar que la introspeccion y el playground esten deshabilitados en produccion."
                }
    except requests.RequestException:
        pass
    return None


def _check_get(endpoint: str, client) -> Optional[dict[str, str]]:
    try:
        r = client.get(endpoint, timeout=4)
        if r.status_code == 200 and any(
            kw in r.text for kw in ["GraphQL", "graphql", "query", "__schema"]
        ):
            return {
                "vuln": "GraphQL Endpoint Detectado (GET)",
                "risk": "Bajo",
                "detail": f"Respuesta GraphQL en '{endpoint}'. Verificar configuracion de seguridad."
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

    deduped = {}
    for r in results:
        key = r["detail"]
        if key not in deduped:
            deduped[key] = r
    return list(deduped.values())
