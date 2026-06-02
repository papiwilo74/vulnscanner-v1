import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from concurrent.futures import ThreadPoolExecutor, as_completed

XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    '"><img src=x onerror=alert(1)>',
    "javascript:alert(1)",
]

def test_xss_payload(parsed, params, param, payload):
    test_params = params.copy()
    test_params[param] = [payload]
    new_query = urlencode(test_params, doseq=True)
    test_url = urlunparse(parsed._replace(query=new_query))
    try:
        r = requests.get(test_url, timeout=5)
        if payload in r.text:
            return {
                "vuln": f"XSS reflejado en parámetro '{param}'",
                "risk": "Alto",
                "detail": f"Payload reflejado: {payload}"
            }
    except:
        pass
    return None

def check_xss(url):
    results = []
    parsed = urlparse(url)
    params = parse_qs(parsed.query)

    if not params:
        return results

    tasks = []
    for param in params:
        for payload in XSS_PAYLOADS:
            tasks.append((param, payload))

    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = {executor.submit(test_xss_payload, parsed, params, t[0], t[1]): t for t in tasks}
        flagged_params = set()
        for future in as_completed(futures):
            param, payload = futures[future]
            if param in flagged_params:
                continue
            res = future.result()
            if res:
                results.append(res)
                flagged_params.add(param)

    return results