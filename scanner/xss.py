import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    '"><img src=x onerror=alert(1)>',
    "javascript:alert(1)",
]

def check_xss(url):
    results = []
    parsed = urlparse(url)
    params = parse_qs(parsed.query)

    if not params:
        return results

    for param in params:
        for payload in XSS_PAYLOADS:
            test_params = params.copy()
            test_params[param] = [payload]
            new_query = urlencode(test_params, doseq=True)
            test_url = urlunparse(parsed._replace(query=new_query))
            try:
                r = requests.get(test_url, timeout=5)
                if payload in r.text:
                    results.append({
                        "vuln": f"XSS reflejado en parámetro '{param}'",
                        "risk": "Alto",
                        "detail": f"Payload reflejado: {payload}"
                    })
                    break
            except:
                pass

    return results