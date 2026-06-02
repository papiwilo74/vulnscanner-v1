SECURITY_HEADERS = {
    "X-Frame-Options":           ("Alto",  "Protege contra clickjacking"),
    "Content-Security-Policy":   ("Alto",  "Previene XSS y code injection"),
    "Strict-Transport-Security": ("Alto",  "Fuerza HTTPS (HSTS)"),
    "X-Content-Type-Options":    ("Medio", "Previene MIME sniffing"),
    "Referrer-Policy":           ("Bajo",  "Controla info en cabecera Referer"),
    "Permissions-Policy":        ("Bajo",  "Controla APIs del navegador"),
}

def check_headers(response):
    results = []

    for header, (risk, desc) in SECURITY_HEADERS.items():
        if header not in response.headers:
            results.append({
                "vuln": f"Header faltante: {header}",
                "risk": risk,
                "detail": desc
            })

    return results