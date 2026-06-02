def check_cookies(response):
    results = []

    for cookie in response.cookies:
        if not cookie.secure:
            results.append({
                "vuln": f"Cookie '{cookie.name}' sin flag Secure",
                "risk": "Alto",
                "detail": "Puede transmitirse por HTTP"
            })
        if not cookie.has_nonstandard_attr("HttpOnly"):
            results.append({
                "vuln": f"Cookie '{cookie.name}' sin flag HttpOnly",
                "risk": "Alto",
                "detail": "Accesible desde JavaScript (riesgo XSS)"
            })

    return results