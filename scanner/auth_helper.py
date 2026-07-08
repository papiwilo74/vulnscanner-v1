import requests
from urllib.parse import urljoin

def dynamic_login(login_url, credentials_str):
    """
    Realiza un inicio de sesión automático contra un endpoint web y retorna
    una sesión autenticada lista para usar en el escáner.
    
    Soporta:
    - Formularios HTML estándar (application/x-www-form-urlencoded)
    - APIs REST que responden con JSON y retornan un token (Bearer)
    
    Args:
        login_url: URL del endpoint de login (ej. https://ejemplo.com/api/auth/login).
        credentials_str: Cadena de credenciales en formato "campo=valor;campo2=valor2"
                         (ej. "username=admin;password=secreto123").
    
    Returns:
        requests.Session configurada y autenticada, o None si el login falla.
    """
    # Parsear las credenciales de la cadena al diccionario
    credentials = {}
    for pair in credentials_str.split(';'):
        pair = pair.strip()
        if '=' in pair:
            key, value = pair.split('=', 1)
            credentials[key.strip()] = value.strip()

    if not credentials:
        print("  ⚠️ No se pudieron parsear las credenciales de login.")
        return None

    session = requests.Session()
    session.headers.update({
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
    })

    print(f"  🔐 Intentando login automático en: {login_url}")
    print(f"  🔐 Campos de credenciales detectados: {list(credentials.keys())}")

    try:
        # Intento 1: Login como formulario estándar HTML (application/x-www-form-urlencoded)
        r = session.post(login_url, data=credentials, timeout=10, allow_redirects=True)

        # Verificar si hubo cookies de sesión en la respuesta (ej. session_id, PHPSESSID, etc.)
        if session.cookies:
            cookie_names = [c.name for c in session.cookies]
            print(f"  ✅ Login exitoso (formulario). Cookies obtenidas: {cookie_names}")
            return session

        # Intento 2: Verificar si la respuesta JSON contiene un token de acceso
        try:
            json_response = r.json()
            token = None

            # Buscar el token bajo claves comunes de APIs modernas
            for key in ['token', 'access_token', 'accessToken', 'jwt', 'id_token', 'authToken']:
                if key in json_response:
                    token = json_response[key]
                    break

            if token:
                session.headers.update({'Authorization': f'Bearer {token}'})
                print(f"  ✅ Login exitoso (API JSON). Token Bearer configurado.")
                return session
        except Exception:
            pass

        # Intento 3: Login como payload JSON (Content-Type: application/json)
        session2 = requests.Session()
        session2.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Content-Type': 'application/json'
        })
        import json
        r2 = session2.post(login_url, json=credentials, timeout=10, allow_redirects=True)

        if session2.cookies:
            cookie_names = [c.name for c in session2.cookies]
            print(f"  ✅ Login exitoso (JSON body). Cookies obtenidas: {cookie_names}")
            return session2

        try:
            json_response2 = r2.json()
            token = None
            for key in ['token', 'access_token', 'accessToken', 'jwt', 'id_token', 'authToken']:
                if key in json_response2:
                    token = json_response2[key]
                    break
            if token:
                session2.headers.update({'Authorization': f'Bearer {token}'})
                print(f"  ✅ Login exitoso (API JSON body). Token Bearer configurado.")
                return session2
        except Exception:
            pass

        print(f"  ⚠️ No se pudo detectar autenticación exitosa (Código: {r.status_code}). Continuando sin sesión autenticada.")
        return None

    except requests.exceptions.ConnectionError:
        print(f"  ❌ Error de conexión al intentar login en: {login_url}")
        return None
    except requests.exceptions.Timeout:
        print(f"  ❌ Tiempo de espera agotado al intentar login en: {login_url}")
        return None
    except Exception as e:
        print(f"  ❌ Error inesperado durante el login: {e}")
        return None
