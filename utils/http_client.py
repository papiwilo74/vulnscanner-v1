import requests

def get(url, timeout=10):
    try:
        response = requests.get(url, timeout=timeout)
        return response
    except requests.exceptions.ConnectionError:
        print(f" No se pudo conectar a {url}")
        return None
    except requests.exceptions.Timeout:
        print(f"⏱ Timeout — {url} tardó demasiado")
        return None
    except Exception as e:
        print(f" Error inesperado: {e}")
        return None