import time
import random

# Lista de User-Agents de navegadores reales modernos para rotar
USER_AGENTS = [
    # Chrome Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    # Chrome Mac
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    # Firefox Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
    # Firefox Mac
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14.4; rv:125.0) Gecko/20100101 Firefox/125.0",
    # Edge Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0",
    # Safari Mac
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    # Chrome Android (móvil)
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36",
]

# Cabeceras HTTP adicionales que imitan un navegador real
BASE_HEADERS = {
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "Accept-Language": "es-CO,es;q=0.9,en-US;q=0.8,en;q=0.7",
    "Accept-Encoding": "gzip, deflate, br",
    "Connection": "keep-alive",
    "Upgrade-Insecure-Requests": "1",
    "Cache-Control": "no-cache",
    "DNT": "1",  # Do Not Track
}


def get_random_user_agent():
    """Retorna un User-Agent aleatorio de la lista."""
    return random.choice(USER_AGENTS)


def apply_stealth_headers(session):
    """
    Aplica cabeceras de navegador real y un User-Agent aleatorio a la sesión.
    Esto hace que el escáner parezca un navegador normal ante el servidor.
    
    Args:
        session: Instancia de requests.Session a configurar.
    """
    stealth_headers = dict(BASE_HEADERS)
    stealth_headers["User-Agent"] = get_random_user_agent()
    session.headers.update(stealth_headers)


def polite_delay(delay=0.0, stealth=False):
    """
    Aplica un retardo entre peticiones para evitar saturar el servidor
    y reducir la visibilidad del escáner como bot.
    
    Args:
        delay: Retardo fijo en segundos (0 = sin retardo).
        stealth: Si es True, aplica un retardo aleatorio entre 1.5 y 4.0 segundos
                 para imitar tiempos de navegación humana real.
    """
    if stealth:
        sleep_time = random.uniform(1.5, 4.0)
        time.sleep(sleep_time)
    elif delay > 0:
        time.sleep(delay)


def create_stealth_session():
    """
    Crea y retorna un requests.Session configurado con cabeceras de navegador
    real y un User-Agent aleatorio para escaneo pasivo/silencioso.
    
    Returns:
        requests.Session con perfil de navegador real.
    """
    import requests
    session = requests.Session()
    apply_stealth_headers(session)
    return session
