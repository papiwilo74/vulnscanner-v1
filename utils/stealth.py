import random
import time
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import requests

# Lista de User-Agents de navegadores reales modernos para rotar
USER_AGENTS: list[str] = [
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
BASE_HEADERS: dict[str, str] = {
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "Accept-Language": "es-CO,es;q=0.9,en-US;q=0.8,en;q=0.7",
    "Accept-Encoding": "gzip, deflate, br",
    "Connection": "keep-alive",
    "Upgrade-Insecure-Requests": "1",
    "Cache-Control": "no-cache",
    "DNT": "1",
    "Sec-Fetch-Dest": "document",
    "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-Site": "none",
    "Sec-Fetch-User": "?1",
}


def get_random_user_agent() -> str:
    """Retorna un User-Agent aleatorio de la lista."""
    return random.choice(USER_AGENTS)


def apply_stealth_headers(session: "requests.Session") -> None:
    """
    Configura la sesion con un User-Agent de navegador real y cabeceras HTTP estandar,
    reduciendo la carga en el servidor destino durante escaneos autorizados.

    Args:
        session: Instancia de requests.Session a configurar.
    """
    stealth_headers = dict(BASE_HEADERS)
    stealth_headers["User-Agent"] = get_random_user_agent()
    session.headers.update(stealth_headers)


def polite_delay(delay: float = 0.0, stealth: bool = False) -> None:
    """
    Aplica un retardo entre peticiones como buena practica de rate-limiting,
    evitando saturar el servidor durante pruebas de seguridad autorizadas.
    El modo sigiloso anade variabilidad aleatoria para distribuir la carga.

    Args:
        delay: Retardo fijo en segundos (0 = sin retardo).
        stealth: Si es True, aplica un delay aleatorio adicional entre 1.5 y 4 segundos.
    """
    if stealth:
        sleep_time = random.uniform(1.5, 4.0)
        time.sleep(sleep_time)
    elif delay > 0:
        time.sleep(delay)


def stealth_check_delay(stealth: bool = False) -> None:
    """
    Micro-delays entre checks individuales en modo sigilo, simulando
    que cada verificacion es una accion distinta del usuario.

    Args:
        stealth: Si es True, aplica un micro-delay aleatorio entre 0.3 y 1.5 segundos.
    """
    if stealth:
        time.sleep(random.uniform(0.3, 1.5))


def create_stealth_session() -> "requests.Session":
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
