"""Cliente HTTP Adaptativo y Evasión Anti-WAF para OmniBreach v3.8.

Implementa control de flujo dinámico estilo AIMD (Additive Increase, Multiplicative Decrease),
manejo inteligente de cabeceras 'Retry-After', rotación de perfiles de navegador y
evasión activa frente a WAFs modernos (Cloudflare, AWS WAF, Akamai, Imperva).
"""
import logging
import random
import threading
import time
from typing import Any, Optional

import requests

from utils.stealth import BASE_HEADERS, USER_AGENTS

_logger = logging.getLogger("VulnScanner.AdaptiveClient")

WAF_SIGNATURE_HEADERS = [
    "cf-ray",
    "cf-cache-status",
    "x-amzn-errortype",
    "x-amz-cf-id",
    "x-akamai-transformed",
    "x-iinfo",
]


class AdaptiveRateLimiter:
    """Controlador de flujo y rate-limiting adaptativo (AIMD)."""

    def __init__(
        self,
        base_rps: float = 10.0,
        min_rps: float = 1.0,
        max_rps: float = 30.0,
        success_step: int = 5,
    ):
        self.min_rps = min_rps
        self.max_rps = max_rps
        self.current_rps = max(min_rps, min(base_rps, max_rps))
        self.success_step = success_step
        self.consecutive_successes = 0
        self.last_request_time: float = 0.0
        self._lock = threading.Lock()

    def acquire(self) -> None:
        """Pausa la ejecución para respetar el límite de peticiones por segundo actual."""
        with self._lock:
            now = time.time()
            interval = 1.0 / self.current_rps
            elapsed = now - self.last_request_time
            if elapsed < interval:
                time.sleep(interval - elapsed)
            self.last_request_time = time.time()

    def on_success(self) -> None:
        """Incremento aditivo: aumenta gradualmente la tasa tras respuestas exitosas consecutivas."""
        with self._lock:
            self.consecutive_successes += 1
            if self.consecutive_successes >= self.success_step:
                self.consecutive_successes = 0
                if self.current_rps < self.max_rps:
                    self.current_rps = min(self.max_rps, self.current_rps + 1.0)
                    _logger.debug("Tasa de peticiones aumentada adaptativamente a %.1f RPS", self.current_rps)

    def on_rate_limit(self, retry_after: Optional[float] = None) -> float:
        """Disminución multiplicativa: reduce la tasa a la mitad ante HTTP 429."""
        with self._lock:
            self.consecutive_successes = 0
            self.current_rps = max(self.min_rps, self.current_rps * 0.5)
            wait_time = retry_after if retry_after is not None and retry_after > 0 else (1.0 + random.uniform(0.5, 2.0))
            _logger.warning(
                "Límite de tasa detectado (429). Reduciendo tasa a %.1f RPS. Enfriando por %.2fs",
                self.current_rps, wait_time
            )
            return wait_time

    def on_waf_block(self) -> float:
        """Reacción ante bloqueo WAF (403/503): reduce al mínimo e inicia enfriamiento sigiloso."""
        with self._lock:
            self.consecutive_successes = 0
            self.current_rps = self.min_rps
            wait_time = 2.0 + random.uniform(1.0, 3.0)
            _logger.warning("Firma de bloqueo WAF detectada. Activando modo sigiloso mínimo (%.1f RPS)", self.current_rps)
            return wait_time


def generate_spoofed_ip() -> str:
    """Genera una dirección IP aleatoria creíble para rotación en cabeceras de proxy."""
    return f"{random.randint(11, 190)}.{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}"


class AdaptiveSession(requests.Session):
    """Sesión HTTP inteligente con control de flujo adaptativo y evasión anti-bloqueo."""

    def __init__(
        self,
        base_rps: float = 10.0,
        min_rps: float = 1.0,
        max_rps: float = 30.0,
        stealth: bool = True,
        max_retries: int = 3,
    ):
        super().__init__()
        self.rate_limiter = AdaptiveRateLimiter(base_rps=base_rps, min_rps=min_rps, max_rps=max_rps)
        self.stealth = stealth
        self.max_retries = max_retries

        # Configurar cabeceras base de navegador real
        base_h = dict(BASE_HEADERS)
        base_h["User-Agent"] = random.choice(USER_AGENTS)
        self.headers.update(base_h)

    def _apply_evasion_headers(self, request: requests.PreparedRequest) -> None:
        """Aplica rotación de IPs de cliente y User-Agents para eludir heurísticas simples de WAF."""
        spoofed_ip = generate_spoofed_ip()
        request.headers["X-Forwarded-For"] = spoofed_ip
        request.headers["X-Real-IP"] = spoofed_ip
        request.headers["X-Originating-IP"] = spoofed_ip

        if random.random() < 0.25:
            request.headers["User-Agent"] = random.choice(USER_AGENTS)

    def send(self, request: requests.PreparedRequest, **kwargs: Any) -> requests.Response:
        """Envía la petición regulando la cadencia y reaccionando adaptativamente a bloqueos."""
        attempts = 0
        while attempts <= self.max_retries:
            attempts += 1
            self.rate_limiter.acquire()

            if self.stealth:
                self._apply_evasion_headers(request)

            try:
                resp = super().send(request, **kwargs)
            except requests.RequestException:
                if attempts > self.max_retries:
                    raise
                time.sleep(1.0)
                continue

            # Caso 1: Rate-Limiting (HTTP 429)
            if resp.status_code == 429:
                retry_header = resp.headers.get("Retry-After")
                retry_seconds: Optional[float] = None
                if retry_header:
                    try:
                        retry_seconds = float(retry_header)
                    except ValueError:
                        retry_seconds = None

                wait_sec = self.rate_limiter.on_rate_limit(retry_seconds)
                if attempts <= self.max_retries:
                    time.sleep(wait_sec)
                    continue

            # Caso 2: Bloqueo sospechoso de WAF (HTTP 403 / 503 con cabeceras características)
            elif resp.status_code in (403, 503):
                has_waf_header = any(h in resp.headers for h in WAF_SIGNATURE_HEADERS)
                server_header = resp.headers.get("Server", "").lower()
                is_cloudflare = "cloudflare" in server_header or "cf-ray" in resp.headers

                if has_waf_header or is_cloudflare:
                    wait_sec = self.rate_limiter.on_waf_block()
                    if attempts <= self.max_retries:
                        time.sleep(wait_sec)
                        continue
                else:
                    self.rate_limiter.on_success()

            # Caso 3: Éxito (HTTP 200 - 399)
            else:
                self.rate_limiter.on_success()

            return resp

        # Fallback final si se superan los reintentos
        return resp


def create_adaptive_session(
    base_rps: float = 10.0,
    min_rps: float = 1.0,
    max_rps: float = 30.0,
    stealth: bool = True,
) -> AdaptiveSession:
    """Crea y retorna una instancia lista de AdaptiveSession."""
    return AdaptiveSession(
        base_rps=base_rps,
        min_rps=min_rps,
        max_rps=max_rps,
        stealth=stealth,
    )
