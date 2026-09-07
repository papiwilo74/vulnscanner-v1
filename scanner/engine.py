"""Motor de escaneo con perfiles, rate limiting, deduplicacion y cancelacion."""
import ipaddress
import logging
import socket
import threading
import time
from dataclasses import dataclass
from enum import Enum
from typing import Optional
from urllib.parse import urlparse

log = logging.getLogger("VulnScanner.Engine")


class ScanProfile(str, Enum):
    PASSIVE = "passive"
    NORMAL = "normal"
    AGGRESSIVE = "aggressive"


PROFILE_CONFIG: dict[ScanProfile, dict] = {
    ScanProfile.PASSIVE: {
        "max_rps": 2,
        "max_total_requests": 200,
        "timeout": 15,
        "active_payloads": False,
        "max_crawl_depth": 1,
        "max_crawl_pages": 3,
        "max_workers": 3,
        "delay": 1.0,
    },
    ScanProfile.NORMAL: {
        "max_rps": 10,
        "max_total_requests": 1000,
        "timeout": 10,
        "active_payloads": True,
        "max_crawl_depth": 3,
        "max_crawl_pages": 20,
        "max_workers": 8,
        "delay": 0.2,
    },
    ScanProfile.AGGRESSIVE: {
        "max_rps": 50,
        "max_total_requests": 5000,
        "timeout": 8,
        "active_payloads": True,
        "max_crawl_depth": 5,
        "max_crawl_pages": 100,
        "max_workers": 20,
        "delay": 0.05,
    },
}

PRIVATE_RANGES = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
]


@dataclass
class ScanConfig:
    profile: ScanProfile = ScanProfile.NORMAL
    max_rps: int = 10
    max_total_requests: int = 1000
    timeout: int = 10
    active_payloads: bool = True
    max_crawl_depth: int = 3
    max_crawl_pages: int = 20
    max_workers: int = 8
    delay: float = 0.2

    target: str = ""
    cookie: Optional[str] = None
    auth_header: Optional[str] = None
    stealth: bool = False
    login_url: Optional[str] = None
    login_creds: Optional[str] = None

    allow_private: bool = False

    @classmethod
    def from_profile(cls, profile: ScanProfile, target: str = "", **overrides) -> "ScanConfig":
        defaults = PROFILE_CONFIG[profile].copy()
        defaults["profile"] = profile
        defaults["target"] = target
        defaults.update(overrides)
        return cls(**defaults)


class ScanEngine:
    """Controla la ejecucion de escaneos con limites y seguridad operacional."""

    def __init__(self, config: ScanConfig):
        self.config = config
        self._request_count: int = 0
        self._lock = threading.Lock()
        self._cancelled = threading.Event()
        self._start_time: float = 0.0
        self._seen_urls: set[str] = set()
        self._request_log: list[dict] = []
        self._ratelimit_window_start: float = time.monotonic()
        self._ratelimit_count: int = 0

    @property
    def request_count(self) -> int:
        return self._request_count

    @property
    def is_cancelled(self) -> bool:
        return self._cancelled.is_set()

    @property
    def elapsed(self) -> float:
        return time.time() - self._start_time if self._start_time > 0 else 0.0

    def cancel(self) -> None:
        log.warning("Escaneo cancelado por el usuario tras %d requests", self._request_count)
        self._cancelled.set()

    def start(self) -> None:
        self._cancelled.clear()
        self._request_count = 0
        self._start_time = time.time()
        self._seen_urls.clear()
        self._request_log.clear()
        self._validate_target()

    def _validate_target(self) -> None:
        target = self.config.target
        if not target:
            return
        parsed = urlparse(target)
        hostname = parsed.hostname or target
        try:
            ip = ipaddress.ip_address(hostname)
        except ValueError:
            try:
                ip = ipaddress.ip_address(socket.gethostbyname(hostname))
            except (socket.gaierror, TypeError):
                return
        if not self.config.allow_private:
            for net in PRIVATE_RANGES:
                if ip in net:
                    raise ValueError(
                        f"Target {hostname} ({ip}) es una IP privada. "
                        f"Usa --allow-private para escanear redes locales."
                    )

    def check_limits(self) -> bool:
        """Retorna True si el escaneo puede continuar."""
        if self._cancelled.is_set():
            return False
        with self._lock:
            if self._request_count >= self.config.max_total_requests:
                log.warning("Limite global de %d requests alcanzado", self.config.max_total_requests)
                return False
        return True

    def record_request(self, url: str, method: str = "GET", status: Optional[int] = None) -> None:
        with self._lock:
            self._request_count += 1
            self._request_log.append({
                "url": url, "method": method, "status": status,
                "timestamp": time.time(),
            })

    def ratelimit(self) -> None:
        if self.config.max_rps <= 0:
            return
        now = time.monotonic()
        with self._lock:
            elapsed = now - self._ratelimit_window_start
            if elapsed >= 1.0:
                self._ratelimit_window_start = now
                self._ratelimit_count = 0
            self._ratelimit_count += 1
            if self._ratelimit_count > self.config.max_rps:
                sleep_time = 1.0 - elapsed + 0.05
                if sleep_time > 0:
                    time.sleep(sleep_time)
                    self._ratelimit_window_start = time.monotonic()
                    self._ratelimit_count = 1

    def normalize_url(self, url: str) -> str:
        """Normaliza una URL para comparacion de equivalencia."""
        parsed = urlparse(url)
        return f"{parsed.scheme}://{parsed.netloc}{parsed.path.rstrip('/') or '/'}"

    def is_duplicate(self, url: str) -> bool:
        norm = self.normalize_url(url)
        with self._lock:
            if norm in self._seen_urls:
                return True
            self._seen_urls.add(norm)
            return False

    def get_summary(self) -> dict:
        return {
            "profile": self.config.profile.value,
            "total_requests": self._request_count,
            "duration_seconds": round(self.elapsed, 2),
            "max_rps": self.config.max_rps,
            "cancelled": self._cancelled.is_set(),
        }


def generate_request_id(url: str, payload: str = "") -> str:
    import hashlib
    raw = f"{url}|{payload}"
    return hashlib.sha256(raw.encode()).hexdigest()[:12]
