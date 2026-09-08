"""Motor de escaneo con perfiles, rate limiting, deduplicacion y cancelacion."""
import ipaddress
import logging
import socket
import threading
import time
from dataclasses import dataclass
from enum import Enum
from typing import Any, Optional
from urllib.parse import urlparse

import requests

from scanner.attack_graph import AttackGraph
from scanner.models import Finding

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
    iast_url: Optional[str] = None
    enable_attack_chain: bool = True

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
        self.adaptive_rate_limiting: bool = True
        self.waf_detected: bool = False
        self._current_rps: float = float(self.config.max_rps)
        self._circuit_state: str = "CLOSED"  # "CLOSED", "OPEN", "HALF-OPEN"
        self._consecutive_throttles: int = 0
        self._circuit_open_until: float = 0.0

    @property
    def current_rps(self) -> float:
        return self._current_rps

    @property
    def circuit_state(self) -> str:
        return self._circuit_state

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

    def handle_response(self, status: Optional[int], headers: Optional[dict] = None) -> None:
        """Adapta el ritmo de peticiones segun codigos de estado del servidor o WAF."""
        if not self.adaptive_rate_limiting or status is None:
            return

        now = time.monotonic()
        with self._lock:
            if status in (429, 503):
                self._consecutive_throttles += 1
                backoff = min(10.0, 1.5 * (2 ** (self._consecutive_throttles - 1)))
                self._circuit_state = "OPEN"
                self._circuit_open_until = now + backoff
                self._current_rps = max(1.0, self._current_rps * 0.5)
                log.warning(
                    "[CircuitBreaker] Servidor devolvio HTTP %d. Circuito ABIERTO por %.1fs. RPS reducido a %.1f",
                    status, backoff, self._current_rps
                )
            elif 200 <= status < 400:
                if self._circuit_state == "OPEN" and now >= self._circuit_open_until:
                    self._circuit_state = "HALF-OPEN"
                elif self._circuit_state == "HALF-OPEN":
                    self._circuit_state = "CLOSED"
                    self._consecutive_throttles = 0
                    self._current_rps = min(float(self.config.max_rps), self._current_rps + 1.0)

    def record_request(self, url: str, method: str = "GET", status: Optional[int] = None) -> None:
        with self._lock:
            self._request_count += 1
            self._request_log.append({
                "url": url, "method": method, "status": status,
                "timestamp": time.time(),
            })
        if status is not None:
            self.handle_response(status)

    def ratelimit(self) -> None:
        target_rps = self._current_rps if self.adaptive_rate_limiting else float(self.config.max_rps)
        if target_rps <= 0:
            return

        now = time.monotonic()
        with self._lock:
            # Si el circuito esta abierto debido a throttling reciente, esperar el enfriamiento
            if self._circuit_state == "OPEN":
                if now < self._circuit_open_until:
                    wait_time = self._circuit_open_until - now
                    time.sleep(wait_time)
                    now = time.monotonic()
                self._circuit_state = "HALF-OPEN"

            elapsed = now - self._ratelimit_window_start
            if elapsed >= 1.0:
                self._ratelimit_window_start = now
                self._ratelimit_count = 0
            self._ratelimit_count += 1
            if self._ratelimit_count > target_rps:
                sleep_time = (1.0 / target_rps) if target_rps > 0 else 0.1
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
            "current_rps": round(self._current_rps, 1),
            "circuit_state": self._circuit_state,
            "waf_detected": self.waf_detected,
            "cancelled": self._cancelled.is_set(),
        }

    def correlate_iast(self, findings: list[Finding], session: Optional[requests.Session] = None) -> int:
        """Consulta telemetría en tiempo de ejecución del agente IAST y correlaciona con hallazgos DAST.

        Retorna el número de hallazgos enriquecidos con archivo fuente, línea y traza de ejecución.
        """
        if not self.config.iast_url:
            return 0

        target_endpoint = f"{self.config.iast_url.rstrip('/')}/__vulnscanner_iast__"
        sess = session or requests.Session()
        try:
            resp = sess.get(target_endpoint, timeout=5)
            if resp.status_code != 200:
                return 0
            data = resp.json()
            telemetry_list: list[dict[str, Any]] = data.get("telemetry", [])
            if not telemetry_list:
                return 0

            enriched_count = 0
            # Mapear eventos de telemetría por tipo de sink
            sink_map: dict[str, list[dict[str, Any]]] = {}
            for t in telemetry_list:
                st = t.get("sink_type", "")
                sink_map.setdefault(st, []).append(t)

            category_sink_pairs = {
                "sqli": "sql",
                "injections": "command",
                "path_traversal": "file",
            }

            for finding in findings:
                expected_sink = category_sink_pairs.get(finding.category)
                if expected_sink and expected_sink in sink_map and sink_map[expected_sink]:
                    event = sink_map[expected_sink][0]
                    finding.iast_source_file = event.get("source_file")
                    finding.iast_source_line = event.get("source_line")
                    finding.iast_call_stack = event.get("call_stack", [])
                    finding.rasp_blocked = event.get("blocked_by_rasp", False)
                    finding.confidence = "certain"
                    enriched_count += 1
            return enriched_count
        except Exception as ex:
            log.debug("No se pudo correlacionar telemetría IAST: %s", ex)
            return 0

    def build_attack_graph(self, findings: list[Finding]) -> AttackGraph:
        """Construye el Grafo de Ataque y calcula los Choke Points defensivos."""
        return AttackGraph.build_from_findings(findings)


def generate_request_id(url: str, payload: str = "") -> str:
    import hashlib
    raw = f"{url}|{payload}"
    return hashlib.sha256(raw.encode()).hexdigest()[:12]
