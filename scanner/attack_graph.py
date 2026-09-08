"""Orquestador de Grafos de Ataque y Análisis de Choke Points Defensivos.

Modela las vulnerabilidades descubiertas como un Grafo Dirigido Acíclico (DAG),
calcula cadenas de explotación progresivas (Initial Access ➔ Credential Access ➔ Impact)
e identifica matemáticamente los Puntos de Estrangulamiento Defensivo (Choke Points)
donde una sola remediación estratégica neutraliza múltiples vectores de ataque.
"""
from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import asdict, dataclass
from typing import Any

from scanner.models import Finding

# Mapeo de categorías de vulnerabilidad a fases de la cadena de muerte cibernética (Cyber Kill Chain / MITRE ATT&CK)
PHASE_MAPPING: dict[str, dict[str, Any]] = {
    "directories": {"phase": "Reconocimiento", "tactic": "TA0043 - Reconnaissance", "order": 1},
    "ports": {"phase": "Reconocimiento", "tactic": "TA0043 - Reconnaissance", "order": 1},
    "subdomains": {"phase": "Reconocimiento", "tactic": "TA0043 - Reconnaissance", "order": 1},
    "headers": {"phase": "Acceso Inicial", "tactic": "TA0001 - Initial Access", "order": 2},
    "cors": {"phase": "Acceso Inicial", "tactic": "TA0001 - Initial Access", "order": 2},
    "open_redirect": {"phase": "Acceso Inicial", "tactic": "TA0001 - Initial Access", "order": 2},
    "fuzzer": {"phase": "Fuga de Credenciales", "tactic": "TA0006 - Credential Access", "order": 3},
    "sensitive_data": {"phase": "Fuga de Credenciales", "tactic": "TA0006 - Credential Access", "order": 3},
    "jwt": {"phase": "Fuga de Credenciales", "tactic": "TA0006 - Credential Access", "order": 3},
    "api": {"phase": "Acceso a APIs / Autenticación", "tactic": "TA0001 - Initial Access", "order": 3},
    "auth": {"phase": "Elevación de Sesión", "tactic": "TA0004 - Privilege Escalation", "order": 4},
    "cookies": {"phase": "Elevación de Sesión", "tactic": "TA0004 - Privilege Escalation", "order": 4},
    "xss": {"phase": "Ejecución / Robo de Contexto", "tactic": "TA0002 - Execution", "order": 4},
    "dom_xss": {"phase": "Ejecución / Robo de Contexto", "tactic": "TA0002 - Execution", "order": 4},
    "sqli": {"phase": "Exfiltración / Manipulación", "tactic": "TA0040 - Impact", "order": 5},
    "path_traversal": {"phase": "Lectura de Archivos del Servidor", "tactic": "TA0009 - Collection", "order": 5},
    "file_upload": {"phase": "Ejecución Remota de Código", "tactic": "TA0002 - Execution", "order": 6},
    "injections": {"phase": "Control Total del Servidor (RCE)", "tactic": "TA0040 - Impact", "order": 6},
    "xxe": {"phase": "Control Total del Servidor (RCE)", "tactic": "TA0040 - Impact", "order": 6},
    "default": {"phase": "Exploración", "tactic": "TA0001 - Initial Access", "order": 2},
}


@dataclass
class AttackNode:
    """Nodo en el grafo de ataque que representa un estado o hallazgo."""
    id: str
    title: str
    category: str
    phase: str
    tactic: str
    phase_order: int
    severity: str
    affected_url: str = ""
    finding_id: str | None = None
    is_critical_impact: bool = False

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class AttackEdge:
    """Arista dirigida que representa una transición de ataque o relación causal."""
    source_id: str
    target_id: str
    technique: str
    description: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ChokePoint:
    """Punto crítico de estrangulamiento defensivo (Choke Point)."""
    node_id: str
    node_title: str
    category: str
    severed_paths_count: int
    downstream_impact_count: int
    defensive_roi_percent: float
    recommended_defense: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class AttackGraph:
    """Grafo Dirigido Acíclico (DAG) que modela escenarios de ataque multi-etapa y defensa."""

    def __init__(self) -> None:
        self.nodes: dict[str, AttackNode] = {}
        self.edges: list[AttackEdge] = []
        self._adj: dict[str, list[str]] = defaultdict(list)
        self._rev_adj: dict[str, list[str]] = defaultdict(list)

    def add_node(self, node: AttackNode) -> None:
        self.nodes[node.id] = node

    def add_edge(self, edge: AttackEdge) -> None:
        if edge.source_id not in self.nodes or edge.target_id not in self.nodes:
            return
        self.edges.append(edge)
        self._adj[edge.source_id].append(edge.target_id)
        self._rev_adj[edge.target_id].append(edge.source_id)

    @classmethod
    def build_from_findings(cls, findings: list[Finding]) -> AttackGraph:
        """Construye automáticamente un Grafo de Ataque a partir de hallazgos descubiertos."""
        graph = cls()
        if not findings:
            return graph

        # 1. Crear nodos para cada hallazgo relevante
        for idx, f in enumerate(findings):
            meta = PHASE_MAPPING.get(f.category, PHASE_MAPPING["default"])
            node_id = f"node_{idx}_{f.category}"
            order_val = int(meta["order"])
            is_impact = f.severity in ("critical", "high") and order_val >= 5

            node = AttackNode(
                id=node_id,
                title=f.title,
                category=f.category,
                phase=str(meta["phase"]),
                tactic=str(meta["tactic"]),
                phase_order=order_val,
                severity=f.severity,
                affected_url=f.affected_url or "",
                finding_id=f.id,
                is_critical_impact=is_impact,
            )
            graph.add_node(node)
            f.attack_chain_id = node_id

        # 2. Sintetizar transiciones causales lógicas entre fases
        nodes_sorted = sorted(graph.nodes.values(), key=lambda n: n.phase_order)

        for i, src in enumerate(nodes_sorted):
            for tgt in nodes_sorted[i + 1:]:
                # No conectar si están en la misma fase
                if src.phase_order >= tgt.phase_order:
                    continue

                # Relaciones causales típicas de ciberseguridad
                can_link = False
                technique = ""
                desc = ""

                # Fuga de credenciales/fuzzer -> Acceso/SQLi/Inyecciones
                if src.category in ("sensitive_data", "fuzzer", "jwt") and tgt.category in ("api", "sqli", "injections"):
                    can_link = True
                    technique = "Reutilización de Credenciales / Tokens Expuestos"
                    desc = f"El atacante usa credenciales de '{src.title}' para alcanzar '{tgt.title}'"

                # Reconocimiento / Directorios -> Fuzzing / APIs
                elif src.category in ("directories", "ports") and tgt.category in ("fuzzer", "sensitive_data", "api"):
                    can_link = True
                    technique = "Enumeración de Superficie Expuesta"
                    desc = f"La exposición de '{src.title}' facilitó el descubrimiento de '{tgt.title}'"

                # XSS / Cookies -> Elevación / Robo de Sesión
                elif src.category in ("xss", "dom_xss", "cookies") and tgt.category in ("api", "sqli", "injections"):
                    can_link = True
                    technique = "Suplantación de Sesión de Usuario"
                    desc = f"Robo de sesión via '{src.title}' permite acceso a funcionalidades privilegiadas"

                # Path Traversal -> Fuga de configuración -> Inyecciones
                elif src.category == "path_traversal" and tgt.category in ("injections", "file_upload"):
                    can_link = True
                    technique = "Lectura de Código Interno / LFI"
                    desc = f"Análisis de archivos locales via '{src.title}' expone lógica vulnerable a '{tgt.title}'"

                # Conexión genérica si hay salto directo a un nodo de impacto
                elif tgt.is_critical_impact and tgt.phase_order - src.phase_order <= 2:
                    can_link = True
                    technique = "Escalamiento Lateral de Privilegios"
                    desc = f"La falta de controles en '{src.title}' sirvió de vector hacia '{tgt.title}'"

                if can_link:
                    graph.add_edge(AttackEdge(
                        source_id=src.id,
                        target_id=tgt.id,
                        technique=technique,
                        description=desc,
                    ))

        return graph

    def calculate_choke_points(self) -> list[ChokePoint]:
        """Calcula los puntos de estrangulamiento defensivo (Choke Points).

        Un Choke Point es un nodo intermedio cuya remediación desconecta el mayor
        número de rutas hacia los nodos de impacto crítico (RCE, SQLi, exfiltración).
        """
        critical_nodes = [nid for nid, node in self.nodes.items() if node.is_critical_impact]
        if not critical_nodes:
            # Si no hay nodos marcados como críticos, usar los de mayor fase
            max_order = max((n.phase_order for n in self.nodes.values()), default=1)
            critical_nodes = [nid for nid, node in self.nodes.items() if node.phase_order == max_order]

        choke_points: list[ChokePoint] = []
        total_paths_to_impact = 0

        # Calcular número de caminos que alcanzan nodos críticos desde cada nodo
        def count_reachable_critical(start_node: str) -> int:
            visited: set[str] = set()
            queue = deque([start_node])
            impact_reached = 0

            while queue:
                curr = queue.popleft()
                if curr in visited:
                    continue
                visited.add(curr)
                if curr != start_node and curr in critical_nodes:
                    impact_reached += 1
                for neighbor in self._adj.get(curr, []):
                    if neighbor not in visited:
                        queue.append(neighbor)
            return impact_reached

        for nid in self.nodes:
            if nid in critical_nodes:
                continue
            reachable = count_reachable_critical(nid)
            total_paths_to_impact += reachable

        # Evaluar beneficio defensivo de cada nodo no-crítico
        for nid, node in self.nodes.items():
            if nid in critical_nodes:
                continue

            reachable = count_reachable_critical(nid)
            if reachable == 0:
                continue

            # Cálculo de ROI defensivo (% de rutas de impacto cortadas)
            roi = (reachable / max(total_paths_to_impact, 1)) * 100.0

            # Estrategia de defensa recomendada según categoría
            recs = {
                "sensitive_data": "Rotar credenciales expuestas y añadir detección de secretos en pre-commit git hooks.",
                "fuzzer": "Restringir acceso a archivos .env/.git con reglas WAF y directivas Nginx/Apache.",
                "api": "Implementar esquemas OAuth2/JWT Bearer obligatorios y control de acceso RBAC.",
                "jwt": "Validar firmas con algoritmo HMAC-SHA256 y forzar expiración de tokens.",
                "xss": "Aplicar cabeceras Content-Security-Policy estrictas y sanitización con DOMPurify.",
                "path_traversal": "Validar nombres de archivo con lista blanca y os.path.realpath() sin aceptar '../'.",
            }
            rec = recs.get(node.category, f"Parchear '{node.title}' para quebrar la cadena de escalamiento del atacante.")

            choke_points.append(ChokePoint(
                node_id=nid,
                node_title=node.title,
                category=node.category,
                severed_paths_count=reachable,
                downstream_impact_count=reachable,
                defensive_roi_percent=round(min(roi, 100.0), 1),
                recommended_defense=rec,
            ))

        # Ordenar por mayor número de rutas neutralizadas (mayor impacto defensivo)
        choke_points.sort(key=lambda cp: cp.severed_paths_count, reverse=True)
        return choke_points

    def to_mermaid(self) -> str:
        """Genera diagrama Mermaid con nodos estilizados y choke points destacados."""
        if not self.nodes:
            return "graph TD\n    empty[No hay suficientes hallazgos para construir un grafo]"

        choke_nodes = {cp.node_id for cp in self.calculate_choke_points()[:3]}
        lines = ["graph LR"]

        # Declarar nodos con estilos
        for nid, node in self.nodes.items():
            safe_title = node.title.replace('"', "'").replace("[", "(").replace("]", ")")
            if nid in choke_nodes:
                # Destacar Choke Point defensivo en azul/cian
                lines.append(f'    {nid}["🛡️ CHOKE POINT DEFENSIVO<br/><b>{safe_title}</b><br/>({node.phase})"]')
            elif node.is_critical_impact:
                # Nodo crítico de impacto final en rojo
                lines.append(f'    {nid}["💥 IMPACTO FINAL<br/><b>{safe_title}</b><br/>({node.severity.upper()})"]')
            else:
                lines.append(f'    {nid}["{safe_title}<br/><small>{node.phase}</small>"]')

        # Declarar aristas
        for edge in self.edges:
            safe_tech = edge.technique.replace('"', "'")
            lines.append(f'    {edge.source_id} -->|"{safe_tech}"| {edge.target_id}')

        # Estilos visuales
        lines.append("    classDef choke fill:#1e3a8a,stroke:#3b82f6,stroke-width:3px,color:#ffffff;")
        lines.append("    classDef impact fill:#7f1d1d,stroke:#ef4444,stroke-width:2px,color:#ffffff;")

        for cn in choke_nodes:
            lines.append(f"    class {cn} choke;")
        for nid, node in self.nodes.items():
            if node.is_critical_impact and nid not in choke_nodes:
                lines.append(f"    class {nid} impact;")

        return "\n".join(lines)

    def to_dict(self) -> dict[str, Any]:
        """Serializa el grafo completo para consumo en API REST y reportes JSON."""
        return {
            "total_nodes": len(self.nodes),
            "total_edges": len(self.edges),
            "nodes": [n.to_dict() for n in self.nodes.values()],
            "edges": [e.to_dict() for e in self.edges],
            "choke_points": [cp.to_dict() for cp in self.calculate_choke_points()],
            "mermaid": self.to_mermaid(),
        }
