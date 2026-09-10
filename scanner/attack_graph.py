"""Orquestador de Grafos de Ataque Probabilísticos y Análisis de Choke Points Defensivos.

Modela las vulnerabilidades descubiertas como un Grafo Dirigido Acíclico (DAG) probabilístico,
calcula probabilidades acumuladas de explotación, métricas de centralidad matemática
(Betweenness Centrality y Degree Centrality) para identificar Puntos de Estrangulamiento (Choke Points),
y ofrece un simulador What-If para proyectar la reducción exacta del riesgo tras aplicar remediaciones.
"""
from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import asdict, dataclass, field
from typing import Any

from scanner.models import Finding

# Mapeo de categorías de vulnerabilidad a fases de la cadena de muerte cibernética (Cyber Kill Chain / MITRE ATT&CK)
PHASE_MAPPING: dict[str, dict[str, Any]] = {
    "directories": {"phase": "Reconocimiento", "tactic": "TA0043 - Reconnaissance", "order": 1, "base_prob": 0.85},
    "ports": {"phase": "Reconocimiento", "tactic": "TA0043 - Reconnaissance", "order": 1, "base_prob": 0.90},
    "subdomains": {"phase": "Reconocimiento", "tactic": "TA0043 - Reconnaissance", "order": 1, "base_prob": 0.80},
    "headers": {"phase": "Acceso Inicial", "tactic": "TA0001 - Initial Access", "order": 2, "base_prob": 0.40},
    "cors": {"phase": "Acceso Inicial", "tactic": "TA0001 - Initial Access", "order": 2, "base_prob": 0.65},
    "open_redirect": {"phase": "Acceso Inicial", "tactic": "TA0001 - Initial Access", "order": 2, "base_prob": 0.70},
    "fuzzer": {"phase": "Fuga de Credenciales", "tactic": "TA0006 - Credential Access", "order": 3, "base_prob": 0.75},
    "sensitive_data": {"phase": "Fuga de Credenciales", "tactic": "TA0006 - Credential Access", "order": 3, "base_prob": 0.85},
    "jwt": {"phase": "Fuga de Credenciales", "tactic": "TA0006 - Credential Access", "order": 3, "base_prob": 0.70},
    "api": {"phase": "Acceso a APIs / Autenticación", "tactic": "TA0001 - Initial Access", "order": 3, "base_prob": 0.75},
    "auth": {"phase": "Elevación de Sesión", "tactic": "TA0004 - Privilege Escalation", "order": 4, "base_prob": 0.60},
    "cookies": {"phase": "Elevación de Sesión", "tactic": "TA0004 - Privilege Escalation", "order": 4, "base_prob": 0.55},
    "xss": {"phase": "Ejecución / Robo de Contexto", "tactic": "TA0002 - Execution", "order": 4, "base_prob": 0.65},
    "dom_xss": {"phase": "Ejecución / Robo de Contexto", "tactic": "TA0002 - Execution", "order": 4, "base_prob": 0.60},
    "sqli": {"phase": "Exfiltración / Manipulación", "tactic": "TA0040 - Impact", "order": 5, "base_prob": 0.90},
    "path_traversal": {"phase": "Lectura de Archivos del Servidor", "tactic": "TA0009 - Collection", "order": 5, "base_prob": 0.80},
    "file_upload": {"phase": "Ejecución Remota de Código", "tactic": "TA0002 - Execution", "order": 6, "base_prob": 0.85},
    "injections": {"phase": "Control Total del Servidor (RCE)", "tactic": "TA0040 - Impact", "order": 6, "base_prob": 0.95},
    "xxe": {"phase": "Control Total del Servidor (RCE)", "tactic": "TA0040 - Impact", "order": 6, "base_prob": 0.80},
    "container_security": {"phase": "Escape de Contenedor / Host Access", "tactic": "TA0004 - Privilege Escalation", "order": 5, "base_prob": 0.85},
    "default": {"phase": "Exploración", "tactic": "TA0001 - Initial Access", "order": 2, "base_prob": 0.50},
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
    betweenness_centrality: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class AttackEdge:
    """Arista dirigida con probabilidad de transición de ataque."""
    source_id: str
    target_id: str
    technique: str
    description: str
    exploit_probability: float = 0.7

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
    betweenness_centrality: float = 0.0
    accumulated_exploit_risk: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class WhatIfResult:
    """Resultado de la simulación de impacto 'What-If' al mitigar vulnerabilidades."""
    remediated_node_ids: list[str]
    initial_risk_score: float
    residual_risk_score: float
    risk_reduction_percent: float
    severed_attack_paths: int
    remaining_critical_nodes: int
    summary_verdict: str
    strategic_advice: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class AttackGraph:
    """Grafo Dirigido Acíclico (DAG) probabilístico con análisis matemático de Choke Points y What-If."""

    def __init__(self) -> None:
        self.nodes: dict[str, AttackNode] = {}
        self.edges: list[AttackEdge] = []
        self._adj: dict[str, list[str]] = defaultdict(list)
        self._rev_adj: dict[str, list[str]] = defaultdict(list)
        self._edge_probs: dict[tuple[str, str], float] = {}

    def add_node(self, node: AttackNode) -> None:
        self.nodes[node.id] = node

    def add_edge(self, edge: AttackEdge) -> None:
        if edge.source_id not in self.nodes or edge.target_id not in self.nodes:
            return
        self.edges.append(edge)
        self._adj[edge.source_id].append(edge.target_id)
        self._rev_adj[edge.target_id].append(edge.source_id)
        self._edge_probs[(edge.source_id, edge.target_id)] = edge.exploit_probability

    @classmethod
    def build_from_findings(cls, findings: list[Finding]) -> AttackGraph:
        """Construye automáticamente un Grafo de Ataque Probabilístico."""
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

        # 2. Sintetizar transiciones causales lógicas con pesos de probabilidad
        nodes_sorted = sorted(graph.nodes.values(), key=lambda n: n.phase_order)

        for i, src in enumerate(nodes_sorted):
            src_meta = PHASE_MAPPING.get(src.category, PHASE_MAPPING["default"])
            src_base_p = float(src_meta.get("base_prob", 0.6))

            for tgt in nodes_sorted[i + 1:]:
                if src.phase_order >= tgt.phase_order:
                    continue

                tgt_meta = PHASE_MAPPING.get(tgt.category, PHASE_MAPPING["default"])
                tgt_base_p = float(tgt_meta.get("base_prob", 0.6))

                can_link = False
                technique = ""
                desc = ""
                prob = round((src_base_p + tgt_base_p) / 2.0, 2)

                # Fuga de credenciales -> Acceso/SQLi/Inyecciones
                if src.category in ("sensitive_data", "fuzzer", "jwt") and tgt.category in ("api", "sqli", "injections"):
                    can_link = True
                    technique = "Reutilización de Credenciales / Tokens Expuestos"
                    desc = f"El atacante usa credenciales de '{src.title}' para alcanzar '{tgt.title}'"
                    prob = max(prob, 0.88)

                # Reconocimiento -> Fuzzing / APIs
                elif src.category in ("directories", "ports") and tgt.category in ("fuzzer", "sensitive_data", "api"):
                    can_link = True
                    technique = "Enumeración de Superficie Expuesta"
                    desc = f"La exposición de '{src.title}' facilitó el descubrimiento de '{tgt.title}'"
                    prob = max(prob, 0.78)

                # XSS / Cookies -> Elevación
                elif src.category in ("xss", "dom_xss", "cookies") and tgt.category in ("api", "sqli", "injections"):
                    can_link = True
                    technique = "Suplantación de Sesión de Usuario"
                    desc = f"Robo de sesión via '{src.title}' permite acceso a funcionalidades privilegiadas"
                    prob = max(prob, 0.72)

                # Path Traversal -> Inyecciones / File Upload
                elif src.category == "path_traversal" and tgt.category in ("injections", "file_upload"):
                    can_link = True
                    technique = "Lectura de Código Interno / LFI"
                    desc = f"Análisis de archivos locales via '{src.title}' expone lógica vulnerable a '{tgt.title}'"
                    prob = max(prob, 0.85)

                # Container Security -> RCE / Impacto
                elif src.category == "container_security" and tgt.is_critical_impact:
                    can_link = True
                    technique = "Escape de Contenedor o Abuso de Privilegios Root"
                    desc = f"Mala configuración en contenedor '{src.title}' permite escalamiento hacia '{tgt.title}'"
                    prob = max(prob, 0.80)

                # Salto genérico hacia nodo de impacto crítico
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
                        exploit_probability=min(prob, 0.99),
                    ))

        # Calcular centralidad matemática de los nodos
        graph._compute_centralities()
        return graph

    def _compute_centralities(self) -> None:
        """Calcula Brandes Betweenness Centrality determinista para cada nodo."""
        cb: dict[str, float] = {nid: 0.0 for nid in self.nodes}
        nodes_list = list(self.nodes.keys())

        for s in nodes_list:
            # BFS para caminos más cortos desde s
            stack: list[str] = []
            pred: dict[str, list[str]] = {w: [] for w in nodes_list}
            sigma: dict[str, int] = {w: 0 for w in nodes_list}
            sigma[s] = 1
            dist: dict[str, int] = {w: -1 for w in nodes_list}
            dist[s] = 0
            queue = deque([s])

            while queue:
                v = queue.popleft()
                stack.append(v)
                for w in self._adj.get(v, []):
                    # w descubierto por primera vez
                    if dist[w] < 0:
                        dist[w] = dist[v] + 1
                        queue.append(w)
                    # camino más corto a w via v
                    if dist[w] == dist[v] + 1:
                        sigma[w] += sigma[v]
                        pred[w].append(v)

            # Acumulación hacia atrás de dependencias
            delta: dict[str, float] = {w: 0.0 for w in nodes_list}
            while stack:
                w = stack.pop()
                for v in pred[w]:
                    if sigma[w] > 0:
                        delta[v] += (sigma[v] / sigma[w]) * (1.0 + delta[w])
                if w != s:
                    cb[w] += delta[w]

        # Normalizar y guardar
        n_count = len(nodes_list)
        norm_factor = (n_count - 1) * (n_count - 2) if n_count > 2 else 1.0
        for nid, val in cb.items():
            normalized = round(val / norm_factor, 4)
            self.nodes[nid].betweenness_centrality = normalized

    def calculate_choke_points(self) -> list[ChokePoint]:
        """Calcula los puntos de estrangulamiento (Choke Points) ponderados por impacto y centralidad."""
        critical_nodes = [nid for nid, node in self.nodes.items() if node.is_critical_impact]
        if not critical_nodes:
            max_order = max((n.phase_order for n in self.nodes.values()), default=1)
            critical_nodes = [nid for nid, node in self.nodes.items() if node.phase_order == max_order]

        choke_points: list[ChokePoint] = []
        total_paths_to_impact = 0

        def count_reachable_critical(start_node: str) -> tuple[int, float]:
            visited: set[str] = set()
            queue: deque[tuple[str, float]] = deque([(start_node, 1.0)])
            impact_reached = 0
            accum_risk = 0.0

            while queue:
                curr, current_prob = queue.popleft()
                if curr in visited:
                    continue
                visited.add(curr)
                if curr != start_node and curr in critical_nodes:
                    impact_reached += 1
                    accum_risk += current_prob

                for neighbor in self._adj.get(curr, []):
                    if neighbor not in visited:
                        edge_p = self._edge_probs.get((curr, neighbor), 0.7)
                        queue.append((neighbor, current_prob * edge_p))

            return impact_reached, round(accum_risk, 3)

        for nid in self.nodes:
            if nid in critical_nodes:
                continue
            reachable, _ = count_reachable_critical(nid)
            total_paths_to_impact += reachable

        for nid, node in self.nodes.items():
            if nid in critical_nodes:
                continue

            reachable, accum_risk = count_reachable_critical(nid)
            if reachable == 0:
                continue

            roi = (reachable / max(total_paths_to_impact, 1)) * 100.0

            recs = {
                "sensitive_data": "Rotar credenciales expuestas y añadir detección de secretos en pre-commit git hooks.",
                "fuzzer": "Restringir acceso a archivos .env/.git con reglas WAF y directivas Nginx/Apache.",
                "api": "Implementar esquemas OAuth2/JWT Bearer obligatorios y control de acceso RBAC.",
                "jwt": "Validar firmas con algoritmo HMAC-SHA256 y forzar expiración de tokens.",
                "xss": "Aplicar cabeceras Content-Security-Policy estrictas y sanitización con DOMPurify.",
                "path_traversal": "Validar nombres de archivo con lista blanca y os.path.realpath() sin aceptar '../'.",
                "container_security": "Modificar Dockerfile para correr como usuario no privilegiado y fijar versiones inmutables.",
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
                betweenness_centrality=node.betweenness_centrality,
                accumulated_exploit_risk=accum_risk,
            ))

        # Ordenar por probabilidad acumulada, centralidad y número de rutas cortadas
        choke_points.sort(
            key=lambda cp: (cp.accumulated_exploit_risk, cp.betweenness_centrality, cp.severed_paths_count),
            reverse=True
        )
        return choke_points

    def simulate_remediation(self, remediated_node_ids: list[str]) -> WhatIfResult:
        """
        Simulador What-If: evalúa el impacto defensivo exacto de mitigar un conjunto de vulnerabilidades.
        Calcula la reducción de riesgo residual y caminos de ataque quebrados.
        """
        remediated_set = set(remediated_node_ids)
        critical_nodes = [nid for nid, node in self.nodes.items() if node.is_critical_impact]
        if not critical_nodes:
            max_order = max((n.phase_order for n in self.nodes.values()), default=1)
            critical_nodes = [nid for nid, node in self.nodes.items() if node.phase_order == max_order]

        # 1. Riesgo inicial: suma de probabilidades en todos los caminos a nodos críticos
        def calculate_total_system_risk(excluded_nodes: set[str]) -> tuple[float, int]:
            total_risk = 0.0
            total_paths = 0

            for start in self.nodes:
                if start in excluded_nodes or start in critical_nodes:
                    continue

                visited: set[str] = set()
                queue: deque[tuple[str, float]] = deque([(start, 1.0)])

                while queue:
                    curr, current_p = queue.popleft()
                    if curr in visited or curr in excluded_nodes:
                        continue
                    visited.add(curr)

                    if curr != start and curr in critical_nodes:
                        total_risk += current_p
                        total_paths += 1

                    for nxt in self._adj.get(curr, []):
                        if nxt not in visited and nxt not in excluded_nodes:
                            p = self._edge_probs.get((curr, nxt), 0.7)
                            queue.append((nxt, current_p * p))

            return round(total_risk, 3), total_paths

        initial_risk, initial_paths = calculate_total_system_risk(excluded_nodes=set())
        residual_risk, remaining_paths = calculate_total_system_risk(excluded_nodes=remediated_set)

        severed_paths = max(0, initial_paths - remaining_paths)
        reduction_pct = 0.0
        if initial_risk > 0:
            reduction_pct = round(((initial_risk - residual_risk) / initial_risk) * 100.0, 1)
        elif severed_paths > 0:
            reduction_pct = 100.0

        # Evaluar nodos críticos remanentes accesibles
        remaining_critical_count = len(critical_nodes) - len(remediated_set.intersection(critical_nodes))

        # Dictamen y recomendaciones estratégicas
        advice: list[str] = []
        if reduction_pct >= 70.0:
            verdict = f"ALTO IMPACTO DEFENSIVO: La remediación propuesta desarticula el {reduction_pct}% del riesgo sistémico."
            advice.append("Priorizar de inmediato el despliegue de estos parches en el sprint actual.")
            advice.append("Monitorear logs de WAF y telemetría IAST para verificar la anulación de las rutas de explotación.")
        elif reduction_pct >= 30.0:
            verdict = f"IMPACTO DEFENSIVO MODERADO: Se reduce el {reduction_pct}% del riesgo sistémico."
            advice.append("Remediación valiosa, pero se recomienda combinar con el aislamiento de Choke Points adicionales.")
        else:
            verdict = f"IMPACTO DEFENSIVO LIMITADO: Solo se reduce el {reduction_pct}% del riesgo."
            advice.append("Los atacantes conservan rutas alternativas hacia el impacto crítico. Considere remediar los Choke Points con mayor Betweenness Centrality.")

        return WhatIfResult(
            remediated_node_ids=remediated_node_ids,
            initial_risk_score=initial_risk,
            residual_risk_score=residual_risk,
            risk_reduction_percent=min(reduction_pct, 100.0),
            severed_attack_paths=severed_paths,
            remaining_critical_nodes=remaining_critical_count,
            summary_verdict=verdict,
            strategic_advice=advice,
        )

    def to_mermaid(self) -> str:
        """Genera diagrama Mermaid con nodos estilizados, pesos de aristas y choke points destacados."""
        if not self.nodes:
            return "graph TD\n    empty[No hay suficientes hallazgos para construir un grafo]"

        choke_nodes = {cp.node_id for cp in self.calculate_choke_points()[:3]}
        lines = ["graph LR"]

        # Declarar nodos con estilos
        for nid, node in self.nodes.items():
            safe_title = node.title.replace('"', "'").replace("[", "(").replace("]", ")")
            if nid in choke_nodes:
                lines.append(f'    {nid}["🛡️ CHOKE POINT DEFENSIVO<br/><b>{safe_title}</b><br/>(BC: {node.betweenness_centrality})"]')
            elif node.is_critical_impact:
                lines.append(f'    {nid}["💥 IMPACTO FINAL<br/><b>{safe_title}</b><br/>({node.severity.upper()})"]')
            else:
                lines.append(f'    {nid}["{safe_title}<br/><small>{node.phase}</small>"]')

        # Declarar aristas con probabilidad
        for edge in self.edges:
            safe_tech = edge.technique.replace('"', "'")
            prob_pct = int(edge.exploit_probability * 100)
            lines.append(f'    {edge.source_id} -->|"{safe_tech} ({prob_pct}%)"| {edge.target_id}')

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
