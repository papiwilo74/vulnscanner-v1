"""Pruebas unitarias para el Orquestador de Grafos de Ataque y Choke Points Defensivos."""
from scanner.attack_graph import AttackGraph
from scanner.models import Finding


class TestAttackGraph:
    def test_empty_graph(self):
        graph = AttackGraph.build_from_findings([])
        assert len(graph.nodes) == 0
        assert len(graph.edges) == 0
        assert "empty" in graph.to_mermaid()

    def test_build_from_multi_stage_findings(self):
        findings = [
            Finding(
                category="directories",
                title="Directorio /admin expuesto",
                severity="low",
                affected_url="http://example.com/admin",
            ),
            Finding(
                category="sensitive_data",
                title="Clave API y credenciales en backup",
                severity="high",
                affected_url="http://example.com/.env",
            ),
            Finding(
                category="api",
                title="API Endpoint sin autenticación (Broken Auth)",
                severity="high",
                affected_url="http://example.com/api/v1/users",
            ),
            Finding(
                category="sqli",
                title="Inyección SQL en parámetro 'id'",
                severity="critical",
                affected_url="http://example.com/api/v1/users?id=1",
            ),
        ]

        graph = AttackGraph.build_from_findings(findings)
        assert len(graph.nodes) == 4
        assert len(graph.edges) >= 2

        # Verificar que se asignó attack_chain_id a los hallazgos
        for f in findings:
            assert f.attack_chain_id is not None
            assert f.attack_chain_id in graph.nodes

        # Verificar cálculo de Choke Points defensivos
        choke_points = graph.calculate_choke_points()
        assert len(choke_points) > 0
        # El choke point debe sugerir remediación estratégica
        top_cp = choke_points[0]
        assert top_cp.severed_paths_count > 0
        assert top_cp.defensive_roi_percent > 0.0
        assert len(top_cp.recommended_defense) > 0

    def test_mermaid_generation(self):
        findings = [
            Finding(
                category="sensitive_data",
                title="Token JWT expuesto",
                severity="high",
                affected_url="http://example.com/token",
            ),
            Finding(
                category="injections",
                title="Command Injection en /system",
                severity="critical",
                affected_url="http://example.com/system",
            ),
        ]

        graph = AttackGraph.build_from_findings(findings)
        mermaid_code = graph.to_mermaid()

        assert "graph LR" in mermaid_code
        assert "classDef choke" in mermaid_code
        assert "classDef impact" in mermaid_code
        assert "node_" in mermaid_code

    def test_to_dict_serialization(self):
        f = Finding(category="xss", title="XSS en search", severity="medium")
        graph = AttackGraph.build_from_findings([f])
        data = graph.to_dict()

        assert "total_nodes" in data
        assert "total_edges" in data
        assert "nodes" in data
        assert "edges" in data
        assert "choke_points" in data
        assert "mermaid" in data
        assert data["total_nodes"] == 1
