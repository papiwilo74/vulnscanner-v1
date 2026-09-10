"""Unit tests for Probabilistic Attack Graph, Centrality and What-If Simulation."""
from scanner.attack_graph import AttackGraph, WhatIfResult
from scanner.models import Finding


def test_probabilistic_attack_graph_weights() -> None:
    findings = [
        Finding(category="ports", title="SSH y RDP expuestos", severity="high"),
        Finding(category="sensitive_data", title="Clave API filtrada", severity="high"),
        Finding(category="sqli", title="SQL Injection crítica", severity="critical"),
    ]
    graph = AttackGraph.build_from_findings(findings)
    assert len(graph.nodes) == 3
    assert len(graph.edges) >= 1

    # Verify probabilities are assigned and clamped [0.1, 1.0]
    for edge in graph.edges:
        assert 0.1 <= edge.exploit_probability <= 1.0

    # Verify Betweenness Centrality is calculated
    for node in graph.nodes.values():
        assert isinstance(node.betweenness_centrality, float)

def test_what_if_remediation_simulation() -> None:
    findings = [
        Finding(category="directories", title="Directorio /admin", severity="low"),
        Finding(category="sensitive_data", title="Credenciales en .env", severity="high"),
        Finding(category="injections", title="RCE en terminal", severity="critical"),
    ]
    graph = AttackGraph.build_from_findings(findings)

    # Identify choke point / intermediate node
    choke_points = graph.calculate_choke_points()
    assert len(choke_points) > 0
    top_cp_id = choke_points[0].node_id

    # Simulate remediating the top choke point
    result = graph.simulate_remediation([top_cp_id])
    assert isinstance(result, WhatIfResult)
    assert result.initial_risk_score >= result.residual_risk_score
    assert result.risk_reduction_percent > 0.0
    assert result.severed_attack_paths > 0
    assert "DEFENSIVO" in result.summary_verdict
    assert len(result.strategic_advice) >= 1
