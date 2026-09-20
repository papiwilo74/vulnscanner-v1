from pathlib import Path
from tempfile import TemporaryDirectory

from scripts.run_benchmarks import BenchmarkHarness
from tests.benchmark_juiceshop import BenchmarkMetrics


def _create_dummy_metrics(precision: float, false_positives: int) -> BenchmarkMetrics:
    return BenchmarkMetrics(
        target_url="http://test.local",
        target_app="OWASP Juice Shop",
        version="20.2.0",
        duration_seconds=10.5,
        total_findings=15,
        ground_truth_challenges=13,
        true_positives=9,
        false_positives=false_positives,
        false_negatives=4,
        precision=precision,
        recall=0.69,
        f1_score=0.81,
        choke_point_identified="CORS",
        choke_point_severed_paths=3,
        detected_challenges=["corsMisconfiguration"],
    )


def test_evaluate_regression_flags_precision_drop():
    """Si la precisión cae respecto a la medición anterior, debe marcarse como regresión."""
    harness = BenchmarkHarness(Path("fake_path.json"))
    current = _create_dummy_metrics(precision=0.90, false_positives=1)
    previous = {"precision": 1.0, "false_positives": 0}

    has_reg, reasons = harness.evaluate_regression(current, previous)
    assert has_reg is True
    assert any("Regresión en Precisión" in r for r in reasons)
    assert any("Regresión en Falsos Positivos" in r for r in reasons)


def test_evaluate_regression_passes_when_improved_or_equal():
    """Si la precisión se mantiene o mejora y los FPs no aumentan, no debe haber regresión."""
    harness = BenchmarkHarness(Path("fake_path.json"))
    current = _create_dummy_metrics(precision=1.0, false_positives=0)
    previous = {"precision": 1.0, "false_positives": 0}

    has_reg, _ = harness.evaluate_regression(current, previous)
    assert has_reg is False


def test_save_and_load_history():
    """Valida la persistencia correcta de métricas en formato JSON."""
    with TemporaryDirectory() as tmpdir:
        hist_file = Path(tmpdir) / "history.json"
        harness = BenchmarkHarness(hist_file)

        metrics = _create_dummy_metrics(precision=1.0, false_positives=0)
        harness.save_metrics(metrics)

        history = harness.load_history()
        assert len(history) == 1
        assert history[0]["precision"] == 1.0
        assert history[0]["target_app"] == "OWASP Juice Shop"
        assert "timestamp" in history[0]
