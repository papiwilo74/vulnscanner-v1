"""
Script de Benchmarking Cuantitativo de Precision y Cobertura para VulnScanner.
Calcula Precision, Recall y F1-Score contra un benchmark controlado.
"""
import os
import sys
from typing import NamedTuple

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scanner.sensitive_data import scan_text_for_sensitive_data
from scanner.xss import analyze_js_code


class BenchmarkResult(NamedTuple):
    true_positives: int
    false_positives: int
    false_negatives: int
    true_negatives: int

    @property
    def precision(self) -> float:
        total = self.true_positives + self.false_positives
        return (self.true_positives / total) if total > 0 else 1.0

    @property
    def recall(self) -> float:
        total = self.true_positives + self.false_negatives
        return (self.true_positives / total) if total > 0 else 1.0

    @property
    def f1_score(self) -> float:
        p, r = self.precision, self.recall
        return (2 * p * r / (p + r)) if (p + r) > 0 else 0.0


def run_benchmark() -> BenchmarkResult:
    tp = 0
    fp = 0
    fn = 0
    tn = 0

    # 1. Benchmark de Detección de Secretos
    secret_cases = [
        ("AKIAIOSFODNN7ABCDEXYZ", True),
        ("postgres://prod_admin:Secret99Pass@internal.db.local:5432/finance", True),
        ("var x = 123; var y = 'hello world';", False),
        ("AKIA_FAKE_KEY_SHORT", False),
    ]
    for text, should_detect in secret_cases:
        detected = len(scan_text_for_sensitive_data(text, "test.js")) > 0
        if should_detect and detected:
            tp += 1
        elif should_detect and not detected:
            fn += 1
        elif not should_detect and detected:
            fp += 1
        else:
            tn += 1

    # 2. Benchmark de DOM XSS
    dom_cases = [
        ("document.write(document.URL);", True),
        ("eval(location.hash);", True),
        ("var user = 'alice'; console.log(user);", False),
        ("function add(a, b) { return a + b; }", False),
    ]
    for code, should_detect in dom_cases:
        detected = len(analyze_js_code(code, "test.js")) > 0
        if should_detect and detected:
            tp += 1
        elif should_detect and not detected:
            fn += 1
        elif not should_detect and detected:
            fp += 1
        else:
            tn += 1

    return BenchmarkResult(tp, fp, fn, tn)


if __name__ == "__main__":
    b = run_benchmark()
    print("=" * 50)
    print("VulnScanner Benchmark Scorecard")
    print("=" * 50)
    print(f"True Positives  (TP): {b.true_positives}")
    print(f"False Positives (FP): {b.false_positives}")
    print(f"False Negatives (FN): {b.false_negatives}")
    print(f"True Negatives  (TN): {b.true_negatives}")
    print("-" * 50)
    print(f"Precision : {b.precision * 100:.1f}%")
    print(f"Recall    : {b.recall * 100:.1f}%")
    print(f"F1-Score  : {b.f1_score * 100:.1f}%")
    print("=" * 50)
