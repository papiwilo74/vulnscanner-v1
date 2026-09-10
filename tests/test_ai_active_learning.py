"""Unit tests for AI Active Learning and Feedback Collection."""
from scanner.ai_check import (
    get_active_learning_feedback,
    predict_payload,
    record_analyst_feedback,
)
from train_ai import load_active_learning_feedback


def test_record_and_read_feedback(tmp_path, monkeypatch) -> None:
    test_feedback_file = str(tmp_path / "ai_feedback.jsonl")
    import scanner.ai_check as ai_module
    monkeypatch.setattr(ai_module, "FEEDBACK_PATH", test_feedback_file)

    ok = record_analyst_feedback("custom_payload_test", is_malicious=True, category="test_xss")
    assert ok is True

    samples = get_active_learning_feedback()
    assert len(samples) >= 1
    assert samples[0]["payload"] == "custom_payload_test"
    assert samples[0]["is_malicious"] is True
    assert samples[0]["label"] == 1

def test_predict_payload_uncertainty() -> None:
    # Safe query should have low probability
    prob, uncertain = predict_payload("usuario_seguro_normal")
    assert isinstance(prob, float)
    assert isinstance(uncertain, bool)
    assert prob < 0.50

def test_train_ai_active_learning_loader(tmp_path, monkeypatch) -> None:
    test_feedback_file = str(tmp_path / "ai_feedback.jsonl")
    with open(test_feedback_file, "w", encoding="utf-8") as f:
        f.write('{"payload": "1\' OR \'1\'=\'1", "label": 1}\n')
        f.write('{"payload": "articulos_deportivos", "label": 0}\n')

    import train_ai as trainer
    monkeypatch.setattr(trainer.os.path, "join", lambda *args: test_feedback_file if "ai_feedback.jsonl" in args else str(tmp_path))

    queries, labels = load_active_learning_feedback()
    assert len(queries) == 2
    assert "articulos_deportivos" in queries
    assert labels[1] == 0
