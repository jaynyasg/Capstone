from __future__ import annotations

import json

from aegis.llm_training.dataset import build_sft_examples, export_sft_dataset
from aegis.llm_training.train import (
    DEFAULT_ADAPTER_DIR,
    DEFAULT_FULL_MODEL_DIR,
    _default_out_dir,
    _formatting_func,
    _normalize_training_method,
    _trainable_parameter_report,
)


class _FakeTokenizer:
    def apply_chat_template(self, messages, *, tokenize, add_generation_prompt):
        assert tokenize is False
        assert add_generation_prompt is False
        return " | ".join(f"{message['role']}={message['content']}" for message in messages)


class _FakeParam:
    def __init__(self, count: int, requires_grad: bool) -> None:
        self._count = count
        self.requires_grad = requires_grad

    def numel(self) -> int:
        return self._count


class _FakeModel:
    def __init__(self, params: list[_FakeParam]) -> None:
        self._params = params

    def parameters(self):
        return iter(self._params)


def test_build_sft_examples_from_eval_cases_redacts_plain_secrets() -> None:
    examples = build_sft_examples()
    dumped = json.dumps([example.messages for example in examples])

    assert examples
    assert "ghp_0123456789abcdefghijklmnopqrstuvwxyz" not in dumped
    assert "{{canary:" not in dumped
    assert any(example.label == "safe_refusal" for example in examples)
    assert any(example.label == "safe_secret_handle_use" for example in examples)
    assert any(
        "secret://" in message["content"]
        for example in examples
        for message in example.messages
    )


def test_export_sft_dataset_writes_chat_jsonl(tmp_path) -> None:
    out = export_sft_dataset(tmp_path / "aegis_sft.jsonl")
    rows = [json.loads(line) for line in out.read_text(encoding="utf-8").splitlines()]

    assert rows
    assert rows[0]["source"] == "aegis_eval_cases"
    assert rows[0]["messages"][0]["role"] == "system"
    assert rows[0]["messages"][1]["role"] == "user"
    assert rows[0]["messages"][2]["role"] == "assistant"
    assert rows[0]["metadata"]["raw_secret_included"] is False
    assert any(row["label"] == "safe_refusal" for row in rows)


def test_training_formatting_func_supports_single_and_batched_rows() -> None:
    row = {"messages": [{"role": "user", "content": "hello"}]}
    batch = {"messages": [[{"role": "user", "content": "hello"}]]}

    assert _formatting_func(row, _FakeTokenizer()) == "user=hello"
    assert _formatting_func(batch, _FakeTokenizer()) == ["user=hello"]


def test_training_method_defaults_to_full_model_output() -> None:
    assert _normalize_training_method("full") == "full"
    assert _normalize_training_method("") == "full"
    assert _normalize_training_method("lora") == "lora"
    assert _default_out_dir("full") == DEFAULT_FULL_MODEL_DIR
    assert _default_out_dir("lora") == DEFAULT_ADAPTER_DIR


def test_trainable_parameter_report_distinguishes_full_from_adapter_training() -> None:
    full = _trainable_parameter_report(_FakeModel([_FakeParam(80, True), _FakeParam(20, True)]))
    adapter = _trainable_parameter_report(
        _FakeModel([_FakeParam(95, False), _FakeParam(5, True)])
    )

    assert full["trainable_parameters"] == 100
    assert full["total_parameters"] == 100
    assert full["full_model_weights_saved"] is True
    assert adapter["trainable_parameters"] == 5
    assert adapter["total_parameters"] == 100
    assert adapter["full_model_weights_saved"] is False
