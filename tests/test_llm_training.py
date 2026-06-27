from __future__ import annotations

import json

from aegis.llm_training.dataset import build_sft_examples, export_sft_dataset


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
