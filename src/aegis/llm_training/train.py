"""Train a local/open-weight LLM adapter from Aegis SFT data.

This command deliberately trains a LoRA adapter, not a full model. Heavy libraries are
imported lazily so normal Aegis installs and the offline verify gate stay lightweight.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from aegis.llm_training.dataset import DEFAULT_DATASET_PATH, export_sft_dataset

DEFAULT_ADAPTER_DIR = Path("models/aegis-local-lora")


def train_lora_adapter(
    *,
    base_model: str,
    dataset_path: Path | str = DEFAULT_DATASET_PATH,
    out_dir: Path | str = DEFAULT_ADAPTER_DIR,
    epochs: float = 1.0,
    max_steps: int = -1,
    learning_rate: float = 2e-4,
    batch_size: int = 1,
    gradient_accumulation_steps: int = 8,
    max_seq_length: int = 1024,
    lora_r: int = 8,
    lora_alpha: int = 16,
    lora_dropout: float = 0.05,
) -> dict[str, Any]:
    try:
        from datasets import load_dataset
        from peft import LoraConfig
        from transformers import AutoModelForCausalLM, AutoTokenizer, TrainingArguments
        from trl import SFTTrainer
    except ImportError as exc:  # pragma: no cover - exercised only without optional deps
        raise RuntimeError(
            "Local LLM training dependencies are missing. Install them with "
            "`uv sync --extra local-llm`."
        ) from exc

    dataset_file = Path(dataset_path)
    if not dataset_file.exists():
        export_sft_dataset(dataset_file)

    out = Path(out_dir)
    dataset = load_dataset("json", data_files=str(dataset_file), split="train")
    tokenizer = AutoTokenizer.from_pretrained(base_model, use_fast=True)
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token

    model = AutoModelForCausalLM.from_pretrained(base_model)
    if hasattr(model, "config"):
        model.config.use_cache = False

    peft_config = LoraConfig(
        r=lora_r,
        lora_alpha=lora_alpha,
        lora_dropout=lora_dropout,
        bias="none",
        task_type="CAUSAL_LM",
        target_modules=["q_proj", "k_proj", "v_proj", "o_proj"],
    )
    args = TrainingArguments(
        output_dir=str(out),
        num_train_epochs=epochs,
        max_steps=max_steps,
        per_device_train_batch_size=batch_size,
        gradient_accumulation_steps=gradient_accumulation_steps,
        learning_rate=learning_rate,
        logging_steps=5,
        save_strategy="epoch",
        report_to=[],
        remove_unused_columns=False,
    )

    trainer_kwargs: dict[str, Any] = {
        "model": model,
        "args": args,
        "train_dataset": dataset,
        "peft_config": peft_config,
        "formatting_func": lambda rows: [
            _format_messages(messages, tokenizer) for messages in rows["messages"]
        ],
    }
    # TRL versions differ on whether max_seq_length is accepted by SFTTrainer or SFTConfig.
    try:
        trainer = SFTTrainer(**trainer_kwargs, max_seq_length=max_seq_length)
    except TypeError:
        trainer = SFTTrainer(**trainer_kwargs)

    trainer.train()
    trainer.save_model(str(out))
    tokenizer.save_pretrained(str(out))

    report = {
        "base_model": base_model,
        "dataset": str(dataset_file),
        "adapter_dir": str(out),
        "examples": len(dataset),
        "epochs": epochs,
        "max_steps": max_steps,
        "lora_r": lora_r,
        "lora_alpha": lora_alpha,
        "max_seq_length": max_seq_length,
    }
    out.mkdir(parents=True, exist_ok=True)
    (out / "aegis_training_report.json").write_text(
        json.dumps(report, indent=2, sort_keys=True),
        encoding="utf-8",
    )
    return report


def _format_messages(messages: list[dict[str, str]], tokenizer: Any) -> str:
    if hasattr(tokenizer, "apply_chat_template"):
        return tokenizer.apply_chat_template(messages, tokenize=False, add_generation_prompt=False)
    parts = []
    for message in messages:
        role = message.get("role", "user").upper()
        parts.append(f"{role}: {message.get('content', '')}")
    return "\n\n".join(parts)


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="Train a local LLM LoRA adapter from Aegis data.")
    parser.add_argument("--base-model", required=True, help="Hugging Face model id or local path.")
    parser.add_argument("--dataset", default=str(DEFAULT_DATASET_PATH))
    parser.add_argument("--out", default=str(DEFAULT_ADAPTER_DIR))
    parser.add_argument("--epochs", type=float, default=1.0)
    parser.add_argument("--max-steps", type=int, default=-1)
    parser.add_argument("--learning-rate", type=float, default=2e-4)
    parser.add_argument("--batch-size", type=int, default=1)
    parser.add_argument("--gradient-accumulation-steps", type=int, default=8)
    parser.add_argument("--max-seq-length", type=int, default=1024)
    parser.add_argument("--lora-r", type=int, default=8)
    parser.add_argument("--lora-alpha", type=int, default=16)
    parser.add_argument("--lora-dropout", type=float, default=0.05)
    args = parser.parse_args(argv)
    report = train_lora_adapter(
        base_model=args.base_model,
        dataset_path=args.dataset,
        out_dir=args.out,
        epochs=args.epochs,
        max_steps=args.max_steps,
        learning_rate=args.learning_rate,
        batch_size=args.batch_size,
        gradient_accumulation_steps=args.gradient_accumulation_steps,
        max_seq_length=args.max_seq_length,
        lora_r=args.lora_r,
        lora_alpha=args.lora_alpha,
        lora_dropout=args.lora_dropout,
    )
    print(
        f"trained Aegis local LLM adapter: {report['examples']} examples -> "
        f"{report['adapter_dir']}"
    )


if __name__ == "__main__":
    main()
