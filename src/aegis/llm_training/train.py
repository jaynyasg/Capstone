"""Train a local/open-weight LLM from Aegis SFT data.

The default path is full-weight supervised fine-tuning: all model parameters are trainable
and the output directory contains a standalone Hugging Face model. A LoRA adapter path is
also available for smaller machines. Heavy libraries are imported lazily so normal Aegis
installs and the offline verify gate stay lightweight.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from aegis.llm_training.dataset import DEFAULT_DATASET_PATH, export_sft_dataset

DEFAULT_ADAPTER_DIR = Path("models/aegis-local-lora")
DEFAULT_FULL_MODEL_DIR = Path("models/aegis-local-full")
TRAINING_METHODS = ("full", "lora")


def train_local_model(
    *,
    base_model: str,
    dataset_path: Path | str = DEFAULT_DATASET_PATH,
    out_dir: Path | str | None = None,
    training_method: str = "full",
    epochs: float = 1.0,
    max_steps: int = -1,
    learning_rate: float | None = None,
    batch_size: int = 1,
    gradient_accumulation_steps: int = 8,
    max_seq_length: int = 1024,
    lora_r: int = 8,
    lora_alpha: int = 16,
    lora_dropout: float = 0.05,
) -> dict[str, Any]:
    method = _normalize_training_method(training_method)
    try:
        from datasets import load_dataset
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

    out = Path(out_dir) if out_dir is not None else _default_out_dir(method)
    dataset = load_dataset("json", data_files=str(dataset_file), split="train")
    tokenizer = AutoTokenizer.from_pretrained(base_model, use_fast=True)
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token

    model = AutoModelForCausalLM.from_pretrained(base_model)
    if hasattr(model, "config"):
        model.config.use_cache = False

    peft_config = None
    if method == "lora":
        try:
            from peft import LoraConfig
        except ImportError as exc:  # pragma: no cover - exercised only without optional deps
            raise RuntimeError(
                "LoRA training dependencies are missing. Install them with "
                "`uv sync --extra local-llm`."
            ) from exc
        peft_config = LoraConfig(
            r=lora_r,
            lora_alpha=lora_alpha,
            lora_dropout=lora_dropout,
            bias="none",
            task_type="CAUSAL_LM",
            target_modules=["q_proj", "k_proj", "v_proj", "o_proj"],
        )

    effective_learning_rate = learning_rate
    if effective_learning_rate is None:
        effective_learning_rate = 5e-5 if method == "full" else 2e-4
    args = TrainingArguments(
        output_dir=str(out),
        num_train_epochs=epochs,
        max_steps=max_steps,
        per_device_train_batch_size=batch_size,
        gradient_accumulation_steps=gradient_accumulation_steps,
        learning_rate=effective_learning_rate,
        logging_steps=5,
        save_strategy="epoch",
        report_to=[],
        remove_unused_columns=False,
    )

    trainer_kwargs: dict[str, Any] = {
        "model": model,
        "args": args,
        "train_dataset": dataset,
        "formatting_func": lambda rows: _formatting_func(rows, tokenizer),
    }
    if peft_config is not None:
        trainer_kwargs["peft_config"] = peft_config
    # TRL versions differ on whether max_seq_length is accepted by SFTTrainer or SFTConfig.
    try:
        trainer = SFTTrainer(**trainer_kwargs, max_seq_length=max_seq_length)
    except TypeError:
        trainer = SFTTrainer(**trainer_kwargs)

    trainer.train()
    trainer.save_model(str(out))
    tokenizer.save_pretrained(str(out))

    trainable = _trainable_parameter_report(trainer.model)
    report = {
        "base_model": base_model,
        "dataset": str(dataset_file),
        "training_method": method,
        "output_dir": str(out),
        "model_dir": str(out) if method == "full" else None,
        "adapter_dir": str(out) if method == "lora" else None,
        "examples": len(dataset),
        "epochs": epochs,
        "max_steps": max_steps,
        "learning_rate": effective_learning_rate,
        "lora_r": lora_r,
        "lora_alpha": lora_alpha,
        "max_seq_length": max_seq_length,
        **trainable,
    }
    out.mkdir(parents=True, exist_ok=True)
    (out / "aegis_training_report.json").write_text(
        json.dumps(report, indent=2, sort_keys=True),
        encoding="utf-8",
    )
    return report


def train_full_model(
    *,
    base_model: str,
    dataset_path: Path | str = DEFAULT_DATASET_PATH,
    out_dir: Path | str = DEFAULT_FULL_MODEL_DIR,
    epochs: float = 1.0,
    max_steps: int = -1,
    learning_rate: float = 5e-5,
    batch_size: int = 1,
    gradient_accumulation_steps: int = 8,
    max_seq_length: int = 1024,
) -> dict[str, Any]:
    return train_local_model(
        base_model=base_model,
        dataset_path=dataset_path,
        out_dir=out_dir,
        training_method="full",
        epochs=epochs,
        max_steps=max_steps,
        learning_rate=learning_rate,
        batch_size=batch_size,
        gradient_accumulation_steps=gradient_accumulation_steps,
        max_seq_length=max_seq_length,
    )


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
    return train_local_model(
        base_model=base_model,
        dataset_path=dataset_path,
        out_dir=out_dir,
        training_method="lora",
        epochs=epochs,
        max_steps=max_steps,
        learning_rate=learning_rate,
        batch_size=batch_size,
        gradient_accumulation_steps=gradient_accumulation_steps,
        max_seq_length=max_seq_length,
        lora_r=lora_r,
        lora_alpha=lora_alpha,
        lora_dropout=lora_dropout,
    )


def _normalize_training_method(method: str) -> str:
    normalized = str(method or "full").lower()
    if normalized not in TRAINING_METHODS:
        raise ValueError(f"unsupported training method {method!r}; use one of: full, lora")
    return normalized


def _default_out_dir(method: str) -> Path:
    return DEFAULT_FULL_MODEL_DIR if method == "full" else DEFAULT_ADAPTER_DIR


def _trainable_parameter_report(model: Any) -> dict[str, Any]:
    total = 0
    trainable = 0
    for param in getattr(model, "parameters", lambda: [])():
        count = int(param.numel())
        total += count
        if getattr(param, "requires_grad", False):
            trainable += count
    ratio = (trainable / total) if total else 0.0
    return {
        "trainable_parameters": trainable,
        "total_parameters": total,
        "trainable_parameter_ratio": ratio,
        "full_model_weights_saved": ratio > 0.5,
    }


def _format_messages(messages: list[dict[str, str]], tokenizer: Any) -> str:
    if hasattr(tokenizer, "apply_chat_template"):
        return tokenizer.apply_chat_template(messages, tokenize=False, add_generation_prompt=False)
    parts = []
    for message in messages:
        role = message.get("role", "user").upper()
        parts.append(f"{role}: {message.get('content', '')}")
    return "\n\n".join(parts)


def _formatting_func(rows: dict[str, Any], tokenizer: Any) -> str | list[str]:
    messages = rows["messages"]
    if messages and isinstance(messages[0], dict):
        return _format_messages(messages, tokenizer)
    return [_format_messages(message_list, tokenizer) for message_list in messages]


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="Train a local LLM from Aegis data.")
    parser.add_argument("--base-model", required=True, help="Hugging Face model id or local path.")
    parser.add_argument("--dataset", default=str(DEFAULT_DATASET_PATH))
    parser.add_argument(
        "--training-method",
        choices=TRAINING_METHODS,
        default="full",
        help="full trains and saves all model weights; lora trains only an adapter.",
    )
    parser.add_argument("--out", default=None)
    parser.add_argument("--epochs", type=float, default=1.0)
    parser.add_argument("--max-steps", type=int, default=-1)
    parser.add_argument(
        "--learning-rate",
        type=float,
        default=None,
        help="Default: 5e-5 for full fine-tune, 2e-4 for LoRA.",
    )
    parser.add_argument("--batch-size", type=int, default=1)
    parser.add_argument("--gradient-accumulation-steps", type=int, default=8)
    parser.add_argument("--max-seq-length", type=int, default=1024)
    parser.add_argument("--lora-r", type=int, default=8)
    parser.add_argument("--lora-alpha", type=int, default=16)
    parser.add_argument("--lora-dropout", type=float, default=0.05)
    args = parser.parse_args(argv)
    report = train_local_model(
        base_model=args.base_model,
        dataset_path=args.dataset,
        out_dir=args.out,
        training_method=args.training_method,
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
    artifact = report["adapter_dir"] if report["training_method"] == "lora" else report["model_dir"]
    print(
        f"trained Aegis local LLM ({report['training_method']}): "
        f"{report['examples']} examples -> {artifact}"
    )


if __name__ == "__main__":
    main()
