"""Local LLM training helpers.

This package is intentionally optional. Importing :mod:`aegis` should never require
Transformers, TRL, PEFT, Accelerate, or a local model download. Heavy dependencies are
loaded only by the training CLI.
"""

from aegis.llm_training.dataset import SftExample, build_sft_examples, export_sft_dataset

__all__ = ["SftExample", "build_sft_examples", "export_sft_dataset"]
