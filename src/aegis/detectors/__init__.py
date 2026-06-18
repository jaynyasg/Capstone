"""Modular detector stages. Each returns the common DetectorResult shape."""

from aegis.detectors.base import Detector, ScanContext
from aegis.detectors.encodings import EncodingScanner
from aegis.detectors.honeytokens import HoneytokenDetector, HoneytokenRegistry
from aegis.detectors.nimbus import NimbusLedger
from aegis.detectors.partial import PartialLeakDetector
from aegis.detectors.patterns import SecretPatternScanner
from aegis.detectors.tool_args import ToolCallArgumentScanner

__all__ = [
    "Detector",
    "ScanContext",
    "EncodingScanner",
    "HoneytokenDetector",
    "HoneytokenRegistry",
    "NimbusLedger",
    "PartialLeakDetector",
    "SecretPatternScanner",
    "ToolCallArgumentScanner",
]
