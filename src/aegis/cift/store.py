"""JSONL persistence for CIFT calibration certificates."""

from __future__ import annotations

import json
from pathlib import Path

from aegis.cift.contracts import CiftCertification

DEFAULT_CERTIFICATIONS_PATH = Path(".aegis/cift/certifications.jsonl")


class CiftCertificationStore:
    def __init__(self, path: Path | str = DEFAULT_CERTIFICATIONS_PATH) -> None:
        self.path = Path(path)

    def append(self, cert: CiftCertification) -> Path:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(cert.model_dump_json() + "\n")
        return self.path

    def list(self, model_id: str | None = None, limit: int = 25) -> list[dict]:
        if not self.path.exists():
            return []
        rows: list[dict] = []
        for line in self.path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            if model_id is None or row.get("model_id") == model_id:
                rows.append(row)
        rows.sort(key=lambda r: r.get("created_at", 0.0), reverse=True)
        return rows[:limit]
