from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import unicodedata
from pathlib import Path
from typing import Any

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
CONTRACT_FIXTURES = REPOSITORY_ROOT / "tests" / "fixtures" / "contracts"


def contract_fixture(name: str = "valid_contract.json") -> Path:
    return CONTRACT_FIXTURES / name


def valid_contract_mapping() -> dict[str, Any]:
    with contract_fixture().open(encoding="utf-8") as stream:
        return json.load(stream)


def expected_contract_hash(mapping: dict[str, Any]) -> str:
    """Independent oracle for the canonical interface hash rule."""

    def normalize(value: Any) -> Any:
        if isinstance(value, str):
            return unicodedata.normalize("NFC", value)
        if isinstance(value, list):
            return [normalize(item) for item in value]
        if isinstance(value, dict):
            return {
                unicodedata.normalize("NFC", key): normalize(item)
                for key, item in value.items()
            }
        return value

    normalized = normalize(mapping)
    normalized.pop("contract_hash", None)
    canonical = json.dumps(
        normalized,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def run_contract_cli(*arguments: object) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    source_root = str(REPOSITORY_ROOT / "src")
    existing_pythonpath = env.get("PYTHONPATH")
    env["PYTHONPATH"] = (
        source_root
        if not existing_pythonpath
        else os.pathsep.join((source_root, existing_pythonpath))
    )
    return subprocess.run(
        [
            sys.executable,
            "-m",
            "q_arbor.contracts.cli",
            *(str(arg) for arg in arguments),
        ],
        cwd=REPOSITORY_ROOT,
        env=env,
        check=False,
        capture_output=True,
        text=True,
    )
