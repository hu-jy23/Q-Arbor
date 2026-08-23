from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from q_arbor.contracts import freeze_contract
from q_arbor.evaluation import ArtifactRef
from q_arbor.hypotheses import freeze_tree
from q_arbor.reporting import audit_research_package

def _ref(root: Path, artifact_id: str, relative_path: str, payload: bytes) -> dict[str, Any]:
    path = root / relative_path
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(payload)
    return {
        "artifact_id": artifact_id,
        "kind": "q-arbor.synthetic.v1",
        "relative_path": relative_path,
        "sha256": hashlib.sha256(payload).hexdigest(),
        "media_type": "application/json",
    }

def _package(root: Path) -> dict[str, Any]:
    contract = freeze_contract(json.loads(Path("tests/fixtures/contracts/valid_contract.json").read_text()))
    contract_path = root / "contract.json"
    contract.write(contract_path)
    tree_draft = json.loads(Path("tests/fixtures/hypotheses/valid_tree_draft.json").read_text())
    tree_draft["contract_hash"] = contract.sha256
    tree = freeze_tree(tree_draft)
    tree_path = root / "tree.json"
    tree.write(tree_path)
    head = {
        "run_id": tree.run_id,
        "contract_hash": contract.sha256,
        "last_sequence": tree.ledger_head["last_sequence"],
        "last_event_hash": tree.ledger_head["last_event_hash"],
    }
    ledger_bytes = json.dumps(head, sort_keys=True, separators=(",", ":")).encode()
    refs = [
        _ref(root, "contract", "contract.json", contract_path.read_bytes()),
        _ref(root, "tree", "tree.json", tree_path.read_bytes()),
        _ref(root, "ledger.head", "ledger/head.json", ledger_bytes),
        _ref(root, "candidate.primary", "candidate.json", b"{}"),
        _ref(root, "report.one", "reports/one.json", b"one"),
        _ref(root, "summary.mobile", "reports/two.json", b"two"),
    ]
    return {
        "schema_version": "1.0",
        "run_id": tree.run_id,
        "contract": refs[0],
        "selected_candidate": refs[3],
        "selected_commit": "a" * 40,
        "tree": refs[1],
        "research_head": dict(tree.ledger_head),
        "ledger": {
            "artifact": refs[2],
            "last_sequence": head["last_sequence"],
            "last_event_hash": head["last_event_hash"],
        },
        "family_snapshot_hash": "b" * 64,
        "reports": [refs[4], refs[5]],
        "stop_reason": "frontier_exhausted",
        "final_state": "sealed_unopened",
        "integrity_status": "pass",
        "claim_scope": "development_only",
        "missing_artifacts": [],
    }

def test_complete_package_passes_from_recomputed_integrity(tmp_path: Path) -> None:
    package = _package(tmp_path)
    package["integrity_status"] = "fail"
    result = audit_research_package(package, tmp_path)
    assert result.integrity_status == "pass"
    assert result.missing_artifacts == ()

def test_missing_report_is_partial_and_stable(tmp_path: Path) -> None:
    package = _package(tmp_path)
    (tmp_path / "reports/two.json").unlink()
    result = audit_research_package(package, tmp_path)
    assert result.integrity_status == "partial"
    assert result.missing_artifacts == ("summary.mobile:missing",)

def test_tampered_tree_fails_closed(tmp_path: Path) -> None:
    package = _package(tmp_path)
    (tmp_path / "tree.json").write_bytes(b"tampered")
    result = audit_research_package(package, tmp_path)
    assert result.integrity_status == "fail"
    assert result.missing_artifacts == ("tree:digest_mismatch",)

def test_null_candidate_requires_terminal_no_valid_candidate(tmp_path: Path) -> None:
    package = _package(tmp_path)
    package["selected_candidate"] = None
    result = audit_research_package(package, tmp_path)
    assert result.integrity_status == "fail"
    assert result.missing_artifacts == ("selected_candidate:inconsistent",)
