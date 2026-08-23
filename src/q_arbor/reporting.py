from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .contracts import load_contract
from .evaluation import ArtifactRef, ContentAddressedArtifactStore
from .evaluation.codec import (
    canonical_json_bytes,
    decode_json_bytes,
    normalize_mapping,
    validate_definition,
    validate_discriminator,
)
from .hypotheses import load_tree

@dataclass(frozen=True, slots=True)
class ResearchPackageAudit:
    integrity_status: str
    missing_artifacts: tuple[str, ...]
    reasons: tuple[str, ...] = ()

    @property
    def status(self) -> str:
        return self.integrity_status

    @property
    def degraded(self) -> bool:
        return self.integrity_status != "pass"

    def to_dict(self) -> dict[str, Any]:
        return {
            "integrity_status": self.integrity_status,
            "missing_artifacts": list(self.missing_artifacts),
            "reasons": list(self.reasons),
        }

def _issue(artifact_id: str, reason: str) -> str:
    return f"{artifact_id}:{reason}"


def _verify(
    store: ContentAddressedArtifactStore,
    root: Path,
    ref: ArtifactRef,
    issues: list[str],
) -> bool:
    try:
        store.verify(ref)
        return True
    except Exception:
        path = root / Path(ref.relative_path)
        if ref.relative_path and path.is_symlink():
            reason = "symlink"
        elif not path.exists():
            reason = "missing"
        else:
            reason = "digest_mismatch"
        issues.append(_issue(ref.artifact_id, reason))
        return False

def _refs(package: Mapping[str, Any]) -> tuple[ArtifactRef, ...]:
    values: list[ArtifactRef] = [
        ArtifactRef.from_mapping(package["contract"]),
        ArtifactRef.from_mapping(package["tree"]),
        ArtifactRef.from_mapping(package["ledger"]["artifact"]),
    ]
    candidate = package["selected_candidate"]
    if candidate is not None:
        values.append(ArtifactRef.from_mapping(candidate))
    values.extend(ArtifactRef.from_mapping(item) for item in package["reports"])
    return tuple(values)

def audit_research_package(
    package: Mapping[str, Any], session_root: str | Path
) -> ResearchPackageAudit:
    raw = normalize_mapping(package)
    if raw.get("artifact_type") == "research_package":
        validate_discriminator(raw, "research_package")
        raw = raw["payload"]  # type: ignore[assignment]
    validate_definition(raw, "ResearchPackage")
    root = Path(session_root)
    refs = _refs(raw)
    issues: list[str] = []
    seen: set[str] = set()
    for ref in refs:
        if ref.artifact_id in seen:
            issues.append(_issue(ref.artifact_id, "conflict"))
        seen.add(ref.artifact_id)
    store = ContentAddressedArtifactStore.create(root)
    available = [_verify(store, root, ref, issues) for ref in refs]
    contract = tree = None
    if available[0]:
        try:
            contract = load_contract(root / refs[0].relative_path)
        except Exception:
            issues.append(_issue(refs[0].artifact_id, "invalid"))
    if available[1]:
        try:
            tree = load_tree(root / refs[1].relative_path)
        except Exception:
            issues.append(_issue(refs[1].artifact_id, "invalid"))
    if contract is not None and tree is not None:
        if tree.contract_hash != contract.sha256:
            issues.append(_issue(refs[1].artifact_id, "contract_mismatch"))
        if tree.run_id != raw["run_id"]:
            issues.append(_issue(refs[1].artifact_id, "run_mismatch"))
        if dict(tree.ledger_head) != dict(raw["research_head"]):
            issues.append(_issue(refs[1].artifact_id, "research_head_mismatch"))
    if available[2]:
        try:
            ledger = normalize_mapping(decode_json_bytes(store.read_bytes(refs[2])))
            if canonical_json_bytes(ledger) != store.read_bytes(refs[2]):
                raise ValueError("noncanonical")
            expected = {
                "run_id": raw["run_id"],
                "contract_hash": contract.sha256 if contract is not None else None,
                "last_sequence": raw["ledger"]["last_sequence"],
                "last_event_hash": raw["ledger"]["last_event_hash"],
            }
            if any(ledger.get(key) != value for key, value in expected.items()):
                issues.append(_issue(refs[2].artifact_id, "head_mismatch"))
            if dict(raw["ledger"]) != {
                "artifact": raw["ledger"]["artifact"],
                "last_sequence": ledger.get("last_sequence"),
                "last_event_hash": ledger.get("last_event_hash"),
            }:
                issues.append(_issue(refs[2].artifact_id, "package_head_mismatch"))
        except Exception:
            issues.append(_issue(refs[2].artifact_id, "invalid"))
    candidate_none = raw["selected_candidate"] is None
    if candidate_none and raw["stop_reason"] != "no_valid_candidate":
        issues.append(_issue("selected_candidate", "inconsistent"))
    unique = tuple(sorted(set(issues)))
    critical_ids = {ref.artifact_id for ref in refs[:3]}
    if raw["selected_candidate"] is not None:
        critical_ids.add(refs[3].artifact_id)
    critical = any(
        item.endswith(":conflict")
        or item.startswith("selected_candidate:")
        or item.split(":", 1)[0] in critical_ids
        for item in unique
    )
    status = "pass" if not unique else ("fail" if critical else "partial")
    return ResearchPackageAudit(status, unique, unique)
verify_research_package = audit_research_package
