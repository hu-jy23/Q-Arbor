from __future__ import annotations

import hashlib
import html
import re
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
    atomic_write,
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


_REPORT_STYLE = """*{box-sizing:border-box}body{margin:0;background:#f4f6fa;color:#172033;font:16px/1.5 ui-sans-serif,system-ui,sans-serif}main,.hero{max-width:1160px;margin:auto;padding:24px}.hero{padding-top:40px}.hero h1{font-size:clamp(2rem,5vw,3.4rem);line-height:1.05;margin:.2rem 0 1rem}.hero,.card{background:#fff;border:1px solid #d6deea;border-radius:16px;margin:18px auto}.hero{border-top:8px solid #2563eb}.hero.pass{border-top-color:#147a4b}.hero.partial{border-top-color:#a45b00}.hero.fail{border-top-color:#b42318}.badge{display:inline-block;border-radius:999px;padding:4px 10px;font-weight:700;margin:3px;background:#e8edf5;overflow-wrap:anywhere}.pass .badge,.badge.pass{background:#d9f5e7;color:#075c36}.partial .badge,.badge.partial{background:#fff0cf;color:#713e00}.fail .badge,.badge.fail{background:#ffe0dd;color:#8e1b13}.grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:16px}.grid>*{min-width:0}.card{padding:20px}h2{font-size:1.35rem;margin-top:0}h3{font-size:1.05rem;margin-bottom:.4rem}dl{display:grid;grid-template-columns:minmax(9rem,15rem) minmax(0,1fr);gap:6px 14px}dt{font-weight:700;color:#43516a}dd{margin:0;overflow-wrap:anywhere}.muted{color:#59677b}.code{font-family:ui-monospace,SFMono-Regular,monospace;overflow-wrap:anywhere}.node{border-left:4px solid #91a4c2;padding-left:14px;margin:14px 0;min-width:0}.node.depth-0{border-left-color:#2563eb}.evidence{scroll-margin-top:1rem;border-top:1px solid #e0e6ef;padding:10px 0;min-width:0;overflow-wrap:anywhere}.evidence:target{background:#fff5cc}.table-wrap{max-width:100%;overflow-x:auto}table{width:100%;table-layout:fixed;border-collapse:collapse}th,td{text-align:left;vertical-align:top;border-bottom:1px solid #e0e6ef;padding:9px;overflow-wrap:anywhere}a{color:#075eaa;text-underline-offset:2px;overflow-wrap:anywhere}ul{padding-left:1.3rem}@media (max-width:720px){.hero,main{padding:16px}.grid{grid-template-columns:minmax(0,1fr)}dl{grid-template-columns:minmax(0,1fr)}.node{border-left:0;padding-left:0;margin-left:0}.hero h1{font-size:2rem}th,td{padding:10px 7px}}"""


def render_research_report(
    package: Mapping[str, Any], session_root: str | Path
) -> str:
    """Render a deterministic, offline HTML view of audited package sources."""
    raw = normalize_mapping(package)
    if raw.get("artifact_type") == "research_package":
        raw = raw["payload"]  # type: ignore[assignment]
    audit = audit_research_package(raw, session_root)
    status = audit.integrity_status
    root = Path(session_root)
    tree: Any = None
    identity_failed = status == "fail"
    if not identity_failed:
        try:
            tree = load_tree(root / str(raw["tree"]["relative_path"]))
        except Exception:
            tree = None
    tree_map = tree.to_dict() if tree is not None else {}
    nodes = tree_map.get("nodes", []) if isinstance(tree_map, Mapping) else []
    nodes = [n for n in nodes if isinstance(n, Mapping)]
    anchors: dict[str, str] = {}
    used: set[str] = set()
    for node in nodes:
        for evidence in _as_records(node.get("evidence_refs")):
            evidence_id = evidence.get("evidence_id")
            if isinstance(evidence_id, str):
                anchors[evidence_id] = _evidence_anchor(evidence_id, used)

    hero = [
        f'<header class="hero {h(status)}"><p>Q-Arbor partial prototype</p>',
        "<h1>Research report</h1>",
        f'<span class="badge {h(status)}">integrity_status={h(status)}</span>',
        f'<span class="badge">claim_scope={h(raw.get("claim_scope"))}</span>',
        f'<span class="badge">final_state={h(raw.get("final_state"))}</span>',
        f"<dl>{_def('Run ID', raw.get('run_id'))}</dl></header>",
    ]
    counts = tree_map.get("counts", {}) if isinstance(tree_map, Mapping) else {}
    summary = ["<section class=\"card\"><h2>Operational counts & audit summary</h2><dl>"]
    for key in ("proposals", "unique_candidates", "candidate_families", "attempts", "evaluation_queries", "admissible_evidence"):
        if isinstance(counts, Mapping) and key in counts:
            summary.append(_def_link(key.replace("_", " "), counts[key], "evidence-tree-source"))
    summary.extend([_def_link("Audited missing/issues", len(audit.missing_artifacts), "audit-artifacts"), _def_link("Declared missing artifacts", raw.get("missing_artifacts"), "audit-artifacts"), "</dl></section>"])
    sections = ["<main>", *hero, '<div class="grid">', *summary, _failure_section(nodes, anchors), _cost_section(nodes), "</div>", _tree_section(nodes, anchors, raw), _split_section(nodes, anchors), _qualification_section(), _artifact_section(raw, audit), "<p class=\"muted\">Caveat: synthetic/development-only; this report does not establish performance conclusions. The sealed final state has not been opened.</p>", "</main>"]
    return "<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"><title>Q-Arbor research report</title><style>" + _REPORT_STYLE + "</style></head><body>" + "".join(sections) + "</body></html>\n"


def write_research_report(
    package: Mapping[str, Any], session_root: str | Path, destination: str | Path
) -> None:
    """Atomically persist deterministic UTF-8 research-report HTML."""
    target = Path(destination)
    target.parent.mkdir(parents=True, exist_ok=True)
    atomic_write(target, render_research_report(package, session_root).encode("utf-8"))


def _as_records(value: Any) -> list[Mapping[str, Any]]:
    return [item for item in value if isinstance(item, Mapping)] if isinstance(value, (list, tuple)) else []


def _evidence_anchor(value: str, used: set[str]) -> str:
    slug = re.sub(r"[^A-Za-z0-9_-]+", "-", value).strip("-") or "id"
    candidate = "evidence-" + slug
    if candidate in used:
        candidate += "-" + hashlib.sha256(value.encode("utf-8")).hexdigest()[:10]
    used.add(candidate)
    return candidate


def h(value: Any) -> str:
    return html.escape("unavailable" if value is None else str(value), quote=True)


def _def(label: str, value: Any) -> str:
    return f"<dt>{h(label)}</dt><dd>{h(value)}</dd>"


def _def_html(label: str, value: str) -> str:
    return f"<dt>{h(label)}</dt><dd>{value}</dd>"


def _def_link(label: str, value: Any, anchor: str) -> str:
    return f'<dt>{h(label)}</dt><dd><a href="#{anchor}">{h(value)}</a></dd>'


def _link(value: Any, anchors: Mapping[str, str]) -> str:
    text = h(value)
    return f'<a href="#{anchors[value]}">{text}</a>' if isinstance(value, str) and value in anchors else text


def _tree_section(nodes: list[Mapping[str, Any]], anchors: Mapping[str, str], raw: Mapping[str, Any]) -> str:
    source, head = raw.get("tree"), raw.get("research_head")
    source_html = f'<div class="evidence" id="evidence-tree-source"><strong>Audited tree source</strong><dl>{_def("artifact_id", _mapping_value(source, "artifact_id"))}{_def("research_head sequence", _mapping_value(head, "last_sequence"))}{_def("research_head hash", _mapping_value(head, "last_event_hash"))}</dl></div>'
    out = ["<section class=\"card\"><h2>Tree overview</h2>", source_html]
    if not nodes:
        return "".join(out + ['<p class="muted">unavailable — tree source missing or invalid.</p></section>'])
    for node in nodes:
        evidence = _as_records(node.get("evidence_refs"))
        valid = [e for e in evidence if e.get("status") == "valid" and e.get("evidence_id") in anchors]
        score = node.get("score")
        score_text = (f'<a href="#{anchors[valid[0]["evidence_id"]]}">score: {h(score)}</a>' if score is not None and valid else "unavailable")
        out.append(f'<article class="node depth-{h(node.get("depth"))}"><h3>{h(node.get("id"))}</h3><p><span class="badge">status={h(node.get("status"))}</span> <span class="badge">admissibility={h(node.get("admissibility"))}</span></p><dl>{_def("Parent", node.get("parent_id"))}{_def_html("Score", score_text)}{_def("Mechanism", _mapping_value(node.get("hypothesis"), "mechanism"))}</dl><h3>Evidence</h3>')
        if not evidence:
            out.append('<p class="muted">unavailable — no evidence persisted.</p>')
        for item in evidence:
            eid = item.get("evidence_id")
            anchor = anchors.get(eid) if isinstance(eid, str) else None
            claim = h(item.get("claim"))
            claim_link = f'<a href="#{anchor}">{claim}</a>' if anchor else claim
            out.append(f'<div class="evidence" id="{h(anchor or "evidence-unavailable")}"><strong>{_link(eid, anchors)}</strong>: {claim_link} <span class="muted">status={h(item.get("status"))}, split={h(item.get("split_role"))}</span></div>')
        out.append("</article>")
    return "".join(out + ["</section>"])


def _mapping_value(value: Any, key: str) -> Any:
    return value.get(key) if isinstance(value, Mapping) else None


def _failure_section(nodes: list[Mapping[str, Any]], anchors: Mapping[str, str]) -> str:
    out = ['<section class="card"><h2>Failure categories</h2>']
    failures = [n for n in nodes if isinstance(n.get("failure"), Mapping) and n["failure"].get("failure_type") != "none"]
    if not failures:
        return "".join(out + ['<p class="muted">unavailable — no persisted failure category.</p></section>'])
    for node in failures:
        failure = node["failure"]
        ids = failure.get("evidence_ids", [])
        out.append(f"<h3>{h(node.get('id'))}: {h(failure.get('failure_type'))}</h3><p>{h(failure.get('summary'))}</p><p>evidence: {', '.join(_link(i, anchors) for i in ids) if isinstance(ids, list) and ids else 'unavailable'}</p>")
    return "".join(out + ["</section>"])


def _cost_section(nodes: list[Mapping[str, Any]]) -> str:
    hashes = sorted({str(_mapping_value(n.get("scope"), "cost_model_sha256")) for n in nodes if _mapping_value(n.get("scope"), "cost_model_sha256")})
    value = h(", ".join(hashes) if hashes else None)
    return '<section class="card"><h2>Cost summary</h2><p>unavailable — no persisted cost metric in package</p><p class="code">cost_model_sha256 provenance: <a href="#evidence-tree-source">' + value + "</a></p></section>"


def _split_section(nodes: list[Mapping[str, Any]], anchors: Mapping[str, str]) -> str:
    rows = []
    for node in nodes:
        for item in _as_records(node.get("evidence_refs")):
            rows.append(f"<tr><td>{h(node.get('id'))}</td><td>{h(item.get('split_role'))}</td><td>{_link(item.get('evidence_id'), anchors)}</td></tr>")
    body = "".join(rows) or '<tr><td colspan="3">unavailable</td></tr>'
    return f'<section class="card"><h2>Split audit</h2><div class="table-wrap"><table><thead><tr><th>Node</th><th>Split role</th><th>Evidence</th></tr></thead><tbody>{body}</tbody></table></div></section>'


def _qualification_section() -> str:
    rows = "".join(f"<tr><td>C0{i}</td><td>unavailable</td><td>unavailable — no package evidence</td></tr>" for i in range(1, 7))
    return f'<section class="card"><h2>C01–C06 naming qualification</h2><div class="table-wrap"><table><thead><tr><th>Component</th><th>Status</th><th>Evidence</th></tr></thead><tbody>{rows}</tbody></table></div></section>'


def _artifact_section(raw: Mapping[str, Any], audit: ResearchPackageAudit) -> str:
    issues = list(audit.missing_artifacts)
    declared = raw.get("missing_artifacts")
    if isinstance(declared, list):
        issues.extend(str(item) for item in declared if str(item) not in issues)
    body = ", ".join(h(item) for item in issues) if issues else "none"
    return f'<section class="card" id="audit-artifacts"><h2>Artifact/missing audit</h2><p>{body}</p></section>'
