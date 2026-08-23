from __future__ import annotations

import hashlib
import html
import json
from pathlib import Path

from q_arbor.reporting import (
    audit_research_package,
    render_research_report,
    write_research_report,
)
from q_arbor.hypotheses import freeze_tree
from tests.integration.test_research_package import _package


def _report_ref(root: Path, payload: bytes) -> dict[str, str]:
    path = root / "reports/research.html"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(payload)
    return {
        "artifact_id": "report.research.html",
        "kind": "q-arbor.synthetic.v1",
        "relative_path": "reports/research.html",
        "sha256": hashlib.sha256(payload).hexdigest(),
        "media_type": "text/html",
    }


def _package_with_report(root: Path) -> dict[str, object]:
    package = _package(root)
    package["reports"] = [
        package["reports"][0],  # type: ignore[index]
        _report_ref(root, b"placeholder report"),
    ]
    return package


def test_research_report_is_auditable_fixed_point_and_self_contained(tmp_path: Path) -> None:
    package = _package_with_report(tmp_path)
    first = render_research_report(package, tmp_path)
    report_ref = _report_ref(tmp_path, first.encode("utf-8"))
    package["reports"][1] = report_ref  # type: ignore[index]
    write_research_report(package, tmp_path, tmp_path / "reports/research.html")

    assert audit_research_package(package, tmp_path).integrity_status == "pass"
    assert first == (tmp_path / "reports/research.html").read_text(encoding="utf-8")
    assert first == render_research_report(package, tmp_path)
    assert "Q-Arbor partial prototype" in first
    assert "final_state=sealed_unopened" in first
    assert "tree overview" in first.lower()
    assert "failure categories" in first.lower()
    assert "cost summary" in first.lower()
    assert "split audit" in first.lower()
    assert "C01" in first and "C06" in first
    assert "artifact/missing audit" in first.lower()
    assert 'id="evidence-evidence-child-1"' in first
    assert 'href="#evidence-evidence-child-1"' in first
    assert "score: 0.125" in first
    assert "unavailable — no persisted cost metric in package" in first
    assert "http://" not in first and "https://" not in first
    assert "<script" not in first.lower() and "<img" not in first.lower()


def test_research_report_degrades_when_named_report_is_missing(tmp_path: Path) -> None:
    package = _package_with_report(tmp_path)
    (tmp_path / "reports/one.json").unlink()
    rendered = render_research_report(package, tmp_path)
    assert audit_research_package(package, tmp_path).integrity_status == "partial"
    assert "report.one:missing" in rendered
    assert "integrity_status=partial" in rendered


def test_identity_failure_is_forensic_only(tmp_path: Path) -> None:
    package = _package_with_report(tmp_path)
    tree_ref = package["tree"]  # type: ignore[index]
    tree_ref["artifact_id"] = "snapshot.primary"  # type: ignore[index]
    tree_path = tmp_path / tree_ref["relative_path"]  # type: ignore[index]
    tree = json.loads(tree_path.read_text(encoding="utf-8"))
    tree["nodes"][1]["score"] = 0.5
    freeze_tree(tree).write(tree_path)
    assert audit_research_package(package, tmp_path).integrity_status == "fail"
    rendered = render_research_report(package, tmp_path)
    assert "integrity_status=fail" in rendered and "snapshot.primary" in rendered
    assert "score: 0.125" not in rendered and "evidence.child.1" not in rendered


def test_research_report_escapes_untrusted_text_and_has_mobile_css(tmp_path: Path) -> None:
    package = _package_with_report(tmp_path)
    tree_path = tmp_path / package["tree"]["relative_path"]  # type: ignore[index]
    tree = json.loads(tree_path.read_text(encoding="utf-8"))
    tree["nodes"][1]["hypothesis"]["mechanism"] = '<img src="x">& evil'
    frozen = freeze_tree(tree)
    frozen.write(tree_path)
    package["tree"]["sha256"] = hashlib.sha256(tree_path.read_bytes()).hexdigest()  # type: ignore[index]
    assert audit_research_package(package, tmp_path).integrity_status == "pass"
    with_report = render_research_report(package, tmp_path)
    assert html.escape('<img src="x">& evil') in with_report
    assert '<img src="x">& evil' not in with_report
    assert '<meta name="viewport" content="width=device-width, initial-scale=1">' in with_report
    assert "grid-template-columns:minmax(0,1fr)" in with_report.replace(" ", "")
    assert "@media(max-width:720px)" in with_report.replace(" ", "")
    assert "overflow-wrap:anywhere" in with_report.replace(" ", "")
    assert "min-width" not in with_report
    assert 'href="#evidence-tree-source"' in with_report
    assert "artifact_id" in with_report and "research_head sequence" in with_report
