from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from q_arbor.hypotheses import (
    QHypothesisTree,
    TreePersistenceError,
    export_tree_json,
    import_arbor_tree,
    render_tree_html,
    write_tree_html,
)

FIXTURE = (
    Path(__file__).resolve().parents[1]
    / "fixtures"
    / "hypotheses"
    / "arbor_v3_tree.json"
)


def _tree() -> QHypothesisTree:
    with FIXTURE.open(encoding="utf-8") as stream:
        legacy = json.load(stream)
    return import_arbor_tree(legacy, run_id="run.render", contract_hash="f" * 64).tree


def test_json_export_is_exact_canonical_model_json() -> None:
    tree = _tree()
    exported = export_tree_json(tree)
    assert exported == tree.to_json()
    assert exported == json.dumps(
        json.loads(exported),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )


def test_html_is_deterministic_self_contained_and_xss_safe() -> None:
    tree = _tree()
    title = 'Audit </style><script>alert("title")</script>'
    first = render_tree_html(tree, title=title)
    second = render_tree_html(tree, title=title)

    assert first == second
    assert first.startswith("<!doctype html>\n")
    assert '<meta charset="utf-8">' in first
    assert "<style>" in first
    assert "http://" not in first
    assert "https://" not in first
    assert "<script" not in first.lower()
    assert "</script" not in first.lower()
    assert "<img" not in first.lower()
    assert "&lt;script&gt;alert(&#x27;root&#x27;)&lt;/script&gt;" in first
    assert "&lt;/style&gt;&lt;script&gt;" in first
    assert "Compatibility quarantine" in first
    assert "status: pending" in first
    assert "admissibility: unevaluated" in first
    assert '<pre id="canonical-json">' in first
    for forbidden in (
        "SYNTHETIC_SECRET",
        "python evaluator.py",
        "/srv/private/submission.csv",
        "Legacy development improvement",
        "Tail clipping helped & needs confirmation",
    ):
        assert forbidden not in first


def test_html_writer_writes_exact_utf8_render(tmp_path: Path) -> None:
    tree = _tree()
    destination = tmp_path / "tree report.html"
    write_tree_html(tree, destination, title="Deterministic tree")
    assert destination.read_text(encoding="utf-8") == render_tree_html(
        tree, title="Deterministic tree"
    )
    assert not list(tmp_path.glob(".tree report.html.*.tmp"))


def test_html_writer_cleanup_failure_remains_typed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    tree = _tree()
    destination = tmp_path / "tree.html"
    destination.write_text("sentinel", encoding="utf-8")

    def fail_replace(source: os.PathLike[str], target: os.PathLike[str]) -> None:
        raise OSError("injected replace failure")

    def fail_unlink(path: os.PathLike[str]) -> None:
        raise OSError("injected cleanup failure")

    monkeypatch.setattr(os, "replace", fail_replace)
    monkeypatch.setattr(os, "unlink", fail_unlink)
    with pytest.raises(TreePersistenceError, match="clean up temporary tree HTML"):
        write_tree_html(tree, destination)
    assert destination.read_text(encoding="utf-8") == "sentinel"
