#!/usr/bin/env python3
"""Verify the C8 importer against the pinned Arbor Node/IdeaTree serializer."""

from __future__ import annotations

import argparse
import importlib.metadata
import json
import subprocess
import tempfile
from pathlib import Path

import arbor
from arbor.coordinator.idea_tree import IdeaTree, Node

from q_arbor.hypotheses import (
    apply_tree_event,
    export_tree_json,
    import_arbor_tree,
    render_tree_html,
)

_CONTRACT_HASH = "f" * 64
_SECRET = "C8_RUNTIME_SECRET_MUST_NOT_CROSS"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--expected-arbor-commit", required=True)
    args = parser.parse_args()

    arbor_file = Path(arbor.__file__).resolve()
    checkout_root = arbor_file.parent.parent
    actual_commit = _git(checkout_root, "rev-parse", "HEAD").strip()
    if actual_commit != args.expected_arbor_commit:
        raise RuntimeError("Arbor source commit differs from the frozen C1 identity")
    if _git(checkout_root, "status", "--porcelain"):
        raise RuntimeError("Arbor source checkout is dirty")

    root = Node(
        id="ROOT",
        parent_id=None,
        children_ids=["1", "2"],
        depth=0,
        hypothesis="Pinned Arbor baseline <script>alert(1)</script>",
        status="done",
        result="legacy root result",
        score=0.1,
        insight="legacy root insight",
        eval_status="scored",
    )
    child = Node(
        id="1",
        parent_id="ROOT",
        depth=1,
        hypothesis="Pinned Arbor candidate",
        status="merged",
        result="legacy child result",
        score=0.2,
        test_score=0.18,
        code_ref="refs/heads/idea-1",
        eval_status="scored",
        stop_reason="finished",
        attempt=2,
    )
    old_mapping = {
        "id": "2",
        "parent_id": "ROOT",
        "children_ids": [],
        "depth": 1,
        "hypothesis": "Pinned old score delta",
        "status": "done",
        "score_delta": -0.03,
        "eval_status": "scored",
    }
    old_node = Node.from_dict(old_mapping)
    if old_node.score != -0.03:
        raise RuntimeError("pinned Arbor no longer accepts score_delta")

    with tempfile.TemporaryDirectory(prefix="q-arbor-c8-") as directory:
        tree_path = Path(directory) / "idea_tree.json"
        legacy_tree = IdeaTree(root=root, json_path=tree_path, max_depth=3)
        # This intentionally exercises the pinned persistence seam without
        # calling add_node, whose behavior is outside the compatibility check.
        legacy_tree._nodes[child.id] = child
        legacy_tree._nodes[old_node.id] = old_node
        legacy_tree.meta.update(
            {
                "metric_direction": "maximize",
                "baseline_score": 0.1,
                "eval_cmd": f"python evaluator.py --token {_SECRET}",
                "eval_cmd_test": "python hidden.py",
                "dataset_info": "/srv/hidden/final.csv",
                "plugin_payload": {"token": _SECRET},
            }
        )
        legacy_tree.save()
        persisted = json.loads(tree_path.read_text(encoding="utf-8"))
        # Node.from_dict proves the pinned reader accepts score_delta; retain the
        # old record spelling here so the Q importer also proves its provenance.
        persisted["nodes"]["2"] = old_mapping

    imported = import_arbor_tree(
        persisted,
        run_id="run.pinned-arbor",
        contract_hash=_CONTRACT_HASH,
    )
    replayed = apply_tree_event(None, imported.events[0])
    if replayed != imported.tree:
        raise RuntimeError("deterministic import event cannot replay the tree")

    mapping = imported.tree.to_dict()
    if any(node["score"] is not None for node in mapping["nodes"]):
        raise RuntimeError("legacy score escaped compatibility quarantine")
    scores = mapping["compatibility"]["legacy_scores_by_node"]
    if scores["2"] != {
        "score": -0.03,
        "score_source": "score_delta",
        "score_split": "dev",
        "test_score": None,
    }:
        raise RuntimeError("legacy score_delta projection changed")
    if mapping["compatibility"]["safe_meta"] != {
        "max_depth": 3,
        "metric_direction": "maximize",
    }:
        raise RuntimeError("legacy metadata whitelist changed")

    standalone = import_arbor_tree(
        child.to_dict(),
        run_id="run.pinned-node",
        contract_hash=_CONTRACT_HASH,
    )
    standalone_mapping = standalone.tree.to_dict()
    if len(standalone.tree.nodes) != 1:
        raise RuntimeError("standalone Node did not normalize to one root")
    if (
        standalone_mapping["root_node_id"] != "1"
        or standalone_mapping["nodes"][0]["parent_id"] is not None
        or standalone_mapping["nodes"][0]["depth"] != 0
    ):
        raise RuntimeError("standalone Node retained unverified parentage")
    if apply_tree_event(None, standalone.events[0]) != standalone.tree:
        raise RuntimeError("standalone import event is not replayable")

    canonical_json = export_tree_json(imported.tree)
    html = render_tree_html(imported.tree, title="Pinned Arbor C8 verification")
    serialized = "\n".join(
        (
            canonical_json,
            json.dumps(imported.events, ensure_ascii=False, sort_keys=True),
            "\n".join(imported.warnings),
            html,
        )
    )
    for forbidden in (_SECRET, "/srv/hidden/final.csv", "python evaluator.py"):
        if forbidden in serialized:
            raise RuntimeError("unsafe legacy metadata crossed the C8 boundary")
    if "<script" in html.lower() or "</script" in html.lower():
        raise RuntimeError("HTML exporter did not escape a legacy hypothesis")

    result = {
        "status": "PASS",
        "arbor_distribution": importlib.metadata.version("arbor-agent"),
        "arbor_module": str(arbor_file),
        "arbor_expected_commit": args.expected_arbor_commit,
        "arbor_actual_commit": actual_commit,
        "arbor_checkout_clean": True,
        "pinned_tree_version": persisted["version"],
        "pinned_node_count": len(persisted["nodes"]),
        "import_event_replayed": True,
        "standalone_node_replayed": True,
        "score_delta_quarantined": True,
        "q_node_scores_null": True,
        "unsafe_meta_absent": True,
        "html_xss_safe": True,
    }
    print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


def _git(repository: Path, *arguments: str) -> str:
    return subprocess.run(
        ["git", "-C", str(repository), *arguments],
        check=True,
        capture_output=True,
        text=True,
    ).stdout


if __name__ == "__main__":
    raise SystemExit(main())
