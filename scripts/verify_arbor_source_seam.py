#!/usr/bin/env python3
"""Verify a C7 projection against the installed frozen Arbor source seams."""

from __future__ import annotations

import argparse
import importlib.metadata
import json
from pathlib import Path
import subprocess

import arbor
from arbor.coordinator.config import CoordinatorConfig
from arbor.coordinator.tools.tree_ops import TreeSetMetaTool
from arbor.plugins.base import Plugin

from q_arbor.contracts import load_contract
from q_arbor.integrations import project_to_arbor


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("contract", type=Path)
    parser.add_argument("--expected-arbor-commit", required=True)
    args = parser.parse_args()

    contract = load_contract(args.contract)
    projection = project_to_arbor(
        contract,
        contract_path=args.contract,
        trunk_branch="q-arbor/c7-trunk",
        baseline_score=0.0,
    )

    tree_meta = projection.tree_meta()
    tree_schema_fields = set(TreeSetMetaTool.input_schema["properties"])
    if not set(tree_meta) <= tree_schema_fields:
        raise RuntimeError("projection contains fields outside TreeSetMeta")

    config_values = projection.config_overrides()
    config = CoordinatorConfig(**config_values)
    if config.trunk_branch != config_values["trunk_branch"]:
        raise RuntimeError("trunk branch did not survive CoordinatorConfig")
    if config.protected_paths != config_values["protected_paths"]:
        raise RuntimeError("protected paths did not survive CoordinatorConfig")

    plugin_values = projection.plugin_overrides()
    plugin = Plugin(**plugin_values)
    if plugin.protected_paths != plugin_values["protected_paths"]:
        raise RuntimeError("protected paths did not survive Plugin")
    if plugin.required_outputs != plugin_values["required_outputs"]:
        raise RuntimeError("required outputs did not survive Plugin")

    runtime_views = (tree_meta, config_values, plugin_values)
    if any("eval_cmd_test" in view for view in runtime_views):
        raise RuntimeError("C7 projection exposed eval_cmd_test")
    if any(any(key.startswith("q_") for key in view) for view in runtime_views):
        raise RuntimeError("Q-only audit identity leaked into Arbor runtime metadata")

    arbor_file = Path(arbor.__file__).resolve()
    checkout_root = arbor_file.parent.parent
    commit_file = checkout_root / ".git"
    if not commit_file.exists():
        raise RuntimeError("Arbor module is not loaded from the expected source checkout")
    actual_commit = subprocess.run(
        ["git", "-C", str(checkout_root), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    if actual_commit != args.expected_arbor_commit:
        raise RuntimeError("Arbor source commit differs from the frozen C1 identity")
    dirty = subprocess.run(
        ["git", "-C", str(checkout_root), "status", "--porcelain"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    if dirty:
        raise RuntimeError("Arbor source checkout is dirty")
    result = {
        "status": "PASS",
        "arbor_distribution": importlib.metadata.version("arbor-agent"),
        "arbor_module": str(arbor_file),
        "arbor_expected_commit": args.expected_arbor_commit,
        "arbor_actual_commit": actual_commit,
        "arbor_checkout_marker_exists": commit_file.exists(),
        "arbor_checkout_clean": True,
        "contract_hash": contract.sha256,
        "tree_meta_keys": sorted(tree_meta),
        "config_override_keys": sorted(config_values),
        "plugin_override_keys": sorted(plugin_values),
        "audit_metadata_keys": sorted(projection.audit_metadata()),
        "eval_cmd_test_present": False,
        "forward_evaluator_implemented": False,
    }
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
