"""Fail-closed import of pinned Arbor v3 Idea Tree state.

The source seam is Arbor commit ``65ffcc8``
``src/coordinator/idea_tree.py``: ``Node.to_dict``/``from_dict`` and
``IdeaTree._save_json`` (C4 M04/M15/M16).  This adapter preserves that graph
surface while constructing the C6 C02 quantitative state; it never invokes
Arbor or treats legacy runtime state as quantitative evidence.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
import unicodedata
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Final, TypeAlias, cast

if TYPE_CHECKING:
    # The frozen C8 contract requires consumers to use the package-level API.
    from q_arbor.hypotheses import QHypothesisTree

LEGACY_UNKNOWN_HASH: Final = "0" * 64
LEGACY_UNKNOWN_TEXT: Final = "legacy:unspecified"

_SOURCE_TIMESTAMP: Final = "1970-01-01T00:00:00Z"
_ARBOR_INPUT_VERSION: Final = 3
_SOURCE_VERSION: Final = "3"
_SCHEMA_VERSION: Final = "1.0"
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,159}$")

_TREE_KEYS: Final = frozenset({"version", "meta", "root_id", "max_depth", "nodes"})
_NODE_KEYS: Final = frozenset(
    {
        "id",
        "parent_id",
        "children_ids",
        "depth",
        "hypothesis",
        "status",
        "insight",
        "result",
        "score",
        "score_delta",
        "score_split",
        "test_score",
        "code_ref",
        "related_work",
        "grounding",
        "eval_status",
        "stop_reason",
        "attempt",
    }
)
_KNOWN_META_KEYS: Final = frozenset(
    {
        "metric_direction",
        "max_depth",
        "baseline_score",
        "trunk_score",
        "test_baseline_score",
        "test_trunk_score",
        "eval_cmd",
        "eval_cmd_test",
        "eval_timeout",
        "eval_retries",
        "eval_retry_base_delay",
        "eval_retry_max_delay",
        "dataset_info",
        "submission_path",
        "sample_submission_path",
    }
)
_COMPATIBILITY_KEYS: Final = frozenset(
    {
        "source",
        "source_version",
        "quarantined",
        "missing_fields_by_node",
        "legacy_scores_by_node",
        "legacy_status_by_node",
        "safe_meta",
        "dropped_meta_keys",
    }
)
_ARBOR_STATUSES: Final = frozenset(
    {"pending", "running", "done", "needs_retry", "merged", "pruned"}
)
_ARBOR_EVAL_STATUSES: Final = frozenset({"scored", "skipped", "failed_to_run"})
_ARBOR_STOP_REASONS: Final = frozenset({"finished", "max_turns"})
_ARBOR_SCORE_SPLITS: Final = frozenset({"dev", "test"})

JSONScalar: TypeAlias = type(None) | bool | int | float | str
JSONValue: TypeAlias = JSONScalar | list["JSONValue"] | dict[str, "JSONValue"]


class _FrozenJSONDict(dict[str, object]):
    """A JSON-serializable mapping that rejects ordinary mutation."""

    @staticmethod
    def _immutable(*_args: object, **_kwargs: object) -> None:
        raise TypeError("import event mappings are immutable")

    __setitem__ = _immutable
    __delitem__ = _immutable
    clear = _immutable
    pop = _immutable
    popitem = _immutable
    setdefault = _immutable
    update = _immutable
    __ior__ = _immutable

    def __copy__(self) -> _FrozenJSONDict:
        return self

    def __deepcopy__(self, _memo: dict[int, object]) -> _FrozenJSONDict:
        return self


@dataclass(frozen=True, slots=True)
class ArborImportResult:
    """Immutable quantitative tree, deterministic import events, and warnings."""

    tree: QHypothesisTree
    events: tuple[Mapping[str, object], ...]
    warnings: tuple[str, ...]

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "events",
            tuple(
                cast(Mapping[str, object], _freeze_json(event)) for event in self.events
            ),
        )
        object.__setattr__(self, "warnings", tuple(self.warnings))


@dataclass(frozen=True, slots=True)
class _LegacyNode:
    id: str
    parent_id: str | None
    children_ids: tuple[str, ...]
    depth: int
    source: Mapping[str, JSONValue]
    source_missing: tuple[str, ...]
    source_parent_id: str | None = None
    source_depth: int | None = None


@dataclass(frozen=True, slots=True)
class _LegacyTree:
    source_kind: str
    root_id: str
    nodes: tuple[_LegacyNode, ...]
    meta: Mapping[str, JSONValue]
    max_depth: int | None
    has_max_depth: bool
    dropped_max_depth: bool
    warnings: tuple[str, ...]


def import_arbor_tree(
    legacy_mapping: Mapping[str, Any],
    *,
    run_id: str,
    contract_hash: str,
    default_scope: object | None = None,
) -> ArborImportResult:
    """Import an Arbor v3 tree or node under an explicit score quarantine."""

    # Use only the package-level C8 model API.  The local import avoids a package
    # initialization cycle when q_arbor.hypotheses re-exports this module.
    from q_arbor.hypotheses import freeze_tree

    checked_run_id = _identifier(run_id, "run_id")
    checked_contract_hash = _sha256(contract_hash, "contract_hash")
    normalized = _normalize_mapping(legacy_mapping)
    source_hash = _canonical_hash(normalized)
    source = _parse_legacy(normalized)
    scope, scope_missing = _scope(default_scope)

    event_id = f"event.arbor-import.0001.{source_hash}"
    missing_by_node: dict[str, JSONValue] = {}
    legacy_scores: dict[str, JSONValue] = {}
    legacy_statuses: dict[str, JSONValue] = {}
    q_nodes: list[dict[str, JSONValue]] = []
    score_count = 0

    for proposal_order, node in enumerate(source.nodes, start=1):
        score_record = _legacy_score_record(node)
        status_record = _legacy_status_record(node)
        if node.source_parent_id is not None or node.source_depth is not None:
            status_record["source_parent_id"] = node.source_parent_id
            status_record["source_depth"] = node.source_depth

        if (
            score_record["score_source"] is not None
            or score_record["test_score"] is not None
        ):
            score_count += 1

        missing = _node_missing_fields(
            node,
            scope_missing=scope_missing,
            score_record=score_record,
            status_record=status_record,
        )
        missing_by_node[node.id] = list(missing)
        legacy_scores[node.id] = score_record
        legacy_statuses[node.id] = status_record
        q_nodes.append(
            _q_node(
                node,
                scope=scope,
                proposal_order=proposal_order,
                event_id=event_id,
            )
        )

    safe_meta, dropped_meta_keys = _project_meta(
        source.meta,
        max_depth=source.max_depth,
        has_max_depth=source.has_max_depth,
        dropped_max_depth=source.dropped_max_depth,
    )
    compatibility: dict[str, JSONValue] = {
        "source": source.source_kind,
        "source_version": _SOURCE_VERSION,
        "quarantined": True,
        "missing_fields_by_node": missing_by_node,
        "legacy_scores_by_node": legacy_scores,
        "legacy_status_by_node": legacy_statuses,
        "safe_meta": safe_meta,
        "dropped_meta_keys": dropped_meta_keys,
    }
    if frozenset(compatibility) != _COMPATIBILITY_KEYS:
        raise AssertionError("internal compatibility whitelist drift")

    proposals = max(0, len(q_nodes) - 1)
    tree_body: dict[str, JSONValue] = {
        "run_id": checked_run_id,
        "contract_hash": checked_contract_hash,
        "root_node_id": source.root_id,
        "run_state": "development",
        "nodes": q_nodes,
        "counts": {
            "proposals": proposals,
            "unique_candidates": 0,
            "candidate_families": 1 if proposals else 0,
            "attempts": 0,
            "evaluation_queries": 0,
            "admissible_evidence": 0,
        },
        "compatibility": compatibility,
    }
    event = _import_event(
        run_id=checked_run_id,
        contract_hash=checked_contract_hash,
        source_hash=source_hash,
        event_id=event_id,
        tree_body=tree_body,
    )
    tree_mapping: dict[str, JSONValue] = {
        "schema_version": _SCHEMA_VERSION,
        "revision": 0,
        **tree_body,
        "ledger_head": {
            "last_sequence": 1,
            "last_event_hash": cast(str, event["event_hash"]),
        },
        "tree_hash": LEGACY_UNKNOWN_HASH,
    }
    tree = freeze_tree(tree_mapping)

    warnings = list(source.warnings)
    warnings.append("legacy source timestamp is unavailable; used " + _SOURCE_TIMESTAMP)
    warnings.append("legacy Arbor state is compatibility-quarantined")
    if score_count:
        warnings.append(f"quarantined legacy score fields on {score_count} node(s)")
    if dropped_meta_keys:
        warnings.append(
            "dropped unsafe Arbor meta fields: " + ", ".join(dropped_meta_keys)
        )

    return ArborImportResult(tree=tree, events=(event,), warnings=tuple(warnings))


def _parse_legacy(mapping: Mapping[str, JSONValue]) -> _LegacyTree:
    if "nodes" in mapping or "root_id" in mapping:
        return _parse_tree(mapping)
    if "id" in mapping:
        return _parse_single_node(mapping)
    _fail("legacy input is neither an Arbor IdeaTree nor Node mapping")


def _parse_tree(mapping: Mapping[str, JSONValue]) -> _LegacyTree:
    unknown = sorted(set(mapping) - _TREE_KEYS)
    if unknown:
        _fail(
            "legacy Arbor tree contains unsupported top-level field "
            + _unknown_key_label(unknown[0])
        )

    warnings: list[str] = []
    if "version" in mapping:
        version = mapping["version"]
        if isinstance(version, bool) or version != _ARBOR_INPUT_VERSION:
            _fail("legacy Arbor tree version must be 3")
    else:
        warnings.append("source version field missing; interpreted as pinned Arbor v3")

    root_id = _identifier(mapping.get("root_id"), "root_id")
    raw_nodes = mapping.get("nodes")
    if not isinstance(raw_nodes, Mapping) or not raw_nodes:
        _fail("legacy Arbor tree nodes must be a non-empty object")
    raw_meta = mapping.get("meta", {})
    if not isinstance(raw_meta, Mapping):
        _fail("legacy Arbor tree meta must be an object")

    has_max_depth = "max_depth" in mapping
    raw_max_depth = mapping.get("max_depth")
    valid_max_depth = raw_max_depth is None or (
        not isinstance(raw_max_depth, bool)
        and isinstance(raw_max_depth, int)
        and raw_max_depth > 0
    )
    max_depth = cast(int | None, raw_max_depth) if valid_max_depth else None
    dropped_max_depth = has_max_depth and not valid_max_depth

    records: dict[str, Mapping[str, JSONValue]] = {}
    source_missing: dict[str, set[str]] = {}
    parents: dict[str, str | None] = {}
    supplied_children: dict[str, tuple[str, ...] | None] = {}
    supplied_depth: dict[str, int | None] = {}

    for raw_key, value in raw_nodes.items():
        node_id = _identifier(raw_key, "nodes key")
        if not isinstance(value, Mapping):
            _fail(f"legacy Arbor node {node_id!r} must be an object")
        record = cast(Mapping[str, JSONValue], value)
        _check_node_keys(record, node_id)
        missing: set[str] = set()

        if "id" in record:
            record_id = _identifier(record["id"], f"node {node_id!r} id")
            if record_id != node_id:
                _fail(f"legacy Arbor node map key {node_id!r} does not match its id")
        else:
            missing.add("source.id")

        if "parent_id" not in record:
            if node_id != root_id:
                _fail(f"legacy Arbor node {node_id!r} has no parent_id")
            parent_id = None
            missing.add("source.parent_id")
        else:
            parent_id = _optional_identifier(
                record["parent_id"], f"node {node_id!r} parent_id"
            )

        children = None
        if "children_ids" in record:
            children = _identifier_list(
                record["children_ids"], f"node {node_id!r} children_ids"
            )
        else:
            missing.add("source.children_ids")

        depth = None
        if "depth" in record:
            depth = _nonnegative_int(record["depth"], f"node {node_id!r} depth")
        else:
            missing.add("source.depth")

        records[node_id] = record
        source_missing[node_id] = missing
        parents[node_id] = parent_id
        supplied_children[node_id] = children
        supplied_depth[node_id] = depth

    if root_id not in records:
        _fail("legacy Arbor root_id is absent from nodes")
    if parents[root_id] is not None:
        _fail("legacy Arbor root must have parent_id null")

    derived_children: dict[str, list[str]] = {node_id: [] for node_id in records}
    for node_id, parent_id in parents.items():
        if node_id == root_id:
            continue
        if parent_id is None:
            _fail(f"legacy Arbor non-root node {node_id!r} has parent_id null")
        if parent_id not in records:
            _fail(f"legacy Arbor node {node_id!r} refers to a missing parent")
        derived_children[parent_id].append(node_id)
    for children in derived_children.values():
        children.sort()

    for node_id, supplied in supplied_children.items():
        if supplied is not None and set(supplied) != set(derived_children[node_id]):
            _fail(f"legacy Arbor node {node_id!r} children_ids are not reciprocal")
        if supplied is not None and tuple(sorted(supplied)) != supplied:
            warnings.append(f"canonicalized children order for node {node_id}")

    depths: dict[str, int] = {}
    order: list[str] = []
    active: set[str] = set()

    def visit(node_id: str, depth: int) -> None:
        if node_id in active:
            _fail("legacy Arbor tree contains a cycle")
        if node_id in depths:
            _fail(f"legacy Arbor node {node_id!r} is reachable more than once")
        active.add(node_id)
        depths[node_id] = depth
        order.append(node_id)
        for child_id in derived_children[node_id]:
            visit(child_id, depth + 1)
        active.remove(node_id)

    visit(root_id, 0)
    if set(depths) != set(records):
        _fail("legacy Arbor tree contains nodes unreachable from root_id")
    for node_id, supplied in supplied_depth.items():
        if supplied is not None and supplied != depths[node_id]:
            _fail(f"legacy Arbor node {node_id!r} depth is inconsistent")
    if (
        valid_max_depth
        and isinstance(max_depth, int)
        and max(depths.values()) > max_depth
    ):
        _fail("legacy Arbor tree exceeds its declared max_depth")

    nodes = tuple(
        _LegacyNode(
            id=node_id,
            parent_id=parents[node_id],
            children_ids=tuple(derived_children[node_id]),
            depth=depths[node_id],
            source=records[node_id],
            source_missing=tuple(sorted(source_missing[node_id])),
        )
        for node_id in order
    )
    return _LegacyTree(
        source_kind="arbor.idea_tree",
        root_id=root_id,
        nodes=nodes,
        meta=cast(Mapping[str, JSONValue], raw_meta),
        max_depth=max_depth,
        has_max_depth=has_max_depth and valid_max_depth,
        dropped_max_depth=dropped_max_depth,
        warnings=tuple(warnings),
    )


def _parse_single_node(mapping: Mapping[str, JSONValue]) -> _LegacyTree:
    _check_node_keys(mapping, "standalone")
    node_id = _identifier(mapping.get("id"), "node id")
    supplied_children = (
        _identifier_list(mapping["children_ids"], "node children_ids")
        if "children_ids" in mapping
        else ()
    )
    if supplied_children:
        _fail("a standalone Arbor node with children cannot form a complete tree")

    source_parent = (
        _optional_identifier(mapping["parent_id"], "node parent_id")
        if "parent_id" in mapping
        else None
    )
    source_depth = (
        _nonnegative_int(mapping["depth"], "node depth") if "depth" in mapping else 0
    )
    source_missing = {
        field
        for field, present in (
            ("source.parent_id", "parent_id" in mapping),
            ("source.children_ids", "children_ids" in mapping),
            ("source.depth", "depth" in mapping),
        )
        if not present
    }

    normalized_graph = source_parent is not None or source_depth != 0
    if normalized_graph:
        source_missing.update(
            {"source.parent_id_normalized", "source.depth_normalized"}
        )
    node = _LegacyNode(
        id=node_id,
        parent_id=None,
        children_ids=(),
        depth=0,
        source=mapping,
        source_missing=tuple(sorted(source_missing)),
        source_parent_id=source_parent if normalized_graph else None,
        source_depth=source_depth if normalized_graph else None,
    )
    warnings = (
        ("normalized a standalone Arbor node to a single compatibility root",)
        if normalized_graph
        else ()
    )

    return _LegacyTree(
        source_kind="arbor.node",
        root_id=node_id,
        nodes=(node,),
        meta={},
        max_depth=None,
        has_max_depth=False,
        dropped_max_depth=False,
        warnings=warnings,
    )


def _q_node(
    node: _LegacyNode,
    *,
    scope: Mapping[str, JSONValue],
    proposal_order: int,
    event_id: str,
) -> dict[str, JSONValue]:
    mechanism = _legacy_text(node.source, "hypothesis")
    if not mechanism:
        mechanism = LEGACY_UNKNOWN_TEXT
    return {
        "schema_version": _SCHEMA_VERSION,
        "id": node.id,
        "parent_id": node.parent_id,
        "children_ids": list(node.children_ids),
        "depth": node.depth,
        "status": "pending",
        "score": None,
        "lifecycle": "pending",
        "admissibility": "unevaluated",
        "hypothesis": {
            "mechanism": mechanism,
            "falsifiable_prediction": LEGACY_UNKNOWN_TEXT,
            "observable": LEGACY_UNKNOWN_TEXT,
            "single_change": LEGACY_UNKNOWN_TEXT,
            "conflicts": [],
        },
        "scope": dict(scope),
        "family": {
            "family_id": LEGACY_UNKNOWN_TEXT,
            "parent_family_id": None,
            "proposal_order": proposal_order,
            "canonical_status": "unavailable",
            "canonical_hash": None,
            "similarity_refs": [],
        },
        "candidate_id": None,
        "candidate_artifact": None,
        "attempt_ids": [],
        "evidence_refs": [],
        "test_family_refs": [],
        "lineage_refs": [],
        "insights": [],
        "failure": {"failure_type": "none", "summary": "", "evidence_ids": []},
        "code_ref": None,
        "prompt_snapshot_sha256": None,
        "created_event_id": event_id,
        "last_event_id": event_id,
    }


def _legacy_score_record(node: _LegacyNode) -> dict[str, JSONValue]:
    source = node.source
    score_source: str | None = None
    score: int | float | None = None
    if "score" in source:
        score_source = "score"
        score = _finite_number_or_none(source["score"], f"node {node.id!r} score")
    elif "score_delta" in source:
        score_source = "score_delta"
        score = _finite_number_or_none(
            source["score_delta"], f"node {node.id!r} score_delta"
        )

    test_score = (
        _finite_number_or_none(source["test_score"], f"node {node.id!r} test_score")
        if "test_score" in source
        else None
    )
    if "score_split" in source:
        score_split = _optional_enum(
            source["score_split"],
            _ARBOR_SCORE_SPLITS,
            f"node {node.id!r} score_split",
        )
    elif score_source is not None:
        score_split = "dev"
    else:
        score_split = None
    return {
        "score": score,
        "score_source": score_source,
        "score_split": score_split,
        "test_score": test_score,
    }


def _legacy_status_record(node: _LegacyNode) -> dict[str, JSONValue]:
    source = node.source
    values: dict[str, JSONValue] = {
        "status": _optional_enum(
            source.get("status"), _ARBOR_STATUSES, f"node {node.id!r} status"
        ),
        "eval_status": _optional_enum(
            source.get("eval_status"),
            _ARBOR_EVAL_STATUSES,
            f"node {node.id!r} eval_status",
        ),
        "stop_reason": _optional_enum(
            source.get("stop_reason"),
            _ARBOR_STOP_REASONS,
            f"node {node.id!r} stop_reason",
        ),
    }
    values["attempt"] = (
        _positive_int(source["attempt"], f"node {node.id!r} attempt")
        if "attempt" in source
        else 1
    )
    for key in ("result", "insight", "code_ref", "related_work", "grounding"):
        values[f"{key}_sha256"] = (
            _text_hash(source[key], f"node {node.id!r} {key}")
            if key in source
            else None
        )
    return values


def _node_missing_fields(
    node: _LegacyNode,
    *,
    scope_missing: tuple[str, ...],
    score_record: Mapping[str, JSONValue],
    status_record: Mapping[str, JSONValue],
) -> tuple[str, ...]:
    missing = set(node.source_missing)
    missing.update(
        {
            "hypothesis.falsifiable_prediction",
            "hypothesis.observable",
            "hypothesis.single_change",
            "hypothesis.conflicts",
            "family",
            "candidate_id",
            "candidate_artifact",
            "attempt_ids",
            "evidence_refs",
            "test_family_refs",
            "lineage_refs",
            "prompt_snapshot_sha256",
        }
    )
    missing.update(scope_missing)
    if not _legacy_text(node.source, "hypothesis"):
        missing.add("hypothesis.mechanism")
    if score_record.get("score_source") is not None:
        missing.add("score.evidence_binding")
    if score_record.get("test_score") is not None:
        missing.add("test_score.evidence_binding")
    if status_record.get("insight_sha256"):
        missing.add("insights.evidence_binding")
    if status_record.get("code_ref_sha256"):
        missing.add("code_ref.trust_binding")
    return tuple(sorted(missing))


def _scope(
    default_scope: object | None,
) -> tuple[dict[str, JSONValue], tuple[str, ...]]:
    if default_scope is None:
        return (
            {
                "market": LEGACY_UNKNOWN_TEXT,
                "universe": LEGACY_UNKNOWN_TEXT,
                "frequency": LEGACY_UNKNOWN_TEXT,
                "horizon": LEGACY_UNKNOWN_TEXT,
                "time_range": None,
                "fields": [],
                "regime_labels": [],
                "data_snapshot_sha256": LEGACY_UNKNOWN_HASH,
                "cost_model_sha256": LEGACY_UNKNOWN_HASH,
            },
            (
                "scope.cost_model_sha256",
                "scope.data_snapshot_sha256",
                "scope.fields",
                "scope.frequency",
                "scope.horizon",
                "scope.market",
                "scope.regime_labels",
                "scope.time_range",
                "scope.universe",
            ),
        )

    if isinstance(default_scope, Mapping):
        raw_scope = default_scope
    else:
        to_dict = getattr(default_scope, "to_dict", None)
        if not callable(to_dict):
            _fail("default_scope must be a Scope value or mapping")
        raw_scope = to_dict()
        if not isinstance(raw_scope, Mapping):
            _fail("default_scope.to_dict() must return a mapping")
    normalized = _normalize_mapping(raw_scope)
    expected = {
        "market",
        "universe",
        "frequency",
        "horizon",
        "time_range",
        "fields",
        "regime_labels",
        "data_snapshot_sha256",
        "cost_model_sha256",
    }
    if set(normalized) != expected:
        _fail("default_scope must contain exactly the C6 Scope fields")
    return normalized, ()


def _project_meta(
    meta: Mapping[str, JSONValue],
    *,
    max_depth: int | None,
    has_max_depth: bool,
    dropped_max_depth: bool,
) -> tuple[dict[str, JSONValue], list[JSONValue]]:
    safe: dict[str, JSONValue] = {}
    dropped: list[str] = []
    if has_max_depth:
        safe["max_depth"] = max_depth
    if dropped_max_depth:
        dropped.append("max_depth")
    for key in sorted(meta):
        value = meta[key]
        accepted = key == "metric_direction" and value in {"maximize", "minimize"}
        if accepted:
            safe[key] = value
        elif key in _KNOWN_META_KEYS:
            dropped.append(key)
        else:
            dropped.append(_unknown_key_label(key))

    # C5 G05 and C6 J01/J04: no legacy eval command, split descriptor,
    # dataset/path, token, plugin payload, or unbound score may cross this
    # compatibility boundary.  Only validated metric direction and the
    # structural max-depth limit survive; node scores remain quarantined.
    return safe, cast(list[JSONValue], sorted(set(dropped)))


def _import_event(
    *,
    run_id: str,
    contract_hash: str,
    source_hash: str,
    event_id: str,
    tree_body: Mapping[str, JSONValue],
) -> dict[str, JSONValue]:
    idempotency_key = f"arbor-import:{source_hash}"
    request_hash = _canonical_hash(
        {
            "tree": tree_body,
            "expected_revision": None,
            "idempotency_key": idempotency_key,
        }
    )
    event: dict[str, JSONValue] = {
        "schema_version": _SCHEMA_VERSION,
        "run_id": run_id,
        "sequence": 1,
        "event_id": event_id,
        "timestamp": _SOURCE_TIMESTAMP,
        "event_type": "run.started",
        "actor": "system",
        "contract_hash": contract_hash,
        "node_id": tree_body["root_node_id"],
        "attempt_id": None,
        "split_role": "none",
        "payload": {
            "schema_version": _SCHEMA_VERSION,
            "kind": "initialize_tree",
            "idempotency_key": idempotency_key,
            "request_hash": request_hash,
            "expected_revision": None,
            "result_revision": 0,
            "tree": dict(tree_body),
        },
        "prev_event_hash": None,
        "event_hash": LEGACY_UNKNOWN_HASH,
    }
    event["event_hash"] = _canonical_hash(event, omit_top_level="event_hash")
    return event


def _check_node_keys(record: Mapping[str, JSONValue], node_id: str) -> None:
    unknown = sorted(set(record) - _NODE_KEYS)
    if unknown:
        _fail(
            f"legacy Arbor node {node_id!r} contains unsupported field "
            + _unknown_key_label(unknown[0])
        )


def _unknown_key_label(key: str) -> str:
    return "unknown-sha256:" + hashlib.sha256(key.encode("utf-8")).hexdigest()


def _legacy_text(mapping: Mapping[str, JSONValue], key: str) -> str | None:
    value = mapping.get(key)
    if value is None:
        return None
    if not isinstance(value, str):
        _fail(f"legacy Arbor field {key!r} must be a string")
    return value or None


def _optional_text(value: JSONValue, field: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        _fail(f"{field} must be a string or null")
    return value


def _optional_enum(
    value: JSONValue | None, allowed: frozenset[str], field: str
) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or value not in allowed:
        _fail(f"{field} is not a recognized pinned Arbor value")
    return value


def _text_hash(value: JSONValue, field: str) -> str | None:
    text = _optional_text(value, field)
    if not text:
        return None
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _identifier(value: object, field: str) -> str:
    if not isinstance(value, str) or not _IDENTIFIER.fullmatch(value):
        _fail(f"{field} is not a valid identifier")
    return value


def _optional_identifier(value: JSONValue, field: str) -> str | None:
    if value is None:
        return None
    return _identifier(value, field)


def _identifier_list(value: JSONValue, field: str) -> tuple[str, ...]:
    if not isinstance(value, list):
        _fail(f"{field} must be an array")
    result = tuple(_identifier(item, field) for item in value)
    if len(result) != len(set(result)):
        _fail(f"{field} contains duplicate identifiers")
    return result


def _nonnegative_int(value: JSONValue, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        _fail(f"{field} must be a non-negative integer")
    return value


def _positive_int(value: JSONValue, field: str) -> int:
    result = _nonnegative_int(value, field)
    if result < 1:
        _fail(f"{field} must be a positive integer")
    return result


def _finite_number_or_none(value: JSONValue, field: str) -> int | float | None:
    if value is None:
        return None
    if not _is_finite_number(value):
        _fail(f"{field} must be a finite number or null")
    return cast(int | float, value)


def _is_finite_number(value: object) -> bool:
    return (
        not isinstance(value, bool)
        and isinstance(value, (int, float))
        and (not isinstance(value, float) or math.isfinite(value))
    )


def _sha256(value: object, field: str) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[a-f0-9]{64}", value):
        _fail(f"{field} must be a lowercase SHA-256 digest")
    return value


def _normalize_mapping(value: object) -> dict[str, JSONValue]:
    if not isinstance(value, Mapping):
        _fail("legacy Arbor input must be a mapping")
    normalized = _normalize_json(value, set())
    if not isinstance(normalized, dict):
        _fail("legacy Arbor input must normalize to an object")
    return normalized


def _normalize_json(value: object, active: set[int]) -> JSONValue:
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, str):
        normalized = unicodedata.normalize("NFC", value)
        try:
            normalized.encode("utf-8", errors="strict")
        except UnicodeEncodeError:
            _fail("legacy Arbor input contains invalid Unicode")
        return normalized
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            _fail("legacy Arbor input contains a non-finite number")
        return value
    if isinstance(value, Mapping):
        identity = id(value)
        if identity in active:
            _fail("legacy Arbor input contains a recursive object")
        active.add(identity)
        try:
            result: dict[str, JSONValue] = {}
            for raw_key, item in value.items():
                if not isinstance(raw_key, str):
                    _fail("legacy Arbor object keys must be strings")
                key = unicodedata.normalize("NFC", raw_key)
                if key in result:
                    _fail("legacy Arbor input has an NFC object-key collision")
                result[key] = _normalize_json(item, active)
            return result
        finally:
            active.remove(identity)
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        identity = id(value)
        if identity in active:
            _fail("legacy Arbor input contains a recursive array")
        active.add(identity)
        try:
            return [_normalize_json(item, active) for item in value]
        finally:
            active.remove(identity)
    _fail("legacy Arbor input contains a non-JSON value")


def _canonical_bytes(value: object) -> bytes:
    normalized = _normalize_json(value, set())
    try:
        return json.dumps(
            normalized,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (RecursionError, TypeError, ValueError, UnicodeEncodeError) as exc:
        _fail("legacy Arbor input cannot be encoded as canonical JSON", cause=exc)


def _canonical_hash(value: object, *, omit_top_level: str | None = None) -> str:
    if omit_top_level is not None:
        if not isinstance(value, Mapping):
            raise TypeError("hash omission requires a mapping")
        detached = dict(value)
        detached.pop(omit_top_level, None)
        value = detached
    return hashlib.sha256(_canonical_bytes(value)).hexdigest()


def _freeze_json(value: object) -> object:
    if isinstance(value, Mapping):
        return _FrozenJSONDict({key: _freeze_json(item) for key, item in value.items()})
    if isinstance(value, (list, tuple)):
        return tuple(_freeze_json(item) for item in value)
    return value


def _fail(message: str, *, cause: BaseException | None = None) -> None:
    from q_arbor.hypotheses import TreeCompatibilityError

    error = TreeCompatibilityError(message)
    if cause is None:
        raise error
    raise error from cause


__all__ = [
    "ArborImportResult",
    "LEGACY_UNKNOWN_HASH",
    "LEGACY_UNKNOWN_TEXT",
    "import_arbor_tree",
]
