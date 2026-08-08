"""Immutable C8 hypothesis node and tree values."""

from __future__ import annotations

import os
import tempfile
from collections.abc import Mapping, Sequence
from hashlib import sha256
from pathlib import Path
from types import MappingProxyType
from typing import Any, TypeAlias, cast

from .codec import (
    JSONScalar,
    JSONValue,
    canonical_normalized_bytes,
    decode_json_bytes,
    normalize_mapping,
    validate_discriminator,
)
from .errors import (
    HypothesisDecodeError,
    TreeIntegrityError,
    TreePersistenceError,
)
from .invariants import validate_node_invariants, validate_tree_invariants

FrozenJSON: TypeAlias = (
    JSONScalar | tuple["FrozenJSON", ...] | Mapping[str, "FrozenJSON"]
)
_HASH_PLACEHOLDER = "0" * 64


def _deep_freeze(value: JSONValue) -> FrozenJSON:
    if isinstance(value, dict):
        return MappingProxyType(
            {key: _deep_freeze(item) for key, item in value.items()}
        )
    if isinstance(value, list):
        return tuple(_deep_freeze(item) for item in value)
    return value


def _deep_thaw(value: FrozenJSON) -> JSONValue:
    if isinstance(value, Mapping):
        return {key: _deep_thaw(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_deep_thaw(item) for item in value]
    return cast(JSONScalar, value)


def _freeze_snapshot(value: JSONValue) -> FrozenJSON:
    try:
        return _deep_freeze(value)
    except RecursionError as exc:
        raise HypothesisDecodeError("hypothesis JSON nesting is too deep") from exc


def _atomic_write(path: str | os.PathLike[str], content: bytes) -> None:
    destination = Path(path)
    temporary_path: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="wb",
            dir=destination.parent,
            prefix=f".{destination.name}.",
            suffix=".tmp",
            delete=False,
        ) as temporary:
            temporary_path = temporary.name
            temporary.write(content)
            temporary.flush()
            os.fsync(temporary.fileno())
        os.replace(temporary_path, destination)
        temporary_path = None
        directory_fd = os.open(destination.parent, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except (OSError, TypeError, ValueError) as exc:
        raise TreePersistenceError(
            "unable to atomically write hypothesis tree"
        ) from exc
    finally:
        if temporary_path is not None:
            try:
                os.unlink(temporary_path)
            except OSError:
                # Preserve the typed primary write failure; cleanup failure must
                # not replace it with a raw filesystem exception.
                pass


class QuantHypothesisNode:
    """An immutable, normalized QuantHypothesisNode snapshot."""

    __slots__ = ("_canonical", "_initialized", "_sha256", "_snapshot")

    def __init__(self, mapping: Mapping[str, Any]) -> None:
        normalized = _validate_node_mapping(mapping)
        self._initialize(normalized)

    @classmethod
    def _from_normalized(cls, normalized: dict[str, JSONValue]) -> QuantHypothesisNode:
        instance = cls.__new__(cls)
        instance._initialize(normalized)
        return instance

    def _initialize(self, normalized: dict[str, JSONValue]) -> None:
        canonical = canonical_normalized_bytes(normalized)
        object.__setattr__(self, "_snapshot", _freeze_snapshot(normalized))
        object.__setattr__(self, "_canonical", canonical)
        object.__setattr__(self, "_sha256", sha256(canonical).hexdigest())
        object.__setattr__(self, "_initialized", True)

    def __setattr__(self, name: str, value: object) -> None:
        if getattr(self, "_initialized", False):
            raise AttributeError("QuantHypothesisNode is immutable")
        object.__setattr__(self, name, value)

    @property
    def id(self) -> str:
        return cast(str, cast(Mapping[str, FrozenJSON], self._snapshot)["id"])

    @property
    def parent_id(self) -> str | None:
        return cast(
            str | None,
            cast(Mapping[str, FrozenJSON], self._snapshot)["parent_id"],
        )

    @property
    def children_ids(self) -> tuple[str, ...]:
        return cast(
            tuple[str, ...],
            cast(Mapping[str, FrozenJSON], self._snapshot)["children_ids"],
        )

    @property
    def depth(self) -> int:
        return cast(int, cast(Mapping[str, FrozenJSON], self._snapshot)["depth"])

    @property
    def status(self) -> str:
        return cast(str, cast(Mapping[str, FrozenJSON], self._snapshot)["status"])

    @property
    def lifecycle(self) -> str:
        return cast(str, cast(Mapping[str, FrozenJSON], self._snapshot)["lifecycle"])

    @property
    def admissibility(self) -> str:
        return cast(
            str, cast(Mapping[str, FrozenJSON], self._snapshot)["admissibility"]
        )

    @property
    def score(self) -> int | float | None:
        return cast(
            int | float | None,
            cast(Mapping[str, FrozenJSON], self._snapshot)["score"],
        )

    @property
    def hypothesis(self) -> Mapping[str, FrozenJSON]:
        return cast(
            Mapping[str, FrozenJSON],
            cast(Mapping[str, FrozenJSON], self._snapshot)["hypothesis"],
        )

    @property
    def scope(self) -> Mapping[str, FrozenJSON]:
        return cast(
            Mapping[str, FrozenJSON],
            cast(Mapping[str, FrozenJSON], self._snapshot)["scope"],
        )

    @property
    def family(self) -> Mapping[str, FrozenJSON]:
        return cast(
            Mapping[str, FrozenJSON],
            cast(Mapping[str, FrozenJSON], self._snapshot)["family"],
        )

    @property
    def candidate_id(self) -> str | None:
        return cast(
            str | None,
            cast(Mapping[str, FrozenJSON], self._snapshot)["candidate_id"],
        )

    @property
    def candidate_artifact(self) -> Mapping[str, FrozenJSON] | None:
        return cast(
            Mapping[str, FrozenJSON] | None,
            cast(Mapping[str, FrozenJSON], self._snapshot)["candidate_artifact"],
        )

    @property
    def attempt_ids(self) -> tuple[str, ...]:
        return cast(
            tuple[str, ...],
            cast(Mapping[str, FrozenJSON], self._snapshot)["attempt_ids"],
        )

    @property
    def evidence_refs(self) -> tuple[Mapping[str, FrozenJSON], ...]:
        return cast(
            tuple[Mapping[str, FrozenJSON], ...],
            cast(Mapping[str, FrozenJSON], self._snapshot)["evidence_refs"],
        )

    @property
    def test_family_refs(self) -> tuple[str, ...]:
        return cast(
            tuple[str, ...],
            cast(Mapping[str, FrozenJSON], self._snapshot)["test_family_refs"],
        )

    @property
    def lineage_refs(self) -> tuple[str, ...]:
        return cast(
            tuple[str, ...],
            cast(Mapping[str, FrozenJSON], self._snapshot)["lineage_refs"],
        )

    @property
    def insights(self) -> tuple[Mapping[str, FrozenJSON], ...]:
        return cast(
            tuple[Mapping[str, FrozenJSON], ...],
            cast(Mapping[str, FrozenJSON], self._snapshot)["insights"],
        )

    @property
    def failure(self) -> Mapping[str, FrozenJSON]:
        return cast(
            Mapping[str, FrozenJSON],
            cast(Mapping[str, FrozenJSON], self._snapshot)["failure"],
        )

    @property
    def code_ref(self) -> str | None:
        return cast(
            str | None,
            cast(Mapping[str, FrozenJSON], self._snapshot).get("code_ref"),
        )

    @property
    def prompt_snapshot_sha256(self) -> str | None:
        return cast(
            str | None,
            cast(Mapping[str, FrozenJSON], self._snapshot)["prompt_snapshot_sha256"],
        )

    @property
    def created_event_id(self) -> str:
        return cast(
            str,
            cast(Mapping[str, FrozenJSON], self._snapshot)["created_event_id"],
        )

    @property
    def last_event_id(self) -> str:
        return cast(
            str, cast(Mapping[str, FrozenJSON], self._snapshot)["last_event_id"]
        )

    @property
    def sha256(self) -> str:
        """Return the digest of the complete canonical node payload."""

        return self._sha256

    def to_dict(self) -> dict[str, JSONValue]:
        """Return a detached mutable copy of the normalized node."""

        return cast(dict[str, JSONValue], _deep_thaw(self._snapshot))

    def to_json(self) -> str:
        """Return canonical compact UTF-8 JSON text."""

        return self._canonical.decode("utf-8")

    def __copy__(self) -> QuantHypothesisNode:
        return self

    def __deepcopy__(self, memo: dict[int, object]) -> QuantHypothesisNode:
        memo[id(self)] = self
        return self

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, QuantHypothesisNode):
            return NotImplemented
        return self._canonical == other._canonical

    def __hash__(self) -> int:
        return hash(self._canonical)

    def __repr__(self) -> str:
        return f"QuantHypothesisNode(id={self.id!r}, sha256={self.sha256!r})"


class NodeDraft:
    """Immutable proposal fields materialized by the event-first reducer."""

    __slots__ = ("_canonical", "_initialized", "_snapshot")

    def __init__(
        self,
        id: str,
        parent_id: str | None,
        hypothesis: Mapping[str, Any],
        scope: Mapping[str, Any],
        family: Mapping[str, Any],
        prompt_snapshot_sha256: str | None,
        candidate_id: str | None = None,
        candidate_artifact: Mapping[str, Any] | None = None,
        test_family_refs: Sequence[str] = (),
        lineage_refs: Sequence[str] = (),
        code_ref: str | None = None,
    ) -> None:
        normalized = normalize_mapping(
            {
                "id": id,
                "parent_id": parent_id,
                "hypothesis": hypothesis,
                "scope": scope,
                "family": family,
                "prompt_snapshot_sha256": prompt_snapshot_sha256,
                "candidate_id": candidate_id,
                "candidate_artifact": candidate_artifact,
                "test_family_refs": list(test_family_refs),
                "lineage_refs": list(lineage_refs),
                "code_ref": code_ref,
            }
        )
        # A provisional event identity exercises the exact frozen node schema and
        # all field-level C8 invariants before a durable event is allocated.
        _validate_node_mapping(
            _materialized_node_mapping(
                normalized,
                depth=0 if parent_id is None else 1,
                event_id="draft:validation",
            )
        )
        object.__setattr__(self, "_snapshot", _freeze_snapshot(normalized))
        object.__setattr__(self, "_canonical", canonical_normalized_bytes(normalized))
        object.__setattr__(self, "_initialized", True)

    @classmethod
    def from_mapping(cls, mapping: Mapping[str, Any]) -> NodeDraft:
        """Construct a draft from its exact public mapping form."""

        normalized = normalize_mapping(mapping)
        expected = {
            "id",
            "parent_id",
            "hypothesis",
            "scope",
            "family",
            "prompt_snapshot_sha256",
            "candidate_id",
            "candidate_artifact",
            "test_family_refs",
            "lineage_refs",
            "code_ref",
        }
        if set(normalized) != expected:
            raise HypothesisDecodeError("NodeDraft fields do not match the C8 shape")
        return cls(
            id=cast(str, normalized["id"]),
            parent_id=cast(str | None, normalized["parent_id"]),
            hypothesis=cast(dict[str, JSONValue], normalized["hypothesis"]),
            scope=cast(dict[str, JSONValue], normalized["scope"]),
            family=cast(dict[str, JSONValue], normalized["family"]),
            prompt_snapshot_sha256=cast(
                str | None, normalized["prompt_snapshot_sha256"]
            ),
            candidate_id=cast(str | None, normalized["candidate_id"]),
            candidate_artifact=cast(
                dict[str, JSONValue] | None, normalized["candidate_artifact"]
            ),
            test_family_refs=cast(list[str], normalized["test_family_refs"]),
            lineage_refs=cast(list[str], normalized["lineage_refs"]),
            code_ref=cast(str | None, normalized["code_ref"]),
        )

    def __setattr__(self, name: str, value: object) -> None:
        if getattr(self, "_initialized", False):
            raise AttributeError("NodeDraft is immutable")
        object.__setattr__(self, name, value)

    @property
    def id(self) -> str:
        return cast(str, cast(Mapping[str, FrozenJSON], self._snapshot)["id"])

    @property
    def parent_id(self) -> str | None:
        return cast(
            str | None,
            cast(Mapping[str, FrozenJSON], self._snapshot)["parent_id"],
        )

    @property
    def hypothesis(self) -> Mapping[str, FrozenJSON]:
        return cast(
            Mapping[str, FrozenJSON],
            cast(Mapping[str, FrozenJSON], self._snapshot)["hypothesis"],
        )

    @property
    def scope(self) -> Mapping[str, FrozenJSON]:
        return cast(
            Mapping[str, FrozenJSON],
            cast(Mapping[str, FrozenJSON], self._snapshot)["scope"],
        )

    @property
    def family(self) -> Mapping[str, FrozenJSON]:
        return cast(
            Mapping[str, FrozenJSON],
            cast(Mapping[str, FrozenJSON], self._snapshot)["family"],
        )

    @property
    def prompt_snapshot_sha256(self) -> str | None:
        return cast(
            str | None,
            cast(Mapping[str, FrozenJSON], self._snapshot)["prompt_snapshot_sha256"],
        )

    @property
    def candidate_id(self) -> str | None:
        return cast(
            str | None,
            cast(Mapping[str, FrozenJSON], self._snapshot)["candidate_id"],
        )

    @property
    def candidate_artifact(self) -> Mapping[str, FrozenJSON] | None:
        return cast(
            Mapping[str, FrozenJSON] | None,
            cast(Mapping[str, FrozenJSON], self._snapshot)["candidate_artifact"],
        )

    @property
    def test_family_refs(self) -> tuple[str, ...]:
        return cast(
            tuple[str, ...],
            cast(Mapping[str, FrozenJSON], self._snapshot)["test_family_refs"],
        )

    @property
    def lineage_refs(self) -> tuple[str, ...]:
        return cast(
            tuple[str, ...],
            cast(Mapping[str, FrozenJSON], self._snapshot)["lineage_refs"],
        )

    @property
    def code_ref(self) -> str | None:
        return cast(
            str | None,
            cast(Mapping[str, FrozenJSON], self._snapshot)["code_ref"],
        )

    @property
    def sha256(self) -> str:
        return sha256(self._canonical).hexdigest()

    def to_dict(self) -> dict[str, JSONValue]:
        return cast(dict[str, JSONValue], _deep_thaw(self._snapshot))

    def to_json(self) -> str:
        return self._canonical.decode("utf-8")

    def __copy__(self) -> NodeDraft:
        return self

    def __deepcopy__(self, memo: dict[int, object]) -> NodeDraft:
        memo[id(self)] = self
        return self

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, NodeDraft):
            return NotImplemented
        return self._canonical == other._canonical

    def __hash__(self) -> int:
        return hash(self._canonical)


def _materialized_node_mapping(
    draft: Mapping[str, JSONValue], *, depth: int, event_id: str
) -> dict[str, JSONValue]:
    node: dict[str, JSONValue] = {
        "schema_version": "1.0",
        "id": draft["id"],
        "parent_id": draft["parent_id"],
        "children_ids": [],
        "depth": depth,
        "status": "pending",
        "score": None,
        "lifecycle": "pending",
        "admissibility": "unevaluated",
        "hypothesis": draft["hypothesis"],
        "scope": draft["scope"],
        "family": draft["family"],
        "candidate_id": draft["candidate_id"],
        "candidate_artifact": draft["candidate_artifact"],
        "attempt_ids": [],
        "evidence_refs": [],
        "test_family_refs": draft["test_family_refs"],
        "lineage_refs": draft["lineage_refs"],
        "insights": [],
        "failure": {"failure_type": "none", "summary": "", "evidence_ids": []},
        "code_ref": draft["code_ref"],
        "prompt_snapshot_sha256": draft["prompt_snapshot_sha256"],
        "created_event_id": event_id,
        "last_event_id": event_id,
    }
    return node


def materialize_node_draft(
    draft: NodeDraft, *, depth: int, event_id: str
) -> QuantHypothesisNode:
    """Materialize a validated draft with reducer-owned runtime fields."""

    return validate_node(
        _materialized_node_mapping(draft.to_dict(), depth=depth, event_id=event_id)
    )


class QHypothesisTree:
    """An immutable normalized QHypothesisTree materialized view."""

    __slots__ = (
        "_canonical",
        "_initialized",
        "_node_index",
        "_nodes",
        "_sha256",
        "_snapshot",
    )

    def __init__(self, mapping: Mapping[str, Any], *, verify_hash: bool = True) -> None:
        normalized, digest = _validate_tree_mapping(mapping, verify_hash=verify_hash)
        self._initialize(normalized, digest)

    @classmethod
    def _from_normalized(
        cls, normalized: dict[str, JSONValue], digest: str
    ) -> QHypothesisTree:
        instance = cls.__new__(cls)
        instance._initialize(normalized, digest)
        return instance

    def _initialize(self, normalized: dict[str, JSONValue], digest: str) -> None:
        node_values = tuple(
            QuantHypothesisNode._from_normalized(cast(dict[str, JSONValue], node))
            for node in cast(list[dict[str, JSONValue]], normalized["nodes"])
        )
        object.__setattr__(self, "_snapshot", _freeze_snapshot(normalized))
        object.__setattr__(self, "_canonical", canonical_normalized_bytes(normalized))
        object.__setattr__(self, "_sha256", digest)
        object.__setattr__(self, "_nodes", node_values)
        object.__setattr__(
            self,
            "_node_index",
            MappingProxyType({node.id: node for node in node_values}),
        )
        object.__setattr__(self, "_initialized", True)

    def __setattr__(self, name: str, value: object) -> None:
        if getattr(self, "_initialized", False):
            raise AttributeError("QHypothesisTree is immutable")
        object.__setattr__(self, name, value)

    @property
    def run_id(self) -> str:
        return cast(str, cast(Mapping[str, FrozenJSON], self._snapshot)["run_id"])

    @property
    def revision(self) -> int:
        return cast(int, cast(Mapping[str, FrozenJSON], self._snapshot)["revision"])

    @property
    def contract_hash(self) -> str:
        return cast(
            str, cast(Mapping[str, FrozenJSON], self._snapshot)["contract_hash"]
        )

    @property
    def root_node_id(self) -> str:
        return cast(str, cast(Mapping[str, FrozenJSON], self._snapshot)["root_node_id"])

    @property
    def run_state(self) -> str:
        return cast(str, cast(Mapping[str, FrozenJSON], self._snapshot)["run_state"])

    @property
    def ledger_head(self) -> Mapping[str, FrozenJSON]:
        return cast(
            Mapping[str, FrozenJSON],
            cast(Mapping[str, FrozenJSON], self._snapshot)["ledger_head"],
        )

    @property
    def counts(self) -> Mapping[str, FrozenJSON]:
        return cast(
            Mapping[str, FrozenJSON],
            cast(Mapping[str, FrozenJSON], self._snapshot)["counts"],
        )

    @property
    def compatibility(self) -> Mapping[str, FrozenJSON] | None:
        return cast(
            Mapping[str, FrozenJSON] | None,
            cast(Mapping[str, FrozenJSON], self._snapshot).get("compatibility"),
        )

    @property
    def nodes(self) -> tuple[QuantHypothesisNode, ...]:
        return self._nodes

    @property
    def sha256(self) -> str:
        """Return the canonical digest excluding only top-level ``tree_hash``."""

        return self._sha256

    @property
    def tree_hash(self) -> str:
        return self._sha256

    def get_node(self, node_id: str) -> QuantHypothesisNode:
        """Return a node by identity, raising ``KeyError`` when absent."""

        return self._node_index[node_id]

    def to_dict(self) -> dict[str, JSONValue]:
        """Return a detached mutable copy of the normalized tree."""

        return cast(dict[str, JSONValue], _deep_thaw(self._snapshot))

    def to_json(self) -> str:
        """Return canonical compact UTF-8 JSON text."""

        return self._canonical.decode("utf-8")

    def write(self, path: str | os.PathLike[str]) -> None:
        """Atomically write canonical JSON with same-directory replacement."""

        _atomic_write(path, self._canonical)

    def __copy__(self) -> QHypothesisTree:
        return self

    def __deepcopy__(self, memo: dict[int, object]) -> QHypothesisTree:
        memo[id(self)] = self
        return self

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, QHypothesisTree):
            return NotImplemented
        return self._canonical == other._canonical

    def __hash__(self) -> int:
        return hash(self._canonical)

    def __repr__(self) -> str:
        return f"QHypothesisTree(run_id={self.run_id!r}, sha256={self.sha256!r})"


def _validate_node_mapping(mapping: Mapping[str, Any]) -> dict[str, JSONValue]:
    normalized = normalize_mapping(mapping)
    validate_discriminator(normalized, "quant_hypothesis_node")
    validate_node_invariants(normalized)
    return normalized


def validate_node(mapping: Mapping[str, Any]) -> QuantHypothesisNode:
    """Normalize and fully validate a C6 QuantHypothesisNode."""

    return QuantHypothesisNode._from_normalized(_validate_node_mapping(mapping))


def freeze_node(mapping: Mapping[str, Any]) -> QuantHypothesisNode:
    """Freeze a node after normalization and complete validation."""

    return validate_node(mapping)


def compute_tree_hash(mapping: Mapping[str, Any]) -> str:
    """Compute the tree digest excluding only the top-level ``tree_hash``."""

    normalized = normalize_mapping(mapping)
    normalized.pop("tree_hash", None)
    return sha256(canonical_normalized_bytes(normalized)).hexdigest()


def canonical_tree_bytes(mapping: Mapping[str, Any]) -> bytes:
    """Return complete normalized canonical tree JSON bytes."""

    return canonical_normalized_bytes(normalize_mapping(mapping))


def _canonicalize_tree_order(tree: dict[str, JSONValue]) -> None:
    nodes = tree.get("nodes")
    root_node_id = tree.get("root_node_id")
    if not isinstance(nodes, list) or not isinstance(root_node_id, str):
        return
    if not all(isinstance(node, dict) for node in nodes):
        return
    node_by_id: dict[str, dict[str, JSONValue]] = {}
    for raw_node in nodes:
        node = cast(dict[str, JSONValue], raw_node)
        node_id = node.get("id")
        children = node.get("children_ids")
        if not isinstance(node_id, str) or node_id in node_by_id:
            return
        if not isinstance(children, list) or not all(
            isinstance(child, str) for child in children
        ):
            return
        node["children_ids"] = sorted(cast(list[str], children))
        node_by_id[node_id] = node
    if root_node_id not in node_by_id:
        return
    ordered: list[dict[str, JSONValue]] = []
    seen: set[str] = set()
    stack = [root_node_id]
    while stack:
        node_id = stack.pop()
        if node_id in seen or node_id not in node_by_id:
            return
        seen.add(node_id)
        node = node_by_id[node_id]
        ordered.append(node)
        stack.extend(reversed(cast(list[str], node["children_ids"])))
    if len(seen) == len(nodes):
        tree["nodes"] = ordered


def _validate_tree_mapping(
    mapping: Mapping[str, Any], *, verify_hash: bool
) -> tuple[dict[str, JSONValue], str]:
    normalized = normalize_mapping(mapping)
    validate_discriminator(normalized, "q_hypothesis_tree")
    validate_tree_invariants(normalized)
    digest = compute_tree_hash(normalized)
    if verify_hash and normalized["tree_hash"] != digest:
        raise TreeIntegrityError("tree_hash does not match canonical tree content")
    return normalized, digest


def validate_tree(
    mapping: Mapping[str, Any], *, verify_hash: bool = True
) -> QHypothesisTree:
    """Normalize, schema-check, invariant-check, and verify a tree hash."""

    normalized, digest = _validate_tree_mapping(mapping, verify_hash=verify_hash)
    return QHypothesisTree._from_normalized(normalized, digest)


def freeze_tree(mapping: Mapping[str, Any]) -> QHypothesisTree:
    """Validate a draft tree, replace ``tree_hash``, and freeze it."""

    normalized = normalize_mapping(mapping)
    normalized["tree_hash"] = _HASH_PLACEHOLDER
    validate_discriminator(normalized, "q_hypothesis_tree")
    _canonicalize_tree_order(normalized)
    validate_tree_invariants(normalized)
    digest = compute_tree_hash(normalized)
    normalized["tree_hash"] = digest
    validate_discriminator(normalized, "q_hypothesis_tree")
    validate_tree_invariants(normalized)
    return QHypothesisTree._from_normalized(normalized, digest)


def load_tree(path: str | os.PathLike[str]) -> QHypothesisTree:
    """Strictly decode and validate a canonical or equivalent tree file."""

    try:
        raw = Path(path).read_bytes()
    except (OSError, TypeError, ValueError) as exc:
        raise TreePersistenceError("unable to read hypothesis tree JSON") from exc
    decoded = decode_json_bytes(raw)
    if not isinstance(decoded, Mapping):
        raise HypothesisDecodeError("hypothesis tree must be a JSON object")
    return validate_tree(decoded)


def write_tree(tree: QHypothesisTree, path: str | os.PathLike[str]) -> None:
    """Atomically write a validated immutable tree."""

    if not isinstance(tree, QHypothesisTree):
        raise TypeError("tree must be a QHypothesisTree")
    tree.write(path)
