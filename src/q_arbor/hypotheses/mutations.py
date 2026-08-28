"""Immutable mutation requests and the pure event reducer."""

from __future__ import annotations

from collections.abc import Mapping
from hashlib import sha256
from types import MappingProxyType
from typing import Any, Final, TypeAlias, cast

from .codec import (
    JSONScalar,
    JSONValue,
    canonical_normalized_bytes,
    normalize_mapping,
    validate_discriminator,
)
from .errors import (
    HypothesisInvariantError,
    TreeConflictError,
    TreeIntegrityError,
)
from .invariants import project_counts, require_identifier, require_sha256
from .models import (
    NodeDraft,
    QHypothesisTree,
    freeze_tree,
    materialize_node_draft,
    validate_node,
)
from .propagation import prepare_insight_propagation

FrozenJSON: TypeAlias = (
    JSONScalar | tuple["FrozenJSON", ...] | Mapping[str, "FrozenJSON"]
)
_EVENT_TYPE_BY_KIND: Final = {
    "add_node": "hypothesis.proposed",
    "update_node": "node.updated",
    "prune_subtree": "prune.completed",
    "propagate_insight": "insight.created",
}
_IMMUTABLE_NODE_FIELDS: Final = frozenset(
    {
        "schema_version",
        "id",
        "parent_id",
        "children_ids",
        "depth",
        "hypothesis",
        "scope",
        "family",
        "prompt_snapshot_sha256",
        "created_event_id",
        "last_event_id",
        "score",
    }
)
_MUTABLE_NODE_FIELDS: Final = frozenset(
    {
        "status",
        "lifecycle",
        "admissibility",
        "candidate_id",
        "candidate_artifact",
        "attempt_ids",
        "evidence_refs",
        "test_family_refs",
        "lineage_refs",
        "insights",
        "failure",
        "code_ref",
    }
)
_ALLOWED_STATUS_TRANSITIONS: Final = frozenset(
    {
        ("pending", "running"),
        ("pending", "invalid"),
        ("pending", "contaminated"),
        ("pending", "incomparable"),
        ("running", "done"),
        ("running", "needs_retry"),
        ("running", "invalid"),
        ("running", "contaminated"),
        ("running", "incomparable"),
        ("needs_retry", "running"),
        ("done", "merged"),
    }
)
_MUTATION_PAYLOAD_KEYS: Final = frozenset(
    {
        "schema_version",
        "kind",
        "idempotency_key",
        "request_hash",
        "expected_revision",
        "result_revision",
        "mutation",
        "changed_nodes",
    }
)
_INITIAL_PAYLOAD_KEYS: Final = frozenset(
    {
        "schema_version",
        "kind",
        "idempotency_key",
        "request_hash",
        "expected_revision",
        "result_revision",
        "tree",
    }
)


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


class TreeMutation:
    """An immutable canonical request, independent of persistence metadata."""

    __slots__ = ("_canonical", "_initialized", "_sha256", "_snapshot")

    def __init__(self, mapping: Mapping[str, Any]) -> None:
        normalized = _validate_mutation_mapping(mapping)
        canonical = canonical_normalized_bytes(normalized)
        object.__setattr__(self, "_snapshot", _deep_freeze(normalized))
        object.__setattr__(self, "_canonical", canonical)
        object.__setattr__(self, "_sha256", sha256(canonical).hexdigest())
        object.__setattr__(self, "_initialized", True)

    @classmethod
    def add_node(cls, draft: NodeDraft) -> TreeMutation:
        if not isinstance(draft, NodeDraft):
            raise TypeError("draft must be a NodeDraft")
        return cls(
            {
                "schema_version": "1.0",
                "kind": "add_node",
                "payload": {"draft": draft.to_dict()},
            }
        )

    @classmethod
    def update_node(cls, node_id: str, updates: Mapping[str, Any]) -> TreeMutation:
        if not isinstance(updates, Mapping):
            raise TypeError("updates must be a mapping")
        return cls(
            {
                "schema_version": "1.0",
                "kind": "update_node",
                "payload": {"node_id": node_id, "updates": updates},
            }
        )

    @classmethod
    def prune_subtree(cls, node_id: str, reason: str) -> TreeMutation:
        return cls(
            {
                "schema_version": "1.0",
                "kind": "prune_subtree",
                "payload": {"node_id": node_id, "reason": reason},
            }
        )

    @classmethod
    def propagate_insight(
        cls, source_node_id: str, target_node_id: str, insight_id: str
    ) -> TreeMutation:
        return cls(
            {
                "schema_version": "1.0",
                "kind": "propagate_insight",
                "payload": {
                    "source_node_id": source_node_id,
                    "target_node_id": target_node_id,
                    "insight_id": insight_id,
                },
            }
        )

    @classmethod
    def from_dict(cls, mapping: Mapping[str, Any]) -> TreeMutation:
        return cls(mapping)

    def __setattr__(self, name: str, value: object) -> None:
        if getattr(self, "_initialized", False):
            raise AttributeError("TreeMutation is immutable")
        object.__setattr__(self, name, value)

    @property
    def kind(self) -> str:
        return cast(str, cast(Mapping[str, FrozenJSON], self._snapshot)["kind"])

    @property
    def payload(self) -> Mapping[str, FrozenJSON]:
        return cast(
            Mapping[str, FrozenJSON],
            cast(Mapping[str, FrozenJSON], self._snapshot)["payload"],
        )

    @property
    def sha256(self) -> str:
        return self._sha256

    def request_hash(self, expected_revision: int, idempotency_key: str) -> str:
        """Bind this mutation to its optimistic revision and idempotency key."""

        if isinstance(expected_revision, bool) or not isinstance(
            expected_revision, int
        ):
            raise HypothesisInvariantError("expected_revision must be an integer")
        if expected_revision < 0:
            raise HypothesisInvariantError("expected_revision cannot be negative")
        require_identifier(idempotency_key, "mutation idempotency_key")
        request = {
            "mutation": self.to_dict(),
            "expected_revision": expected_revision,
            "idempotency_key": idempotency_key,
        }
        return sha256(canonical_normalized_bytes(request)).hexdigest()

    def to_dict(self) -> dict[str, JSONValue]:
        return cast(dict[str, JSONValue], _deep_thaw(self._snapshot))

    def to_json(self) -> str:
        return self._canonical.decode("utf-8")

    def __copy__(self) -> TreeMutation:
        return self

    def __deepcopy__(self, memo: dict[int, object]) -> TreeMutation:
        memo[id(self)] = self
        return self

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, TreeMutation):
            return NotImplemented
        return self._canonical == other._canonical

    def __hash__(self) -> int:
        return hash(self._canonical)


def _validate_mutation_mapping(mapping: Mapping[str, Any]) -> dict[str, JSONValue]:
    normalized = normalize_mapping(mapping)
    if set(normalized) != {"schema_version", "kind", "payload"}:
        raise HypothesisInvariantError("TreeMutation fields do not match the interface shape")
    if normalized["schema_version"] != "1.0":
        raise HypothesisInvariantError("TreeMutation schema_version must equal 1.0")
    kind = normalized["kind"]
    if kind not in _EVENT_TYPE_BY_KIND:
        raise HypothesisInvariantError("TreeMutation kind is not supported")
    payload = normalized["payload"]
    if not isinstance(payload, dict):
        raise HypothesisInvariantError("TreeMutation payload must be an object")
    if kind == "add_node":
        if set(payload) != {"draft"} or not isinstance(payload["draft"], dict):
            raise HypothesisInvariantError("add_node mutation payload is malformed")
        NodeDraft.from_mapping(cast(dict[str, JSONValue], payload["draft"]))
    elif kind == "update_node":
        if set(payload) != {"node_id", "updates"} or not isinstance(
            payload["updates"], dict
        ):
            raise HypothesisInvariantError("update_node mutation payload is malformed")
        require_identifier(payload["node_id"], "mutation node_id")
        if not payload["updates"]:
            raise TreeConflictError("update_node requires at least one changed field")
    elif kind == "prune_subtree":
        if set(payload) != {"node_id", "reason"}:
            raise HypothesisInvariantError(
                "prune_subtree mutation payload is malformed"
            )
        require_identifier(payload["node_id"], "mutation node_id")
        reason = payload["reason"]
        if not isinstance(reason, str) or not reason.strip():
            raise TreeConflictError("prune_subtree requires a non-empty reason")
    else:
        expected = {"source_node_id", "target_node_id", "insight_id"}
        if set(payload) != expected:
            raise HypothesisInvariantError(
                "propagate_insight mutation payload is malformed"
            )
        for field in sorted(expected):
            require_identifier(payload[field], f"mutation {field}")
    return normalized


def compute_ledger_event_hash(event: Mapping[str, Any]) -> str:
    """Hash canonical LedgerEvent content excluding only ``event_hash``."""

    normalized = normalize_mapping(event)
    normalized.pop("event_hash", None)
    return sha256(canonical_normalized_bytes(normalized)).hexdigest()


def _validate_post_nodes(
    tree: QHypothesisTree, nodes: list[dict[str, JSONValue]]
) -> tuple[dict[str, JSONValue], ...]:
    mapping = tree.to_dict()
    mapping["nodes"] = nodes
    mapping["counts"] = project_counts(
        cast(list[Mapping[str, JSONValue]], nodes), tree.root_node_id
    )
    provisional = freeze_tree(mapping)
    return tuple(node.to_dict() for node in provisional.nodes)


def _replace_or_add_nodes(
    tree: QHypothesisTree, changed_nodes: list[dict[str, JSONValue]]
) -> list[dict[str, JSONValue]]:
    result = [node.to_dict() for node in tree.nodes]
    index = {cast(str, node["id"]): position for position, node in enumerate(result)}
    for changed in changed_nodes:
        node_id = cast(str, changed["id"])
        position = index.get(node_id)
        if position is None:
            index[node_id] = len(result)
            result.append(changed)
        else:
            result[position] = changed
    return result


def _ensure_operation_identity_consistency(
    tree: QHypothesisTree, changed_nodes: list[dict[str, JSONValue]]
) -> None:
    changed_ids = {cast(str, node["id"]) for node in changed_nodes}
    evidence: dict[str, dict[str, JSONValue]] = {}
    insights: dict[str, dict[str, JSONValue]] = {}
    artifacts: dict[str, dict[str, JSONValue]] = {}
    candidates: dict[str, dict[str, JSONValue]] = {}

    def record_node(node: dict[str, JSONValue]) -> None:
        for field, identity_field, index in (
            ("evidence_refs", "evidence_id", evidence),
            ("insights", "insight_id", insights),
        ):
            local_ids: set[str] = set()
            for record in cast(list[dict[str, JSONValue]], node[field]):
                identity = cast(str, record[identity_field])
                if identity in local_ids:
                    raise TreeConflictError(f"mutation repeats one {identity_field}")
                local_ids.add(identity)
                previous = index.get(identity)
                if previous is not None and canonical_normalized_bytes(
                    previous
                ) != canonical_normalized_bytes(record):
                    raise TreeConflictError(
                        f"{identity_field} already identifies different content"
                    )
                index[identity] = record
                if field == "evidence_refs":
                    for artifact in cast(
                        list[dict[str, JSONValue]], record["artifact_refs"]
                    ):
                        artifact_id = cast(str, artifact["artifact_id"])
                        prior_artifact = artifacts.get(artifact_id)
                        if prior_artifact is not None and canonical_normalized_bytes(
                            prior_artifact
                        ) != canonical_normalized_bytes(artifact):
                            raise TreeConflictError(
                                "artifact_id already identifies different content"
                            )
                        artifacts[artifact_id] = artifact
        candidate_id = node["candidate_id"]
        candidate_artifact = node["candidate_artifact"]
        if isinstance(candidate_id, str) and isinstance(candidate_artifact, dict):
            previous_candidate = candidates.get(candidate_id)
            if previous_candidate is not None and canonical_normalized_bytes(
                previous_candidate
            ) != canonical_normalized_bytes(candidate_artifact):
                raise TreeConflictError(
                    "candidate_id already identifies a different artifact"
                )
            candidates[candidate_id] = candidate_artifact
            artifact_id = cast(str, candidate_artifact["artifact_id"])
            prior_artifact = artifacts.get(artifact_id)
            if prior_artifact is not None and canonical_normalized_bytes(
                prior_artifact
            ) != canonical_normalized_bytes(candidate_artifact):
                raise TreeConflictError(
                    "artifact_id already identifies different content"
                )
            artifacts[artifact_id] = candidate_artifact

    for node in tree.nodes:
        if node.id not in changed_ids:
            record_node(node.to_dict())
    for node in changed_nodes:
        record_node(node)


def _prepare_add_node(
    tree: QHypothesisTree, mutation: TreeMutation, event_id: str
) -> tuple[str, list[dict[str, JSONValue]]]:
    payload = cast(dict[str, JSONValue], mutation.to_dict()["payload"])
    draft = NodeDraft.from_mapping(cast(dict[str, JSONValue], payload["draft"]))
    if draft.parent_id is None:
        raise TreeConflictError("only the initial root draft may have parent_id null")
    try:
        parent = tree.get_node(draft.parent_id)
    except KeyError as exc:
        raise TreeConflictError("new node parent does not exist") from exc
    try:
        tree.get_node(draft.id)
    except KeyError:
        pass
    else:
        raise TreeConflictError("new node ID already exists")

    child = materialize_node_draft(draft, depth=parent.depth + 1, event_id=event_id)
    parent_mapping = parent.to_dict()
    children = cast(list[str], parent_mapping["children_ids"])
    children.append(child.id)
    parent_mapping["children_ids"] = sorted(children)
    parent_mapping["last_event_id"] = event_id
    changed = [validate_node(parent_mapping).to_dict(), child.to_dict()]
    _ensure_operation_identity_consistency(tree, changed)
    all_nodes = _replace_or_add_nodes(tree, changed)
    ordered = _validate_post_nodes(tree, all_nodes)
    changed_ids = {parent.id, child.id}
    return child.id, [node for node in ordered if node["id"] in changed_ids]


def _prepare_update_node(
    tree: QHypothesisTree, mutation: TreeMutation, event_id: str
) -> tuple[str, list[dict[str, JSONValue]]]:
    payload = cast(dict[str, JSONValue], mutation.to_dict()["payload"])
    node_id = cast(str, payload["node_id"])
    try:
        current = tree.get_node(node_id)
    except KeyError as exc:
        raise TreeConflictError("updated node does not exist") from exc
    updates = cast(dict[str, JSONValue], payload["updates"])
    forbidden = set(updates) & _IMMUTABLE_NODE_FIELDS
    unknown = set(updates) - _MUTABLE_NODE_FIELDS
    if forbidden:
        raise TreeConflictError("node mutation attempts to change an immutable field")
    if unknown:
        raise TreeConflictError("node mutation contains an unsupported field")

    current_mapping = current.to_dict()
    new_status = cast(str, updates.get("status", current.status))
    if new_status == "pruned":
        raise TreeConflictError("pruned status requires prune_subtree")
    if (
        new_status != current.status
        and (
            current.status,
            new_status,
        )
        not in _ALLOWED_STATUS_TRANSITIONS
    ):
        raise TreeConflictError("node status transition is not allowed")
    if (
        current.status == "pruned"
        and "admissibility" in updates
        and updates["admissibility"] != current.admissibility
    ):
        raise TreeConflictError("pruned admissibility preserves its prior value")
    if (
        current.status in {"invalid", "contaminated", "incomparable", "pruned"}
        and new_status == current.status
        and "failure" in updates
        and updates["failure"] != current_mapping["failure"]
    ):
        # Terminal failure records remain append-only history.
        raise TreeConflictError("terminal failure records are immutable")
    if (
        current.candidate_id is not None
        and "candidate_id" in updates
        and updates["candidate_id"] != current.candidate_id
    ):
        raise TreeConflictError("assigned candidate_id is immutable")
    if current.candidate_artifact is not None and "candidate_artifact" in updates:
        existing_artifact = cast(JSONValue, current_mapping["candidate_artifact"])
        if updates["candidate_artifact"] != existing_artifact:
            raise TreeConflictError("assigned candidate_artifact is immutable")
    if "attempt_ids" in updates:
        old_attempts = cast(list[str], current_mapping["attempt_ids"])
        new_attempts = updates["attempt_ids"]
        if (
            not isinstance(new_attempts, list)
            or new_attempts[: len(old_attempts)] != old_attempts
        ):
            raise TreeConflictError("attempt IDs are append-only")
    for field in ("test_family_refs", "lineage_refs"):
        if field in updates:
            old_refs = cast(list[str], current_mapping[field])
            new_refs = updates[field]
            if not isinstance(new_refs, list) or new_refs[: len(old_refs)] != old_refs:
                raise TreeConflictError(f"{field} records are append-only")
    if "evidence_refs" in updates:
        old_evidence = cast(
            list[dict[str, JSONValue]], current_mapping["evidence_refs"]
        )
        new_evidence = updates["evidence_refs"]
        if not isinstance(new_evidence, list) or len(new_evidence) < len(old_evidence):
            raise TreeConflictError("evidence records cannot be erased")
        for position, old_record in enumerate(old_evidence):
            new_record = new_evidence[position]
            if (
                not isinstance(new_record, dict)
                or new_record.get("evidence_id") != old_record["evidence_id"]
            ):
                raise TreeConflictError("evidence identities are append-only")
            old_without_status = dict(old_record)
            new_without_status = dict(new_record)
            old_status = old_without_status.pop("status")
            new_status = new_without_status.pop("status", None)
            if canonical_normalized_bytes(
                old_without_status
            ) != canonical_normalized_bytes(new_without_status):
                raise TreeConflictError("existing evidence content is immutable")
            if new_status != old_status and not (
                old_status == "valid"
                and new_status in {"invalidated", "contaminated", "incomparable"}
            ):
                raise TreeConflictError("evidence status transition is not allowed")
    if "insights" in updates:
        old_insights = cast(list[dict[str, JSONValue]], current_mapping["insights"])
        new_insights = updates["insights"]
        if not isinstance(new_insights, list) or len(new_insights) < len(old_insights):
            raise TreeConflictError("insight records cannot be erased")
        for position, old_record in enumerate(old_insights):
            new_record = new_insights[position]
            if (
                not isinstance(new_record, dict)
                or new_record.get("insight_id") != old_record["insight_id"]
            ):
                raise TreeConflictError("insight identities are append-only")
            old_fixed = {
                key: value
                for key, value in old_record.items()
                if key
                not in {
                    "evidence_ids",
                    "grade",
                    "validity",
                    "invalidation_reason",
                }
            }
            new_fixed = {
                key: value
                for key, value in new_record.items()
                if key
                not in {
                    "evidence_ids",
                    "grade",
                    "validity",
                    "invalidation_reason",
                }
            }
            if canonical_normalized_bytes(old_fixed) != canonical_normalized_bytes(
                new_fixed
            ):
                raise TreeConflictError("existing insight content is immutable")
            old_evidence_ids = cast(list[str], old_record["evidence_ids"])
            new_evidence_ids = new_record.get("evidence_ids")
            if (
                not isinstance(new_evidence_ids, list)
                or new_evidence_ids[: len(old_evidence_ids)] != old_evidence_ids
            ):
                raise TreeConflictError("insight evidence references are append-only")
            old_validity = old_record["validity"]
            new_validity = new_record.get("validity")
            allowed_validity = {
                "active": {"active", "uncertain", "invalidated"},
                "uncertain": {"active", "uncertain", "invalidated"},
                "invalidated": {"invalidated"},
            }
            if new_validity not in allowed_validity[cast(str, old_validity)]:
                raise TreeConflictError("insight validity transition is not allowed")
            old_grade = cast(str, old_record["grade"])
            new_grade = new_record.get("grade")
            allowed_grade = {
                "unverified": {
                    "unverified",
                    "development_supported",
                    "gate_supported",
                },
                "development_supported": {
                    "development_supported",
                    "gate_supported",
                },
                "gate_supported": {"gate_supported"},
                "contradicted": {"contradicted"},
            }
            if new_grade == "contradicted":
                if new_validity != "invalidated":
                    raise TreeConflictError(
                        "contradicted grade requires invalidated validity"
                    )
            elif new_grade not in allowed_grade[old_grade]:
                raise TreeConflictError("insight grade transition is not allowed")
            if old_validity == "invalidated" and canonical_normalized_bytes(
                old_record
            ) != canonical_normalized_bytes(new_record):
                raise TreeConflictError("invalidated insight records are immutable")

    current_mapping.update(updates)
    current_mapping["last_event_id"] = event_id
    for field, identity_field in (
        ("evidence_refs", "evidence_id"),
        ("insights", "insight_id"),
    ):
        records = cast(list[dict[str, JSONValue]], current_mapping[field])
        identities = [record.get(identity_field) for record in records]
        if len(identities) != len(set(identities)):
            raise TreeConflictError(f"mutation repeats one {identity_field}")
    changed = validate_node(current_mapping).to_dict()
    _ensure_operation_identity_consistency(tree, [changed])
    all_nodes = _replace_or_add_nodes(tree, [changed])
    _validate_post_nodes(tree, all_nodes)
    return node_id, [changed]


def _descendant_ids(tree: QHypothesisTree, node_id: str) -> list[str]:
    result: list[str] = []
    stack = [node_id]
    while stack:
        current = stack.pop()
        result.append(current)
        stack.extend(reversed(tree.get_node(current).children_ids))
    return result


def _prepare_prune_subtree(
    tree: QHypothesisTree, mutation: TreeMutation, event_id: str
) -> tuple[str, list[dict[str, JSONValue]]]:
    payload = cast(dict[str, JSONValue], mutation.to_dict()["payload"])
    node_id = cast(str, payload["node_id"])
    if node_id == tree.root_node_id:
        raise TreeConflictError("the tree root cannot be pruned")
    try:
        root = tree.get_node(node_id)
    except KeyError as exc:
        raise TreeConflictError("pruned node does not exist") from exc
    if root.status == "pruned":
        raise TreeConflictError("subtree is already pruned")

    changed: list[dict[str, JSONValue]] = []
    for descendant_id in _descendant_ids(tree, node_id):
        mapping = tree.get_node(descendant_id).to_dict()
        mapping["status"] = "pruned"
        mapping["lifecycle"] = "pruned"
        mapping["last_event_id"] = event_id
        if mapping["admissibility"] != "admissible":
            mapping["score"] = None
        changed.append(validate_node(mapping).to_dict())
    all_nodes = _replace_or_add_nodes(tree, changed)
    ordered = _validate_post_nodes(tree, all_nodes)
    changed_ids = set(_descendant_ids(tree, node_id))
    return node_id, [node for node in ordered if node["id"] in changed_ids]


def _prepare_propagation(
    tree: QHypothesisTree, mutation: TreeMutation, event_id: str
) -> tuple[str, list[dict[str, JSONValue]]]:
    payload = cast(dict[str, JSONValue], mutation.to_dict()["payload"])
    target_node_id = cast(str, payload["target_node_id"])
    changed = prepare_insight_propagation(
        tree,
        cast(str, payload["source_node_id"]),
        target_node_id,
        cast(str, payload["insight_id"]),
        event_id=event_id,
    )
    if changed is None:
        return target_node_id, []
    all_nodes = _replace_or_add_nodes(tree, [changed.to_dict()])
    _validate_post_nodes(tree, all_nodes)
    return target_node_id, [changed.to_dict()]


def prepare_mutation(
    tree: QHypothesisTree,
    mutation: TreeMutation,
    *,
    event_id: str,
    idempotency_key: str | None = None,
) -> tuple[str, str, dict[str, JSONValue]]:
    """Prepare an event type, primary node ID, and replay-complete payload."""

    if not isinstance(tree, QHypothesisTree) or not isinstance(mutation, TreeMutation):
        raise TypeError("prepare_mutation requires a frozen tree and TreeMutation")
    require_identifier(event_id, "mutation event_id")
    if tree.run_state not in {"setup", "development"}:
        raise TreeConflictError("tree run_state does not permit node mutation")
    if idempotency_key is None:
        idempotency_key = mutation.sha256
    require_identifier(idempotency_key, "mutation idempotency_key")

    if mutation.kind == "add_node":
        node_id, changed = _prepare_add_node(tree, mutation, event_id)
    elif mutation.kind == "update_node":
        node_id, changed = _prepare_update_node(tree, mutation, event_id)
    elif mutation.kind == "prune_subtree":
        node_id, changed = _prepare_prune_subtree(tree, mutation, event_id)
    else:
        node_id, changed = _prepare_propagation(tree, mutation, event_id)
    payload: dict[str, JSONValue] = {
        "schema_version": "1.0",
        "kind": mutation.kind,
        "idempotency_key": idempotency_key,
        "request_hash": mutation.request_hash(tree.revision, idempotency_key),
        "expected_revision": tree.revision,
        "result_revision": tree.revision + 1,
        "mutation": mutation.to_dict(),
        "changed_nodes": changed,
    }
    # Identities and complete changed records are
    # fixed before the ledger event is hashed and durably appended.
    return _EVENT_TYPE_BY_KIND[mutation.kind], node_id, payload


def prepare_initial_tree_payload(
    tree_body: Mapping[str, Any], *, idempotency_key: str
) -> dict[str, JSONValue]:
    """Prepare the exact run.started payload for native or compatibility state."""

    require_identifier(idempotency_key, "initial idempotency_key")
    normalized = normalize_mapping(tree_body)
    required = {
        "run_id",
        "contract_hash",
        "root_node_id",
        "run_state",
        "nodes",
        "counts",
    }
    if set(normalized) not in (required, required | {"compatibility"}):
        raise HypothesisInvariantError("initial tree body has unexpected fields")
    provisional: dict[str, JSONValue] = {
        "schema_version": "1.0",
        "run_id": normalized["run_id"],
        "revision": 0,
        "contract_hash": normalized["contract_hash"],
        "root_node_id": normalized["root_node_id"],
        "run_state": normalized["run_state"],
        "ledger_head": {"last_sequence": 1, "last_event_hash": "0" * 64},
        "nodes": normalized["nodes"],
        "counts": normalized["counts"],
        "tree_hash": "0" * 64,
    }
    if "compatibility" in normalized:
        provisional["compatibility"] = normalized["compatibility"]
    frozen = freeze_tree(provisional).to_dict()
    canonical_body = {
        key: value
        for key, value in frozen.items()
        if key not in {"schema_version", "revision", "ledger_head", "tree_hash"}
    }
    initial_request = {
        "tree": canonical_body,
        "expected_revision": None,
        "idempotency_key": idempotency_key,
    }
    request_hash = sha256(canonical_normalized_bytes(initial_request)).hexdigest()
    return {
        "schema_version": "1.0",
        "kind": "initialize_tree",
        "idempotency_key": idempotency_key,
        "request_hash": request_hash,
        "expected_revision": None,
        "result_revision": 0,
        "tree": canonical_body,
    }


def prepare_run_started(
    *,
    run_id: str,
    contract_hash: str,
    root: NodeDraft,
    event_id: str,
    idempotency_key: str = "run.started",
) -> tuple[str, dict[str, JSONValue]]:
    """Prepare a native single-root run.started node ID and event payload."""

    require_identifier(run_id, "initial run_id")
    require_sha256(contract_hash, "initial contract_hash")
    require_identifier(event_id, "initial event_id")
    if not isinstance(root, NodeDraft):
        raise TypeError("root must be a NodeDraft")
    if root.parent_id is not None:
        raise TreeConflictError("initial root draft must have parent_id null")
    root_node = materialize_node_draft(root, depth=0, event_id=event_id)
    nodes = [root_node.to_dict()]
    body: dict[str, JSONValue] = {
        "run_id": run_id,
        "contract_hash": contract_hash,
        "root_node_id": root.id,
        "run_state": "development",
        "nodes": nodes,
        "counts": project_counts(cast(list[Mapping[str, JSONValue]], nodes), root.id),
    }
    return root.id, prepare_initial_tree_payload(body, idempotency_key=idempotency_key)


def _validated_ledger_event(event: Mapping[str, Any]) -> dict[str, JSONValue]:
    normalized = normalize_mapping(event)
    validate_discriminator(normalized, "ledger_event")
    require_identifier(normalized["run_id"], "ledger event run_id")
    require_identifier(normalized["event_id"], "ledger event event_id")
    require_sha256(normalized["contract_hash"], "ledger event contract_hash")
    _prev = normalized["prev_event_hash"]
    if _prev is not None:
        require_sha256(_prev, "ledger event prev_event_hash")
    require_sha256(normalized["event_hash"], "ledger event event_hash")
    if normalized.get("node_id") is not None:
        require_identifier(normalized["node_id"], "ledger event node_id")
    if compute_ledger_event_hash(normalized) != normalized["event_hash"]:
        raise TreeIntegrityError("ledger event hash does not match its content")
    return normalized


def _apply_initial_event(event: dict[str, JSONValue]) -> QHypothesisTree:
    if event["event_type"] != "run.started":
        raise TreeConflictError("the first tree event must be run.started")
    if event["sequence"] != 1 or event["prev_event_hash"] is not None:
        raise TreeIntegrityError("run.started must begin the ledger chain")
    if event["actor"] != "system":
        raise TreeConflictError("run.started actor must be system")
    if event.get("split_role") != "none" or event.get("attempt_id") is not None:
        raise TreeConflictError(
            "tree lifecycle events cannot carry split or attempt scope"
        )
    payload = event["payload"]
    if not isinstance(payload, dict) or set(payload) != _INITIAL_PAYLOAD_KEYS:
        raise HypothesisInvariantError("run.started payload has unexpected fields")
    if payload["schema_version"] != "1.0" or payload["kind"] != "initialize_tree":
        raise HypothesisInvariantError("run.started payload version or kind is invalid")
    require_identifier(payload["idempotency_key"], "initial idempotency_key")
    require_sha256(payload["request_hash"], "initial request_hash")
    if payload["expected_revision"] is not None or payload["result_revision"] != 0:
        raise TreeConflictError("run.started revision transition is invalid")
    tree_body = payload["tree"]
    if not isinstance(tree_body, dict):
        raise HypothesisInvariantError("run.started tree body must be an object")
    expected_payload = prepare_initial_tree_payload(
        tree_body, idempotency_key=cast(str, payload["idempotency_key"])
    )
    if canonical_normalized_bytes(expected_payload) != canonical_normalized_bytes(
        payload
    ):
        raise TreeIntegrityError(
            "run.started payload is not canonical or self-consistent"
        )
    if tree_body["run_id"] != event["run_id"]:
        raise TreeIntegrityError("run.started run identity does not match its tree")
    if tree_body["contract_hash"] != event["contract_hash"]:
        raise TreeIntegrityError(
            "run.started contract identity does not match its tree"
        )
    if event.get("node_id") != tree_body["root_node_id"]:
        raise TreeIntegrityError("run.started node_id does not identify its root")
    for node in cast(list[dict[str, JSONValue]], tree_body["nodes"]):
        if (
            node["created_event_id"] != event["event_id"]
            or node["last_event_id"] != event["event_id"]
        ):
            raise TreeIntegrityError(
                "initial nodes must identify their materializing run.started event"
            )

    mapping: dict[str, JSONValue] = {
        "schema_version": "1.0",
        "run_id": tree_body["run_id"],
        "revision": 0,
        "contract_hash": tree_body["contract_hash"],
        "root_node_id": tree_body["root_node_id"],
        "run_state": tree_body["run_state"],
        "ledger_head": {
            "last_sequence": 1,
            "last_event_hash": event["event_hash"],
        },
        "nodes": tree_body["nodes"],
        "counts": tree_body["counts"],
        "tree_hash": "0" * 64,
    }
    if "compatibility" in tree_body:
        mapping["compatibility"] = tree_body["compatibility"]
    return freeze_tree(mapping)


def apply_tree_event(
    tree: QHypothesisTree | None, ledger_event: Mapping[str, Any]
) -> QHypothesisTree:
    """Purely replay one verified event into an immutable materialized tree."""

    event = _validated_ledger_event(ledger_event)
    if tree is None:
        return _apply_initial_event(event)
    if not isinstance(tree, QHypothesisTree):
        raise TypeError("tree must be a QHypothesisTree or None")
    if event["run_id"] != tree.run_id or event["contract_hash"] != tree.contract_hash:
        raise TreeIntegrityError("ledger event identity does not match the tree")
    if event.get("split_role") != "none" or event.get("attempt_id") is not None:
        raise TreeConflictError(
            "tree mutation events cannot carry split or attempt scope"
        )
    expected_sequence = tree.revision + 2
    if cast(int, event["sequence"]) <= tree.revision + 1:
        raise TreeConflictError("ledger event revision is stale")
    if event["sequence"] != expected_sequence:
        raise TreeIntegrityError("ledger event sequence contains a gap")
    if event["prev_event_hash"] != tree.ledger_head["last_event_hash"]:
        raise TreeIntegrityError("ledger event does not extend the tree ledger head")

    payload = event["payload"]
    if not isinstance(payload, dict) or set(payload) != _MUTATION_PAYLOAD_KEYS:
        raise HypothesisInvariantError("mutation event payload has unexpected fields")
    if payload["schema_version"] != "1.0":
        raise HypothesisInvariantError("mutation event payload version is invalid")
    require_identifier(payload["idempotency_key"], "mutation idempotency_key")
    require_sha256(payload["request_hash"], "mutation request_hash")
    if (
        payload["expected_revision"] != tree.revision
        or payload["result_revision"] != tree.revision + 1
    ):
        raise TreeConflictError("mutation event revision is stale")
    mutation_mapping = payload["mutation"]
    if not isinstance(mutation_mapping, dict):
        raise HypothesisInvariantError("mutation event request must be an object")
    mutation = TreeMutation.from_dict(mutation_mapping)
    if payload["kind"] != mutation.kind or payload[
        "request_hash"
    ] != mutation.request_hash(tree.revision, cast(str, payload["idempotency_key"])):
        raise TreeIntegrityError("mutation request hash or kind does not match")
    expected_type, expected_node_id, expected_payload = prepare_mutation(
        tree,
        mutation,
        event_id=cast(str, event["event_id"]),
        idempotency_key=cast(str, payload["idempotency_key"]),
    )
    if event["event_type"] != expected_type or event.get("node_id") != expected_node_id:
        raise TreeIntegrityError("ledger event type or node identity does not match")
    if canonical_normalized_bytes(expected_payload) != canonical_normalized_bytes(
        payload
    ):
        raise TreeIntegrityError(
            "ledger event changed-node records do not match reducer output"
        )

    changed = cast(list[dict[str, JSONValue]], payload["changed_nodes"])
    nodes = _replace_or_add_nodes(tree, changed)
    mapping = tree.to_dict()
    mapping["revision"] = tree.revision + 1
    mapping["ledger_head"] = {
        "last_sequence": event["sequence"],
        "last_event_hash": event["event_hash"],
    }
    mapping["nodes"] = nodes
    mapping["counts"] = project_counts(
        cast(list[Mapping[str, JSONValue]], nodes), tree.root_node_id
    )
    # Replay consumes only the durable event; the
    # tree snapshot is a derived projection whose hash is computed afterwards.
    return freeze_tree(mapping)
