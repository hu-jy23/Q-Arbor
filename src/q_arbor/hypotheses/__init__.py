"""Immutable quantitative hypothesis trees and pure event reduction."""

from __future__ import annotations

from .codec import canonical_json_bytes
from .compatibility import (
    LEGACY_UNKNOWN_HASH,
    LEGACY_UNKNOWN_TEXT,
    ArborImportResult,
    import_arbor_tree,
)
from .errors import (
    HypothesisDecodeError,
    HypothesisError,
    HypothesisInvariantError,
    HypothesisSchemaError,
    TreeCompatibilityError,
    TreeConflictError,
    TreeIntegrityError,
    TreePersistenceError,
)
from .models import (
    NodeDraft,
    QHypothesisTree,
    QuantHypothesisNode,
    canonical_tree_bytes,
    compute_tree_hash,
    freeze_node,
    freeze_tree,
    load_tree,
    materialize_node_draft,
    validate_node,
    validate_tree,
    write_tree,
)
from .mutations import (
    TreeMutation,
    apply_tree_event,
    compute_ledger_event_hash,
    prepare_initial_tree_payload,
    prepare_mutation,
    prepare_run_started,
)
from .propagation import prepare_insight_propagation
from .render import export_tree_json, render_tree_html, write_tree_html
from .store import HypothesisTreeStore, TreeVerification

__all__ = [
    "LEGACY_UNKNOWN_HASH",
    "LEGACY_UNKNOWN_TEXT",
    "ArborImportResult",
    "HypothesisDecodeError",
    "HypothesisError",
    "HypothesisInvariantError",
    "HypothesisSchemaError",
    "HypothesisTreeStore",
    "NodeDraft",
    "QHypothesisTree",
    "QuantHypothesisNode",
    "TreeCompatibilityError",
    "TreeConflictError",
    "TreeIntegrityError",
    "TreeMutation",
    "TreePersistenceError",
    "TreeVerification",
    "apply_tree_event",
    "canonical_json_bytes",
    "canonical_tree_bytes",
    "compute_ledger_event_hash",
    "compute_tree_hash",
    "export_tree_json",
    "freeze_node",
    "freeze_tree",
    "import_arbor_tree",
    "load_tree",
    "materialize_node_draft",
    "prepare_initial_tree_payload",
    "prepare_insight_propagation",
    "prepare_mutation",
    "prepare_run_started",
    "render_tree_html",
    "validate_node",
    "validate_tree",
    "write_tree",
    "write_tree_html",
]
