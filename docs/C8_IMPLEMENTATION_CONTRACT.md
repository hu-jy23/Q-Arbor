# C8 implementation contract — Quantitative Hypothesis Tree

This contract is the coordination surface for C8. It implements only the C6 `QuantHypothesisNode`, `QHypothesisTree`, `EvidenceRef`, `InsightRecord`, `FailureRecord`, `Scope`, and the minimum event-first mutation subset needed to prove serial persistence. C9 owns evaluator results, C10 owns capability/evidence-ledger policy, C11 owns the live Arbor coordinator adapter, and C12 owns full-session recovery/reporting.

## Public package surface

`q_arbor.hypotheses` exports:

- typed errors for decode, schema, invariant, conflict, integrity, compatibility, and persistence failures;
- immutable `QuantHypothesisNode` and `QHypothesisTree` values with detached `to_dict()`, canonical `to_json()`, and stable hash behavior;
- `validate_node`, `validate_tree`, `freeze_tree`, `load_tree`, and atomic tree writing;
- `TreeMutation`, mutation builders, a pure reducer, scope-aware insight propagation, and `HypothesisTreeStore`;
- `import_arbor_tree`, deterministic JSON export, and a self-contained escaped HTML export.

The exact C8 public names are frozen here:

```python
class HypothesisError(Exception): ...
class HypothesisDecodeError(HypothesisError): ...
class HypothesisSchemaError(HypothesisError): ...
class HypothesisInvariantError(HypothesisError): ...
class TreeConflictError(HypothesisError): ...
class TreeIntegrityError(HypothesisError): ...
class TreeCompatibilityError(HypothesisError): ...
class TreePersistenceError(HypothesisError): ...

freeze_node(mapping) -> QuantHypothesisNode
validate_node(mapping) -> QuantHypothesisNode
freeze_tree(mapping) -> QHypothesisTree             # replaces tree_hash
validate_tree(mapping, *, verify_hash=True) -> QHypothesisTree
load_tree(path) -> QHypothesisTree
QHypothesisTree.write(path) -> None                   # same-dir temp, fsync, replace

TreeMutation.add_node(draft: NodeDraft) -> TreeMutation
TreeMutation.update_node(node_id, updates) -> TreeMutation
TreeMutation.prune_subtree(node_id, reason) -> TreeMutation
TreeMutation.propagate_insight(source_node_id, target_node_id, insight_id) -> TreeMutation
apply_tree_event(tree, ledger_event) -> QHypothesisTree

HypothesisTreeStore.create(
    directory, *, run_id, contract_hash, root: NodeDraft,
    clock=None, event_id_factory=None, fault_hook=None,
) -> HypothesisTreeStore
HypothesisTreeStore.open(
    directory, *, clock=None, event_id_factory=None, fault_hook=None,
) -> HypothesisTreeStore
store.load() -> QHypothesisTree
store.apply(mutation, *, expected_revision, idempotency_key,
            actor="coordinator") -> QHypothesisTree
store.recover() -> QHypothesisTree
store.verify() -> TreeVerification

import_arbor_tree(legacy_mapping, *, run_id, contract_hash,
                  default_scope=None) -> ArborImportResult
export_tree_json(tree) -> str
render_tree_html(tree, *, title="Q-Arbor Hypothesis Tree") -> str
write_tree_html(tree, path, *, title="Q-Arbor Hypothesis Tree") -> None
```

`NodeDraft` is immutable and contains `id`, `parent_id`, `hypothesis`, `scope`, `family`, and `prompt_snapshot_sha256`, plus optional candidate/artifact, test-family, lineage, and code references. Store/reducer code supplies depth, empty runtime collections, initial composite status, failure=`none`, and creation/last event IDs. `TreeMutation.to_dict()` is `{"schema_version":"1.0","kind":...,"payload":...}` and its `sha256` hashes that complete normalized mapping. Module-level builder aliases may exist, but tests use the class methods above.

`clock` is a zero-argument callable returning a timezone-aware `datetime`; `event_id_factory` receives the next integer sequence and returns a valid identifier. `fault_hook(stage)` is called at the documented `"after_event_fsync"` seam. Default factories may vary between runs; injected factories make qualification tests deterministic.

Error ownership is fixed: malformed/ambiguous input uses `HypothesisDecodeError`; frozen-schema failure uses `HypothesisSchemaError`; schema-valid node/tree cross-invariant failure uses `HypothesisInvariantError`; a wrong `tree_hash`, journal/snapshot chain failure, or snapshot-ahead state uses `TreeIntegrityError`; stale revision, different-request idempotency reuse, scope/sibling/non-active propagation rejection, or immutable-field mutation uses `TreeConflictError`; propagation from compatibility-quarantined state uses `TreeCompatibilityError`; and filesystem/lock/atomic-write failure uses `TreePersistenceError`.

All C8 artifacts validate through the packaged, hash-checked C6 discriminator schema. Canonical JSON is NFC-normalized, sorted, compact UTF-8 with non-finite numbers and ambiguous/recursive values rejected. `tree_hash` hashes the complete normalized tree payload after omitting only its top-level `tree_hash` field.

## Node semantics

Every node preserves Arbor's `id`, `parent_id`, `children_ids`, `depth`, `status`, and `score` surface while adding the frozen hypothesis, scope, family, candidate, evidence, insight, failure, prompt, and event identities.

The composite status is checked against lifecycle/admissibility:

| status | lifecycle | admissibility |
|---|---|---|
| `pending` | `pending` | `unevaluated` |
| `running` | `running` | `unevaluated` |
| `needs_retry` | `needs_retry` | `unevaluated` |
| `done` | `done` | `admissible` |
| `merged` | `merged` | `admissible` |
| `invalid` | `done` | `invalid` |
| `contaminated` | `done` | `contaminated` |
| `incomparable` | `done` | `incomparable` |
| `pruned` | `pruned` | prior admissibility, preserved explicitly |

Only admissible `done`, `merged`, or `pruned` nodes may expose a finite `score`, and each non-null score requires a valid observed evidence reference with a non-null `result_id`. C8 checks provenance shape; C9 binds the referenced `EvaluationResult`. Contaminated or invalidated evidence cannot support an active insight. Node IDs, ancestry, dispatched hypothesis, scope/family identity, prompt snapshot, and creation event are immutable after proposal.

A complete node answers: why it exists (`mechanism` and prediction), what changes (`single_change`), what is observed, which market/data/config scope applies, which candidate family it belongs to, what evidence/failure was obtained, and whether its status permits continuation.

## Tree invariants

- One root has `parent_id=null` and depth zero; every other node has one existing parent and parent depth plus one.
- IDs are unique; parent/child links are reciprocal; the graph is acyclic, fully reachable, and deterministically ordered.
- Evidence, insight, attempt, lineage, and family references are unique where the C6 schema requires uniqueness.
- Counts are deterministic projections of the current nodes and referenced records. No C8 code invents evaluation-query evidence.
- The tree's contract hash, ledger head, revision, and tree hash are mutually consistent.
- A legacy/missing-field compatibility flag quarantines incomplete state from admissible scoring or propagation.

Counts have one C8 definition: `proposals` is the number of non-root nodes; `unique_candidates` and `candidate_families` are distinct non-null candidate/family IDs on non-root nodes; `attempts` is the number of distinct attempt IDs; `evaluation_queries` is the number of distinct non-null `result_id` references (a referenced-result projection until C10 replaces it with the authoritative ledger count); and `admissible_evidence` is the number of distinct evidence IDs whose status is `valid` on an admissible node.

## Scope-aware propagation

Propagation is upward from a source node to one of its ancestors. The copied `InsightRecord` retains its original scope and evidence IDs; the target also receives the referenced evidence records, without rewriting their claims or grades. Propagation requires matching market, universe, frequency, horizon, data snapshot hash, and cost-model hash. Time range, fields, and regime labels remain attached to the original insight scope and are never silently generalized.

Only active, non-contradicted insights supported by valid, non-contaminated evidence may propagate. A duplicate insight ID with identical canonical content is idempotent; the same ID with different content is a conflict. Sibling transfer and propagation from compatibility-quarantined nodes fail closed.

## Mutation journal and recovery

`HypothesisTreeStore` owns `tree.json`, `tree.events.jsonl`, and a lock file inside one caller-supplied state directory. It uses an OS file lock for cross-process serialization. A mutation requires `expected_revision` and an `idempotency_key`.

For every accepted mutation:

1. lock and verify/replay the hash-chained journal;
2. reject a stale revision or key reuse with different canonical request content;
3. validate the complete post-mutation node state;
4. append one canonical C6 `LedgerEvent` and `fsync` it;
5. apply the deterministic reducer;
6. atomically replace and directory-sync the tree snapshot.

The C8 event subset is `run.started`, `hypothesis.proposed`, `node.updated`, `insight.created`, and `prune.completed`. Event payloads contain a versioned mutation kind, idempotency key, request hash, expected/result revision, and the complete changed node records needed for replay. The initial event produces revision zero; thereafter `ledger_sequence = tree_revision + 1`.

Recovery treats the verified journal as history and `tree.json` as a materialized view. A missing or event-behind snapshot is rebuilt. A broken event hash/sequence, conflicting idempotency record, snapshot-ahead state, or unrecoverable partial event fails with `TreeIntegrityError`; it is never silently accepted. Tests inject a failure after event `fsync` and before snapshot replacement, then require exact recovery and idempotent retry.

## Arbor v3 compatibility

The importer accepts the pinned Arbor v3 `idea_tree.json` shape (`root_id`, node map, meta) and individual `Node.to_dict()` records. It never guesses missing quantitative facts:

- the legacy hypothesis text is retained as mechanism; absent prediction/change/scope/family/evidence fields receive explicit compatibility sentinels and per-node missing-field flags;
- unbound legacy scores and test scores are quarantined in tree compatibility metadata, while Q-node `score` remains null and cannot drive selection;
- legacy status/result/insight/code references are retained only in safe typed projections; raw eval commands, dataset descriptions, paths, tokens, and plugin payloads are dropped and listed;
- callers supply the destination run ID and contract hash; absent scope hashes use documented zero-hash sentinels and keep the node quarantined until resolved.

Compatibility uses `LEGACY_UNKNOWN_HASH = "0" * 64` and `LEGACY_UNKNOWN_TEXT = "legacy:unspecified"`. `ArborImportResult` contains the immutable tree, a tuple of deterministic import `LedgerEvent` mappings, and warnings. Tree compatibility metadata uses exactly `source`, `source_version`, `quarantined`, `missing_fields_by_node`, `legacy_scores_by_node`, `legacy_status_by_node`, `safe_meta`, and `dropped_meta_keys`.

Each `legacy_scores_by_node` value has exactly `score`, `score_source`, `score_split`, and `test_score`: `score_source` is `score`, `score_delta`, or null; both scores are finite numbers or null; `score_split` is `dev`, `test`, or null. This preserves `score_delta` compatibility and a separate test score without assigning either to Q-node `score`. Each `legacy_status_by_node` value has exactly `status`, `eval_status`, `stop_reason`, `attempt`, `result_sha256`, `insight_sha256`, `code_ref_sha256`, `related_work_sha256`, and `grounding_sha256`; the first three use pinned Arbor enums or null, `attempt` is a positive integer or null, and free text is represented only by an NFC UTF-8 content digest or null. A normalized standalone node may additionally record `source_parent_id` and `source_depth`.

`safe_meta` may contain only a validated `metric_direction` (`maximize` or `minimize`) and `max_depth` (positive integer or null); all other legacy metadata is excluded. `dropped_meta_keys` and warnings identify known unsafe fields by field name only, represent unknown keys as `unknown-sha256:<64 lowercase hex>`, and never copy a dropped value. Import event IDs/hashes are derived from canonical legacy input and sequence; absent source time uses the fixed sentinel `1970-01-01T00:00:00Z` and is reported as missing, so identical inputs produce identical output.

JSON export is canonical. HTML export is deterministic, self-contained, UTF-8, and escapes every untrusted string and embedded JSON delimiter. It shows tree structure, status/admissibility, hypothesis, scope, evidence grade, failure, insights, and compatibility warnings.

## Required qualification tests

1. node/tree schema, canonical hash, immutability, detached output, and round-trip;
2. ancestry, cycle, depth, child reciprocity, count, status/admissibility, score/evidence, and immutable-field conflicts;
3. successful scoped propagation, idempotent propagation, scope mismatch, sibling rejection, invalidated/contaminated evidence, and failure insight behavior;
4. actual pinned Arbor node/tree import, old `score_delta`, missing-field flags, score quarantine, dropped unsafe meta, canonical JSON, and HTML XSS escaping;
5. sequential and multi-process mutations, stale revision, duplicate/different idempotency requests, hash-chain tamper, snapshot tamper, missing snapshot, and injected event-before-snapshot crash recovery;
6. both repositories remain clean at exit; frozen C6 schema hash and C7 contract/projection tests remain unchanged and green.

Passing C8 proves the quantitative research-state and durable tree mutation layer. It does not prove an evaluator, adaptive-testing control, live Coordinator loop, complete checkpoint/report, HM1 result, or the `Q-Arbor prototype` name.
