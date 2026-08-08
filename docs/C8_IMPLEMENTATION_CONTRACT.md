# C8 implementation contract — Quantitative Hypothesis Tree

This contract is the coordination surface for C8. It implements only the C6 `QuantHypothesisNode`, `QHypothesisTree`, `EvidenceRef`, `InsightRecord`, `FailureRecord`, `Scope`, and the minimum event-first mutation subset needed to prove serial persistence. C9 owns evaluator results, C10 owns capability/evidence-ledger policy, C11 owns the live Arbor coordinator adapter, and C12 owns full-session recovery/reporting.

## Public package surface

`q_arbor.hypotheses` exports:

- typed errors for decode, schema, invariant, conflict, integrity, compatibility, and persistence failures;
- immutable `QuantHypothesisNode` and `QHypothesisTree` values with detached `to_dict()`, canonical `to_json()`, and stable hash behavior;
- `validate_node`, `validate_tree`, `freeze_tree`, `load_tree`, and atomic tree writing;
- `TreeMutation`, mutation builders, a pure reducer, scope-aware insight propagation, and `HypothesisTreeStore`;
- `import_arbor_tree`, deterministic JSON export, and a self-contained escaped HTML export.

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

JSON export is canonical. HTML export is deterministic, self-contained, UTF-8, and escapes every untrusted string and embedded JSON delimiter. It shows tree structure, status/admissibility, hypothesis, scope, evidence grade, failure, insights, and compatibility warnings.

## Required qualification tests

1. node/tree schema, canonical hash, immutability, detached output, and round-trip;
2. ancestry, cycle, depth, child reciprocity, count, status/admissibility, score/evidence, and immutable-field conflicts;
3. successful scoped propagation, idempotent propagation, scope mismatch, sibling rejection, invalidated/contaminated evidence, and failure insight behavior;
4. actual pinned Arbor node/tree import, old `score_delta`, missing-field flags, score quarantine, dropped unsafe meta, canonical JSON, and HTML XSS escaping;
5. sequential and multi-process mutations, stale revision, duplicate/different idempotency requests, hash-chain tamper, snapshot tamper, missing snapshot, and injected event-before-snapshot crash recovery;
6. both repositories remain clean at exit; frozen C6 schema hash and C7 contract/projection tests remain unchanged and green.

Passing C8 proves the quantitative research-state and durable tree mutation layer. It does not prove an evaluator, adaptive-testing control, live Coordinator loop, complete checkpoint/report, HM1 result, or the `Q-Arbor prototype` name.
