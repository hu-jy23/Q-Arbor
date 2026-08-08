# C7 implementation contract

This document fixes the public seams used by the parallel C7 lanes.

## Contract API

`q_arbor.contracts` must export:

- `ContractError`, `ContractDecodeError`, `ContractSchemaError`, `ContractInvariantError`, `ContractHashMismatch`;
- `QuantResearchContract`;
- `load_contract(path)`;
- `freeze_contract(mapping)`;
- `validate_contract(mapping, *, verify_hash=True)`;
- `canonical_contract_bytes(mapping)`;
- `compute_contract_hash(mapping)`.

`QuantResearchContract` is an immutable value object with `sha256`, `to_dict()`, `to_json()`, and `write(path)`. Returned nested state must not permit mutation of the stored snapshot.

## Canonicalization and validation order

1. Decode strict JSON: duplicate keys and `NaN`/`Infinity` fail.
2. NFC-normalize string keys and values; a normalization-induced key collision fails.
3. Validate the frozen schema through the `quant_research_contract` discriminator.
4. Validate cross-field time, path, role, metric, split, secret, and hash invariants.
5. Canonicalize with sorted keys, compact separators, UTF-8, and `allow_nan=False`; omit `contract_hash` when computing its digest.
6. Deep-freeze the normalized snapshot.

Excessive JSON nesting fails as `ContractDecodeError` at decode, normalization, or canonicalization boundaries. Runtime `fullmatch` checks close terminal-newline behavior in every QuantResearchContract identifier and SHA-256 field. Contract paths are bounded to 4095 UTF-8 bytes in total and 255 UTF-8 bytes per component so accepted values remain representable at the pinned Git/filesystem seam.

## Data-locator and path boundary

The frozen C6 bytes and hash remain unchanged. `ConstraintSpec.threshold` is the only schema-open value inside `QuantResearchContract`; C7 gives it a closed runtime meaning: comparison operators accept a JSON scalar, and `in` accepts a non-empty array of JSON scalars. Filesystem and URI locator strings fail validation in either form. Narrative fields retain their schema-defined free-text semantics and are not scanned as locators.

C7 assumes trusted contract intake for narrative and statistical scalar values. Its structural checks are not a general-purpose secret or entropy detector. C10 remains responsible for capability enforcement and prompt/artifact redaction; raw credentials and restricted data remain forbidden by the repository contract.

Split content is bound by each sanctioned `manifest_sha256`, and the three role manifests are pairwise distinct. Data `snapshot_id`, split `dataset_id` values, and `source_version` are opaque provenance labels and cannot encode filesystem or URI locations. A shared source dataset may therefore retain one `dataset_id`; distinct manifest hashes establish development/gate/final identity. C10 owns raw split locator resolution and access capabilities.

`editable_surface` and `protected_paths` retain Arbor-compatible full-path `fnmatch` globs. Every `required_outputs` entry is a literal Git path covered by at least one editable pattern. This matches Arbor's two merge seams, which check output existence with `git show branch:path`; it also prevents a pre-existing uneditable file from satisfying the merge guard. These runtime checks enforce C6 C01 and J03 before projection.

## Arbor projection API

`q_arbor.integrations` must export `ArborRunProjection` and `project_to_arbor(contract, *, contract_path, trunk_branch, baseline_score=None)`.

The projection accepts an exact `QuantResearchContract`, revalidates its detached payload, recomputes its hash, and compares its canonical bytes. The persisted `contract_path` must load to that same canonical snapshot, not merely repeat a claimed digest. Each projection view returns detached state. This closes the C6 C01/J01/J04 identity seam before Arbor receives mutable metadata.

The projection includes development `eval_cmd`, `metric_direction`, a syntactically unambiguous non-default `trunk_branch`, `protected_paths`, `required_outputs`, contract/baseline references, and an optional finite `baseline_score`. Repository-local branch existence and exact `refs/heads/...` identity remain launcher/integration checks for C11 because C7 projection has no repository argument. It never includes raw gate/final paths, split manifests, hidden seeds, credentials, tokens, or `eval_cmd_test`; C10 owns gate capability plumbing.

The flat mapping is an audit view. Injection uses four detached views because Arbor has separate ownership seams:

- `tree_meta()` → `TreeSetMeta`: development `eval_cmd`, direction, optional baseline;
- `config_overrides()` → `CoordinatorConfig`: independent trunk and protected paths;
- `plugin_overrides()` → Arbor plugin/merge guard: protected paths and required outputs;
- `audit_metadata()` → Q-Arbor's external session artifact: contract identity and projection version.

The emitted `q_arbor.evaluation` command is a C9 forward interface. C7 freezes and quotes the template but does not execute or claim an evaluator implementation.

## Test boundary

Synthetic fixtures must cover valid round-trip/hash stability plus missing field, duplicate key, non-finite value, excessive nesting, Unicode equivalence, invalid hash, time overlap and overflow, unsafe/oversized/overlapping path, literal and editable required outputs, opaque split identities, distinct split manifests, threshold locator smuggling, bad role capability, incomplete final split, secret-like field, projection quoting, and projection non-leakage.
