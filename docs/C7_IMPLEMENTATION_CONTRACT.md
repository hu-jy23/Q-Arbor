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

## Arbor projection API

`q_arbor.integrations` must export `ArborRunProjection` and `project_to_arbor(contract, *, contract_path, trunk_branch, baseline_score=None)`.

The projection exposes a new mapping on every call. It includes development `eval_cmd`, `metric_direction`, `trunk_branch`, `protected_paths`, `required_outputs`, contract/baseline references, and optional verified `baseline_score`. It never includes raw gate/final paths, split manifests, hidden seeds, credentials, tokens, or `eval_cmd_test`; C10 owns gate capability plumbing.

## Test boundary

Synthetic fixtures must cover valid round-trip/hash stability plus missing field, duplicate key, non-finite value, Unicode equivalence, invalid hash, time overlap, unsafe/overlapping path, bad role capability, incomplete final split, secret-like field, projection quoting, and projection non-leakage.

