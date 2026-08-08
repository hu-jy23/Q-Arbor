# Q-Arbor

> Status: **Q-Arbor partial prototype**. The name `Q-Arbor prototype` is reserved until the C13 synthetic and HM1 identity gate passes.

Q-Arbor adapts Arbor's persistent Coordinator and Hypothesis-Tree Refinement substrate to auditable quantitative research. The first implementation checkpoint freezes a quantitative task contract before any research run can start.

## C7 scope

- load strict JSON with duplicate-key and non-finite-number rejection;
- validate a `QuantResearchContract` against the frozen C6 Draft 2020-12 schema and cross-field invariants;
- canonicalize Unicode/JSON, freeze an immutable snapshot, and compute a stable SHA-256 contract identity;
- project only development-safe metadata into Arbor;
- fail before launch on incomplete time, path, capability, final, or hash configuration.

C7 does not implement the hypothesis tree, evaluation firewall, plugins, recovery, formal benchmarks, or sealed-final access. Those remain C8–C13 work.

## Development

```bash
python -m venv .venv
.venv/bin/pip install -e '.[test]'
.venv/bin/python -m pytest
```

The canonical design schema is packaged at `q_arbor/spec/C6_INTERFACE_SCHEMA.json`; its expected SHA-256 is recorded in `q_arbor/spec/MANIFEST.json`.

Basic contract operations:

```bash
q-arbor-contract freeze tests/fixtures/contracts/valid_contract.json --output frozen.json
q-arbor-contract validate frozen.json
q-arbor-contract show-hash frozen.json
```

`project_to_arbor(...)` returns separate `tree_meta()`, `config_overrides()`, `plugin_overrides()`, and `audit_metadata()` views. Its development evaluation command is a forward contract for C9 and is intentionally not executable in C7.
