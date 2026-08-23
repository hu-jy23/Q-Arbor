# Q-Arbor

> Status: **Q-Arbor prototype**. C13 naming qualification passed on synthetic and HM1 engineering evidence. This status does not claim benchmark superiority, OOS generalization, statistical control, or trading readiness.

Q-Arbor adapts Arbor's persistent Coordinator and Hypothesis-Tree Refinement substrate to auditable quantitative research. It binds a frozen quantitative task contract, typed hypothesis tree, refinement control path, task plugins, evaluation firewall/evidence ledger, and recovery/report package into one auditable prototype.

## Prototype scope

- freeze and validate a canonical `QuantResearchContract` before launch;
- persist a typed Q-Hypothesis Tree with family, scope, evidence, failure, and lineage;
- execute a bounded propose→dispatch→evaluate→decide refinement path;
- evaluate synthetic and HM1 candidates through the same typed plugin boundary;
- enforce split capabilities and append-only evidence-ledger history;
- recover interrupted sessions and emit auditable ResearchPackage/HTML reports.

The C13 qualification covers mechanism and engineering operability. Formal benchmarks, native-baseline comparisons, ablations, repeated statistical experiments, HM2 OOS validation, sealed-final access, and performance conclusions remain later-goal work.

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

`project_to_arbor(...)` returns separate `tree_meta()`, `config_overrides()`, `plugin_overrides()`, and `audit_metadata()` views. Executable evaluation remains behind the typed plugin and capability-broker boundaries.

The tracked `configs/`, `benchmarks/`, `artifacts/`, and `.q-arbor/sessions/` READMEs freeze ownership and data boundaries. Generated artifacts, sessions, and all raw market data remain ignored.
