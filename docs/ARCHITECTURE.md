# Architecture

## Control path

```text
task contract
    ↓
proposal snapshot → isolated dispatch → capability gate + budget debit
                                          ↓
                                  task-local runner
                                          ↓
                                  result envelope
                                          ↓
typed decision → hypothesis-tree update → checkpoint / report
```

## Shared core

The shared core owns:

- typed hypothesis and evidence state;
- proposal, dispatch, evaluation and decision identity;
- evaluation capability checks and persistent budget accounting;
- metric-neutral result handling;
- recovery, finalization and research-package generation.

## Task-local boundary

A task integration owns:

- candidate and invocation codecs;
- data and split identities;
- metric definitions and optimization direction;
- runner environment and required outputs;
- evaluator implementation and protected labels;
- namespaced stage policy and feedback rules.

The core treats task, metric, objective and stage identifiers as open values. Structured predictions remain artifact references; the core does not inspect task data schemas.

## Identity chain

Accepted results bind the cell contract, candidate, adapter, runner, evaluator, data manifest, split manifest, environment lock, stage policy, code commit and artifact manifest. Missing, invalid or delayed results remain explicit typed states.

## Relationship to Arbor

Arbor supplies the persistent Coordinator/Executor and Hypothesis-Tree Refinement substrate. Q-Arbor adds quantitative task contracts, stage-aware evaluation governance, identity-bound result handling, a persistent evidence ledger and recoverable public research packages.
