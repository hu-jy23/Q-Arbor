# Benchmark adapters

This directory reserves task-owned adapters while control logic remains under `q_arbor`.

- `synthetic/`: null/planted-signal fixtures for mechanism tests;
- `hm1_futures/`: schema/access adapter only; restricted raw data stays in its original user-owned location;
- `formula_alpha/`: future public formula-alpha contract seam.

C7 defines no executable evaluator here. The shared `QuantTaskPlugin` interface and evaluators are C9 work; formal benchmark protocols are a later goal.

