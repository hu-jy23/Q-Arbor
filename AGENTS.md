# Q-Arbor contributor contract

- This repository is a **Q-Arbor prototype** qualified by C13. Do not describe it as benchmark-validated, production-ready, statistically superior, or safe for real trading without later-goal evidence.
- Treat `src/q_arbor/spec/C6_INTERFACE_SCHEMA.json` and its recorded hash as frozen C6 input. A schema change requires a new checkpoint decision; ordinary implementation work may not edit it.
- Keep sealed final closed. C7 may describe final capability fields but may not open, query, emulate, or return final data.
- Never copy secrets or restricted HM1 data. Tests use synthetic fixtures only.
- Contract validation is fail-closed. Reject ambiguous JSON, unsafe paths, inconsistent time ranges, invalid role capabilities, incomplete final configuration, secret-like fields, and hash drift before any Arbor call.
- Canonicalization is deterministic UTF-8 JSON with NFC strings, sorted keys, compact separators, and `allow_nan=False`; `contract_hash` is excluded from its own digest.
- Arbor projection is an adapter boundary. It may expose development-safe metadata and protected-path declarations; it may not expose gate/final paths, manifests, seeds, credentials, or raw capability tokens.
- Add tests for every behavior change. Preserve concise evidence comments that cite `C5 Gxx` or `C6 C0x` where the rationale matters.
- Keep dependencies minimal and public. Do not modify the sibling `Arbor/` checkout or user worktrees.
