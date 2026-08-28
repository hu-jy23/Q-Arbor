# Security and data boundary

## Report vulnerabilities

Please report security issues privately to the repository owner before public disclosure.

## Never commit

- API keys, cookies, provider tokens or capability secrets;
- raw or derived row-level benchmark data;
- hidden labels, unopened time tails or sealed inputs;
- protected evaluator or selector implementations;
- internal Agent prompts, sessions, worktrees, attempts or ledgers;
- virtual environments, caches, coverage files or build products.

The default `.gitignore` blocks common credential, data and generated-artifact paths. Task integrations should expose only hash-addressed identities to Q-Arbor's shared control plane.
